import type { Plugin } from 'vite';
import {
  isParsedEvtLogLine,
  parseEvtLogLine,
  redactFieldValue,
  sanitizeLogFilename,
  sanitizeEvtLogFields,
} from '../domain/logParser';

const diagnosticLogsPath = '/api/v1/diagnostic-logs';
const diagnosticLogStatuses = ['stored', 'quarantined', 'expired', 'deleted'] as const;
const diagnosticLogAvailableActions = ['view', 'read', 'content', 'download'] as const;
const contentSchemaVersion = 'evt-diagnostic-content-v1';
const maximumDownloadBytes = 20 * 1024 * 1024;
const maximumJsonResponseBytes = 4 * 1024 * 1024;
const upstreamRequestTimeoutMs = 30_000;
const dashboardConfigurationMissingCode = 'dashboard_configuration_missing';
const upstreamErrorCodes = new Set([
  'invalid_file',
  'file_too_large',
  'unauthorized',
  'forbidden',
  'quota_exceeded',
  'storage_unavailable',
  'not_found',
]);
const listQueryKeys = [
  'page',
  'page_size',
  'from',
  'to',
  'app_version',
  'platform',
  'device_ref',
  'trace_id',
  'level',
  'event',
  'error_code',
  'status',
  'keyword',
  'sort',
] as const;

type DashboardApiRoute =
  | { readonly kind: 'list' }
  | { readonly kind: 'detail'; readonly id: string }
  | { readonly kind: 'content'; readonly id: string; readonly requestedCursor?: string }
  | { readonly kind: 'download'; readonly id: string };

interface DashboardReadBffOptions {
  readonly dashboardToken: string;
  readonly target: string;
  readonly fetch?: typeof fetch;
}

interface IncomingRequest {
  readonly method?: string;
  readonly url?: string;
  readonly headers: Readonly<Record<string, string | string[] | undefined>>;
}

interface OutgoingResponse {
  statusCode: number;
  setHeader(name: string, value: string): void;
  end(body?: string | Uint8Array): void;
}

/** Raised when the upstream response cannot be safely normalized for the browser. */
export class DashboardBffContractError extends Error {
  constructor() {
    super('日志服务响应不符合 EVT 看板契约。');
    this.name = 'DashboardBffContractError';
  }
}

class DashboardBffPayloadLimitError extends Error {
  constructor() {
    super('日志响应超过本机联调允许的大小。');
    this.name = 'DashboardBffPayloadLimitError';
  }
}

/**
 * Creates the local-only read BFF used by the Vite development server.
 * The browser never receives the dashboard token or unapproved upstream fields.
 */
export function createDashboardReadBff(options: DashboardReadBffOptions): Plugin {
  const dashboardToken = options.dashboardToken.trim();
  const target = new URL(options.target).origin;
  const requestFetch = options.fetch ?? globalThis.fetch.bind(globalThis);

  return {
    name: 'evt-dashboard-read-bff',
    configureServer(server) {
      server.middlewares.use((request, response, next) => {
        const incomingRequest = request as unknown as IncomingRequest;
        const outgoingResponse = response as unknown as OutgoingResponse;
        const route = resolveDashboardRoute(incomingRequest.url);

        if (route === undefined) {
          next();
          return;
        }
        if (route === null) {
          sendJson(outgoingResponse, 404, { code: 'not_found' });
          return;
        }
        applyLoopbackCors(incomingRequest, outgoingResponse);
        if (incomingRequest.method !== 'GET' && incomingRequest.method !== 'HEAD') {
          sendJson(outgoingResponse, 405, { code: 'method_not_allowed' }, { Allow: 'GET, HEAD' });
          return;
        }

        void forwardDashboardRead({
          request: incomingRequest,
          response: outgoingResponse,
          route,
          dashboardToken,
          target,
          requestFetch,
        });
      });
    },
  };
}

/**
 * The Vite server binds to loopback, but users commonly open either
 * `localhost` or `127.0.0.1`. Treat those two development origins as the
 * same local dashboard and keep credentialed requests usable without opening
 * the proxy to arbitrary web origins.
 */
function applyLoopbackCors(request: IncomingRequest, response: OutgoingResponse): void {
  const origin = headerValue(request.headers, 'origin');
  if (origin !== 'http://localhost:5173' && origin !== 'http://127.0.0.1:5173') {
    return;
  }
  response.setHeader('Access-Control-Allow-Origin', origin);
  response.setHeader('Access-Control-Allow-Credentials', 'true');
  response.setHeader('Vary', 'Origin');
}

function headerValue(
  headers: Readonly<Record<string, string | string[] | undefined>>,
  name: string,
): string | undefined {
  const value = headers[name] ?? headers[name.toLowerCase()];
  return Array.isArray(value) ? value[0] : value;
}

/**
 * Converts a narrow, approved subset of the upstream response into the exact
 * browser contract. The legacy content form is parsed and redacted before it
 * is serialized, so raw lines never enter Vue state.
 */
export function normalizeDashboardApiPayload(route: DashboardApiRoute, payload: unknown): unknown {
  if (route.kind === 'list') {
    return normalizeListResponse(payload);
  }
  if (route.kind === 'detail') {
    return normalizeDetailResponse(payload, route.id);
  }
  if (route.kind === 'content') {
    return normalizeContentResponse(payload, route.id, route.requestedCursor);
  }
  return payload;
}

async function forwardDashboardRead(input: {
  readonly request: IncomingRequest;
  readonly response: OutgoingResponse;
  readonly route: DashboardApiRoute;
  readonly dashboardToken: string;
  readonly target: string;
  readonly requestFetch: typeof fetch;
}): Promise<void> {
  // Keep the API route JSON-shaped when the local proxy was started without a
  // dashboard credential.  Without this guard Vite's SPA fallback returns
  // index.html, which the browser reports as a misleading contract failure.
  if (!input.dashboardToken) {
    sendJson(input.response, 503, { code: dashboardConfigurationMissingCode });
    return;
  }

  const abortController = new AbortController();
  const timeout = setTimeout(() => abortController.abort(), upstreamRequestTimeoutMs);
  try {
    const requestUrl = new URL(input.request.url ?? '/', 'http://dashboard.local');
    const upstreamUrl = createUpstreamUrl(requestUrl, input.route, input.target);
    const upstreamResponse = await input.requestFetch(upstreamUrl, {
      method: input.request.method,
      headers: {
        Accept: input.route.kind === 'download' ? 'application/octet-stream' : 'application/json',
        Authorization: `Bearer ${input.dashboardToken}`,
      },
      signal: abortController.signal,
    });

    if (input.request.method === 'HEAD') {
      forwardHeadResponse(input.response, upstreamResponse);
      return;
    }
    if (!upstreamResponse.ok) {
      sendJson(input.response, upstreamResponse.status, {
        code: await readStableErrorCode(upstreamResponse),
      });
      return;
    }
    if (input.route.kind === 'download') {
      await forwardDownloadResponse(input.response, upstreamResponse);
      return;
    }

    const payload = await readJsonPayload(upstreamResponse);
    const normalized = normalizeDashboardApiPayload(input.route, payload);
    sendJson(input.response, upstreamResponse.status, normalized);
  } catch (error) {
    if (error instanceof DashboardBffContractError) {
      sendJson(input.response, 502, { code: 'upstream_contract_invalid' });
      return;
    }
    if (error instanceof DashboardBffPayloadLimitError) {
      sendJson(input.response, 413, { code: 'file_too_large' });
      return;
    }
    sendJson(input.response, 502, { code: 'storage_unavailable' });
  } finally {
    clearTimeout(timeout);
  }
}

function createUpstreamUrl(requestUrl: URL, route: DashboardApiRoute, target: string): URL {
  const upstreamUrl = new URL(requestUrl.pathname, target);
  if (route.kind === 'list') {
    for (const key of listQueryKeys) {
      const value = requestUrl.searchParams.get(key);
      if (value) {
        upstreamUrl.searchParams.set(key, value);
      }
    }
    return upstreamUrl;
  }
  if (route.kind === 'content') {
    if (route.requestedCursor !== undefined) {
      upstreamUrl.searchParams.set('cursor', route.requestedCursor);
    }
    const requestedLimit = requestUrl.searchParams.get('limit');
    if (requestedLimit !== null) {
      if (!/^[1-9]\d*$/.test(requestedLimit) || Number(requestedLimit) > 500) {
        throw new DashboardBffContractError();
      }
      upstreamUrl.searchParams.set('limit', requestedLimit);
    }
  }
  return upstreamUrl;
}

function resolveDashboardRoute(requestUrl: string | undefined): DashboardApiRoute | null | undefined {
  const parsedUrl = new URL(requestUrl ?? '/', 'http://dashboard.local');
  const { pathname } = parsedUrl;
  if (pathname !== diagnosticLogsPath && !pathname.startsWith(`${diagnosticLogsPath}/`)) {
    return undefined;
  }
  if (pathname === diagnosticLogsPath) {
    return { kind: 'list' };
  }

  const suffix = pathname.slice(`${diagnosticLogsPath}/`.length);
  const segments = suffix.split('/');
  const id = decodeIdentifier(segments[0]);
  if (!id) {
    return null;
  }
  if (segments.length === 1) {
    return { kind: 'detail', id };
  }
  if (segments.length === 2 && segments[1] === 'content') {
    const requestedCursor = parsedUrl.searchParams.get('cursor') ?? undefined;
    return { kind: 'content', id, requestedCursor };
  }
  if (segments.length === 2 && segments[1] === 'download') {
    return { kind: 'download', id };
  }
  return null;
}

function decodeIdentifier(value: string | undefined): string | undefined {
  if (!value) {
    return undefined;
  }
  try {
    const decoded = decodeURIComponent(value);
    return isDiagnosticLogIdentifier(decoded) ? decoded : undefined;
  } catch {
    return undefined;
  }
}

function normalizeListResponse(payload: unknown): Record<string, unknown> {
  if (!isPlainRecord(payload)
    || !Array.isArray(payload.items)
    || !isPositiveSafeInteger(payload.page)
    || !isPositiveSafeInteger(payload.page_size)
    || !isNonNegativeSafeInteger(payload.total)) {
    throw new DashboardBffContractError();
  }

  return {
    items: payload.items.map(normalizeListItem),
    page: payload.page,
    page_size: payload.page_size,
    total: payload.total,
  };
}

function normalizeListItem(value: unknown): Record<string, unknown> {
  if (!isPlainRecord(value)
    || !isDiagnosticLogIdentifier(value.id)
    || !isUtcIsoTimestamp(value.received_at)
    || !isDiagnosticLogStatus(value.status)) {
    throw new DashboardBffContractError();
  }

  const item: Record<string, unknown> = {
    id: value.id,
    received_at: value.received_at,
    status: value.status,
  };
  assignOptionalUtcIsoTimestamp(item, 'uploaded_at', value.uploaded_at);
  assignOptionalString(item, 'app_version', value.app_version);
  assignOptionalString(item, 'platform', value.platform);
  assignOptionalDeviceRef(item, value.device_ref);
  assignOptionalNonNegativeNumber(item, 'bytes', value.bytes);
  assignOptionalStringArray(item, 'error_codes', value.error_codes);
  assignOptionalNonNegativeSafeInteger(item, 'warning_count', value.warning_count);
  assignOptionalNonNegativeSafeInteger(item, 'error_count', value.error_count);
  return item;
}

function normalizeDetailResponse(payload: unknown, expectedId: string): Record<string, unknown> {
  if (!isPlainRecord(payload)
    || payload.id !== expectedId
    || !isDiagnosticLogIdentifier(payload.id)
    || !isDiagnosticLogStatus(payload.status)) {
    throw new DashboardBffContractError();
  }

  const detail: Record<string, unknown> = {
    id: payload.id,
    status: payload.status,
  };
  assignOptionalFilename(detail, payload.source_filename);
  assignOptionalUtcIsoTimestamp(detail, 'received_at', payload.received_at);
  assignOptionalUtcIsoTimestamp(detail, 'uploaded_at', payload.uploaded_at);
  assignOptionalNonNegativeNumber(detail, 'bytes', payload.bytes);
  assignOptionalDeviceRef(detail, payload.device_ref);
  assignOptionalActions(detail, payload.available_actions);
  return detail;
}

function normalizeContentResponse(
  payload: unknown,
  expectedId: string,
  requestedCursor: string | undefined,
): Record<string, unknown> {
  if (!isPlainRecord(payload)) {
    throw new DashboardBffContractError();
  }
  if (payload.schema_version === contentSchemaVersion) {
    return normalizeStructuredContentResponse(payload, expectedId, requestedCursor);
  }
  if (payload.schema === contentSchemaVersion) {
    return normalizeLegacyContentResponse(payload, expectedId, requestedCursor);
  }
  throw new DashboardBffContractError();
}

function normalizeStructuredContentResponse(
  payload: Record<string, unknown>,
  expectedId: string,
  requestedCursor: string | undefined,
): Record<string, unknown> {
  const expectedResponseCursor = requestedCursor ?? null;
  if (payload.id !== expectedId
    || payload.cursor !== expectedResponseCursor
    || !isNullableString(payload.next_cursor)
    || typeof payload.has_more !== 'boolean'
    || !Array.isArray(payload.items)
    || (payload.has_more && !payload.next_cursor)
    || (!payload.has_more && payload.next_cursor !== null)) {
    throw new DashboardBffContractError();
  }

  return {
    schema_version: contentSchemaVersion,
    id: expectedId,
    cursor: expectedResponseCursor,
    next_cursor: payload.next_cursor,
    has_more: payload.has_more,
    items: payload.items.map(normalizeStructuredContentItem),
  };
}

function normalizeStructuredContentItem(value: unknown): Record<string, unknown> {
  if (!isPlainRecord(value)
    || !isPositiveSafeInteger(value.line_no)
    || !isContentParseStatus(value.parse_status)) {
    throw new DashboardBffContractError();
  }

  const item: Record<string, unknown> = {
    line_no: value.line_no,
    parse_status: value.parse_status,
  };
  if (value.parse_status !== 'parsed') {
    return item;
  }
  if (typeof value.timestamp !== 'string'
    || typeof value.level !== 'string'
    || typeof value.scope !== 'string'
    || typeof value.event !== 'string') {
    throw new DashboardBffContractError();
  }

  item.timestamp = value.timestamp;
  item.level = value.level;
  item.scope = value.scope;
  item.event = value.event;
  assignOptionalString(item, 'trace_id', value.trace_id);
  assignOptionalString(item, 'operation', value.operation);
  assignOptionalString(item, 'stage', value.stage);
  assignOptionalString(item, 'result', value.result);
  assignOptionalNonNegativeNumber(item, 'elapsed_ms', value.elapsed_ms);
  if (value.fields !== undefined && value.fields !== null) {
    if (!isPlainRecord(value.fields)) {
      throw new DashboardBffContractError();
    }
    item.fields = sanitizeEvtLogFields(value.fields);
  }
  return item;
}

function normalizeLegacyContentResponse(
  payload: Record<string, unknown>,
  expectedId: string,
  requestedCursor: string | undefined,
): Record<string, unknown> {
  const expectedLegacyCursor = requestedCursor ?? '0';
  if (payload.id !== expectedId
    || payload.cursor !== expectedLegacyCursor
    || !isLegacyOffset(payload.cursor)
    || !Array.isArray(payload.lines)
    || !payload.lines.every((line) => typeof line === 'string')
    || typeof payload.has_more !== 'boolean'
    || !isNullableString(payload.next_cursor)
    || (payload.has_more && !isLegacyOffset(payload.next_cursor))
    || (!payload.has_more && payload.next_cursor !== null)) {
    throw new DashboardBffContractError();
  }

  const offset = Number(payload.cursor);
  const nextCursor = payload.next_cursor;
  if (payload.has_more && Number(nextCursor) <= offset) {
    throw new DashboardBffContractError();
  }
  if (offset > Number.MAX_SAFE_INTEGER - payload.lines.length) {
    throw new DashboardBffContractError();
  }

  return {
    schema_version: contentSchemaVersion,
    id: expectedId,
    cursor: requestedCursor ?? null,
    next_cursor: nextCursor,
    has_more: payload.has_more,
    items: payload.lines.map((line, index) => normalizeLegacyLine(line, offset + index + 1)),
  };
}

function normalizeLegacyLine(line: string, lineNumber: number): Record<string, unknown> {
  const parsed = parseEvtLogLine(line, lineNumber);
  if (!isParsedEvtLogLine(parsed)) {
    return {
      line_no: lineNumber,
      parse_status: parsed.parseStatus,
    };
  }

  const item: Record<string, unknown> = {
    line_no: lineNumber,
    parse_status: 'parsed',
    timestamp: parsed.timestamp,
    level: parsed.level,
    scope: parsed.scope,
    event: parsed.event,
    elapsed_ms: parsed.elapsedMs,
  };
  if (parsed.traceId) item.trace_id = parsed.traceId;
  if (parsed.operation) item.operation = parsed.operation;
  if (parsed.stage) item.stage = parsed.stage;
  if (parsed.result) item.result = parsed.result;
  if (Object.keys(parsed.fields).length > 0) item.fields = parsed.fields;
  return item;
}

function assignOptionalString(target: Record<string, unknown>, key: string, value: unknown): void {
  if (value === undefined || value === null) {
    return;
  }
  if (typeof value !== 'string') {
    throw new DashboardBffContractError();
  }
  target[key] = value;
}

function assignOptionalFilename(target: Record<string, unknown>, value: unknown): void {
  if (value === undefined || value === null) {
    return;
  }
  if (typeof value !== 'string') {
    throw new DashboardBffContractError();
  }
  target.source_filename = sanitizeLogFilename(value, '服务器日志.log');
}

function assignOptionalDeviceRef(target: Record<string, unknown>, value: unknown): void {
  if (value === undefined || value === null) {
    return;
  }
  if (typeof value !== 'string') {
    throw new DashboardBffContractError();
  }
  const sanitized = redactFieldValue('device_ref', value).trim();
  if (sanitized && !sanitized.includes('已隐藏')) {
    target.device_ref = sanitized;
  }
}

function assignOptionalUtcIsoTimestamp(target: Record<string, unknown>, key: string, value: unknown): void {
  if (value === undefined || value === null) {
    return;
  }
  if (!isUtcIsoTimestamp(value)) {
    throw new DashboardBffContractError();
  }
  target[key] = value;
}

function assignOptionalNonNegativeNumber(target: Record<string, unknown>, key: string, value: unknown): void {
  if (value === undefined || value === null) {
    return;
  }
  if (!isNonNegativeNumber(value)) {
    throw new DashboardBffContractError();
  }
  target[key] = value;
}

function assignOptionalNonNegativeSafeInteger(target: Record<string, unknown>, key: string, value: unknown): void {
  if (value === undefined || value === null) {
    return;
  }
  if (!isNonNegativeSafeInteger(value)) {
    throw new DashboardBffContractError();
  }
  target[key] = value;
}

function assignOptionalStringArray(target: Record<string, unknown>, key: string, value: unknown): void {
  if (value === undefined || value === null) {
    return;
  }
  if (!Array.isArray(value) || !value.every((entry) => typeof entry === 'string')) {
    throw new DashboardBffContractError();
  }
  target[key] = [...value];
}

function assignOptionalActions(target: Record<string, unknown>, value: unknown): void {
  if (value === undefined || value === null) {
    return;
  }
  if (!Array.isArray(value)
    || !value.every((action) => typeof action === 'string' && diagnosticLogAvailableActions.includes(action as (typeof diagnosticLogAvailableActions)[number]))) {
    throw new DashboardBffContractError();
  }
  target.available_actions = [...value];
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isDiagnosticLogIdentifier(value: unknown): value is string {
  return typeof value === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,191}$/.test(value);
}

function isDiagnosticLogStatus(value: unknown): value is (typeof diagnosticLogStatuses)[number] {
  return typeof value === 'string' && diagnosticLogStatuses.includes(value as (typeof diagnosticLogStatuses)[number]);
}

function isUtcIsoTimestamp(value: unknown): value is string {
  return typeof value === 'string'
    && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(value)
    && !Number.isNaN(Date.parse(value));
}

function isContentParseStatus(value: unknown): value is 'parsed' | 'unparsed' | 'redacted' {
  return value === 'parsed' || value === 'unparsed' || value === 'redacted';
}

function isPositiveSafeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
}

function isNonNegativeSafeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function isNonNegativeNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0;
}

function isNullableString(value: unknown): value is string | null {
  return value === null || typeof value === 'string';
}

function isLegacyOffset(value: unknown): value is string {
  return typeof value === 'string' && /^(?:0|[1-9]\d*)$/.test(value) && Number.isSafeInteger(Number(value));
}

async function readJsonPayload(response: Response): Promise<unknown> {
  try {
    const bytes = await readBoundedBody(response, maximumJsonResponseBytes);
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch (error) {
    if (error instanceof DashboardBffPayloadLimitError) {
      throw error;
    }
    throw new DashboardBffContractError();
  }
}

async function readStableErrorCode(response: Response): Promise<string> {
  try {
    const payload = await response.json();
    if (isPlainRecord(payload) && typeof payload.code === 'string' && upstreamErrorCodes.has(payload.code)) {
      return payload.code;
    }
  } catch {
    // The browser only needs a stable error code, never an upstream body.
  }
  return 'upstream_request_failed';
}

async function forwardDownloadResponse(response: OutgoingResponse, upstream: Response): Promise<void> {
  const content = await readBoundedBody(upstream, maximumDownloadBytes);
  response.statusCode = upstream.status;
  copySafeResponseHeader(response, upstream, 'content-type');
  copySafeResponseHeader(response, upstream, 'content-disposition');
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('Content-Length', String(content.byteLength));
  response.end(content);
}

function forwardHeadResponse(response: OutgoingResponse, upstream: Response): void {
  response.statusCode = upstream.status;
  copySafeResponseHeader(response, upstream, 'content-type');
  copySafeResponseHeader(response, upstream, 'content-disposition');
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.end();
}

function copySafeResponseHeader(response: OutgoingResponse, upstream: Response, name: string): void {
  const value = upstream.headers.get(name);
  if (value) {
    response.setHeader(name, value);
  }
}

function sendJson(
  response: OutgoingResponse,
  status: number,
  body: unknown,
  extraHeaders: Readonly<Record<string, string>> = {},
): void {
  const serialized = JSON.stringify(body);
  response.statusCode = status;
  response.setHeader('Content-Type', 'application/json; charset=utf-8');
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('X-Content-Type-Options', 'nosniff');
  for (const [name, value] of Object.entries(extraHeaders)) {
    response.setHeader(name, value);
  }
  response.end(serialized);
}

async function readBoundedBody(response: Response, maximumBytes: number): Promise<Uint8Array> {
  const advertisedLength = response.headers.get('content-length');
  if (advertisedLength && /^\d+$/.test(advertisedLength) && Number(advertisedLength) > maximumBytes) {
    throw new DashboardBffPayloadLimitError();
  }
  if (!response.body) {
    return new Uint8Array();
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      length += value.byteLength;
      if (length > maximumBytes) {
        await reader.cancel();
        throw new DashboardBffPayloadLimitError();
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const content = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    content.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return content;
}
