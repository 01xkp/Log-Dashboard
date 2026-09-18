/**
 * EVT diagnostic-log dashboard API client.
 *
 * `baseUrl` is the backend origin, for example `https://logs.example.com`.
 * The diagnostic-log API path is intentionally fixed by the server contract.
 * When no base URL is configured this client rejects before calling `fetch`.
 */

import { sanitizeEvtLogFields } from '../domain/logParser';

const diagnosticLogStatuses = ['stored', 'quarantined', 'expired', 'deleted'] as const;
const diagnosticLogAvailableActions = ['view', 'read', 'content', 'download'] as const;

export type DiagnosticLogStatus = (typeof diagnosticLogStatuses)[number];
export type DiagnosticLogAvailableAction = (typeof diagnosticLogAvailableActions)[number];

export interface DiagnosticLogListItem {
  id: string;
  received_at: string;
  uploaded_at?: string;
  app_version?: string;
  platform?: string;
  device_ref?: string;
  bytes?: number;
  status: DiagnosticLogStatus;
  error_codes?: string[];
  warning_count?: number;
  error_count?: number;
}

export interface DiagnosticLogListResponse {
  items: DiagnosticLogListItem[];
  page: number;
  page_size: number;
  total: number;
}

export interface DiagnosticLogListQuery {
  page?: number;
  page_size?: number;
  from?: string;
  to?: string;
  app_version?: string;
  platform?: string;
  device_ref?: string;
  trace_id?: string;
  level?: string;
  event?: string;
  error_code?: string;
  status?: DiagnosticLogStatus;
  keyword?: string;
  sort?: 'received_at:desc' | 'received_at:asc';
}

export interface DiagnosticLogDetail {
  id: string;
  source_filename?: string;
  received_at?: string;
  uploaded_at?: string;
  app_id?: string;
  app_version?: string;
  platform?: string;
  device_ref?: string;
  trace_id?: string;
  bytes?: number;
  sha256?: string;
  status: DiagnosticLogStatus;
  severity_counts?: Record<string, number>;
  error_codes?: string[];
  parse_status?: string;
  summary?: string;
  available_actions?: DiagnosticLogAvailableAction[];
  [key: string]: unknown;
}

export type DiagnosticLogContentParseStatus = 'parsed' | 'unparsed' | 'redacted';

export interface DiagnosticLogContentItem {
  line_no: number;
  parse_status: DiagnosticLogContentParseStatus;
  timestamp?: string;
  level?: string;
  scope?: string;
  trace_id?: string;
  operation?: string;
  stage?: string;
  event?: string;
  result?: string;
  elapsed_ms?: number | null;
  fields?: Record<string, unknown>;
  summary?: string;
}

export interface DiagnosticLogContentResponse {
  schema_version: 'evt-diagnostic-content-v1' | string;
  id: string;
  cursor: string | null;
  next_cursor: string | null;
  has_more: boolean;
  items: DiagnosticLogContentItem[];
}

export interface DiagnosticLogContentQuery {
  cursor?: string;
  limit?: number;
}

export interface DiagnosticLogApiClientOptions {
  /** Backend origin. When defined, overrides the runtime service address. */
  baseUrl?: string | null;
  /** Injection point for tests or alternate browser runtimes. */
  fetch?: typeof fetch;
}

interface RuntimeApiConfig {
  VITE_LOG_API_BASE_URL?: unknown;
  API_BASE_URL?: unknown;
  VITE_API_BASE_URL?: unknown;
}

interface RuntimeGlobal {
  __LOG_DASHBOARD_CONFIG__?: RuntimeApiConfig;
  process?: { env?: RuntimeApiConfig };
}

const diagnosticLogsPath = '/api/v1/diagnostic-logs';

/** Raised before a request when the dashboard has no approved API address. */
export class LogApiConfigurationError extends Error {
  readonly code = 'api_base_url_missing';

  constructor() {
    super(
      '未配置日志服务地址，日志看板不会发起真实网络请求。请设置 VITE_LOG_API_BASE_URL，或创建客户端时传入 baseUrl。',
    );
    this.name = 'LogApiConfigurationError';
  }
}

/** A stable, display-safe summary of a backend HTTP failure. */
export class LogApiRequestError extends Error {
  readonly status: number;
  readonly code?: string;

  constructor(status: number, message: string, code?: string) {
    super(message);
    this.name = 'LogApiRequestError';
    this.status = status;
    this.code = code;
  }
}

/** Raised when an otherwise successful response violates the dashboard contract. */
export class LogApiContractError extends Error {
  readonly code: 'response_not_json' | 'list_contract_invalid' | 'detail_contract_invalid' | 'content_contract_invalid';

  constructor(code: LogApiContractError['code'] = 'content_contract_invalid') {
    super(
      code === 'content_contract_invalid'
        ? '日志内容响应不符合 EVT 看板契约，已停止加载以避免误判。'
        : '日志服务响应不符合 EVT 看板契约，已停止加载以避免误判。',
    );
    this.name = 'LogApiContractError';
    this.code = code;
  }
}

/**
 * Reads explicitly injected runtime configuration first, then build-time Vite
 * configuration. The latter is intentionally read without requiring Vite
 * types, so this file can also be consumed by tests or another Vue build tool.
 */
export function getConfiguredApiBaseUrl(): string | undefined {
  const runtime = globalThis as typeof globalThis & RuntimeGlobal;
  const viteEnvironment = (import.meta as { env?: RuntimeApiConfig }).env ?? {};
  const configured =
    runtime.__LOG_DASHBOARD_CONFIG__?.VITE_LOG_API_BASE_URL ??
    runtime.__LOG_DASHBOARD_CONFIG__?.API_BASE_URL ??
    runtime.__LOG_DASHBOARD_CONFIG__?.VITE_API_BASE_URL ??
    runtime.process?.env?.VITE_LOG_API_BASE_URL ??
    runtime.process?.env?.API_BASE_URL ??
    runtime.process?.env?.VITE_API_BASE_URL ??
    viteEnvironment.VITE_LOG_API_BASE_URL ??
    viteEnvironment.API_BASE_URL ??
    viteEnvironment.VITE_API_BASE_URL;

  return normalizeBaseUrl(configured);
}

/**
 * Creates a client for the server contract described in
 * `evt-log-service-dashboard-requirements.md`.
 */
export function createDiagnosticLogApi(
  options: DiagnosticLogApiClientOptions = {},
) {
  const configuredBaseUrl = options.baseUrl === undefined
    ? getConfiguredApiBaseUrl()
    : normalizeBaseUrl(options.baseUrl);
  const requestFetch = options.fetch ?? globalThis.fetch?.bind(globalThis);

  function endpoint(path = ''): string {
    if (!configuredBaseUrl) {
      throw new LogApiConfigurationError();
    }

    return `${configuredBaseUrl}${diagnosticLogsPath}${path}`;
  }

  async function request(path = '', query?: object): Promise<unknown> {
    const url = new URL(endpoint(path));

    if (!requestFetch) {
      throw new LogApiRequestError(0, '当前运行环境不支持 fetch，无法请求日志服务。');
    }

    appendQuery(url.searchParams, query);

    const response = await requestFetch(url.toString(), {
      method: 'GET',
      credentials: 'include',
    });

    if (!response.ok) {
      throw await createRequestError(response);
    }

    try {
      return await response.json();
    } catch {
      throw new LogApiContractError('response_not_json');
    }
  }

  return {
    list(query: DiagnosticLogListQuery = {}) {
      return request('', query).then(validateDiagnosticLogListResponse);
    },

    get(id: string) {
      const expectedId = requireIdentifier(id, '日志 ID');
      return request(`/${encodeURIComponent(expectedId)}`).then((response) => (
        validateDiagnosticLogDetail(response, expectedId)
      ));
    },

    getContent(id: string, query: DiagnosticLogContentQuery = {}) {
      const expectedId = requireIdentifier(id, '日志 ID');
      return request(
        `/${encodeURIComponent(expectedId)}/content`,
        query,
      ).then((response) => validateDiagnosticLogContentResponse(response, expectedId, query.cursor));
    },

    /**
     * Returns the protected download endpoint. Navigate to this URL from the
     * UI so browser cookies or the server's signed redirect remain effective.
     */
    getDownloadUrl(id: string) {
      return endpoint(`/${encodeRequiredPathSegment(id, '日志 ID')}/download`);
    },
  };
}

export type DiagnosticLogApi = ReturnType<typeof createDiagnosticLogApi>;

/** Shared default client. It is inert until VITE_LOG_API_BASE_URL is configured. */
export const diagnosticLogApi = createDiagnosticLogApi();

function normalizeBaseUrl(value: unknown): string | undefined {
  if (typeof value !== 'string') {
    return undefined;
  }

  const trimmed = value.trim();
  if (!trimmed) {
    return undefined;
  }

  try {
    const url = new URL(trimmed);
    if (url.protocol === 'https:') {
      return url.origin;
    }
    if (url.protocol !== 'http:' || !isLoopbackHost(url.hostname)) {
      return undefined;
    }
    return url.origin;
  } catch {
    return undefined;
  }
}

function isLoopbackHost(hostname: string): boolean {
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]';
}

function appendQuery(searchParams: URLSearchParams, query?: object): void {
  if (!query) {
    return;
  }

  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null || value === '') {
      continue;
    }
    searchParams.set(key, String(value));
  }
}

function encodeRequiredPathSegment(value: string, label: string): string {
  return encodeURIComponent(requireIdentifier(value, label));
}

function requireIdentifier(value: string, label: string): string {
  const normalized = value.trim();
  if (!isDiagnosticLogIdentifier(normalized)) {
    throw new LogApiRequestError(0, `${label}不能为空。`);
  }
  return normalized;
}

function validateDiagnosticLogListResponse(response: unknown): DiagnosticLogListResponse {
  if (!isPlainRecord(response)
    || !Array.isArray(response.items)
    || !isPositiveSafeInteger(response.page)
    || !isPositiveSafeInteger(response.page_size)
    || !isNonNegativeSafeInteger(response.total)) {
    throw new LogApiContractError('list_contract_invalid');
  }

  return {
    items: response.items.map(validateDiagnosticLogListItem),
    page: response.page,
    page_size: response.page_size,
    total: response.total,
  };
}

function validateDiagnosticLogListItem(value: unknown): DiagnosticLogListItem {
  if (!isPlainRecord(value)
    || !isDiagnosticLogIdentifier(value.id)
    || !isUtcIsoTimestamp(value.received_at)
    || !isOptionalUtcIsoTimestamp(value.uploaded_at)
    || !isDiagnosticLogStatus(value.status)
    || !isOptionalString(value.app_version)
    || !isOptionalString(value.platform)
    || !isOptionalString(value.device_ref)
    || !isOptionalNonNegativeNumber(value.bytes)
    || !isOptionalStringArray(value.error_codes)
    || !isOptionalNonNegativeSafeInteger(value.warning_count)
    || !isOptionalNonNegativeSafeInteger(value.error_count)) {
    throw new LogApiContractError('list_contract_invalid');
  }

  const item: DiagnosticLogListItem = {
    id: value.id,
    received_at: value.received_at,
    status: value.status,
  };
  if (typeof value.uploaded_at === 'string') item.uploaded_at = value.uploaded_at;
  if (typeof value.app_version === 'string') item.app_version = value.app_version;
  if (typeof value.platform === 'string') item.platform = value.platform;
  if (typeof value.device_ref === 'string') item.device_ref = value.device_ref;
  if (typeof value.bytes === 'number') item.bytes = value.bytes;
  if (Array.isArray(value.error_codes)) item.error_codes = [...value.error_codes] as string[];
  if (typeof value.warning_count === 'number') item.warning_count = value.warning_count;
  if (typeof value.error_count === 'number') item.error_count = value.error_count;
  return item;
}

function validateDiagnosticLogDetail(response: unknown, expectedId: string): DiagnosticLogDetail {
  if (!isPlainRecord(response)
    || response.id !== expectedId
    || !isDiagnosticLogIdentifier(response.id)
    || !isDiagnosticLogStatus(response.status)
    || !isOptionalString(response.source_filename)
    || !isOptionalUtcIsoTimestamp(response.received_at)
    || !isOptionalUtcIsoTimestamp(response.uploaded_at)
    || !isOptionalNonNegativeNumber(response.bytes)
    || !isOptionalString(response.device_ref)
    || !isOptionalDiagnosticLogAvailableActions(response.available_actions)) {
    throw new LogApiContractError('detail_contract_invalid');
  }

  const detail: DiagnosticLogDetail = {
    id: response.id,
    status: response.status,
  };
  if (typeof response.source_filename === 'string') detail.source_filename = response.source_filename;
  if (typeof response.received_at === 'string') detail.received_at = response.received_at;
  if (typeof response.uploaded_at === 'string') detail.uploaded_at = response.uploaded_at;
  if (typeof response.bytes === 'number') detail.bytes = response.bytes;
  if (typeof response.device_ref === 'string') detail.device_ref = response.device_ref;
  if (Array.isArray(response.available_actions)) {
    detail.available_actions = [...response.available_actions] as DiagnosticLogAvailableAction[];
  }
  return detail;
}

function validateDiagnosticLogContentResponse(
  response: unknown,
  expectedId: string,
  requestedCursor: string | undefined,
): DiagnosticLogContentResponse {
  if (!isPlainRecord(response)
    || response.schema_version !== 'evt-diagnostic-content-v1'
    || response.id !== expectedId
    || !isNullableString(response.cursor)
    || !isNullableString(response.next_cursor)
    || typeof response.has_more !== 'boolean'
    || !Array.isArray(response.items)
    || response.cursor !== (requestedCursor ?? null)
    || (response.has_more && (typeof response.next_cursor !== 'string' || !response.next_cursor))
    || (!response.has_more && response.next_cursor !== null)
    || !response.items.every(isDiagnosticLogContentItem)) {
    throw new LogApiContractError();
  }

  return {
    schema_version: response.schema_version,
    id: response.id,
    cursor: response.cursor,
    next_cursor: response.next_cursor,
    has_more: response.has_more,
    items: (response.items as DiagnosticLogContentItem[]).map(sanitizeDiagnosticLogContentItem),
  };
}

/**
 * The API client is the first browser-state boundary. Preserve only fields
 * consumed by the parser and scrub nested values before callers receive them.
 */
function sanitizeDiagnosticLogContentItem(value: DiagnosticLogContentItem): DiagnosticLogContentItem {
  const item: DiagnosticLogContentItem = {
    line_no: value.line_no,
    parse_status: value.parse_status,
  };

  if (value.parse_status !== 'parsed') {
    return item;
  }

  if (typeof value.timestamp === 'string') item.timestamp = value.timestamp;
  if (typeof value.level === 'string') item.level = value.level;
  if (typeof value.scope === 'string') item.scope = value.scope;
  if (typeof value.trace_id === 'string') item.trace_id = value.trace_id;
  if (typeof value.operation === 'string') item.operation = value.operation;
  if (typeof value.stage === 'string') item.stage = value.stage;
  if (typeof value.event === 'string') item.event = value.event;
  if (typeof value.result === 'string') item.result = value.result;
  if (typeof value.elapsed_ms === 'number' || value.elapsed_ms === null) item.elapsed_ms = value.elapsed_ms;
  if (isPlainRecord(value.fields)) item.fields = { ...sanitizeEvtLogFields(value.fields) };

  return item;
}

function isDiagnosticLogContentItem(value: unknown): value is DiagnosticLogContentItem {
  if (!isPlainRecord(value)) {
    return false;
  }
  const lineNumber = value.line_no;
  if (typeof lineNumber !== 'number'
    || !Number.isSafeInteger(lineNumber)
    || lineNumber <= 0
    || !isContentParseStatus(value.parse_status)
    || !isOptionalPlainRecord(value.fields)
    || !isOptionalNonNegativeNumber(value.elapsed_ms)
    || !areOptionalStrings(value, ['timestamp', 'level', 'scope', 'trace_id', 'operation', 'stage', 'event', 'result', 'summary'])) {
    return false;
  }

  return value.parse_status !== 'parsed'
    || (typeof value.timestamp === 'string'
      && typeof value.level === 'string'
      && typeof value.scope === 'string'
      && typeof value.event === 'string');
}

function isContentParseStatus(value: unknown): value is DiagnosticLogContentParseStatus {
  return value === 'parsed' || value === 'unparsed' || value === 'redacted';
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isDiagnosticLogIdentifier(value: unknown): value is string {
  return typeof value === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,191}$/.test(value);
}

function isDiagnosticLogStatus(value: unknown): value is DiagnosticLogStatus {
  return typeof value === 'string' && diagnosticLogStatuses.includes(value as DiagnosticLogStatus);
}

function isUtcIsoTimestamp(value: unknown): value is string {
  return typeof value === 'string'
    && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(value)
    && !Number.isNaN(Date.parse(value));
}

function isOptionalUtcIsoTimestamp(value: unknown): boolean {
  return value === undefined || isUtcIsoTimestamp(value);
}

function isOptionalString(value: unknown): boolean {
  return value === undefined || typeof value === 'string';
}

function isOptionalStringArray(value: unknown): boolean {
  return value === undefined || (Array.isArray(value) && value.every((entry) => typeof entry === 'string'));
}

function isOptionalDiagnosticLogAvailableActions(value: unknown): value is DiagnosticLogAvailableAction[] | undefined {
  return value === undefined || (
    Array.isArray(value)
    && value.every((entry) => diagnosticLogAvailableActions.includes(entry as DiagnosticLogAvailableAction))
  );
}

function isPositiveSafeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
}

function isNonNegativeSafeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function isNullableString(value: unknown): value is string | null {
  return value === null || typeof value === 'string';
}

function isOptionalPlainRecord(value: unknown): boolean {
  return value === undefined || isPlainRecord(value);
}

function isOptionalNonNegativeNumber(value: unknown): boolean {
  return value === undefined || value === null || (typeof value === 'number' && Number.isFinite(value) && value >= 0);
}

function isOptionalNonNegativeSafeInteger(value: unknown): boolean {
  return value === undefined || isNonNegativeSafeInteger(value);
}

function areOptionalStrings(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return keys.every((key) => value[key] === undefined || typeof value[key] === 'string');
}

async function createRequestError(response: Response): Promise<LogApiRequestError> {
  let code: string | undefined;

  try {
    const body = (await response.json()) as { code?: unknown };
    if (typeof body.code === 'string') {
      code = body.code;
    }
  } catch {
    // Keep the browser message independent of an arbitrary response body.
  }

  return new LogApiRequestError(response.status, getStableErrorMessage(response.status, code), code);
}

function getStableErrorMessage(status: number, code: string | undefined): string {
  const byCode: Readonly<Record<string, string>> = {
    invalid_file: '日志文件不符合服务端要求。',
    file_too_large: '日志文件超过服务端允许的大小。',
    upstream_contract_invalid: '日志服务响应不符合 EVT 看板契约，已停止加载以避免误判。',
    dashboard_configuration_missing: '看板查询凭证未配置，请使用受保护的 token 启动本地联调。',
    unauthorized: '当前登录状态无效，请重新登录。',
    forbidden: '当前账号没有此日志操作权限。',
    quota_exceeded: '日志服务存储额度已满。',
    storage_unavailable: '日志存储暂时不可用，请稍后重试。',
    not_found: '未找到指定日志。',
  };
  if (code && byCode[code]) {
    return byCode[code];
  }
  if (status === 401) {
    return '当前登录状态无效，请重新登录。';
  }
  if (status === 403) {
    return '当前账号没有此日志操作权限。';
  }
  if (status === 404) {
    return '未找到指定日志。';
  }
  if (status === 413) {
    return '日志文件超过服务端允许的大小。';
  }
  if (status === 429) {
    return '日志服务请求过于频繁，请稍后重试。';
  }
  if (status >= 500) {
    return '日志服务暂时不可用，请稍后重试。';
  }
  return '日志服务请求失败，请检查服务状态。';
}
