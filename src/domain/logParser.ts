import {
  EVT_DIAGNOSTIC_LINE_SCHEMA,
  EVT_LOG_SAFE_FIELD_KEYS,
  EVT_FUNCTION_CATEGORY_META,
  type EvtDirectionCounts,
  type EvtFlowNode,
  type EvtFlowReviewReason,
  type EvtFlowStatusInference,
  type EvtFunctionCategory,
  type EvtLogContentItem,
  type EvtLogDirection,
  type EvtLogFields,
  type EvtLogLine,
  type EvtLogParseResult,
  type EvtLogUnparsedReason,
  type ParsedEvtLogLine,
  type UnparsedEvtLogLine,
} from './logTypes';

const ISO_UTC_TIMESTAMP = /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z/;
const SENSITIVE_KEY = /^(?:raw_packet_hex|packet_hex|payload_hex|wire|wire_summary|tx_hex|rx_hex|security_code|securitycode|pass_code|passcode|verification_code|password|private_key|authorization|token|secret|credential|pin|api[_-]?key|account|username|user|host|sftp_host|sftp_port|remote_path|directory|storage_key)$/i;
const SENSITIVE_NATURAL_LANGUAGE_LABEL = '(?:security[\\s_-]*code|verification[\\s_-]*code|pass[\\s_-]*code|passcode|pin|password|private[\\s_-]*key|authorization|token|secret|credential|api[\\s_-]*key|account|username|user|sftp[\\s_-]*host|sftp[\\s_-]*port|remote[\\s_-]*path|directory|storage[\\s_-]*key)';
const SENSITIVE_NATURAL_LANGUAGE_ASSIGNMENT = new RegExp(
  `\\b(${SENSITIVE_NATURAL_LANGUAGE_LABEL})\\s*(?:[:=：]|\\s+)\\s*([^\\s|，,。;；]+)`,
  'gi',
);
const SENSITIVE_NATURAL_LANGUAGE_VALUE = new RegExp(SENSITIVE_NATURAL_LANGUAGE_ASSIGNMENT.source, 'i');
const SENSITIVE_VALUE = new RegExp(
  `(?:\\b(?:raw_|packet_|payload|wire|tx_hex|rx_hex|security_code|securitycode|pass_code|passcode|verification_code|password|private[_-]?key|authorization|token|secret|credential|pin|api[_-]?key|account|username|sftp_host|remote_path|storage_key)\\b|${SENSITIVE_NATURAL_LANGUAGE_VALUE.source}|(?:安全码|验证码|口令|密码|私钥|令牌|密钥|账号|账户|用户名)\\s*[:=：]?\\s*[^\\s|，,。;；]+|(?:https?|sftp|file|content):(?:\\/\\/)?|[a-z]:[\\\\/]|(?:^|[\\s"'=])\\/(?:[^\\s/]+\\/)+|\\b[0-9a-f]{12,}\\b|\\b[0-9a-f]{2}(?:\\s+[0-9a-f]{2}){5,}\\b)`,
  'i',
);
const MAC_ADDRESS = /(?:[0-9a-f]{2}:){5}[0-9a-f]{2}/gi;
const UUID = /\b[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\b/gi;
const EMAIL_ADDRESS = /\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b/i;
const EMAIL_ADDRESSES = /\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b/gi;
const REQUIRED_IDENTIFIER = /^[a-zA-Z][a-zA-Z0-9_.-]{0,127}$/;
const TRACE_IDENTIFIER = /^[a-f0-9]{6,64}$/i;
const SUCCESS_RESULT = /^(?:success|succeeded|completed|accepted|ready|confirmed)$/i;
const FAILURE_RESULT = /^(?:failed|timeout|error|rejected)$/i;
const CANCELLATION_RESULT = /^(?:cancelled|canceled|revoked)$/i;
const FAILURE_EVENT = /(?:failed|timeout|error|rejected)/i;
const CANCELLATION_EVENT = /(?:cancelled|canceled|revoked)/i;
const SAFE_EVT_LOG_FIELD_KEYS = new Set<string>(EVT_LOG_SAFE_FIELD_KEYS);
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/g;
const FILENAME_INVALID_CHARACTERS = /[<>:"|?*]/g;
const URL_PREFIX = /(?:https?|sftp|file):\/\//i;
const FILENAME_SENSITIVE_FRAGMENT = /(?:security(?:[\s_-]?code)?|pass(?:[\s_-]?code)?|verification[\s_-]?code|password|private[\s_-]?key|authorization|token|secret|credential|api[\s_-]?key|account|username|remote[\s_-]?path|storage[\s_-]?key|tenant[\s_-]?code|email)|(?:^|[._=-])(?:pin|host|server|directory|path)(?:$|[._=-])/i;
const MAX_SAFE_LOG_FILENAME_LENGTH = 120;
const DEFAULT_SAFE_LOG_FILENAME = '日志文件.log';

/**
 * Replaces values that are unsafe to keep in browser state. This is a second
 * line of defence; the server remains the authoritative redaction boundary.
 */
export function redactSensitiveContent(value: unknown): string {
  return String(value ?? '')
    .replace(/raw_packet_hex=(?:empty|[0-9A-F]{2}(?:\s+[0-9A-F]{2})*)/gi, 'raw_packet_hex=omitted')
    .replace(/"raw_packet_hex"\s*:\s*"(?:empty|[0-9A-F]{2}(?:\s+[0-9A-F]{2})*)"/gi, '"raw_packet_hex":"omitted"')
    .replace(/\b(raw_packet_hex|packet_hex|payload_hex|wire|tx_hex|rx_hex)=([^|\n]*)/gi, '$1=[已脱敏]')
    .replace(SENSITIVE_NATURAL_LANGUAGE_ASSIGNMENT, '$1=[已隐藏]')
    .replace(/\b(security_code|securitycode|pass_code|passcode|verification_code|password|private_key|authorization|token|secret|credential|pin|api[_-]?key|account|username|user|host|sftp_host|sftp_port|remote_path|directory|storage_key)=([^\s|]+)/gi, '$1=[已隐藏]')
    .replace(/"(security_code|securitycode|pass_code|passcode|verification_code|password|private_key|authorization|token|secret|credential|pin|api[_-]?key|account|username|user|host|sftp_host|sftp_port|remote_path|directory|storage_key)"\s*:\s*"[^"]*"/gi, '"$1":"[已隐藏]"')
    .replace(/(安全码|验证码|口令|密码|私钥|令牌|密钥|账号|账户|用户名)\s*[:=：]?\s*[^\s|，,。;；]+/gi, '$1=[已隐藏]')
    .replace(/\bwire_summary=([^|\n]*)/gi, 'wire_summary=[已脱敏]')
    .replace(/(?:https?|sftp|file|content):(?:\/\/)?[^\s|]+/gi, '[地址已隐藏]')
    .replace(/[a-z]:[\\/][^\s|]*/gi, '[路径已隐藏]')
    .replace(/(?:^|[\s"'=])\/(?:[^\s/]+\/)+[^\s|]*/g, '$1[路径已隐藏]')
    .replace(EMAIL_ADDRESSES, '[邮箱已隐藏]')
    .replace(MAC_ADDRESS, '[设备地址已隐藏]')
    .replace(UUID, '[设备标识已隐藏]');
}

/**
 * Produces a display-safe filename for local and server log references.
 * Only the terminal path segment is retained; potentially sensitive names
 * fall back to a fixed safe filename rather than being partially displayed.
 */
export function sanitizeLogFilename(value: unknown, fallback = DEFAULT_SAFE_LOG_FILENAME): string {
  const safeFallback = normalizeLogFilenameSegment(fallback) ?? DEFAULT_SAFE_LOG_FILENAME;
  return normalizeLogFilenameSegment(value) ?? safeFallback;
}

function normalizeLogFilenameSegment(value: unknown): string | null {
  const source = String(value ?? '').replace(CONTROL_CHARACTERS, '').trim();
  if (!source || URL_PREFIX.test(source) || /[\\/]$/.test(source)) {
    return null;
  }

  const segment = source.split(/[\\/]+/).filter(Boolean).at(-1)?.trim() ?? '';
  if (!segment || segment === '.' || segment === '..' || hasSensitiveFilenameContent(segment)) {
    return null;
  }

  const normalized = segment
    .replace(CONTROL_CHARACTERS, '')
    .replace(FILENAME_INVALID_CHARACTERS, '')
    .replace(/\s+/g, ' ')
    .trim();
  if (!normalized || normalized === '.' || normalized === '..' || hasSensitiveFilenameContent(normalized)) {
    return null;
  }

  return truncateFilename(normalized, MAX_SAFE_LOG_FILENAME_LENGTH);
}

function hasSensitiveFilenameContent(value: string): boolean {
  return EMAIL_ADDRESS.test(value)
    || SENSITIVE_VALUE.test(value)
    || FILENAME_SENSITIVE_FRAGMENT.test(value)
    || /(?:[0-9a-f]{2}:){5}[0-9a-f]{2}/i.test(value)
    || /\b[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\b/i.test(value);
}

function truncateFilename(value: string, maximumLength: number): string {
  const characters = [...value];
  if (characters.length <= maximumLength) {
    return value;
  }

  const extension = value.match(/\.[a-z0-9]{1,10}$/i)?.[0] ?? '';
  const extensionCharacters = [...extension];
  const baseLength = Math.max(1, maximumLength - extensionCharacters.length);
  return `${characters.slice(0, baseLength).join('')}${extension}`;
}

/** Returns a display-safe value for one structured field. */
export function redactFieldValue(key: string, value: unknown): string {
  const normalizedKey = key.trim().toLowerCase();
  const raw = String(value ?? '').trim();

  if (!raw) {
    return '';
  }
  if (normalizedKey === 'raw_packet_hex') {
    return 'omitted';
  }
  if (normalizedKey === 'device_suffix' && !/^\.\.\.[a-f0-9]{4}$/i.test(raw)) {
    return '[已隐藏]';
  }
  if (SENSITIVE_KEY.test(normalizedKey) || SENSITIVE_VALUE.test(raw) || EMAIL_ADDRESS.test(raw)) {
    return '[已隐藏]';
  }

  const redacted = omitUnknownStructuredAssignments(redactSensitiveContent(raw)).trim();
  return redacted || '[已隐藏]';
}

/**
 * Parses optional `key=value` fields without relying on their order. Values
 * may contain spaces and stop at the next field key or a vertical-bar column.
 */
export function parseEvtLogFields(detail: string): EvtLogFields {
  const fields: Record<string, string> = {};
  const normalized = redactSensitiveContent(detail);
  const keyPattern = /(?:^|\s)([a-zA-Z][a-zA-Z0-9_]*)=([^|]*?)(?=(?:\s+[a-zA-Z][a-zA-Z0-9_]*=)|\s*\||$)/g;

  for (const match of normalized.matchAll(keyPattern)) {
    const key = match[1].toLowerCase();
    addSafeField(fields, key, match[2]);
  }

  return fields;
}

/**
 * Applies the same explicit field allowlist to structured server content as
 * local text imports. Unknown fields are omitted before they can reach a
 * summary, export, or component state.
 */
export function sanitizeEvtLogFields(source: Readonly<Record<string, unknown>> | undefined): EvtLogFields {
  const fields: Record<string, string> = {};
  if (!source || typeof source !== 'object' || Array.isArray(source)) {
    return fields;
  }

  for (const [rawKey, rawValue] of Object.entries(source)) {
    if (typeof rawValue !== 'string' && typeof rawValue !== 'number' && typeof rawValue !== 'boolean') {
      continue;
    }
    addSafeField(fields, rawKey.trim().toLowerCase(), rawValue);
  }

  return fields;
}

function addSafeField(fields: Record<string, string>, key: string, rawValue: unknown): void {
  if (!SAFE_EVT_LOG_FIELD_KEYS.has(key)) {
    return;
  }

  const raw = String(rawValue ?? '').trim();
  if (!raw || raw.length > 512) {
    return;
  }

  const value = redactFieldValue(key, raw);
  if (value) {
    fields[key] = value;
  }
}

function omitUnknownStructuredAssignments(value: string): string {
  const keyPattern = /(^|\s)([a-zA-Z][a-zA-Z0-9_.-]*)=([^|]*?)(?=(?:\s+[a-zA-Z][a-zA-Z0-9_.-]*=)|\s*\||$)/g;
  return value.replace(keyPattern, (match, prefix: string, rawKey: string) => (
    SAFE_EVT_LOG_FIELD_KEYS.has(rawKey.toLowerCase()) ? match : `${prefix}[未公开字段]`
  ));
}

/** Parses one `evt-diagnostic-line-v1` source line into a display-safe value. */
export function parseEvtLogLine(source: string, lineNumber = 1): EvtLogLine {
  const sourceText = String(source ?? '');
  const trimmed = sourceText.trim();

  if (!trimmed) {
    return unparsedLine(lineNumber, 'empty', '空行');
  }

  if (containsSensitiveSource(sourceText)) {
    return unparsedLine(lineNumber, 'sensitive_content', '该行包含敏感内容，已隐藏。', 'redacted');
  }

  const timestampMatch = sourceText.match(ISO_UTC_TIMESTAMP);
  if (!timestampMatch || timestampMatch.index === undefined) {
    return unparsedLine(lineNumber, 'timestamp_not_found', '未识别到 EVT UTC 时间戳。');
  }

  const timestamp = timestampMatch[0];
  if (Number.isNaN(Date.parse(timestamp))) {
    return unparsedLine(lineNumber, 'invalid_timestamp', '时间戳格式无效。');
  }

  const prefix = omitUnknownStructuredAssignments(redactSensitiveContent(sourceText.slice(0, timestampMatch.index))).trim();
  const parts = sourceText
    .slice(timestampMatch.index)
    .split(/\s*\|\s*/)
    .map((part) => redactSensitiveContent(part).trim());

  if (parts.length < 8) {
    return unparsedLine(lineNumber, 'not_enough_columns', 'EVT 固定字段不足，无法解析。');
  }

  const [time, level, scope, trace, operation, stage, event, result, elapsed, ...fieldParts] = parts;
  if (!time || !level || !scope || !event || !isMachineIdentifier(level) || !isMachineIdentifier(scope) || !isMachineIdentifier(event)) {
    return unparsedLine(lineNumber, 'invalid_required_field', 'EVT 必填字段格式无效。');
  }

  const warnings = [] as ('legacy_missing_elapsed_ms')[];
  let elapsedMs: number | null = null;
  let details = fieldParts.join(' | ');

  if (parts.length === 8) {
    warnings.push('legacy_missing_elapsed_ms');
    details = '';
  } else {
    elapsedMs = parseElapsedMs(elapsed);
  }

  const parsed: ParsedEvtLogLine = {
    parseStatus: 'parsed',
    lineNumber,
    prefix,
    timestamp: time,
    level: level.toUpperCase(),
    scope: scope.toUpperCase(),
    traceId: normalizeOptionalIdentifier(trace),
    operation: normalizeOptionalIdentifier(operation),
    stage: normalizeOptionalIdentifier(stage),
    event: event.toLowerCase(),
    result: normalizeOptionalIdentifier(result)?.toLowerCase() ?? null,
    elapsedMs,
    fields: parseEvtLogFields(details),
    direction: inferEvtLogDirection(prefix, scope, event),
    summary: '',
    warnings,
  };

  return { ...parsed, summary: buildSafeSummary(parsed) };
}

/** Parses a text file and keeps unparsed/redacted lines as safe diagnostics. */
export function parseEvtLogText(source: string): EvtLogParseResult {
  const sourceText = String(source ?? '');
  const sourceLines = sourceText.split(/\r?\n/);
  if (/\r?\n$/.test(sourceText)) {
    // Split creates one synthetic empty item for the final separator. Keep
    // every other blank line because it is meaningful parse diagnostics.
    sourceLines.pop();
  }
  const lines = sourceLines.map((line, index) => parseEvtLogLine(line, index + 1));
  const records = lines.filter(isParsedEvtLogLine);
  const unparsedCount = lines.filter((line) => line.parseStatus === 'unparsed').length;
  const redactedCount = lines.filter((line) => line.parseStatus === 'redacted').length;

  return {
    schemaVersion: EVT_DIAGNOSTIC_LINE_SCHEMA,
    lines,
    records,
    parsedCount: records.length,
    unparsedCount,
    redactedCount,
  };
}

/**
 * Converts `evt-diagnostic-content-v1` items into the same sanitized domain
 * representation used by locally imported text. Server ordering is not
 * trusted, so line numbers are normalized before flow aggregation.
 */
export function parseEvtLogContentItems(items: readonly EvtLogContentItem[]): EvtLogParseResult {
  const orderedItems = items
    .map((item, index) => ({ item, index, lineNumber: normalizeContentLineNumber(item.line_no) }))
    .sort((left, right) => left.lineNumber - right.lineNumber || left.index - right.index);
  const lines = orderedItems.map(({ item, index }) => parseEvtLogContentItem(item, index + 1));
  const records = lines.filter(isParsedEvtLogLine);
  const unparsedCount = lines.filter((line) => line.parseStatus === 'unparsed').length;
  const redactedCount = lines.filter((line) => line.parseStatus === 'redacted').length;

  return {
    schemaVersion: EVT_DIAGNOSTIC_LINE_SCHEMA,
    lines,
    records,
    parsedCount: records.length,
    unparsedCount,
    redactedCount,
  };
}

/** Backward-friendly name for callers that treat the source as a log file. */
export const parseLogFile = parseEvtLogText;

export function isParsedEvtLogLine(line: EvtLogLine): line is ParsedEvtLogLine {
  return line.parseStatus === 'parsed';
}

function parseEvtLogContentItem(item: EvtLogContentItem, fallbackLineNumber: number): EvtLogLine {
  const lineNumber = getContentLineNumber(item.line_no, fallbackLineNumber);

  if (item.parse_status === 'redacted') {
    return unparsedLine(lineNumber, 'server_redacted', '服务端已隐藏包含敏感内容的日志行。', 'redacted');
  }
  if (item.parse_status !== 'parsed') {
    return unparsedLine(lineNumber, 'server_unparsed', '服务端标记为未解析的日志行。');
  }

  const timestamp = String(item.timestamp ?? '').trim();
  const level = String(item.level ?? '').trim();
  const scope = String(item.scope ?? '').trim();
  const event = String(item.event ?? '').trim().toLowerCase();
  if (!isValidContentTimestamp(timestamp) || !isMachineIdentifier(level) || !isMachineIdentifier(scope) || !isMachineIdentifier(event)) {
    return unparsedLine(lineNumber, 'invalid_required_field', '服务端返回的结构化日志字段无效。');
  }

  const parsed: ParsedEvtLogLine = {
    parseStatus: 'parsed',
    lineNumber,
    prefix: '',
    timestamp,
    level: level.toUpperCase(),
    scope: scope.toUpperCase(),
    traceId: normalizeOptionalIdentifier(item.trace_id),
    operation: normalizeOptionalIdentifier(item.operation),
    stage: normalizeOptionalIdentifier(item.stage),
    event,
    result: normalizeOptionalIdentifier(item.result)?.toLowerCase() ?? null,
    elapsedMs: parseContentElapsedMs(item.elapsed_ms),
    fields: sanitizeEvtLogFields(item.fields),
    direction: inferEvtLogDirection('', scope, event),
    summary: '',
    warnings: [],
  };

  return { ...parsed, summary: buildSafeSummary(parsed) };
}

function normalizeContentLineNumber(value: unknown): number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0
    ? value
    : Number.MAX_SAFE_INTEGER;
}

function getContentLineNumber(value: unknown, fallbackLineNumber: number): number {
  const normalized = normalizeContentLineNumber(value);
  return normalized === Number.MAX_SAFE_INTEGER ? fallbackLineNumber : normalized;
}

function isValidContentTimestamp(value: string): boolean {
  const match = value.match(ISO_UTC_TIMESTAMP);
  return match?.[0] === value && !Number.isNaN(Date.parse(value));
}

function parseContentElapsedMs(value: unknown): number | null {
  if (typeof value === 'number') {
    return Number.isFinite(value) && value >= 0 ? value : null;
  }
  return typeof value === 'string' ? parseElapsedMs(value) : null;
}

/** Determines whether a safe record represents App traffic, device traffic, or local processing. */
export function inferEvtLogDirection(prefix: string, scope: string, event: string): EvtLogDirection {
  const displayPrefix = prefix.trim();
  const normalizedScope = scope.trim().toUpperCase();
  const normalizedEvent = event.trim().toLowerCase();

  if (/(?:发送|读取|下发|写入)\s*[:：]/.test(displayPrefix)) {
    return 'app';
  }
  if (/(?:接收|回包)\s*[:：]/.test(displayPrefix)) {
    return 'device';
  }
  if (normalizedScope === 'CMD' && /^evt_(?:stream_)?command_(?:queued|admitted|transmit_)/.test(normalizedEvent)) {
    return 'app';
  }
  if (/^(?:evt_command_response|evt_command_frame|notification_received|indication_received)/.test(normalizedEvent)) {
    return 'device';
  }
  if (normalizedScope === 'CMD' && /^evt_(?:stream_)?command_completed$/.test(normalizedEvent)) {
    return 'device';
  }
  return 'system';
}

/** Classifies a record into the workflow-oriented node shown by the dashboard. */
export function classifyEvtLogRecord(record: ParsedEvtLogLine): EvtFunctionCategory {
  const haystack = `${record.scope} ${record.operation ?? ''} ${record.stage ?? ''} ${record.event}`.toLowerCase();

  if (record.scope === 'RECONNECT' || record.operation === 'device_reconnect') {
    return 'reconnect';
  }
  if (record.stage === 'upload' || /^app_log_upload_/.test(record.event)) {
    return 'upload';
  }
  if (isAuthenticationRecord(record)) {
    return 'auth';
  }
  if (/^evt_command_client_(?:closing|closed)$/.test(record.event)) {
    return 'other';
  }
  if (['evt_command_client_opened', 'evt_response_channel_initialized', 'characteristic_stream_listening', 'session_authentication_ready'].includes(record.event)) {
    return 'subscribe';
  }
  if (hasAnyToken(haystack, ['notification', 'subscription', 'ccc']) || /^characteristic_subscription/.test(record.event)) {
    return 'subscribe';
  }
  if (record.operation === 'device_scan' || hasAnyToken(haystack, ['scan', 'candidate'])) {
    return 'scan';
  }
  if (record.operation === 'audio_playback' || hasAnyToken(haystack, ['playback', 'player', 'audio'])) {
    return 'playback';
  }
  if (hasAnyToken(haystack, ['record', 'recording'])) {
    return 'record';
  }
  if (hasAnyToken(haystack, ['file', 'download', 'import', 'archive'])) {
    return 'file';
  }
  if (hasAnyToken(haystack, ['privacy', 'configuration', 'config'])) {
    return 'config';
  }
  if (record.event === 'native_log_stream_listening') {
    return 'other';
  }
  if (record.operation === 'device_connect' || record.scope === 'SESSION_FLOW' || hasAnyToken(haystack, ['gatt', 'service', 'discovery', 'connection'])) {
    return 'gatt';
  }
  if (record.scope === 'CMD' || hasAnyToken(haystack, ['evt', 'protocol', 'response'])) {
    return 'protocol';
  }
  return 'other';
}

/**
 * Generates a stable node key. A usable trace id keeps concurrent operations
 * separate. Historical entries without a trace return a base key; aggregation
 * adds an ordered segment at a conservative terminal-operation boundary.
 */
export function getEvtFlowGroupKey(record: ParsedEvtLogLine): string {
  const category = classifyEvtLogRecord(record);
  const operation = getGroupOperation(record, category);
  const trace = record.traceId;
  const tracePart = trace && TRACE_IDENTIFIER.test(trace) ? `trace:${trace.toLowerCase()}` : 'trace:-';
  return `${category}|${tracePart}|operation:${operation}`;
}

function resolveLegacyFlowBaseKey(
  record: ParsedEvtLogLine,
  category: EvtFunctionCategory,
  activeLegacyGroups: ReadonlyMap<string, FlowRecordGroup>,
): string {
  const baseKey = getEvtFlowGroupKey(record);
  if (hasUsableTraceId(record)
    || category !== 'auth'
    || !isTraceLessCommandTransaction(record)
    || getGroupOperationValue(record, category) !== null) {
    return baseKey;
  }

  // The command client emits no operation for V1.6 0x09 -> 0x89 traffic.
  // Attach it to the single in-flight auth flow so business results stay with
  // the matching App send and device reply.
  const activeAuthenticationKeys = [...activeLegacyGroups.entries()]
    .filter(([key, group]) => key.startsWith('auth|trace:-|operation:') && !group.closed)
    .map(([key]) => key);
  return activeAuthenticationKeys.length === 1 ? activeAuthenticationKeys[0] : baseKey;
}

/** Builds ordered EVT workflow nodes from parsed events. */
export function aggregateEvtFlowNodes(records: readonly ParsedEvtLogLine[]): readonly EvtFlowNode[] {
  const tracedGroups = new Map<string, FlowRecordGroup>();
  const activeLegacyGroups = new Map<string, FlowRecordGroup>();
  const legacySegmentCounts = new Map<string, number>();
  const legacyCommandState: LegacyCommandFlowState = {
    flowsByBaseKey: new Map<string, LegacyCommandFlow[]>(),
    flowsByWaitKey: new Map<string, LegacyCommandFlow>(),
  };
  const groups: FlowRecordGroup[] = [];

  for (const record of [...records].sort((left, right) => left.lineNumber - right.lineNumber)) {
    const category = classifyEvtLogRecord(record);
    const baseKey = resolveLegacyFlowBaseKey(record, category, activeLegacyGroups);
    if (hasUsableTraceId(record)) {
      const group = getOrCreateFlowGroup(tracedGroups, groups, baseKey);
      group.records.push(record);
      continue;
    }

    if (isTraceLessCommandTransaction(record) && category !== 'auth') {
      const group = resolveLegacyCommandGroup(record, baseKey, legacyCommandState, legacySegmentCounts, groups);
      group.records.push(record);
      if (isCommandFlowTerminal(record)) {
        group.closed = true;
      }
      continue;
    }

    let group = activeLegacyGroups.get(baseKey);
    const startsNewAuthenticationAttempt = category === 'auth' && isAuthenticationAttemptStart(record);
    const continuesClosedAuthenticationAttempt = category === 'auth' && !startsNewAuthenticationAttempt;
    if (!group
      || startsNewAuthenticationAttempt
      || (group.closed && beginsNewLegacySegment(record) && !continuesClosedAuthenticationAttempt)) {
      const segment = (legacySegmentCounts.get(baseKey) ?? 0) + 1;
      legacySegmentCounts.set(baseKey, segment);
      group = { key: `${baseKey}|segment:${segment}`, records: [], closed: false };
      activeLegacyGroups.set(baseKey, group);
      groups.push(group);
    }

    group.records.push(record);
    if (isLegacyFlowTerminal(record)) {
      group.closed = true;
    }
  }

  const nodes = groups.map(({ key, records: grouped }) => buildFlowNode(key, grouped));
  return nodes.sort((left, right) => {
    const categoryOrder = EVT_FUNCTION_CATEGORY_META[left.category].order - EVT_FUNCTION_CATEGORY_META[right.category].order;
    if (categoryOrder !== 0) {
      return categoryOrder;
    }
    return left.startedAt.localeCompare(right.startedAt) || left.id.localeCompare(right.id);
  });
}

interface FlowRecordGroup {
  readonly key: string;
  readonly records: ParsedEvtLogLine[];
  closed?: boolean;
}

interface LegacyCommandFlow {
  readonly group: FlowRecordGroup;
  readonly baseKey: string;
  readonly signature: string | null;
  waitId?: string;
}

interface LegacyCommandFlowState {
  readonly flowsByBaseKey: Map<string, LegacyCommandFlow[]>;
  readonly flowsByWaitKey: Map<string, LegacyCommandFlow>;
}

function getOrCreateFlowGroup(
  groupsByKey: Map<string, FlowRecordGroup>,
  groups: FlowRecordGroup[],
  key: string,
): FlowRecordGroup {
  const existing = groupsByKey.get(key);
  if (existing) {
    return existing;
  }

  const created: FlowRecordGroup = { key, records: [] };
  groupsByKey.set(key, created);
  groups.push(created);
  return created;
}

function hasUsableTraceId(record: ParsedEvtLogLine): boolean {
  return record.traceId !== null && TRACE_IDENTIFIER.test(record.traceId);
}

function isTraceLessCommandTransaction(record: ParsedEvtLogLine): boolean {
  if (record.scope !== 'CMD') {
    return false;
  }

  return Boolean(getCommandWaitId(record) || getCommandSignature(record))
    || /^(?:evt_(?:stream_)?command_(?:queued|admitted|transmit_|response_|frame_|completed)|evt_response_wait_|write_)/.test(record.event);
}

function resolveLegacyCommandGroup(
  record: ParsedEvtLogLine,
  baseKey: string,
  state: LegacyCommandFlowState,
  legacySegmentCounts: Map<string, number>,
  groups: FlowRecordGroup[],
): FlowRecordGroup {
  const waitId = getCommandWaitId(record);
  const signature = getCommandSignature(record);
  const waitKey = waitId ? `${baseKey}|wait:${waitId}` : null;
  let flow: LegacyCommandFlow | undefined;

  if (isCommandRequestStart(record)) {
    flow = createLegacyCommandFlow(baseKey, signature, state, legacySegmentCounts, groups);
  } else if (waitKey) {
    flow = state.flowsByWaitKey.get(waitKey);
    if (flow?.group.closed && isCommandWaitStart(record)) {
      flow = undefined;
    }
    if (!flow) {
      flow = findOldestUnboundCommandFlow(state, baseKey, signature)
        ?? createLegacyCommandFlow(baseKey, signature, state, legacySegmentCounts, groups);
      flow.waitId = waitId ?? undefined;
      state.flowsByWaitKey.set(waitKey, flow);
    }
  } else {
    flow = findMostRecentOpenCommandFlow(state, baseKey, signature);
    if (!flow && isCommandCompletionRecord(record)) {
      flow = findMostRecentCompletingCommandFlow(state, baseKey, signature);
    }
    flow ??= createLegacyCommandFlow(baseKey, signature, state, legacySegmentCounts, groups);
  }

  return flow.group;
}

function createLegacyCommandFlow(
  baseKey: string,
  signature: string | null,
  state: LegacyCommandFlowState,
  legacySegmentCounts: Map<string, number>,
  groups: FlowRecordGroup[],
): LegacyCommandFlow {
  const segment = (legacySegmentCounts.get(baseKey) ?? 0) + 1;
  legacySegmentCounts.set(baseKey, segment);
  const group: FlowRecordGroup = {
    key: `${baseKey}|command:${signature ?? 'unpaired'}|segment:${segment}`,
    records: [],
    closed: false,
  };
  const flow: LegacyCommandFlow = { group, baseKey, signature };
  const flows = state.flowsByBaseKey.get(baseKey) ?? [];
  flows.push(flow);
  state.flowsByBaseKey.set(baseKey, flows);
  groups.push(group);
  return flow;
}

function findOldestUnboundCommandFlow(
  state: LegacyCommandFlowState,
  baseKey: string,
  signature: string | null,
): LegacyCommandFlow | undefined {
  const candidates = (state.flowsByBaseKey.get(baseKey) ?? []).filter((flow) => (
    !flow.group.closed && !flow.waitId && commandSignaturesMatch(flow.signature, signature)
  ));
  return candidates[0];
}

function findMostRecentOpenCommandFlow(
  state: LegacyCommandFlowState,
  baseKey: string,
  signature: string | null,
): LegacyCommandFlow | undefined {
  const flows = state.flowsByBaseKey.get(baseKey) ?? [];
  const matching = flows.filter((flow) => !flow.group.closed && commandSignaturesMatch(flow.signature, signature));
  const candidates = matching.length > 0 ? matching : flows.filter((flow) => !flow.group.closed);
  return candidates.reduce<LegacyCommandFlow | undefined>((latest, candidate) => {
    if (!latest) {
      return candidate;
    }
    const latestLine = latest.group.records.at(-1)?.lineNumber ?? 0;
    const candidateLine = candidate.group.records.at(-1)?.lineNumber ?? 0;
    return candidateLine >= latestLine ? candidate : latest;
  }, undefined);
}

function findMostRecentCompletingCommandFlow(
  state: LegacyCommandFlowState,
  baseKey: string,
  signature: string | null,
): LegacyCommandFlow | undefined {
  const flows = (state.flowsByBaseKey.get(baseKey) ?? []).filter((flow) => {
    const lastRecord = flow.group.records.at(-1);
    return flow.group.closed
      && commandSignaturesMatch(flow.signature, signature)
      && lastRecord !== undefined
      && lastRecord.event !== 'evt_command_completed'
      && (lastRecord.event === 'evt_response_wait_finished' || isFailureRecord(lastRecord));
  });
  return flows.at(-1);
}

function commandSignaturesMatch(left: string | null, right: string | null): boolean {
  return left === null || right === null || left === right;
}

function getCommandWaitId(record: ParsedEvtLogLine): string | null {
  const value = String(record.fields.wait_id ?? '').trim();
  return /^[a-zA-Z0-9_.-]{1,64}$/.test(value) ? value : null;
}

function getCommandSignature(record: ParsedEvtLogLine): string | null {
  const expected = normalizeCommand(record.fields.expected_command);
  if (expected) {
    return `expected:${expected}`;
  }

  const command = normalizeCommand(record.fields.command);
  if (command) {
    return `command:${command}`;
  }

  const actual = normalizeCommand(record.fields.actual_command);
  return actual ? `response:${actual}` : null;
}

function isCommandRequestStart(record: ParsedEvtLogLine): boolean {
  return /^(?:evt_(?:stream_)?command_queued|write_requested)$/.test(record.event);
}

function isCommandWaitStart(record: ParsedEvtLogLine): boolean {
  return /^(?:evt_response_wait_started|evt_response_wait_armed)$/.test(record.event);
}

function isCommandFlowTerminal(record: ParsedEvtLogLine): boolean {
  if (isFailureRecord(record) || isCancellationRecord(record)) {
    return true;
  }
  return /^(?:evt_(?:stream_)?command_completed)$/.test(record.event)
    && SUCCESS_RESULT.test(record.result ?? '');
}

function isCommandCompletionRecord(record: ParsedEvtLogLine): boolean {
  return /^(?:evt_(?:stream_)?command_completed)$/.test(record.event);
}

function startsLegacyFlow(record: ParsedEvtLogLine): boolean {
  if (/(?:^|_)(?:requested|queued|started|dispatching|initiated|opening|connecting|scanning|begun)$/.test(record.event)) {
    return true;
  }

  return classifyEvtLogRecord(record) === 'gatt' && (
    record.event === 'gatt_service_discovery_completed' || record.fields.phase_to === 'connecting'
  );
}

function beginsNewLegacySegment(record: ParsedEvtLogLine): boolean {
  // A second terminal record cannot be evidence for the already-finished
  // operation. It is retained as a separate, reviewable legacy segment even
  // when historical logs omitted an explicit request event.
  return startsLegacyFlow(record) || isLegacyFlowTerminal(record);
}

function isLegacyFlowTerminal(record: ParsedEvtLogLine): boolean {
  if (isFailureRecord(record) || isCancellationRecord(record)) {
    return true;
  }
  if (!SUCCESS_RESULT.test(record.result ?? '')) {
    return false;
  }
  const category = classifyEvtLogRecord(record);
  if (isExplicitLegacySuccessTerminal(record, category)) {
    return true;
  }
  if (category === 'auth' && /^evt_(?:stream_)?command_completed$/.test(record.event)) {
    // The protocol client has completed transport, but V1.6 authentication
    // still needs the session/controller result before the business flow ends.
    return false;
  }
  // A service-discovery completion is only an intermediate GATT milestone;
  // the compatibility contract is the terminal connection evidence. Scan
  // events likewise use their explicit accepted/selected outcomes below.
  if (category === 'scan' || category === 'gatt') {
    return false;
  }
  if (/^(?:evt_(?:stream_)?command_transmit_completed|write_completed|evt_response_wait_finished|evt_command_(?:response_received|response_matched|frame_decoded))$/.test(record.event)) {
    return false;
  }
  return /(?:_completed|_succeeded|_finished)$/.test(record.event);
}

function isExplicitLegacySuccessTerminal(record: ParsedEvtLogLine, category: EvtFunctionCategory): boolean {
  if (category === 'scan') {
    return record.event === 'scan_result_accepted' || record.event === 'scan_candidate_selected';
  }
  if (category === 'gatt') {
    return record.event === 'gatt_contract_verified' || record.event === 'evt_gatt_contract_checked';
  }
  return false;
}

/** Applies conservative pass/fail/review inference to one already grouped node. */
export function inferEvtFlowStatus(records: readonly ParsedEvtLogLine[], category: EvtFunctionCategory): EvtFlowStatusInference {
  if (records.some(isFailureRecord)) {
    return {
      status: 'failure',
      conclusion: '链路中出现失败、超时或拒绝事件，请查看事件顺序和稳定错误码。',
    };
  }

  if (category === 'reconnect' || category === 'other') {
    return review('auxiliary_events', '这组为辅助或回连事件，需要结合主链路判断，不单独作为联调结论。');
  }

  if (category === 'gatt') {
    return inferGattStatus(records);
  }

  if (category === 'scan') {
    return inferScanStatus(records);
  }

  if (category === 'auth') {
    return inferAuthenticationStatus(records);
  }

  if (category === 'protocol') {
    return inferProtocolStatus(records);
  }

  const hasCancellation = records.some(isCancellationRecord);
  const hasSuccess = records.some((record) => SUCCESS_RESULT.test(record.result ?? ''));
  const hasAppCommand = records.some(isAppCommandRecord);
  const hasDeviceReply = records.some((record) => record.direction === 'device');

  if (hasAppCommand && !hasDeviceReply) {
    return review('awaiting_device_response', 'App 已下发协议步骤，当前日志未见匹配的设备回包或业务终态。');
  }
  if (hasSuccess) {
    return {
      status: 'success',
      conclusion: '日志包含成功或完成事件，可作为当前功能联调成功证据。',
    };
  }
  if (hasCancellation) {
    return review('cancelled', '链路因用户操作或连接状态变化结束，不能判定为联调成功或失败。');
  }
  return review('incomplete_evidence', '当前日志缺少可确认业务终态的证据，需要继续联调或补充日志。');
}

function inferGattStatus(records: readonly ParsedEvtLogLine[]): EvtFlowStatusInference {
  const hasContractVerification = records.some((record) => (
    (record.event === 'gatt_contract_verified' || record.event === 'evt_gatt_contract_checked')
    && SUCCESS_RESULT.test(record.result ?? '')
  ));
  if (hasContractVerification) {
    return {
      status: 'success',
      conclusion: '已发现服务并完成 EVT GATT 契约校验，可作为连接联调成功证据。',
    };
  }

  if (records.some(isCancellationRecord)) {
    return review('cancelled', 'GATT 建立流程已取消，不能判定为联调成功或失败。');
  }
  return review('incomplete_evidence', '当前仅见服务发现或连接中间事件，尚未见 EVT GATT 契约校验通过。');
}

function inferScanStatus(records: readonly ParsedEvtLogLine[]): EvtFlowStatusInference {
  const hasAcceptedTarget = records.some((record) => (
    (record.event === 'scan_result_accepted' || record.event === 'scan_candidate_selected')
    && SUCCESS_RESULT.test(record.result ?? '')
  ));
  if (hasAcceptedTarget) {
    return {
      status: 'success',
      conclusion: '已发现并接受符合条件的目标设备，可作为扫描联调成功证据。',
    };
  }
  if (records.some(isCancellationRecord)) {
    return review('cancelled', '扫描流程已取消，不能判定为联调成功或失败。');
  }
  return review('incomplete_evidence', '当前仅见扫描启动、停止或清理事件，尚未见目标设备被接受。');
}

function inferProtocolStatus(records: readonly ParsedEvtLogLine[]): EvtFlowStatusInference {
  const hasAppCommand = records.some(isAppCommandRecord);
  const hasExplicitMatchedDeviceReply = records.some((record) => (
    record.direction === 'device' && record.event === 'evt_command_response_matched'
  ));
  const hasLegacyConfirmedReply = records.some((record) => (
    record.direction === 'device' && record.event === 'evt_command_response_received'
  )) && records.some((record) => (
    record.event === 'evt_response_wait_finished' && SUCCESS_RESULT.test(record.result ?? '')
  ));
  const hasMatchedDeviceReply = hasExplicitMatchedDeviceReply || hasLegacyConfirmedReply;
  const hasCompletedCommand = records.some((record) => (
    record.direction === 'device'
    && /^evt_(?:stream_)?command_completed$/.test(record.event)
    && SUCCESS_RESULT.test(record.result ?? '')
  ));

  if (hasAppCommand && hasMatchedDeviceReply && hasCompletedCommand) {
    return {
      status: 'success',
      conclusion: 'App 下发、匹配设备回包和命令完成事件均已出现，可作为 EVT 协议联调成功证据。',
    };
  }
  if (hasAppCommand && !hasMatchedDeviceReply) {
    return review('awaiting_device_response', 'App 已下发 EVT 命令，当前日志未见匹配的设备回包。');
  }
  if (records.some(isCancellationRecord)) {
    return review('cancelled', 'EVT 协议链路已取消，不能判定为联调成功或失败。');
  }
  return review('incomplete_evidence', '当前日志缺少完整的 App 下发、匹配回包和命令完成证据。');
}

function buildFlowNode(key: string, records: readonly ParsedEvtLogLine[]): EvtFlowNode {
  const ordered = [...records].sort((left, right) => left.lineNumber - right.lineNumber);
  const first = ordered[0];
  const category = classifyEvtLogRecord(first);
  const operation = getGroupOperationValue(first, category);
  const status = inferEvtFlowStatus(ordered, category);
  const title = getFlowTitle(category, operation);
  const startedAt = first.timestamp;
  const endedAt = ordered[ordered.length - 1].timestamp;

  return {
    id: `${key}|line:${first.lineNumber}`,
    category,
    title,
    traceId: first.traceId,
    operation,
    startedAt,
    endedAt,
    durationMs: durationBetween(startedAt, endedAt),
    directionCounts: countDirections(ordered),
    eventCount: ordered.length,
    records: ordered,
    ...status,
  };
}

function inferAuthenticationStatus(records: readonly ParsedEvtLogLine[]): EvtFlowStatusInference {
  const request = [...records].reverse().find(isAuthenticationRequest);
  const cancellation = records.some(isCancellationRecord);

  if (!request) {
    return cancellation
      ? review('cancelled', '认证流程在发起请求前取消，不能作为联调失败。')
      : review('incomplete_evidence', '当前日志未识别到认证请求，无法确认认证联调结果。');
  }

  const expectedCommand = normalizeCommand(request.fields.expected_command) ?? '0x89';
  const response = records.find((record) => record.lineNumber > request.lineNumber && isMatchingAuthenticationResponse(record, expectedCommand));
  if (!response) {
    return review('awaiting_device_response', `App 已下发认证请求，等待设备 ${expectedCommand} 回包。`);
  }

  const terminalSuccess = records.some((record) =>
    record.lineNumber >= response.lineNumber &&
    /^(?:legacy_authentication_completed|legacy_security_exchange_completed)$/.test(record.event) &&
    /^(?:success|succeeded|completed|accepted)$/i.test(record.result ?? ''),
  );
  if (terminalSuccess) {
    return {
      status: 'success',
      conclusion: '认证请求、匹配设备回包和认证业务完成事件均已出现，认证联调成功。',
    };
  }
  return review('incomplete_evidence', '已收到认证回包，但当前日志未见认证业务完成事件，仍需复核。');
}

function isAuthenticationRecord(record: ParsedEvtLogLine): boolean {
  const endpoint = String(record.fields.endpoint ?? record.fields.characteristic ?? '').toLowerCase();
  const command = String(record.fields.command ?? '').toLowerCase();
  const expected = String(record.fields.expected_command ?? '').toLowerCase();
  return record.scope === 'AUTH'
    || record.operation === 'device_bind'
    || record.operation === 'device_authenticate'
    || record.stage === 'fa19_write'
    || expected === '0x89'
    || (command === '0x09' && /^(?:evt_command_|write_)/.test(record.event))
    || (endpoint === '0xfa19' && /^write_/.test(record.event));
}

function isAuthenticationRequest(record: ParsedEvtLogLine): boolean {
  const expected = normalizeCommand(record.fields.expected_command);
  const command = normalizeCommand(record.fields.command);
  if (record.direction === 'device') {
    return false;
  }

  if (record.event === 'legacy_authentication_requested' || record.event === 'legacy_security_exchange_dispatching') {
    return true;
  }

  const isOutgoingCommandEvent = /^(?:evt_(?:stream_)?command_(?:queued|admitted|transmit_started)|write_(?:requested|native_invoked|completed))$/.test(record.event);
  return isOutgoingCommandEvent && (record.direction === 'app' || expected === '0x89' || command === '0x09');
}

function isAuthenticationAttemptStart(record: ParsedEvtLogLine): boolean {
  return record.event === 'legacy_authentication_requested';
}

function isMatchingAuthenticationResponse(record: ParsedEvtLogLine, expectedCommand: string): boolean {
  if (record.direction !== 'device') {
    return false;
  }
  return [record.fields.command, record.fields.actual_command, record.fields.response_command]
    .map(normalizeCommand)
    .some((value) => value === expectedCommand);
}

function isFailureRecord(record: ParsedEvtLogLine): boolean {
  return FAILURE_RESULT.test(record.result ?? '') || FAILURE_EVENT.test(record.event);
}

function isCancellationRecord(record: ParsedEvtLogLine): boolean {
  return CANCELLATION_RESULT.test(record.result ?? '') || CANCELLATION_EVENT.test(record.event);
}

function isAppCommandRecord(record: ParsedEvtLogLine): boolean {
  return record.direction === 'app' && /^(?:evt_(?:stream_)?command_|write_)/.test(record.event);
}

function review(reviewReason: EvtFlowReviewReason, conclusion: string): EvtFlowStatusInference {
  return { status: 'review', reviewReason, conclusion };
}

function getGroupOperation(record: ParsedEvtLogLine, category: EvtFunctionCategory): string {
  return getGroupOperationValue(record, category) ?? 'unknown';
}

function getGroupOperationValue(record: ParsedEvtLogLine, category: EvtFunctionCategory): string | null {
  if (category === 'auth') {
    if (record.operation === 'device_authenticate') {
      return 'device_authenticate';
    }
    if (record.operation === 'device_bind') {
      return 'device_bind';
    }
  }
  return record.operation;
}

function getFlowTitle(category: EvtFunctionCategory, operation: string | null): string {
  if (category === 'auth' && operation === 'device_bind') {
    return '安全码认证（绑定）';
  }
  return EVT_FUNCTION_CATEGORY_META[category].title;
}

function countDirections(records: readonly ParsedEvtLogLine[]): EvtDirectionCounts {
  return records.reduce<EvtDirectionCounts>(
    (counts, record) => ({ ...counts, [record.direction]: counts[record.direction] + 1 }),
    { app: 0, device: 0, system: 0 },
  );
}

function durationBetween(startedAt: string, endedAt: string): number | null {
  const start = Date.parse(startedAt);
  const end = Date.parse(endedAt);
  if (Number.isNaN(start) || Number.isNaN(end)) {
    return null;
  }
  return Math.max(0, end - start);
}

function parseElapsedMs(value: string | undefined): number | null {
  if (!value || value === '-') {
    return null;
  }
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : null;
}

function normalizeOptionalIdentifier(value: string | undefined): string | null {
  const normalized = String(value ?? '').trim();
  if (!normalized || normalized === '-' || !/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/.test(normalized)) {
    return null;
  }
  return redactSensitiveContent(normalized);
}

function normalizeCommand(value: string | undefined): string | null {
  const normalized = String(value ?? '').trim().toLowerCase();
  return /^0x[0-9a-f]{2}$/.test(normalized) ? normalized : null;
}

function isMachineIdentifier(value: string): boolean {
  return REQUIRED_IDENTIFIER.test(value) && !SENSITIVE_KEY.test(value);
}

function hasAnyToken(value: string, tokens: readonly string[]): boolean {
  return tokens.some((token) => new RegExp(`(?:^|[\\s_])${token}(?=$|[\\s_])`).test(value));
}

function containsSensitiveSource(source: string): boolean {
  if (/\b(?:raw_packet_hex|packet_hex|payload_hex|tx_hex|rx_hex)=(?:[0-9A-F]{2}(?:\s+[0-9A-F]{2})*)/i.test(source)) {
    return true;
  }

  const naturalLanguageAssignments = source.matchAll(SENSITIVE_NATURAL_LANGUAGE_ASSIGNMENT);
  for (const assignment of naturalLanguageAssignments) {
    if (!isRedactedMarker(assignment[2])) {
      return true;
    }
  }

  const assignments = source.matchAll(/\b(?:security_code|securitycode|pass_code|passcode|verification_code|password|private_key|authorization|token|secret|credential|pin|api[_-]?key|account|username|user|host|sftp_host|sftp_port|remote_path|directory|storage_key)=([^\s|]+)/gi);
  for (const assignment of assignments) {
    if (!isRedactedMarker(assignment[1])) {
      return true;
    }
  }
  return false;
}

function isRedactedMarker(value: string | undefined): boolean {
  const normalized = String(value ?? '').trim().replace(/^["']|["']$/g, '').toLowerCase();
  return ['redacted', 'omitted', 'hidden', '[已隐藏]', '[已脱敏]'].includes(normalized);
}

function buildSafeSummary(record: ParsedEvtLogLine): string {
  const fixed = [
    record.timestamp,
    record.level,
    record.scope,
    record.traceId ?? '-',
    record.operation ?? '-',
    record.stage ?? '-',
    record.event,
    record.result ?? '-',
    record.elapsedMs?.toString() ?? '-',
  ];
  const fields = Object.entries(record.fields).map(([key, value]) => `${key}=${value}`);
  return [...fixed, ...fields].join(' | ');
}

function unparsedLine(
  lineNumber: number,
  reason: EvtLogUnparsedReason,
  summary: string,
  parseStatus: UnparsedEvtLogLine['parseStatus'] = 'unparsed',
): UnparsedEvtLogLine {
  return { parseStatus, lineNumber, reason, summary };
}
