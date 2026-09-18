/**
 * EVT diagnostic-log domain contract.
 *
 * These types deliberately model the browser-side, already-sanitized view of
 * a log. Raw source text and credentials must never be kept in UI state.
 */

export const EVT_DIAGNOSTIC_LINE_SCHEMA = 'evt-diagnostic-line-v1' as const;

/**
 * The dashboard only retains these structured supplemental fields. The list
 * mirrors the display-safe EVT diagnostics contract and intentionally omits
 * credentials, raw packets, storage paths, host data, and unrecognized data.
 */
export const EVT_LOG_SAFE_FIELD_KEYS = [
  'action',
  'actual_command',
  'actual_crc32',
  'actual_size_bytes',
  'archive_state',
  'attempt',
  'authentication_ready',
  'authentication_window_ms',
  'automatic',
  'bytes',
  'characteristic',
  'characteristic_count',
  'check',
  'checks',
  'checkpoint_phase',
  'chunk_bytes',
  'chunk_length',
  'code_length',
  'command',
  'configured',
  'connection_attempt',
  'content_length',
  'count',
  'crc',
  'crc32',
  'critical',
  'current_operation',
  'cycle',
  'device_file_state',
  'device_ref',
  'device_suffix',
  'discarded_bytes',
  'duration_code',
  'duration_ms',
  'duration_seconds',
  'elapsed_ms',
  'endpoint',
  'endpoint_capabilities',
  'engine',
  'error_code',
  'error_type',
  'event_kind',
  'expected_command',
  'expected_crc32',
  'expected_size_bytes',
  'failure_category',
  'failure_kind',
  'file_count',
  'file_count_on_first_page',
  'file_size_bytes',
  'file_state',
  'file_transfer',
  'foreground_before',
  'frame_summary',
  'free_mb',
  'gatt_cache_refresh_attempted',
  'gatt_cache_refresh_result',
  'gatt_cache_refresh_supported',
  'gatt_ready',
  'gatt_status',
  'grant_bits',
  'granted',
  'granted_permissions',
  'has_active_or_connecting_session',
  'has_name',
  'http_status',
  'idle_ms',
  'instance_id',
  'ios_ccc_mode_conflict_count',
  'is_foreground',
  'last_valid_snapshot_at',
  'last_valid_snapshot_source',
  'length',
  'listed_size_bytes',
  'manufacturer_data_length',
  'manufacturer_prefix',
  'max_retries',
  'method',
  'missing_count',
  'missing_endpoints',
  'mode',
  'mtu',
  'name_format_valid',
  'next_action',
  'occurred_at',
  'offset',
  'onboarding_complete',
  'onboarding_loaded',
  'operation',
  'operation_name',
  'pairing_required',
  'percent',
  'permissions',
  'phase',
  'phase_from',
  'phase_to',
  'platform',
  'previous_state',
  'protocol_version',
  'raw_packet_hex_omitted',
  'reason',
  'record_mode',
  'record_status',
  'record_type',
  'reported_write_payload',
  'received_bytes',
  'reconnect_paused_for_background',
  'rejected_frames',
  'remaining_ms',
  'request_bytes',
  'requested_mode',
  'required',
  'required_mtu',
  'response_bytes',
  'response_command',
  'response_count',
  'result',
  'rssi',
  'safe',
  'segment_count',
  'segment_index',
  'service_count',
  'service_uuid_present',
  'session_id',
  'setup_completed',
  'setup_mode',
  'size',
  'size_bytes',
  'stage',
  'state',
  'status',
  'sub_command',
  'subscription_count',
  'supports_indicate',
  'supports_notify',
  'sync_state',
  'text_length',
  'timeout_ms',
  'total_bytes',
  'total_mb',
  'transaction_hash',
  'type',
  'utc_seconds',
  'variant',
  'wait_id',
  'window',
  'wire_summary',
  // Flutter's `nested` field is an app-private recursively sanitized map.
  // The dashboard API only admits scalar fields, so it must never enter UI
  // state as a rehydrated JSON object.
] as const;

export type EvtLogSafeFieldKey = (typeof EVT_LOG_SAFE_FIELD_KEYS)[number];

export type EvtLogParseStatus = 'parsed' | 'unparsed' | 'redacted';

export type EvtLogDirection = 'app' | 'device' | 'system';

export type EvtFunctionCategory =
  | 'scan'
  | 'gatt'
  | 'subscribe'
  | 'auth'
  | 'record'
  | 'file'
  | 'config'
  | 'playback'
  | 'protocol'
  | 'upload'
  | 'reconnect'
  | 'other';

/**
 * A result of `review` means the available log evidence is incomplete or
 * ambiguous. It must not be rendered as either a passed or a failed test.
 */
export type EvtFlowStatus = 'success' | 'failure' | 'review';

export type EvtFlowReviewReason =
  | 'awaiting_device_response'
  | 'cancelled'
  | 'auxiliary_events'
  | 'incomplete_evidence';

export interface EvtFunctionCategoryMeta {
  readonly title: string;
  readonly order: number;
}

export const EVT_FUNCTION_CATEGORY_META: Readonly<Record<EvtFunctionCategory, EvtFunctionCategoryMeta>> = {
  scan: { title: '扫描与目标选择', order: 1 },
  gatt: { title: 'GATT 建立与服务发现', order: 2 },
  subscribe: { title: 'EVT 响应通道订阅', order: 3 },
  auth: { title: '安全码认证', order: 4 },
  record: { title: '设备录音控制', order: 5 },
  file: { title: '设备文件下载', order: 6 },
  config: { title: '设备配置与隐私', order: 7 },
  playback: { title: '本地音频播放', order: 8 },
  protocol: { title: 'EVT 协议交互', order: 9 },
  upload: { title: '运行日志上报', order: 10 },
  reconnect: { title: '自动回连', order: 11 },
  other: { title: '应用运行环境', order: 12 },
};

export type EvtLogFields = Readonly<Record<string, string>>;

export interface ParsedEvtLogLine {
  readonly parseStatus: 'parsed';
  readonly lineNumber: number;
  /** Chinese display prefix before the UTC timestamp, already sanitized. */
  readonly prefix: string;
  readonly timestamp: string;
  readonly level: string;
  readonly scope: string;
  readonly traceId: string | null;
  readonly operation: string | null;
  readonly stage: string | null;
  readonly event: string;
  readonly result: string | null;
  readonly elapsedMs: number | null;
  readonly fields: EvtLogFields;
  readonly direction: EvtLogDirection;
  /** A display-safe reconstruction of the parsed line. */
  readonly summary: string;
  /** Non-fatal parsing caveats, for example an old eight-column line. */
  readonly warnings: readonly EvtLogParseWarning[];
}

export interface UnparsedEvtLogLine {
  readonly parseStatus: 'unparsed' | 'redacted';
  readonly lineNumber: number;
  /** Never contains the raw input line. */
  readonly summary: string;
  readonly reason: EvtLogUnparsedReason;
}

export type EvtLogLine = ParsedEvtLogLine | UnparsedEvtLogLine;

/**
 * The safe, structured shape returned by `evt-diagnostic-content-v1`.
 * Values still pass through the browser-side whitelist and redaction layer.
 */
export interface EvtLogContentItem {
  readonly line_no: number;
  readonly parse_status: EvtLogParseStatus;
  readonly timestamp?: string;
  readonly level?: string;
  readonly scope?: string;
  readonly trace_id?: string;
  readonly operation?: string;
  readonly stage?: string;
  readonly event?: string;
  readonly result?: string;
  readonly elapsed_ms?: number | null;
  readonly fields?: Readonly<Record<string, unknown>>;
  readonly summary?: string;
}

export type EvtLogParseWarning = 'legacy_missing_elapsed_ms';

export type EvtLogUnparsedReason =
  | 'empty'
  | 'timestamp_not_found'
  | 'invalid_timestamp'
  | 'not_enough_columns'
  | 'invalid_required_field'
  | 'sensitive_content'
  | 'server_unparsed'
  | 'server_redacted';

export interface EvtLogParseResult {
  readonly schemaVersion: typeof EVT_DIAGNOSTIC_LINE_SCHEMA;
  readonly lines: readonly EvtLogLine[];
  readonly records: readonly ParsedEvtLogLine[];
  readonly parsedCount: number;
  readonly unparsedCount: number;
  readonly redactedCount: number;
}

export interface EvtDirectionCounts {
  readonly app: number;
  readonly device: number;
  readonly system: number;
}

export interface EvtFlowStatusInference {
  readonly status: EvtFlowStatus;
  readonly reviewReason?: EvtFlowReviewReason;
  readonly conclusion: string;
}

export interface EvtFlowNode extends EvtFlowStatusInference {
  readonly id: string;
  readonly category: EvtFunctionCategory;
  readonly title: string;
  readonly traceId: string | null;
  readonly operation: string | null;
  readonly startedAt: string;
  readonly endedAt: string;
  readonly durationMs: number | null;
  readonly directionCounts: EvtDirectionCounts;
  readonly eventCount: number;
  readonly records: readonly ParsedEvtLogLine[];
}
