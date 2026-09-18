# EVT 日志服务对接

本看板只读取已经由 App 上传、并由服务端完成脱敏的日志。浏览器不会直连 SFTP，也不实现日志上传接口。

## 服务地址与认证

在项目根目录复制 <code>.env.example</code> 为 <code>.env.local</code>，只填写服务根地址：

~~~text
VITE_LOG_API_BASE_URL=https://logs.example.internal
~~~

- 必须使用 HTTPS。仅开发环境允许 <code>http://localhost[:port]</code> 或 <code>http://127.0.0.1[:port]</code>；其他 HTTP 地址会被前端拒绝，且不会发出请求。本机 Vite 代理模式应填写看板自己的地址，例如 <code>http://localhost:5173</code>。
- 地址只使用协议、主机和端口；不要填写 <code>/api</code>、SFTP 地址、账号、目录、私钥或令牌。
- 独立看板只使用已建立的 HttpOnly Cookie/SSO 会话认证；所有请求均为 <code>GET</code>，使用 <code>credentials: include</code>。跨域服务需只放行看板实际 Origin，并返回 <code>Access-Control-Allow-Credentials: true</code>。
- 当前页面没有 Bearer Token 配置、输入或注入能力，也不会在请求中主动设置 <code>Authorization</code>。不要把令牌写入 <code>VITE_*</code> 变量、URL 或页面配置。受控本机联调时，Vite 服务端可从 Node 进程的非 <code>VITE_*</code> 环境变量 <code>EVT_LOG_DASHBOARD_TOKEN</code> 读取凭证，并仅代理 <code>/api/v1/diagnostic-logs</code> 到固定日志服务；该 token 不会进入浏览器资源，也不能用于生产部署。该本机中间层会丢弃空的可选字段，并把当前服务的旧 <code>schema + lines</code> 内容响应在服务端解析、脱敏为本节规定的内容结构；生产服务仍必须直接实现本契约，不能把原始 <code>lines</code> 返回浏览器。

固定 API 根路径为 <code>/api/v1/diagnostic-logs</code>。

## 日志列表

~~~text
GET /api/v1/diagnostic-logs
~~~

看板默认请求第 1 页、每页 20 条，并固定使用 <code>sort=received_at:desc</code>。用户可切换每页 20、50、100 条。

| 查询参数 | 说明 |
| --- | --- |
| <code>page</code>、<code>page_size</code> | 分页；当前界面默认 <code>1</code>、<code>20</code>。 |
| <code>from</code>、<code>to</code> | 接收时间范围，UTC ISO 8601，例如 <code>2026-09-17T03:21:26.781Z</code>。 |
| <code>app_version</code> | App 版本。 |
| <code>platform</code> | <code>android</code> 或 <code>ios</code>。 |
| <code>device_ref</code> | 已脱敏的设备引用，不能是完整 MAC、UUID 或设备地址。 |
| <code>error_code</code> | 稳定错误码。 |
| <code>status</code> | <code>stored</code>、<code>quarantined</code>、<code>expired</code>、<code>deleted</code>。 |
| <code>keyword</code> | 关键字。 |
| <code>sort</code> | 当前界面固定 <code>received_at:desc</code>。 |

空参数不会发送。客户端类型还预留 <code>trace_id</code>、<code>level</code>、<code>event</code> 和 <code>received_at:asc</code>，当前界面没有对应筛选控件。

列表响应只能包含以下字段：

~~~json
{
  "items": [
    {
      "id": "log_01J...",
      "received_at": "2026-09-17T03:21:26.781Z",
      "uploaded_at": "2026-09-17T03:21:22.104Z",
      "app_version": "0.0.4",
      "platform": "android",
      "device_ref": "A1B2",
      "bytes": 23840,
      "status": "stored",
      "error_codes": ["gatt_timeout"],
      "warning_count": 1,
      "error_count": 0
    }
  ],
  "page": 1,
  "page_size": 20,
  "total": 126
}
~~~

每个列表项必须有 <code>id</code>、<code>received_at</code>、<code>status</code>；其他字段可省略。<code>uploaded_at</code> 是 App 请求中上报的 UTC 时间，可选；看板用它对应 App 侧看到的上传时间，并在与 <code>received_at</code> 不同时同时标示服务器接收时间。它不参与服务端排序、筛选或审计，列表仍按 <code>received_at</code> 处理。<code>id</code> 应是安全的不可猜测引用，不能带存储路径。

## 详情、读取与下载

~~~text
GET /api/v1/diagnostic-logs/{id}
GET /api/v1/diagnostic-logs/{id}/content?cursor=<opaque>&limit=500
GET /api/v1/diagnostic-logs/{id}/download
~~~

详情响应前端验证并保留的白名单为 <code>id</code>、<code>source_filename</code>、<code>received_at</code>、<code>uploaded_at</code>、<code>device_ref</code>、<code>bytes</code>、<code>status</code>、<code>available_actions</code>。<code>id</code> 必须与请求的日志 ID 完全一致，<code>source_filename</code> 只能是文件名，不能是本机或服务端路径。

<code>status</code> 必须是 <code>stored</code>、<code>quarantined</code>、<code>expired</code>、<code>deleted</code> 之一。只有 <code>stored</code> 日志可以读取或下载：

| 动作 | 前端判定 |
| --- | --- |
| 读取链路 | <code>status=stored</code>，并且 <code>available_actions</code> 缺失/为空（兼容旧服务），或其中包含 <code>view</code>、<code>read</code>、<code>content</code> 之一。 |
| 下载日志 | <code>status=stored</code>，且 <code>available_actions</code> 明确包含 <code>download</code>。 |

服务端应始终返回明确的 <code>available_actions</code>，例如 <code>["read", "download"]</code>，以便按账号权限控制操作。非 <code>stored</code> 状态不应授予读取或下载动作。下载由新窗口打开，服务端应返回附件流，或返回经过鉴权的短时跳转；不要将持久下载凭据放进 URL。

## 内容分页与联调判定

内容接口响应使用 <code>evt-diagnostic-content-v1</code>：

~~~json
{
  "schema_version": "evt-diagnostic-content-v1",
  "id": "log_01J...",
  "cursor": null,
  "next_cursor": "500",
  "has_more": true,
  "items": [
    {
      "line_no": 1,
      "parse_status": "parsed",
      "timestamp": "2026-09-17T03:21:26.781350Z",
      "level": "INFO",
      "scope": "CMD",
      "trace_id": "ab12cd",
      "operation": "device_authenticate",
      "stage": "response",
      "event": "evt_command_response_received",
      "result": "accepted",
      "elapsed_ms": 30,
      "fields": {"actual_command": "0x89"}
    }
  ]
}
~~~

- 看板首次请求 <code>limit=500</code>，随后按服务端返回的 opaque <code>next_cursor</code> 继续加载，最多 20 页、10,000 行。
- 每个 <code>line_no</code> 必须是正安全整数。前端不信任返回顺序，会按 <code>line_no</code> 排序后再聚合联调链路。
- <code>has_more=true</code> 时必须返回非空、未重复的 <code>next_cursor</code>。缺失或重复时，看板停止加载且拒绝生成联调结论，避免将不完整日志误判为成功或失败。
- <code>parse_status=parsed</code> 时，<code>timestamp</code> 必须是严格 UTC ISO 时间；<code>level</code>、<code>scope</code>、<code>event</code> 必须是机器标识符。可选字段只有 <code>trace_id</code>、<code>operation</code>、<code>stage</code>、<code>result</code>、非负 <code>elapsed_ms</code>、<code>fields</code>。
- <code>parse_status=unparsed</code> 或 <code>redacted</code> 时，只能返回 <code>line_no</code>、<code>parse_status</code> 和已审核的安全 <code>summary</code>。不得返回原始文本、协议包或其他明细；这两类记录不参与成功/失败判定。

## 前端响应契约校验

列表、详情和内容接口必须返回 JSON。看板在使用响应前执行白名单契约校验；不合规时会显示“响应不符合 EVT 看板契约”，停止当前列表刷新或链路加载，不用不完整响应生成联调结论。

| 接口 | 必须通过的校验 |
| --- | --- |
| 列表 | 根对象必须包含 <code>items</code>、正整数 <code>page</code>/<code>page_size</code>、非负整数 <code>total</code>；每项的 ID、UTC 接收时间、保存状态和已提供的可选字段类型必须有效。 |
| 详情 | 响应 ID 必须等于请求 ID；<code>status</code> 必须是已知状态；文件名、接收时间、设备引用、大小和 <code>available_actions</code> 必须符合类型约束。 |
| 内容 | <code>schema_version</code> 必须为 <code>evt-diagnostic-content-v1</code>；响应 ID、请求 cursor、<code>has_more</code>/<code>next_cursor</code> 必须一致；每项必须有正整数 <code>line_no</code> 和合法 <code>parse_status</code>，<code>parsed</code> 项还必须提供字符串形式的时间、级别、范围和事件。 |

前端只把白名单字段带入看板状态：列表和详情中的未知字段会丢弃；内容项中不参与解析的字段不会展示，<code>fields</code> 还会继续按下方安全键白名单过滤。服务端仍不得把额外字段视为可传输数据；已知字段缺失、类型错误、ID/游标不匹配或 schema 错误都会中止加载。内容项通过结构校验但不符合严格 EVT 时间或标识符格式时，会转为未解析安全摘要，不参与联调成功/失败判定。

## 字段白名单与脱敏

服务端是主脱敏边界。列表、详情、内容根对象和内容项只能返回本说明列出的字段；禁止额外透传数据库字段、原始日志行或存储元数据。

<code>fields</code> 只能使用前端 <code>EVT_LOG_SAFE_FIELD_KEYS</code> 白名单。服务端应与 [logTypes.ts](../src/domain/logTypes.ts) 中的列表保持一致；未知键、对象、数组和超过 512 字符的值不得返回。允许的键包括：

~~~text
action, actual_command, actual_crc32, actual_size_bytes, archive_state, attempt,
authentication_ready, authentication_window_ms, automatic, bytes, characteristic,
characteristic_count, check, checks, checkpoint_phase, chunk_bytes, chunk_length,
code_length, command, configured, connection_attempt, content_length, count, crc,
crc32, critical, current_operation, cycle, device_file_state, device_ref, device_suffix,
discarded_bytes, duration_code, duration_ms, duration_seconds, elapsed_ms, endpoint,
endpoint_capabilities, engine, error_code, error_type, event_kind, expected_command,
expected_crc32, expected_size_bytes, failure_category, failure_kind, file_count,
file_count_on_first_page, file_size_bytes, file_state, file_transfer, foreground_before,
frame_summary, free_mb, gatt_cache_refresh_attempted, gatt_cache_refresh_result,
gatt_cache_refresh_supported, gatt_ready, gatt_status, grant_bits, granted,
granted_permissions, has_active_or_connecting_session, has_name, http_status, idle_ms,
instance_id, ios_ccc_mode_conflict_count, is_foreground, last_valid_snapshot_at,
last_valid_snapshot_source, length, listed_size_bytes, manufacturer_data_length,
manufacturer_prefix, max_retries, method, missing_count, missing_endpoints, mode, mtu,
name_format_valid, next_action, occurred_at, offset, onboarding_complete,
onboarding_loaded, operation, operation_name, pairing_required, percent, permissions,
phase, phase_from, phase_to, platform, previous_state, protocol_version,
raw_packet_hex_omitted, reason, record_mode, record_status, record_type,
reported_write_payload, received_bytes, reconnect_paused_for_background, rejected_frames,
remaining_ms, request_bytes,
requested_mode, required, required_mtu, response_bytes, response_command, response_count,
result, rssi, safe, segment_count, segment_index, service_count, service_uuid_present,
session_id, setup_completed, setup_mode, size, size_bytes, stage, state, status,
sub_command, subscription_count, supports_indicate, supports_notify, sync_state,
text_length, timeout_ms, total_bytes, total_mb, transaction_hash, type, utc_seconds,
variant, wait_id, window, wire_summary
~~~

<code>critical</code> 只能为布尔值，<code>reported_write_payload</code> 只能为非负整数。<code>frame_summary</code> 和 <code>wire_summary</code> 仅允许 Flutter <code>EvtPacketLogSummary</code> 输出的固定控制帧摘要、认证码已掩码摘要或已省略标记；看板会复核帧头、长度、命令和允许的载荷长度，任意伪造、未知或原始包摘要都会被丢弃。

<code>nested</code> 是 App 私有日志中递归脱敏的结构化字段，不属于浏览器 API 的标量 <code>fields</code> 契约；服务端不得返回它，看板也不会将其载入状态。

严禁返回或下载：原始包（<code>raw_packet_hex</code>、<code>packet_hex</code>、<code>payload_hex</code>、<code>tx_hex</code>、<code>rx_hex</code>）、安全码/PIN/口令、密码、私钥、Token、Authorization、API Key、账号、用户名、服务器主机和 SFTP 端口、远端目录、存储路径、完整 MAC/UUID、URI、本机路径、邮箱。<code>raw_packet_hex_omitted</code> 只能表示“已省略”，不能携带包内容。

前端还会再次删除未知字段和敏感值，但服务端不得依赖这层兜底。错误响应只应给出稳定 <code>code</code>，不要让 <code>message</code> 暴露路径或凭据；已识别 <code>invalid_file</code>、<code>file_too_large</code>、<code>unauthorized</code>、<code>forbidden</code>、<code>quota_exceeded</code>、<code>storage_unavailable</code>、<code>not_found</code>。
