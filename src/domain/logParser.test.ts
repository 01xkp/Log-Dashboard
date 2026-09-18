import { describe, expect, it } from 'vitest';
import {
  aggregateEvtFlowNodes,
  parseEvtLogContentItems,
  parseEvtLogLine,
  parseEvtLogText,
  redactSensitiveContent,
  sanitizeLogFilename,
} from './logParser';

describe('EVT log parser', () => {
  it('parses the current Flutter reconnect and lifecycle line contract', () => {
    const result = parseEvtLogText([
      '2026-09-18T01:00:00.000Z | INFO | RECONNECT | - | device_reconnect | waitingToRetry | reconnect_retry_scheduled | pending | - | attempt=2 cycle=3 phase=waitingToRetry',
      '2026-09-18T01:00:00.001Z | INFO | APP_LIFECYCLE | - | - | - | app_resumed | completed | -',
    ].join('\n'));

    expect(result).toMatchObject({ parsedCount: 2, unparsedCount: 0, redactedCount: 0 });
    expect(result.records[0]).toMatchObject({
      scope: 'RECONNECT',
      operation: 'device_reconnect',
      stage: 'waitingToRetry',
      fields: { attempt: '2', cycle: '3', phase: 'waitingToRetry' },
    });
    expect(aggregateEvtFlowNodes(result.records).map((node) => node.category)).toEqual(['reconnect', 'other']);
  });

  it('only marks authentication successful after request, matching response, and business completion', () => {
    const result = parseEvtLogText([
      '2026-09-17T01:00:00.000Z | INFO | CMD | ab12cd | device_authenticate | fa19_write | evt_command_transmit_started | pending | - | command=0x09 expected_command=0x89',
      '2026-09-17T01:00:00.030Z | INFO | CMD | ab12cd | device_authenticate | response | evt_command_response_received | accepted | 30 | actual_command=0x89',
      '2026-09-17T01:00:00.040Z | INFO | SESSION | ab12cd | device_authenticate | sync | legacy_authentication_completed | success | 40',
    ].join('\n'));

    const auth = aggregateEvtFlowNodes(result.records).find((node) => node.category === 'auth');

    expect(auth?.status).toBe('success');
    expect(auth?.directionCounts).toMatchObject({ app: 1, device: 1 });
  });

  it('does not mistake a completed authentication event for a later request', () => {
    const result = parseEvtLogText([
      '2026-09-17T01:00:00.000Z | INFO | CMD | ab12cd | device_authenticate | fa19_write | evt_command_transmit_started | pending | - | command=0x09 expected_command=0x89',
      '2026-09-17T01:00:00.030Z | INFO | CMD | ab12cd | device_authenticate | response | evt_command_response_matched | accepted | 30 | actual_command=0x89 expected_command=0x89',
      '2026-09-17T01:00:00.040Z | INFO | SESSION | ab12cd | device_authenticate | sync | legacy_authentication_completed | success | 40 | expected_command=0x89',
    ].join('\n'));

    const auth = aggregateEvtFlowNodes(result.records).find((node) => node.category === 'auth');

    expect(auth?.status).toBe('success');
  });

  it('keeps an App-only command as review instead of incorrectly passing the flow', () => {
    const result = parseEvtLogText(
      '2026-09-17T01:00:00.000Z | INFO | CMD | ab12cd | device_authenticate | fa19_write | evt_command_transmit_started | pending | - | command=0x09 expected_command=0x89',
    );

    const auth = aggregateEvtFlowNodes(result.records).find((node) => node.category === 'auth');

    expect(auth?.status).toBe('review');
    expect(auth?.reviewReason).toBe('awaiting_device_response');
  });

  it('keeps a trace-less V1.6 authentication failure in one business chain', () => {
    const result = parseEvtLogText([
      '2026-09-17T01:00:00.000Z | INFO | AUTH | - | device_authenticate | challenge | legacy_authentication_requested | pending | - | action=authenticate',
      '2026-09-17T01:00:00.001Z | INFO | SESSION | - | device_authenticate | fa19_write | legacy_security_exchange_dispatching | pending | 1 | command=0x09 expected_command=0x89',
      '【协议】【发送：等待写入设备】 2026-09-17T01:00:00.002Z | INFO | CMD | - | - | request | evt_command_queued | pending | - | command=0x09 expected_command=0x89',
      '【协议】【发送：App到设备】 2026-09-17T01:00:00.003Z | INFO | CMD | - | - | write | evt_command_transmit_started | pending | - | command=0x09 expected_command=0x89 wait_id=7',
      '【协议】【接收：设备到App】 2026-09-17T01:00:00.004Z | INFO | CMD | - | - | response | evt_command_response_matched | success | 2 | actual_command=0x89 command=0x89 expected_command=0x89 wait_id=7',
      '【协议】【接收：设备到App】 2026-09-17T01:00:00.005Z | INFO | CMD | - | - | response | evt_command_completed | completed | 3 | actual_command=0x89 command=0x09 expected_command=0x89',
      '2026-09-17T01:00:00.006Z | INFO | SESSION | - | device_authenticate | response | legacy_security_exchange_result_received | failed | 4 | command=0x89',
      '2026-09-17T01:00:00.007Z | WARNING | AUTH | - | device_authenticate | challenge | legacy_authentication_device_rejected | failed | - | action=authenticate',
      '2026-09-17T01:00:00.008Z | WARNING | AUTH | - | device_authenticate | challenge | legacy_authentication_failed | failed | - | action=authenticate',
    ].join('\n'));

    const nodes = aggregateEvtFlowNodes(result.records).filter((node) => node.category === 'auth');

    expect(nodes).toHaveLength(1);
    expect(nodes[0]).toMatchObject({
      operation: 'device_authenticate',
      status: 'failure',
      eventCount: 9,
      directionCounts: { app: 2, device: 2 },
    });
  });

  it('does not treat protocol cleanup events as a successful EVT transaction', () => {
    const result = parseEvtLogText([
      '2026-09-17T01:00:00.000Z | INFO | CMD | - | - | idle | evt_command_client_closing | pending | - | state=closing',
      '2026-09-17T01:00:00.001Z | INFO | CMD | - | - | idle | evt_command_client_closed | completed | 1 | state=closed',
    ].join('\n'));

    const node = aggregateEvtFlowNodes(result.records)[0];

    expect(node).toMatchObject({ category: 'other', status: 'review', reviewReason: 'auxiliary_events' });
  });

  it('keeps scan shutdown events under review until a target is accepted', () => {
    const result = parseEvtLogText([
      '2026-09-17T01:00:00.000Z | INFO | BLE | - | device_scan | idle | scan_stop_requested | pending | -',
      '2026-09-17T01:00:00.001Z | INFO | BLE | - | device_scan | idle | scan_stopped | completed | 1',
    ].join('\n'));

    const node = aggregateEvtFlowNodes(result.records)[0];

    expect(node).toMatchObject({ category: 'scan', status: 'review', reviewReason: 'incomplete_evidence' });
  });

  it('requires a matched reply before a protocol transaction passes', () => {
    const result = parseEvtLogText([
      '【协议】【发送：App到设备】 2026-09-17T01:00:00.000Z | INFO | CMD | - | - | write | evt_command_queued | pending | - | command=0x01 expected_command=0x81',
      '【协议】【接收：设备到App】 2026-09-17T01:00:00.001Z | INFO | CMD | - | - | response | evt_command_response_received | accepted | 1 | actual_command=0x81 command=0x81 expected_command=0x81',
      '【协议】【接收：设备到App】 2026-09-17T01:00:00.002Z | INFO | CMD | - | - | response | evt_command_completed | completed | 2 | actual_command=0x81 command=0x01 expected_command=0x81',
    ].join('\n'));

    const node = aggregateEvtFlowNodes(result.records)[0];

    expect(node).toMatchObject({ category: 'protocol', status: 'review', reviewReason: 'awaiting_device_response' });
  });

  it('does not confuse a file-read stage with an App-sent direction prefix', () => {
    const result = parseEvtLogText(
      '【协议】【接收：设备到App】【信息】【阶段：文件读取】 2026-09-17T01:00:00.000Z | INFO | CMD | ab12cd | device_file_import | download | evt_command_completed | success | 30 | actual_command=0xa3',
    );

    expect(result.records[0]?.direction).toBe('device');
  });

  it('does not retain raw security codes in parsed browser state', () => {
    const result = parseEvtLogText(
      '2026-09-17T01:00:00.000Z | INFO | CMD | - | device_authenticate | fa19_write | evt_command_transmit_started | pending | - | security_code=123456',
    );

    expect(result.redactedCount).toBe(1);
    expect(result.records).toHaveLength(0);
    expect(result.lines[0].summary).not.toContain('123456');
    expect(redactSensitiveContent('wire=ED 0A 00 09 00 31 32 33 34 35 36')).not.toContain('31 32 33');
  });

  it('keeps only Flutter-approved packet summaries and scalar transport fields', () => {
    const frameSummary = 'evt_control cmd=0x07 content=01';
    const wireSummary = 'evt_control cmd=0x07 wire=ED 04 00 07 01 00 00';
    const local = parseEvtLogText(
      `2026-09-17T01:00:00.000Z | INFO | CMD | - | - | write | evt_command_transmit_started | pending | - | bytes=7 critical=true reported_write_payload=244 nested={"safe":{"length":3}} frame_summary=${frameSummary} wire_summary=${wireSummary}`,
    );

    expect(local.records[0]?.fields).toEqual({
      bytes: '7',
      critical: 'true',
      reported_write_payload: '244',
      frame_summary: frameSummary,
      wire_summary: wireSummary,
    });
    expect(local.records[0]?.fields).not.toHaveProperty('nested');

    const authenticationFrame = 'evt_authentication cmd=0x09 action=0x02 security_code=redacted';
    const authenticationWire = 'evt_authentication cmd=0x09 action=0x02 wire=ED 0A 00 09 02 ** ** ** ** ** ** DE 3C';
    const authentication = parseEvtLogText(
      `2026-09-17T01:00:00.001Z | INFO | CMD | - | device_authenticate | write | evt_command_transmit_started | pending | - | frame_summary=${authenticationFrame} wire_summary=${authenticationWire}`,
    );

    expect(authentication.records[0]?.fields).toEqual({
      frame_summary: authenticationFrame,
      wire_summary: authenticationWire,
    });

    const server = parseEvtLogContentItems([{
      line_no: 1,
      parse_status: 'parsed',
      timestamp: '2026-09-17T01:00:00.000Z',
      level: 'INFO',
      scope: 'CMD',
      event: 'evt_command_transmit_started',
      fields: {
        critical: false,
        reported_write_payload: 512,
        frame_summary: frameSummary,
        wire_summary: wireSummary,
        nested: '{"safe":{"length":3}}',
      },
    }]);

    expect(server.records[0]?.fields).toEqual({
      critical: 'false',
      reported_write_payload: '512',
      frame_summary: frameSummary,
      wire_summary: wireSummary,
    });
  });

  it('drops forged packet summaries and invalid scalar transport fields', () => {
    const result = parseEvtLogContentItems([{
      line_no: 1,
      parse_status: 'parsed',
      timestamp: '2026-09-17T01:00:00.000Z',
      level: 'INFO',
      scope: 'CMD',
      event: 'evt_command_transmit_started',
      fields: {
        critical: 'yes',
        reported_write_payload: '-1',
        frame_summary: 'evt_control cmd=0x09 content=00',
        wire_summary: 'evt_control cmd=0x07 wire=AA 04 00 07 01 00 00',
        nested: '{"token":"must-not-enter-browser"}',
      },
    }]);

    expect(result.records[0]?.fields).toEqual({});
    expect(result.records[0]?.summary).not.toContain('must-not-enter-browser');
  });

  it('redacts English security-code labels from local and server log data', () => {
    const local = parseEvtLogText(
      '2026-09-17T01:00:00.000Z | INFO | CMD | - | device_authenticate | fa19_write | evt_command_transmit_started | pending | - | reason=security code: 123456',
    );
    const server = parseEvtLogContentItems([{
      line_no: 1,
      parse_status: 'parsed',
      timestamp: '2026-09-17T01:00:00.000Z',
      level: 'INFO',
      scope: 'AUTH',
      event: 'legacy_authentication_requested',
      fields: { reason: 'verification-code: 654321' },
    }]);
    const redactedText = [
      'security code: 123456',
      'security-code=234567',
      'verification code: 345678',
      'pass code=456789',
      'PIN 567890',
    ].map(redactSensitiveContent).join('\n');

    expect(local).toMatchObject({ parsedCount: 0, redactedCount: 1 });
    expect(local.lines[0]?.summary).not.toContain('123456');
    expect(server.records[0]?.fields).toEqual({ reason: '[已隐藏]' });
    expect(server.records[0]?.summary).not.toContain('654321');
    expect(redactedText).not.toMatch(/123456|234567|345678|456789|567890/);
  });

  it('splits repeated legacy operations after a terminal failure and a new request', () => {
    const result = parseEvtLogText([
      '2026-09-17T01:00:00.000Z | INFO | CMD | - | device_file_import | request | evt_command_transmit_started | pending | - | command=0x23 expected_command=0xa3',
      '2026-09-17T01:00:02.000Z | WARNING | CMD | - | device_file_import | response | evt_response_wait_finished | timeout | 2000 | expected_command=0xa3',
      '2026-09-17T01:01:00.000Z | INFO | CMD | - | device_file_import | request | evt_command_transmit_started | pending | - | command=0x23 expected_command=0xa3',
      '【协议】【接收：设备到App】 2026-09-17T01:01:00.050Z | INFO | CMD | - | device_file_import | download | evt_command_completed | success | 50 | actual_command=0xa3',
    ].join('\n'));

    const nodes = aggregateEvtFlowNodes(result.records).filter((node) => node.operation === 'device_file_import');

    expect(nodes).toHaveLength(2);
    expect(nodes.map((node) => node.status)).toEqual(['failure', 'success']);
    expect(nodes.map((node) => node.eventCount)).toEqual([2, 2]);
  });

  it('keeps records with the same usable trace id in one flow even after a retry', () => {
    const result = parseEvtLogText([
      '2026-09-17T01:00:00.000Z | INFO | CMD | ab12cd | device_file_import | request | evt_command_transmit_started | pending | - | command=0x23 expected_command=0xa3',
      '2026-09-17T01:00:02.000Z | WARNING | CMD | ab12cd | device_file_import | response | evt_response_wait_finished | timeout | 2000 | expected_command=0xa3',
      '2026-09-17T01:01:00.000Z | INFO | CMD | ab12cd | device_file_import | request | evt_command_transmit_started | pending | - | command=0x23 expected_command=0xa3',
      '【协议】【接收：设备到App】 2026-09-17T01:01:00.050Z | INFO | CMD | ab12cd | device_file_import | download | evt_command_completed | success | 50 | actual_command=0xa3',
    ].join('\n'));

    const nodes = aggregateEvtFlowNodes(result.records).filter((node) => node.operation === 'device_file_import');

    expect(nodes).toHaveLength(1);
    expect(nodes[0]).toMatchObject({ status: 'failure', eventCount: 4, traceId: 'ab12cd' });
  });

  it('separates repeated trace-less GATT contract successes into distinct connection nodes', () => {
    const result = parseEvtLogText([
      '2026-09-17T01:00:00.000Z | INFO | SESSION | - | device_connect | validation | gatt_service_discovery_completed | success | 100 | endpoint=0xfa11',
      '2026-09-17T01:00:00.050Z | INFO | SESSION | - | device_connect | validation | gatt_contract_verified | success | 150 | endpoint=0xfa11',
      '2026-09-17T01:02:00.000Z | INFO | SESSION | - | device_connect | validation | gatt_service_discovery_completed | success | 110 | endpoint=0xfa11',
      '2026-09-17T01:02:00.050Z | INFO | SESSION | - | device_connect | validation | gatt_contract_verified | success | 180 | endpoint=0xfa11',
    ].join('\n'));

    const nodes = aggregateEvtFlowNodes(result.records).filter((node) => node.operation === 'device_connect');

    expect(nodes).toHaveLength(2);
    expect(nodes.map((node) => node.status)).toEqual(['success', 'success']);
    expect(nodes.map((node) => node.eventCount)).toEqual([2, 2]);
  });

  it('drops unknown fields from local parsed fields and the reconstructed summary', () => {
    const result = parseEvtLogText(
      '2026-09-17T01:00:00.000Z | INFO | CMD | - | device_authenticate | fa19_write | evt_command_transmit_started | pending | - | command=0x09 expected_command=0x89 email=alice@example.com tenant_code=customer-42',
    );

    expect(result.records[0]?.fields).toEqual({ command: '0x09', expected_command: '0x89' });
    expect(result.records[0]?.summary).not.toContain('email');
    expect(result.records[0]?.summary).not.toContain('tenant_code');
    expect(result.records[0]?.summary).not.toContain('alice@example.com');
    expect(result.records[0]?.summary).not.toContain('customer-42');
  });

  it('preserves Flutter safe preflight reasons without splitting Action=2', () => {
    const reason = '【解绑预检】设备尚未完成认证并进入可用状态，未打开安全码输入，也未发送 Action=2';
    const result = parseEvtLogText(
      `2026-09-17T01:00:00.000Z | INFO | SESSION | - | device_unbind | preflight | evt_unbind_preflight_rejected | failed | - | reason=${reason}`,
    );

    expect(result).toMatchObject({ parsedCount: 1, unparsedCount: 0, redactedCount: 0 });
    expect(result.records[0]?.fields).toEqual({ reason });
    expect(result.records[0]?.summary).toContain(`reason=${reason}`);
    expect(result.records[0]?.fields).not.toHaveProperty('action');
  });

  it('maps unsafe Flutter identifier fragments to safe empty values', () => {
    const result = parseEvtLogText(
      '2026-09-17T01:00:00.000Z | INFO | CMD | - | device_token_exchange | payload | authorization_complete | secret | - | wait_id=7',
    );

    expect(result).toMatchObject({ parsedCount: 1, unparsedCount: 0, redactedCount: 0 });
    expect(result.records[0]).toMatchObject({
      event: 'unknown_event',
      operation: null,
      stage: null,
      result: null,
      fields: { wait_id: '7' },
    });

    const uuidResult = parseEvtLogLine(
      '2026-09-17T01:00:00.000Z | INFO | SESSION | - | device_550e8400-e29b-41d4-a716-446655440000_connected | connect | device_connected | success | -',
    );
    expect(uuidResult).toMatchObject({ parseStatus: 'parsed', operation: null });
  });

  it('keeps numeric-leading and 12-character Flutter trace identifiers', () => {
    const result = parseEvtLogText(
      '2026-09-17T01:00:00.000Z | INFO | CMD | 0123456789ab | - | - | evt_command_queued | pending | - | command=0x01',
    );

    expect(result.records[0]?.traceId).toBe('0123456789ab');
    expect(result.records[0]?.summary).toContain('0123456789ab');
  });

  it('normalizes server content order and keeps only approved structured fields', () => {
    const result = parseEvtLogContentItems([
      {
        line_no: 3,
        parse_status: 'redacted',
        summary: 'security_code=123456 email=alice@example.com',
      },
      {
        line_no: 2,
        parse_status: 'parsed',
        timestamp: '2026-09-17T01:00:00.000Z',
        level: 'INFO',
        scope: 'CMD',
        trace_id: '-',
        operation: 'device_authenticate',
        stage: 'fa19_write',
        event: 'evt_command_transmit_started',
        result: 'pending',
        elapsed_ms: null,
        fields: {
          command: '0x09',
          email: 'alice@example.com',
          reason: 'retry tenant_code=customer-42',
          tenant_code: 'customer-42',
        },
        summary: 'command=0x09 email=alice@example.com tenant_code=customer-42',
      },
      {
        line_no: 1,
        parse_status: 'unparsed',
        summary: 'tenant_code=customer-42',
      },
    ]);

    expect(result.lines.map((line) => line.lineNumber)).toEqual([1, 2, 3]);
    expect(result).toMatchObject({ parsedCount: 1, unparsedCount: 1, redactedCount: 1 });
    expect(result.records[0]?.fields).toEqual({ command: '0x09', reason: 'retry [未公开字段]' });
    expect(result.lines.map((line) => line.summary).join('\n')).not.toContain('email');
    expect(result.lines.map((line) => line.summary).join('\n')).not.toContain('tenant_code');
    expect(result.lines.map((line) => line.summary).join('\n')).not.toContain('123456');
  });

  it('ignores a final line separator while retaining a meaningful empty middle line', () => {
    const first = '2026-09-17T01:00:00.000Z | INFO | BLE | - | device_scan | scanning | scan_start_requested | pending | -';
    const second = '2026-09-17T01:00:01.000Z | INFO | BLE | - | device_scan | scanning | scan_result_accepted | accepted | 1000';

    const trailingNewline = parseEvtLogText(`${first}\n`);
    const withMiddleEmptyLine = parseEvtLogText(`${first}\n\n${second}\n`);

    expect(trailingNewline).toMatchObject({ parsedCount: 1, unparsedCount: 0, redactedCount: 0 });
    expect(trailingNewline.lines).toHaveLength(1);
    expect(withMiddleEmptyLine).toMatchObject({ parsedCount: 2, unparsedCount: 1, redactedCount: 0 });
    expect(withMiddleEmptyLine.lines.map((line) => line.lineNumber)).toEqual([1, 2, 3]);
  });

  it('pairs trace-less EVT command transactions by their request and wait id', () => {
    const result = parseEvtLogText([
      '【AIPIN联调】【协议】【发送：等待写入设备】 2026-09-17T01:00:00.000Z | INFO | CMD | - | - | request | evt_command_queued | pending | - | characteristic=0xFA11 command=0x01 content_length=0 expected_command=0x81 max_retries=1 timeout_ms=2000',
      '【AIPIN联调】【协议】 2026-09-17T01:00:00.001Z | INFO | CMD | - | - | write | evt_command_admitted | accepted | - | attempt=1 characteristic=0xFA11 command=0x01 expected_command=0x81',
      '【AIPIN联调】【协议】【回包监听：等待设备响应】 2026-09-17T01:00:00.002Z | INFO | CMD | - | - | response | evt_response_wait_started | pending | 0 | command=0x01 expected_command=0x81 state=write_pending wait_id=7',
      '【AIPIN联调】【协议】【发送：App到设备】 2026-09-17T01:00:00.003Z | INFO | CMD | - | - | write | evt_command_transmit_started | pending | - | command=0x01 expected_command=0x81 wait_id=7',
      '【AIPIN联调】【协议】【接收：设备到App】 2026-09-17T01:00:00.004Z | INFO | CMD | - | - | response | evt_command_response_received | accepted | - | actual_command=0x81 command=0x81 expected_command=0x81 wait_id=7',
      '【AIPIN联调】【协议】【回包监听：等待设备响应】 2026-09-17T01:00:00.005Z | INFO | CMD | - | - | response | evt_response_wait_finished | success | 3 | command=0x01 expected_command=0x81 state=success wait_id=7',
      '【AIPIN联调】【协议】【接收：设备到App】 2026-09-17T01:00:00.006Z | INFO | CMD | - | - | response | evt_command_completed | completed | 4 | actual_command=0x81 command=0x01 expected_command=0x81',
      '【AIPIN联调】【协议】【发送：等待写入设备】 2026-09-17T01:00:01.000Z | INFO | CMD | - | - | request | evt_command_queued | pending | - | characteristic=0xFA11 command=0x01 content_length=0 expected_command=0x81 max_retries=1 timeout_ms=2000',
      '【AIPIN联调】【协议】 2026-09-17T01:00:01.001Z | INFO | CMD | - | - | write | evt_command_admitted | accepted | - | attempt=1 characteristic=0xFA11 command=0x01 expected_command=0x81',
      '【AIPIN联调】【协议】【回包监听：等待设备响应】 2026-09-17T01:00:01.002Z | INFO | CMD | - | - | response | evt_response_wait_started | pending | 0 | command=0x01 expected_command=0x81 state=write_pending wait_id=8',
      '【AIPIN联调】【协议】【发送：App到设备】 2026-09-17T01:00:01.003Z | INFO | CMD | - | - | write | evt_command_transmit_started | pending | - | command=0x01 expected_command=0x81 wait_id=8',
      '【AIPIN联调】【协议】【接收：设备到App】 2026-09-17T01:00:01.004Z | INFO | CMD | - | - | response | evt_command_response_received | accepted | - | actual_command=0x81 command=0x81 expected_command=0x81 wait_id=8',
      '【AIPIN联调】【协议】【回包监听：等待设备响应】 2026-09-17T01:00:01.005Z | INFO | CMD | - | - | response | evt_response_wait_finished | success | 3 | command=0x01 expected_command=0x81 state=success wait_id=8',
      '【AIPIN联调】【协议】【接收：设备到App】 2026-09-17T01:00:01.006Z | INFO | CMD | - | - | response | evt_command_completed | completed | 4 | actual_command=0x81 command=0x01 expected_command=0x81',
    ].join('\n'));

    const nodes = aggregateEvtFlowNodes(result.records).filter((node) => node.category === 'protocol');

    expect(nodes).toHaveLength(2);
    expect(nodes.map((node) => node.status)).toEqual(['success', 'success']);
    expect(nodes.map((node) => node.eventCount)).toEqual([7, 7]);
    expect(nodes.map((node) => node.records.find((record) => record.fields.wait_id)?.fields.wait_id)).toEqual(['7', '8']);
  });

  it('keeps a complete server-side EVT protocol transaction successful without display prefixes', () => {
    const result = parseEvtLogContentItems([
      {
        line_no: 1,
        parse_status: 'parsed',
        timestamp: '2026-09-17T01:00:00.000Z',
        level: 'INFO',
        scope: 'CMD',
        event: 'evt_command_queued',
        result: 'pending',
        fields: { command: '0x01', expected_command: '0x81', wait_id: '9' },
      },
      {
        line_no: 2,
        parse_status: 'parsed',
        timestamp: '2026-09-17T01:00:00.010Z',
        level: 'INFO',
        scope: 'CMD',
        event: 'evt_command_response_matched',
        result: 'accepted',
        fields: { actual_command: '0x81', expected_command: '0x81', wait_id: '9' },
      },
      {
        line_no: 3,
        parse_status: 'parsed',
        timestamp: '2026-09-17T01:00:00.020Z',
        level: 'INFO',
        scope: 'CMD',
        event: 'evt_command_completed',
        result: 'completed',
        fields: { command: '0x01', actual_command: '0x81', expected_command: '0x81', wait_id: '9' },
      },
    ]);

    const node = aggregateEvtFlowNodes(result.records).find((candidate) => candidate.category === 'protocol');

    expect(node).toMatchObject({ status: 'success', directionCounts: { app: 1, device: 2 } });
  });

  it('keeps a timeout and its later trace-less command completion in one transaction', () => {
    const result = parseEvtLogText([
      '【AIPIN联调】【协议】【发送：等待写入设备】 2026-09-17T01:00:00.000Z | INFO | CMD | - | - | request | evt_command_queued | pending | - | command=0x02 expected_command=0x82',
      '【AIPIN联调】【协议】【回包监听：等待设备响应】 2026-09-17T01:00:00.001Z | INFO | CMD | - | - | response | evt_response_wait_started | pending | 0 | command=0x02 expected_command=0x82 wait_id=9',
      '【AIPIN联调】【协议】【回包监听：等待设备响应】 2026-09-17T01:00:02.000Z | WARNING | CMD | - | - | response | evt_response_wait_finished | timeout | 2000 | command=0x02 expected_command=0x82 wait_id=9',
      '【AIPIN联调】【协议】 2026-09-17T01:00:02.001Z | WARNING | CMD | - | - | response | evt_command_completed | failed | 2001 | command=0x02 expected_command=0x82',
    ].join('\n'));

    const nodes = aggregateEvtFlowNodes(result.records).filter((node) => node.category === 'protocol');

    expect(nodes).toHaveLength(1);
    expect(nodes[0]).toMatchObject({ status: 'failure', eventCount: 4 });
  });

  it('keeps a GATT discovery-only sequence under review until the EVT contract is verified', () => {
    const result = parseEvtLogText(
      '【AIPIN联调】【会话】【信息】【阶段：数据校验】 2026-09-17T01:00:00.000Z | INFO | SESSION | - | device_connect | validation | gatt_service_discovery_completed | success | 8 | characteristic_count=10 service_count=3',
    );

    const gatt = aggregateEvtFlowNodes(result.records).find((node) => node.category === 'gatt');

    expect(gatt).toMatchObject({ status: 'review', reviewReason: 'incomplete_evidence' });
  });

  it('returns a display-safe last path segment for log filenames', () => {
    expect(sanitizeLogFilename('C:\\logs\\aipin-2026-09-17-10-00-00.log')).toBe('aipin-2026-09-17-10-00-00.log');
    expect(sanitizeLogFilename('/var/logs/中文联调日志.txt')).toBe('中文联调日志.txt');
    expect(sanitizeLogFilename('evt\u0000-2026.log')).toBe('evt-2026.log');
    expect(sanitizeLogFilename('https://logs.example.test/private/aipin.log', 'safe.log')).toBe('safe.log');
    expect(sanitizeLogFilename('security_code=123456.log', 'safe.log')).toBe('safe.log');
    expect(sanitizeLogFilename('mail-alice@example.com.log', 'safe.log')).toBe('safe.log');
    expect(sanitizeLogFilename('host=logs.example.test.log', 'safe.log')).toBe('safe.log');
    const longName = sanitizeLogFilename(`${'z'.repeat(240)}.log`);
    expect(longName).toMatch(/\.log$/);
    expect([...longName]).toHaveLength(120);
  });
});
