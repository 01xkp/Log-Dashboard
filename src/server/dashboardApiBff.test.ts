import { describe, expect, it, vi } from 'vitest';
import {
  DashboardBffContractError,
  createDashboardReadBff,
  normalizeDashboardApiPayload,
} from './dashboardApiBff';

describe('dashboard API BFF compatibility layer', () => {
  it('returns a JSON configuration error instead of the Vite SPA fallback when the token is missing', async () => {
    const upstreamFetch = vi.fn();
    const use = vi.fn();
    const plugin = createDashboardReadBff({
      dashboardToken: '',
      target: 'https://logs.example.test',
      fetch: upstreamFetch,
    });

    const configureServer = plugin.configureServer as unknown as (server: unknown) => void;
    configureServer({ middlewares: { use } });
    const middleware = use.mock.calls[0]?.[0] as (
      request: unknown,
      response: unknown,
      next: () => void,
    ) => void;
    const response = createMockResponse();
    middleware({
      method: 'GET',
      url: '/api/v1/diagnostic-logs',
      headers: {},
    }, response, vi.fn());
    await Promise.resolve();

    expect(upstreamFetch).not.toHaveBeenCalled();
    expect(response.statusCode).toBe(503);
    expect(response.body).toBe(JSON.stringify({ code: 'dashboard_configuration_missing' }));
    expect(response.headers['content-type']).toBe('application/json; charset=utf-8');
  });

  it('drops nullable optional fields and unknown metadata from the list response', () => {
    const response = normalizeDashboardApiPayload({ kind: 'list' }, {
      page: 1,
      page_size: 20,
      total: 1,
      items: [{
        id: 'log-001',
        received_at: '2026-09-17T01:00:00Z',
        uploaded_at: '2026-09-17T01:00:03Z',
        status: 'stored',
        app_version: '0.0.4+5',
        device_ref: null,
        storage_key: '/private/logs/001',
      }],
    });

    expect(response).toEqual({
      page: 1,
      page_size: 20,
      total: 1,
      items: [{
        id: 'log-001',
        received_at: '2026-09-17T01:00:00Z',
        uploaded_at: '2026-09-17T01:00:03Z',
        status: 'stored',
        app_version: '0.0.4+5',
      }],
    });
  });

  it('converts legacy raw lines into safe structured content before sending it to the browser', () => {
    const response = normalizeDashboardApiPayload({
      kind: 'content',
      id: 'log-001',
    }, {
      schema: 'evt-diagnostic-content-v1',
      id: 'log-001',
      cursor: '0',
      limit: 500,
      lines: [
        '2026-09-17T01:00:00.000Z | INFO | CMD | - | device_authenticate | request | evt_command_queued | accepted | 30 | command=0x09',
        '2026-09-17T01:00:01.000Z | INFO | CMD | - | device_authenticate | response | evt_command_response_received | accepted | 10 | raw_packet_hex=DE AD BE EF',
      ],
      next_cursor: null,
      has_more: false,
    });

    expect(response).toEqual({
      schema_version: 'evt-diagnostic-content-v1',
      id: 'log-001',
      cursor: null,
      next_cursor: null,
      has_more: false,
      items: [
        {
          line_no: 1,
          parse_status: 'parsed',
          timestamp: '2026-09-17T01:00:00.000Z',
          level: 'INFO',
          scope: 'CMD',
          event: 'evt_command_queued',
          operation: 'device_authenticate',
          stage: 'request',
          result: 'accepted',
          elapsed_ms: 30,
          fields: { command: '0x09' },
        },
        {
          line_no: 2,
          parse_status: 'redacted',
        },
      ],
    });
    expect(JSON.stringify(response)).not.toContain('DE AD BE EF');
  });

  it('keeps the legacy pagination offset while translating the cursor contract', () => {
    const response = normalizeDashboardApiPayload({
      kind: 'content',
      id: 'log-001',
      requestedCursor: '500',
    }, {
      schema: 'evt-diagnostic-content-v1',
      id: 'log-001',
      cursor: '500',
      lines: ['not an EVT line'],
      next_cursor: '501',
      has_more: true,
    });

    expect(response).toMatchObject({
      cursor: '500',
      next_cursor: '501',
      has_more: true,
      items: [{ line_no: 501, parse_status: 'unparsed' }],
    });
  });

  it('does not allow a legacy response to expose unknown fields', () => {
    const response = normalizeDashboardApiPayload({
      kind: 'detail',
      id: 'log-001',
    }, {
      id: 'log-001',
      status: 'stored',
      device_ref: null,
      available_actions: ['content', 'download'],
      storage_key: '/private/logs/001',
    });

    expect(response).toEqual({
      id: 'log-001',
      status: 'stored',
      available_actions: ['content', 'download'],
    });
  });

  it('sanitizes optional filename and device fields before returning a detail response', () => {
    const response = normalizeDashboardApiPayload({
      kind: 'detail',
      id: 'log-001',
    }, {
      id: 'log-001',
      status: 'stored',
      source_filename: 'C:\\private\\aipin-2026-09-17.log',
      uploaded_at: '2026-09-17T01:00:03Z',
      device_ref: 'AA:BB:CC:DD:EE:FF',
    });

    expect(response).toEqual({
      id: 'log-001',
      status: 'stored',
      source_filename: 'aipin-2026-09-17.log',
      uploaded_at: '2026-09-17T01:00:03Z',
    });
  });

  it('rejects an invalid App upload time instead of passing it to the browser', () => {
    expect(() => normalizeDashboardApiPayload({ kind: 'list' }, {
      page: 1,
      page_size: 20,
      total: 1,
      items: [{
        id: 'log-001',
        received_at: '2026-09-17T01:00:00Z',
        uploaded_at: '2026-09-17 01:00:03',
        status: 'stored',
      }],
    })).toThrow(DashboardBffContractError);
  });

  it('rejects an unsafe legacy response instead of passing raw lines through', () => {
    expect(() => normalizeDashboardApiPayload({
      kind: 'content',
      id: 'log-001',
    }, {
      schema: 'evt-diagnostic-content-v1',
      id: 'log-001',
      cursor: '0',
      lines: ['not an EVT line'],
      next_cursor: null,
      has_more: true,
    })).toThrow(DashboardBffContractError);
  });
});

function createMockResponse(): {
  statusCode: number;
  headers: Record<string, string>;
  body?: string | Uint8Array;
  setHeader(name: string, value: string): void;
  end(body?: string | Uint8Array): void;
} {
  const response = {
    statusCode: 0,
    headers: {} as Record<string, string>,
    body: undefined as string | Uint8Array | undefined,
    setHeader(name: string, value: string) {
      response.headers[name.toLowerCase()] = value;
    },
    end(body?: string | Uint8Array) {
      response.body = body;
    },
  };
  return response;
}
