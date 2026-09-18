import { describe, expect, it, vi } from 'vitest';
import {
  createDiagnosticLogApi,
  getConfiguredApiBaseUrl,
  LogApiConfigurationError,
  LogApiContractError,
} from './logApi';

describe('diagnostic log API client', () => {
  it('does not make a request without an approved base URL', async () => {
    const fetch = vi.fn();
    const api = createDiagnosticLogApi({ baseUrl: '', fetch });

    await expect(api.list()).rejects.toBeInstanceOf(LogApiConfigurationError);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('uses the contract path and sends only configured list query values', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      items: [],
      page: 1,
      page_size: 20,
      total: 0,
    }), { status: 200 }));
    const api = createDiagnosticLogApi({
      baseUrl: 'https://logs.example.test/base-path-is-ignored',
      fetch,
    });

    await api.list({ page: 1, page_size: 20, keyword: '认证', platform: undefined });

    expect(fetch).toHaveBeenCalledWith(
      'https://logs.example.test/api/v1/diagnostic-logs?page=1&page_size=20&keyword=%E8%AE%A4%E8%AF%81',
      {
        method: 'GET',
        credentials: 'include',
      },
    );
  });

  it('reads the documented Vite log-service variable', () => {
    const runtime = globalThis as typeof globalThis & {
      __LOG_DASHBOARD_CONFIG__?: { VITE_LOG_API_BASE_URL?: string };
    };
    const previous = runtime.__LOG_DASHBOARD_CONFIG__;

    try {
      runtime.__LOG_DASHBOARD_CONFIG__ = {
        VITE_LOG_API_BASE_URL: 'https://logs.example.test/ignored-path',
      };
      expect(getConfiguredApiBaseUrl()).toBe('https://logs.example.test');
    } finally {
      runtime.__LOG_DASHBOARD_CONFIG__ = previous;
    }
  });

  it('lets an explicit empty base URL disable a configured runtime address', async () => {
    const runtime = globalThis as typeof globalThis & {
      __LOG_DASHBOARD_CONFIG__?: { VITE_LOG_API_BASE_URL?: string };
    };
    const previous = runtime.__LOG_DASHBOARD_CONFIG__;
    const fetch = vi.fn();

    try {
      runtime.__LOG_DASHBOARD_CONFIG__ = { VITE_LOG_API_BASE_URL: 'https://logs.example.test' };
      const api = createDiagnosticLogApi({ baseUrl: '', fetch });
      await expect(api.list()).rejects.toBeInstanceOf(LogApiConfigurationError);
      expect(fetch).not.toHaveBeenCalled();
    } finally {
      runtime.__LOG_DASHBOARD_CONFIG__ = previous;
    }
  });

  it('serializes server-side dashboard filters and pagination', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      items: [],
      page: 2,
      page_size: 50,
      total: 120,
    }), { status: 200 }));
    const api = createDiagnosticLogApi({ baseUrl: 'https://logs.example.test', fetch });

    await api.list({
      page: 2,
      page_size: 50,
      from: '2026-09-17T00:00:00.000Z',
      to: '2026-09-17T08:00:00.000Z',
      app_version: '0.0.4+5',
      platform: 'android',
      device_ref: '...8423',
      error_code: 'connection_timeout',
      status: 'stored',
      keyword: '认证',
      sort: 'received_at:desc',
    });

    const [calledUrl] = fetch.mock.calls[0] as [string];
    const url = new URL(calledUrl);
    expect(url.pathname).toBe('/api/v1/diagnostic-logs');
    expect(Object.fromEntries(url.searchParams)).toMatchObject({
      page: '2',
      page_size: '50',
      from: '2026-09-17T00:00:00.000Z',
      to: '2026-09-17T08:00:00.000Z',
      app_version: '0.0.4+5',
      platform: 'android',
      device_ref: '...8423',
      error_code: 'connection_timeout',
      status: 'stored',
      keyword: '认证',
      sort: 'received_at:desc',
    });
  });

  it('rejects a non-HTTPS service outside local development', async () => {
    const fetch = vi.fn();
    const api = createDiagnosticLogApi({ baseUrl: 'http://logs.example.test', fetch });

    await expect(api.list()).rejects.toBeInstanceOf(LogApiConfigurationError);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('maps server failures to stable Chinese messages', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      code: 'storage_unavailable',
      message: '/private/server/path should never be displayed',
    }), { status: 503 }));
    const api = createDiagnosticLogApi({ baseUrl: 'https://logs.example.test', fetch });

    await expect(api.list()).rejects.toMatchObject({
      message: '日志存储暂时不可用，请稍后重试。',
      code: 'storage_unavailable',
      status: 503,
    });
  });

  it('explains that the local dashboard proxy needs a server-side credential', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      code: 'dashboard_configuration_missing',
    }), { status: 503 }));
    const api = createDiagnosticLogApi({ baseUrl: 'http://localhost:5173', fetch });

    await expect(api.list()).rejects.toMatchObject({
      message: '看板查询凭证未配置，请使用受保护的 token 启动本地联调。',
      code: 'dashboard_configuration_missing',
      status: 503,
    });
  });

  it('keeps a BFF contract failure distinct from a network failure', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      code: 'upstream_contract_invalid',
    }), { status: 502 }));
    const api = createDiagnosticLogApi({ baseUrl: 'https://logs.example.test', fetch });

    await expect(api.list()).rejects.toMatchObject({
      message: '日志服务响应不符合 EVT 看板契约，已停止加载以避免误判。',
      code: 'upstream_contract_invalid',
      status: 502,
    });
  });

  it('validates the list response and drops unapproved fields before returning it', async () => {
    const fetch = vi.fn().mockResolvedValue(jsonResponse({
      page: 1,
      page_size: 20,
      total: 1,
      items: [{
        id: 'log-001',
        received_at: '2026-09-17T01:00:00.000Z',
        uploaded_at: '2026-09-17T01:00:03.000Z',
        status: 'stored',
        app_version: '0.0.4',
        bytes: 128,
        device_ref: '...8423',
        server_path: '/private/should-not-reach-state',
      }],
    }));
    const api = createDiagnosticLogApi({ baseUrl: 'https://logs.example.test', fetch });

    await expect(api.list()).resolves.toEqual({
      page: 1,
      page_size: 20,
      total: 1,
      items: [{
        id: 'log-001',
        received_at: '2026-09-17T01:00:00.000Z',
        uploaded_at: '2026-09-17T01:00:03.000Z',
        status: 'stored',
        app_version: '0.0.4',
        bytes: 128,
        device_ref: '...8423',
      }],
    });
  });

  it.each([
    ['错误分页类型', { page: '1' }],
    ['错误日志状态', { items: [{ ...validListItem(), status: 'unknown' }] }],
    ['带路径的日志 ID', { items: [{ ...validListItem(), id: '../private-log' }] }],
    ['错误 App 上传时间', { items: [{ ...validListItem(), uploaded_at: '2026-09-17 01:00:03' }] }],
  ])('rejects %s in a list response', async (_label, override) => {
    const fetch = vi.fn().mockResolvedValue(jsonResponse({ ...validListResponse(), ...override }));
    const api = createDiagnosticLogApi({ baseUrl: 'https://logs.example.test', fetch });

    await expect(api.list()).rejects.toBeInstanceOf(LogApiContractError);
  });

  it('validates details against the requested ID and action shape', async () => {
    const fetch = vi.fn().mockResolvedValue(jsonResponse({
      id: 'log-001',
      status: 'stored',
      source_filename: 'aipin-2026-09-17.log',
      received_at: '2026-09-17T01:00:00.000Z',
      uploaded_at: '2026-09-17T01:00:03.000Z',
      device_ref: '...8423',
      bytes: 128,
      available_actions: ['read', 'download'],
      storage_secret: 'must-not-reach-state',
    }));
    const api = createDiagnosticLogApi({ baseUrl: 'https://logs.example.test', fetch });

    await expect(api.get('log-001')).resolves.toEqual({
      id: 'log-001',
      status: 'stored',
      source_filename: 'aipin-2026-09-17.log',
      received_at: '2026-09-17T01:00:00.000Z',
      uploaded_at: '2026-09-17T01:00:03.000Z',
      device_ref: '...8423',
      bytes: 128,
      available_actions: ['read', 'download'],
    });
  });

  it.each([
    ['错误详情 ID', { id: 'another-log' }],
    ['错误权限字段类型', { available_actions: 'download' }],
    ['未知权限动作', { available_actions: ['read', 'unexpected'] }],
    ['错误详情状态', { status: 'unknown' }],
    ['错误详情 App 上传时间', { uploaded_at: '2026-09-17 01:00:03' }],
  ])('rejects %s in a detail response', async (_label, override) => {
    const fetch = vi.fn().mockResolvedValue(jsonResponse({ ...validDetailResponse(), ...override }));
    const api = createDiagnosticLogApi({ baseUrl: 'https://logs.example.test', fetch });

    await expect(api.get('log-001')).rejects.toBeInstanceOf(LogApiContractError);
  });

  it('accepts a complete EVT content response for the requested log and cursor', async () => {
    const fetch = vi.fn().mockResolvedValue(jsonResponse(validContentResponse()));
    const api = createDiagnosticLogApi({ baseUrl: 'https://logs.example.test', fetch });

    await expect(api.getContent('log-001')).resolves.toMatchObject({
      schema_version: 'evt-diagnostic-content-v1',
      id: 'log-001',
      cursor: null,
      items: [{ line_no: 1, parse_status: 'parsed' }],
    });
  });

  it('scrubs unknown and sensitive server content fields before returning them', async () => {
    const fetch = vi.fn().mockResolvedValue(jsonResponse({
      ...validContentResponse(),
      items: [{
        ...validContentResponse().items[0],
        fields: {
          command: '0x09',
          reason: 'security code: 123456',
          raw_packet_hex: 'ED 0A 00 09 00 31 32 33 34 35 36',
          security_code: '123456',
          server_path: '/private/server/path',
        },
        summary: 'security code: 123456',
        internal_note: 'must not enter dashboard state',
      }],
    }));
    const api = createDiagnosticLogApi({ baseUrl: 'https://logs.example.test', fetch });

    const response = await api.getContent('log-001');
    const serialized = JSON.stringify(response);

    expect(response.items[0]).toEqual(expect.objectContaining({
      line_no: 1,
      parse_status: 'parsed',
      fields: { command: '0x09', reason: '[已隐藏]' },
    }));
    expect(response.items[0]).not.toHaveProperty('summary');
    expect(response.items[0]).not.toHaveProperty('internal_note');
    expect(serialized).not.toMatch(/123456|31 32 33|server_path|internal_note/);
  });

  it.each([
    ['错误 schema_version', { schema_version: 'unexpected-schema' }],
    ['错误日志 ID', { id: 'another-log' }],
    ['缺少 cursor', { cursor: undefined }],
    ['items 类型错误', { items: 'not-an-array' }],
    ['下一页状态不一致', { has_more: true, next_cursor: null }],
    ['parsed 项缺少必填字段', { items: [{ line_no: 1, parse_status: 'parsed', timestamp: '2026-09-17T01:00:00.000Z' }] }],
  ])('rejects %s in an EVT content response', async (_label, override) => {
    const body = { ...validContentResponse(), ...override };
    const fetch = vi.fn().mockResolvedValue(jsonResponse(body));
    const api = createDiagnosticLogApi({ baseUrl: 'https://logs.example.test', fetch });

    await expect(api.getContent('log-001')).rejects.toBeInstanceOf(LogApiContractError);
  });
});

function validListItem(): Record<string, unknown> {
  return {
    id: 'log-001',
    received_at: '2026-09-17T01:00:00.000Z',
    status: 'stored',
  };
}

function validListResponse(): Record<string, unknown> {
  return {
    items: [validListItem()],
    page: 1,
    page_size: 20,
    total: 1,
  };
}

function validDetailResponse(): Record<string, unknown> {
  return {
    id: 'log-001',
    status: 'stored',
    source_filename: 'aipin-2026-09-17.log',
    received_at: '2026-09-17T01:00:00.000Z',
    available_actions: ['read'],
  };
}

function validContentResponse(): {
  schema_version: string;
  id: string;
  cursor: null;
  next_cursor: null;
  has_more: boolean;
  items: Record<string, unknown>[];
} {
  return {
    schema_version: 'evt-diagnostic-content-v1',
    id: 'log-001',
    cursor: null,
    next_cursor: null,
    has_more: false,
    items: [{
      line_no: 1,
      parse_status: 'parsed',
      timestamp: '2026-09-17T01:00:00.000Z',
      level: 'INFO',
      scope: 'CMD',
      event: 'evt_command_completed',
      result: 'success',
      fields: { command: '0x09' },
    }],
  };
}

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200 });
}
