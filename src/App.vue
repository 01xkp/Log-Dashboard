<script setup lang="ts">
import { computed, nextTick, ref } from 'vue';
import { ElMessage, ElMessageBox } from 'element-plus';
import {
  diagnosticLogApi,
  getConfiguredApiBaseUrl,
  LogApiConfigurationError,
  LogApiContractError,
  LogApiRequestError,
  type DiagnosticLogContentItem,
  type DiagnosticLogListItem,
  type DiagnosticLogStatus,
} from './api/logApi';
import { demoLogSources } from './data/demoLogs';
import {
  aggregateEvtFlowNodes,
  parseEvtLogContentItems,
  parseEvtLogText,
  redactFieldValue,
  sanitizeLogFilename,
} from './domain/logParser';
import type {
  EvtFlowNode,
  EvtFlowStatus,
  EvtLogParseResult,
  ParsedEvtLogLine,
} from './domain/logTypes';

type LogSource = 'sample' | 'local' | 'server';
type SourceFilter = 'all' | LogSource;
type FileStatus = EvtFlowStatus | 'pending';
type StatusFilter = 'all' | FileStatus;

interface DashboardLogFile {
  readonly id: string;
  readonly source: LogSource;
  readonly filename: string;
  readonly bytes: number | null;
  readonly receivedAt: string | null;
  readonly deviceRef: string | null;
  readonly parseResult: EvtLogParseResult;
  readonly nodes: readonly EvtFlowNode[];
  readonly localImportKey?: string;
  readonly serverId?: string;
  readonly serverStatus?: string;
  readonly serverActions?: readonly string[];
  readonly isLoadedFromServer?: boolean;
}

interface FileTableRow {
  readonly kind: 'file';
  readonly id: string;
  readonly file: DashboardLogFile;
  readonly status: FileStatus;
  readonly children: readonly NodeTableRow[];
}

interface NodeTableRow {
  readonly kind: 'node';
  readonly id: string;
  readonly file: DashboardLogFile;
  readonly node: EvtFlowNode;
  readonly status: EvtFlowStatus;
}

type DashboardTableRow = FileTableRow | NodeTableRow;

interface DetailContext {
  readonly file: DashboardLogFile;
  readonly node: EvtFlowNode;
}

interface TableExpose {
  toggleRowExpansion?: (row: DashboardTableRow, expanded?: boolean) => void;
}

const EMPTY_PARSE_RESULT: EvtLogParseResult = {
  schemaVersion: 'evt-diagnostic-line-v1',
  lines: [],
  records: [],
  parsedCount: 0,
  unparsedCount: 0,
  redactedCount: 0,
};

const apiBaseUrl = getConfiguredApiBaseUrl();
const filePicker = ref<HTMLInputElement | null>(null);
const tableRef = ref<TableExpose | null>(null);
const files = ref<DashboardLogFile[]>(
  demoLogSources.map((source) => createDashboardFile({
    id: source.id,
    source: 'sample',
    filename: source.filename,
    bytes: source.bytes,
    content: source.content,
  })),
);
const keyword = ref('');
const sourceFilter = ref<SourceFilter>('all');
const statusFilter = ref<StatusFilter>('all');
const serverLoading = ref(false);
const serverDateRange = ref<string[] | null>(null);
const serverAppVersion = ref('');
const serverPlatform = ref('');
const serverDeviceRef = ref('');
const serverErrorCode = ref('');
const serverStatus = ref<DiagnosticLogStatus | ''>('');
const serverPage = ref(1);
const serverPageSize = ref(20);
const serverTotal = ref(0);
const hasLoadedServerList = ref(false);
const importing = ref(false);
const detail = ref<DetailContext | null>(null);
const detailOpen = ref(false);
const showAllDetailEvents = ref(false);
let latestServerListRequest = 0;

const statistics = computed(() => {
  const allNodes = files.value.flatMap((file) => file.nodes);
  return {
    files: files.value.length,
    success: allNodes.filter((node) => node.status === 'success').length,
    failure: allNodes.filter((node) => node.status === 'failure').length,
    review: allNodes.filter((node) => node.status === 'review').length,
  };
});

const visibleRows = computed<readonly FileTableRow[]>(() => {
  const query = keyword.value.trim().toLocaleLowerCase('zh-CN');

  return files.value.flatMap((file) => {
    if (sourceFilter.value !== 'all' && file.source !== sourceFilter.value) {
      return [];
    }

    const isUnloadedServerFile = file.source === 'server' && !file.isLoadedFromServer;
    const fileMatches = isUnloadedServerFile || matchesFile(file, query);
    const pendingOnly = statusFilter.value === 'pending';
    const matchedNodes = pendingOnly ? [] : file.nodes.filter((node) => {
      const statusMatches = statusFilter.value === 'all' || node.status === statusFilter.value;
      return statusMatches && matchesNode(node, query);
    });
    const needsStatusMatch = statusFilter.value !== 'all';

    if (pendingOnly) {
      if (!isUnloadedServerFile) {
        return [];
      }
      return [{
        kind: 'file' as const,
        id: file.id,
        file,
        status: 'pending' as const,
        children: [],
      }];
    }
    if (needsStatusMatch && matchedNodes.length === 0) {
      return [];
    }
    if (!needsStatusMatch && !fileMatches && matchedNodes.length === 0) {
      return [];
    }

    const children = (fileMatches && !needsStatusMatch ? file.nodes : matchedNodes).map((node) => ({
      kind: 'node' as const,
      id: `${file.id}::${node.id}`,
      file,
      node,
      status: node.status,
    }));

    return [{
      kind: 'file' as const,
      id: file.id,
      file,
      status: overallStatus(file),
      children,
    }];
  });
});

const activeDetailEvents = computed(() => {
  const records = detail.value?.node.records ?? [];
  if (showAllDetailEvents.value || records.length <= 60) {
    return records;
  }
  return [...records.slice(0, 30), ...records.slice(-30)];
});

const hiddenDetailEventCount = computed(() => {
  const count = detail.value?.node.records.length ?? 0;
  return count > 60 && !showAllDetailEvents.value ? count - 60 : 0;
});

function createDashboardFile(input: {
  id: string;
  source: LogSource;
  filename: string;
  bytes: number | null;
  content?: string;
  parseResult?: EvtLogParseResult;
  receivedAt?: string | null;
  deviceRef?: string | null;
  localImportKey?: string;
  serverId?: string;
  serverStatus?: string;
  serverActions?: readonly string[];
  isLoadedFromServer?: boolean;
}): DashboardLogFile {
  const parseResult = input.parseResult ?? parseEvtLogText(input.content ?? '');
  const nodes = aggregateEvtFlowNodes(parseResult.records);
  const firstRecord = parseResult.records[0];
  const deviceRef = input.deviceRef ? sanitizeDeviceRef(input.deviceRef) : findDeviceRef(parseResult.records);

  return {
    id: input.id,
    source: input.source,
    filename: sanitizeLogFilename(
      input.filename,
      input.source === 'server' ? '服务器日志.log' : '日志文件.log',
    ),
    bytes: input.bytes,
    receivedAt: input.receivedAt ?? firstRecord?.timestamp ?? null,
    deviceRef,
    parseResult,
    nodes,
    localImportKey: input.localImportKey,
    serverId: input.serverId,
    serverStatus: input.serverStatus,
    serverActions: input.serverActions,
    isLoadedFromServer: input.isLoadedFromServer,
  };
}

function sanitizeDeviceRef(value: unknown): string | null {
  const safeValue = redactFieldValue('device_ref', value).trim();
  return safeValue && safeValue !== '[已隐藏]' ? safeValue : null;
}

function findDeviceRef(records: readonly ParsedEvtLogLine[]): string | null {
  for (const record of records) {
    const candidate = record.fields.device_suffix ?? record.fields.device_ref;
    if (candidate && candidate !== '[已隐藏]') {
      return candidate;
    }
  }
  return null;
}

function matchesFile(file: DashboardLogFile, query: string): boolean {
  if (!query) {
    return true;
  }
  return [file.filename, file.deviceRef ?? '', file.receivedAt ?? '', file.serverStatus ?? '']
    .join(' ')
    .toLocaleLowerCase('zh-CN')
    .includes(query);
}

function matchesNode(node: EvtFlowNode, query: string): boolean {
  if (!query) {
    return true;
  }
  return [node.title, node.operation ?? '', node.conclusion, ...node.records.map((record) => record.event)]
    .join(' ')
    .toLocaleLowerCase('zh-CN')
    .includes(query);
}

function overallStatus(file: DashboardLogFile): FileStatus {
  if (file.source === 'server' && !file.isLoadedFromServer) {
    return 'pending';
  }
  if (file.nodes.some((node) => node.status === 'failure')) {
    return 'failure';
  }
  if (file.parseResult.unparsedCount > 0 || file.parseResult.redactedCount > 0) {
    return 'review';
  }
  if (file.nodes.length > 0 && file.nodes.every((node) => node.status === 'success')) {
    return 'success';
  }
  return 'review';
}

function fileParseSummary(file: DashboardLogFile): string {
  const parts = [
    sourceLabel(file.source),
    formatBytes(file.bytes),
    `${file.parseResult.parsedCount} 条已解析`,
  ];
  if (file.parseResult.unparsedCount > 0) {
    parts.push(`${file.parseResult.unparsedCount} 条未解析`);
  }
  if (file.parseResult.redactedCount > 0) {
    parts.push(`${file.parseResult.redactedCount} 条已隐藏`);
  }
  return parts.join(' · ');
}

function statusLabel(status: FileStatus): string {
  return {
    success: '联调成功',
    failure: '联调失败',
    review: '需要复核',
    pending: '尚未分析',
  }[status];
}

function statusTagType(status: FileStatus): 'success' | 'danger' | 'warning' | 'info' {
  return ({
    success: 'success',
    failure: 'danger',
    review: 'warning',
    pending: 'info',
  } as const)[status];
}

function sourceLabel(source: LogSource): string {
  return {
    sample: '样例日志',
    local: '本地导入',
    server: '服务器日志',
  }[source];
}

function formatBytes(bytes: number | null): string {
  if (bytes === null) {
    return '-';
  }
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatTime(value: string | null): string {
  if (!value) {
    return '-';
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return new Intl.DateTimeFormat('zh-CN', {
    dateStyle: 'short',
    timeStyle: 'medium',
    hour12: false,
  }).format(date);
}

function formatDuration(milliseconds: number | null): string {
  if (milliseconds === null) {
    return '-';
  }
  if (milliseconds < 1000) {
    return `${milliseconds} ms`;
  }
  return `${(milliseconds / 1000).toFixed(milliseconds >= 10000 ? 0 : 1)} 秒`;
}

function chooseFiles(): void {
  filePicker.value?.click();
}

async function importFiles(event: Event): Promise<void> {
  const input = event.target as HTMLInputElement;
  const selected = Array.from(input.files ?? []);
  input.value = '';
  if (selected.length === 0) {
    return;
  }

  importing.value = true;
  try {
    const imported = await Promise.all(selected.map(async (file) => {
      const content = await file.text();
      return createDashboardFile({
        id: `local:${crypto.randomUUID()}`,
        source: 'local',
        filename: file.name,
        bytes: file.size,
        content,
        localImportKey: `${sanitizeLogFilename(file.name)}\u0000${file.size}\u0000${file.lastModified}`,
      });
    }));
    const importedKeys = new Set(imported.map((file) => file.localImportKey));
    files.value = [
      ...imported,
      ...files.value.filter((file) => file.source !== 'local' || !importedKeys.has(file.localImportKey)),
    ];
    const parsedLines = imported.reduce((sum, file) => sum + file.parseResult.parsedCount, 0);
    ElMessage.success(`已导入 ${imported.length} 份日志，解析到 ${parsedLines} 条结构化事件。`);
    await nextTick();
    setAllExpanded(true);
  } catch {
    ElMessage.error('日志读取失败，请确认文件为 UTF-8 文本后重试。');
  } finally {
    importing.value = false;
  }
}

async function refreshServer(): Promise<void> {
  serverPage.value = 1;
  await loadServerPage();
}

async function loadServerPage(): Promise<void> {
  if (!apiBaseUrl) {
    ElMessage.info('未配置 VITE_LOG_API_BASE_URL，当前保持本地分析模式。');
    return;
  }

  const requestId = ++latestServerListRequest;
  const query = {
    page: serverPage.value,
    page_size: serverPageSize.value,
    from: toUtcIso(serverDateRange.value?.[0]),
    to: toUtcIso(serverDateRange.value?.[1]),
    app_version: serverAppVersion.value.trim() || undefined,
    platform: serverPlatform.value || undefined,
    device_ref: serverDeviceRef.value.trim() || undefined,
    error_code: serverErrorCode.value.trim() || undefined,
    status: serverStatus.value || undefined,
    keyword: keyword.value.trim() || undefined,
    sort: 'received_at:desc' as const,
  };
  serverLoading.value = true;
  try {
    const response = await diagnosticLogApi.list(query);
    if (requestId !== latestServerListRequest) {
      return;
    }
    const serverFiles = response.items.map(createServerPlaceholder);
    files.value = [...serverFiles, ...files.value.filter((file) => file.source !== 'server')];
    serverPage.value = response.page;
    serverPageSize.value = response.page_size;
    serverTotal.value = response.total;
    hasLoadedServerList.value = true;
    ElMessage.success(`已读取第 ${response.page} 页的 ${serverFiles.length} 份服务器日志。`);
  } catch (error) {
    if (requestId === latestServerListRequest) {
      showApiError(error);
    }
  } finally {
    if (requestId === latestServerListRequest) {
      serverLoading.value = false;
    }
  }
}

function createServerPlaceholder(item: DiagnosticLogListItem): DashboardLogFile {
  return createDashboardFile({
    id: `server:${item.id}`,
    source: 'server',
    filename: item.id,
    bytes: item.bytes ?? null,
    receivedAt: item.received_at,
    deviceRef: item.device_ref,
    parseResult: EMPTY_PARSE_RESULT,
    serverId: item.id,
    serverStatus: item.status,
    isLoadedFromServer: false,
  });
}

async function loadServerFile(file: DashboardLogFile): Promise<void> {
  if (!file.serverId) {
    return;
  }
  if (!apiBaseUrl) {
    ElMessage.info('未配置服务端地址，无法读取服务器日志内容。');
    return;
  }

  try {
    const detailResponse = await diagnosticLogApi.get(file.serverId);
    const detailFile = createDashboardFile({
      id: file.id,
      source: 'server',
      filename: detailResponse.source_filename ?? file.filename,
      bytes: detailResponse.bytes ?? file.bytes,
      receivedAt: detailResponse.received_at ?? file.receivedAt,
      deviceRef: detailResponse.device_ref ?? file.deviceRef,
      parseResult: EMPTY_PARSE_RESULT,
      serverId: file.serverId,
      serverStatus: detailResponse.status,
      serverActions: detailResponse.available_actions,
      isLoadedFromServer: false,
    });
    files.value = files.value.map((candidate) => candidate.id === file.id ? detailFile : candidate);
    if (!canReadServerContent(detailFile)) {
      ElMessage.warning(`服务器状态为“${serverStatusLabel(detailResponse.status)}”，当前不可读取日志内容。`);
      return;
    }

    const items = await loadAllServerContent(file.serverId);
    const hydrated = createDashboardFile({
      id: file.id,
      source: 'server',
      filename: detailResponse.source_filename ?? file.filename,
      bytes: detailResponse.bytes ?? file.bytes,
      receivedAt: detailResponse.received_at ?? file.receivedAt,
      deviceRef: detailResponse.device_ref ?? file.deviceRef,
      parseResult: parseEvtLogContentItems(items),
      serverId: file.serverId,
      serverStatus: detailResponse.status,
      serverActions: detailResponse.available_actions,
      isLoadedFromServer: true,
    });
    files.value = files.value.map((candidate) => candidate.id === file.id ? hydrated : candidate);
    ElMessage.success(`已加载 ${hydrated.nodes.length} 条功能链路。`);
    await nextTick();
    setAllExpanded(true);
  } catch (error) {
    showApiError(error);
  }
}

async function loadAllServerContent(serverId: string): Promise<DiagnosticLogContentItem[]> {
  const items: DiagnosticLogContentItem[] = [];
  let cursor: string | undefined;
  let pages = 0;
  const seenCursors = new Set<string>();

  do {
    if (cursor) {
      if (seenCursors.has(cursor)) {
        throw new Error('日志内容分页游标重复，已停止加载以避免误判。');
      }
      seenCursors.add(cursor);
    }
    const response = await diagnosticLogApi.getContent(serverId, { cursor, limit: 500 });
    items.push(...response.items);
    pages += 1;
    if (response.has_more) {
      const nextCursor = response.next_cursor;
      if (!nextCursor) {
        throw new Error('日志内容分页响应缺少 next_cursor，已停止加载以避免误判。');
      }
      cursor = nextCursor;
    } else {
      cursor = undefined;
    }
    if (pages >= 20 && cursor) {
      throw new Error('日志内容超过 10000 行，请通过服务端筛选后再查看。');
    }
  } while (cursor);

  return items;
}

function toUtcIso(value: string | undefined): string | undefined {
  if (!value) {
    return undefined;
  }
  const date = new Date(value.replace(' ', 'T'));
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

function changeServerPage(page: number): void {
  serverPage.value = page;
  void loadServerPage();
}

function changeServerPageSize(size: number): void {
  serverPageSize.value = size;
  serverPage.value = 1;
  void loadServerPage();
}

function showApiError(error: unknown): void {
  if (error instanceof LogApiContractError) {
    ElMessage.error(error.message);
    return;
  }
  if (error instanceof LogApiConfigurationError || error instanceof LogApiRequestError) {
    ElMessage.error(error.message);
    return;
  }
  if (error instanceof Error && error.message.startsWith('日志内容')) {
    ElMessage.warning(error.message);
    return;
  }
  ElMessage.error('日志服务请求失败，请检查网络和服务端状态。');
}

function setAllExpanded(expanded: boolean): void {
  for (const row of visibleRows.value) {
    tableRef.value?.toggleRowExpansion?.(row, expanded);
  }
}

function openDetail(file: DashboardLogFile, node: EvtFlowNode): void {
  detail.value = { file, node };
  showAllDetailEvents.value = false;
  detailOpen.value = true;
}

function handleFileAction(file: DashboardLogFile): void {
  if (file.source === 'server' && !file.isLoadedFromServer) {
    if (!canReadServerContent(file)) {
      ElMessage.warning(`服务器状态为“${serverStatusLabel(file.serverStatus)}”，当前不可读取日志内容。`);
      return;
    }
    void loadServerFile(file);
    return;
  }
  const firstNode = file.nodes[0];
  if (firstNode) {
    openDetail(file, firstNode);
  } else {
    ElMessage.info('当前日志没有可展示的结构化事件。');
  }
}

function fileActionLabel(file: DashboardLogFile): string {
  if (file.source === 'server' && !file.isLoadedFromServer) {
    return canReadServerContent(file) ? '加载链路' : '查看状态';
  }
  return '查看链路';
}

function downloadServerFile(file: DashboardLogFile): void {
  if (!file.serverId || !canDownloadServerFile(file)) {
    return;
  }
  try {
    window.open(diagnosticLogApi.getDownloadUrl(file.serverId), '_blank', 'noopener,noreferrer');
  } catch (error) {
    showApiError(error);
  }
}

function removeLocalFile(file: DashboardLogFile): void {
  if (file.source !== 'local') {
    return;
  }
  files.value = files.value.filter((candidate) => candidate.id !== file.id);
  ElMessage.success(`已移除 ${file.filename}。`);
}

function serverStatusLabel(status: string | undefined): string {
  return {
    stored: '已保存',
    quarantined: '已隔离',
    expired: '已过期',
    deleted: '已删除',
  }[status ?? ''] ?? '状态未知';
}

function canReadServerContent(file: DashboardLogFile): boolean {
  if (file.source !== 'server' || file.serverStatus !== 'stored') {
    return false;
  }
  if (!file.serverActions || file.serverActions.length === 0) {
    return true;
  }
  return file.serverActions.some((action) => ['view', 'read', 'content'].includes(action));
}

function canDownloadServerFile(file: DashboardLogFile): boolean {
  return file.source === 'server'
    && file.serverStatus === 'stored'
    && Boolean(file.serverActions?.includes('download'));
}

function exportVisibleReport(): void {
  const lines = [
    'EVT 脱敏联调报告',
    `导出时间：${new Date().toISOString()}`,
    `日志文件数：${visibleRows.value.length}`,
    '',
  ];

  for (const row of visibleRows.value) {
    lines.push(`文件：${row.file.filename}`);
    lines.push(`来源：${sourceLabel(row.file.source)} | 会话时间：${row.file.receivedAt ?? '-'} | 设备引用：${row.file.deviceRef ?? '-'}`);
    for (const child of row.children) {
      lines.push(`  [${statusLabel(child.status)}] ${child.node.title}`);
      lines.push(`  结论：${child.node.conclusion}`);
      for (const record of child.node.records) {
        lines.push(`  ${record.summary}`);
      }
    }
    lines.push('');
  }

  downloadText(`evt-脱敏联调报告-${fileTimestamp()}.txt`, lines.join('\n'));
}

function exportDetail(): void {
  const active = detail.value;
  if (!active) {
    return;
  }
  const lines = [
    'EVT 脱敏联调链路报告',
    `日志文件：${active.file.filename}`,
    `功能链路：${active.node.title}`,
    `状态：${statusLabel(active.node.status)}`,
    `结论：${active.node.conclusion}`,
    '',
    ...active.node.records.map((record) => record.summary),
  ];
  downloadText(`evt-脱敏链路-${active.node.category}-${fileTimestamp()}.txt`, lines.join('\n'));
}

function downloadText(filename: string, content: string): void {
  const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

function fileTimestamp(): string {
  return new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
}

async function resetLocalLogs(): Promise<void> {
  try {
    await ElMessageBox.confirm('将移除本地导入和服务器摘要，恢复两份脱敏样例日志。', '恢复样例', {
      confirmButtonText: '恢复样例',
      cancelButtonText: '取消',
      type: 'warning',
    });
  } catch {
    return;
  }

  files.value = demoLogSources.map((source) => createDashboardFile({
    id: source.id,
    source: 'sample',
    filename: source.filename,
    bytes: source.bytes,
    content: source.content,
  }));
  keyword.value = '';
  sourceFilter.value = 'all';
  statusFilter.value = 'all';
  serverPage.value = 1;
  serverTotal.value = 0;
  hasLoadedServerList.value = false;
  ElMessage.success('已恢复样例日志。');
}
</script>

<template>
  <main class="dashboard-shell">
    <header class="page-header">
      <div>
        <p class="eyebrow">AIPIN EVT · 结构化联调证据</p>
        <h1>日志看板</h1>
        <p class="page-description">一份日志对应一个父节点，展开后查看扫描、连接、认证、录音、文件、播放与上报的完整链路。</p>
      </div>
      <div class="mode-panel">
        <el-tag :type="apiBaseUrl ? 'success' : 'info'" effect="plain">
          {{ apiBaseUrl ? '服务端接口已配置' : '本地分析模式' }}
        </el-tag>
        <span v-if="apiBaseUrl" class="mode-address">{{ apiBaseUrl }}</span>
        <span v-else class="mode-address">导入脱敏日志即可开始分析</span>
      </div>
    </header>

    <section class="stat-grid" aria-label="日志统计">
      <div class="stat-item"><span>日志文件</span><strong>{{ statistics.files }}</strong></div>
      <div class="stat-item success"><span>联调成功</span><strong>{{ statistics.success }}</strong></div>
      <div class="stat-item warning"><span>需要复核</span><strong>{{ statistics.review }}</strong></div>
      <div class="stat-item danger"><span>联调失败</span><strong>{{ statistics.failure }}</strong></div>
    </section>

    <section class="toolbar-band" aria-label="日志筛选和操作">
      <div class="filter-group">
        <el-input v-model="keyword" clearable placeholder="文件名、功能、事件或设备引用" aria-label="搜索日志">
          <template #prepend>筛选</template>
        </el-input>
        <el-select v-model="sourceFilter" aria-label="选择日志来源">
          <el-option label="全部来源" value="all" />
          <el-option label="样例日志" value="sample" />
          <el-option label="本地导入" value="local" />
          <el-option label="服务器日志" value="server" />
        </el-select>
        <el-select v-model="statusFilter" aria-label="选择联调状态">
          <el-option label="全部状态" value="all" />
          <el-option label="联调成功" value="success" />
          <el-option label="需要复核" value="review" />
          <el-option label="联调失败" value="failure" />
          <el-option label="尚未分析（服务器）" value="pending" />
        </el-select>
      </div>
      <div class="action-group">
        <input ref="filePicker" class="visually-hidden" type="file" accept=".log,.txt,text/plain" multiple @change="importFiles" />
        <el-button :loading="importing" @click="chooseFiles">导入日志</el-button>
        <el-button :loading="serverLoading" @click="refreshServer">读取服务器</el-button>
        <el-button @click="setAllExpanded(true)">展开全部</el-button>
        <el-button @click="setAllExpanded(false)">收起全部</el-button>
        <el-button @click="exportVisibleReport">导出当前结果</el-button>
        <el-button @click="resetLocalLogs">恢复样例</el-button>
      </div>
    </section>

    <section v-if="apiBaseUrl" class="server-filter-band" aria-label="服务器日志筛选">
      <div class="server-filter-heading">
        <h2>服务器筛选</h2>
        <span v-if="hasLoadedServerList" class="result-count">服务器共 {{ serverTotal }} 份</span>
      </div>
      <div class="server-filter-controls">
        <el-date-picker
          v-model="serverDateRange"
          type="datetimerange"
          value-format="YYYY-MM-DD HH:mm:ss"
          format="YYYY-MM-DD HH:mm"
          range-separator="至"
          start-placeholder="接收开始时间"
          end-placeholder="接收结束时间"
          aria-label="服务器接收时间范围"
        />
        <el-input v-model="serverAppVersion" clearable placeholder="App 版本" aria-label="服务器 App 版本" @keyup.enter="refreshServer" />
        <el-select v-model="serverPlatform" clearable placeholder="平台" aria-label="服务器平台">
          <el-option label="Android" value="android" />
          <el-option label="iOS" value="ios" />
        </el-select>
        <el-input v-model="serverDeviceRef" clearable placeholder="设备引用" aria-label="服务器设备引用" @keyup.enter="refreshServer" />
        <el-input v-model="serverErrorCode" clearable placeholder="错误码" aria-label="服务器错误码" @keyup.enter="refreshServer" />
        <el-select v-model="serverStatus" clearable placeholder="保存状态" aria-label="服务器保存状态">
          <el-option label="已保存" value="stored" />
          <el-option label="已隔离" value="quarantined" />
          <el-option label="已过期" value="expired" />
          <el-option label="已删除" value="deleted" />
        </el-select>
      </div>
    </section>

    <section class="table-band" aria-labelledby="table-title">
      <div class="section-heading">
        <div>
          <h2 id="table-title">联调日志</h2>
          <p>状态只依据当前日志证据判定；未见完整终态时显示“需要复核”。</p>
        </div>
        <span class="result-count">{{ visibleRows.length }} 份日志</span>
      </div>

      <el-table
        ref="tableRef"
        :data="visibleRows"
        row-key="id"
        :tree-props="{ children: 'children' }"
        default-expand-all
        class="log-table"
        empty-text="没有匹配的日志或功能链路"
      >
        <el-table-column label="日志文件 / 功能链路" min-width="310">
          <template #default="{ row }: { row: DashboardTableRow }">
            <template v-if="row.kind === 'file'">
              <div class="file-cell">
                <strong>{{ row.file.filename }}</strong>
                <span>{{ fileParseSummary(row.file) }}<template v-if="row.file.source === 'server'"> · 服务器{{ serverStatusLabel(row.file.serverStatus) }}</template></span>
              </div>
            </template>
            <template v-else>
              <div class="node-cell">
                <strong>{{ row.node.title }}</strong>
                <span>{{ row.node.eventCount }} 条事件 · {{ row.node.operation ?? '未标记操作' }}</span>
              </div>
            </template>
          </template>
        </el-table-column>

        <el-table-column label="会话时间" min-width="180">
          <template #default="{ row }: { row: DashboardTableRow }">
            <template v-if="row.kind === 'file'">{{ formatTime(row.file.receivedAt) }}</template>
            <template v-else>{{ formatTime(row.node.startedAt) }}<br><span class="muted">{{ formatDuration(row.node.durationMs) }}</span></template>
          </template>
        </el-table-column>

        <el-table-column label="设备引用" min-width="130">
          <template #default="{ row }: { row: DashboardTableRow }">
            {{ row.file.deviceRef ?? '-' }}
          </template>
        </el-table-column>

        <el-table-column label="App 下发 / 设备回包" min-width="165">
          <template #default="{ row }: { row: DashboardTableRow }">
            <template v-if="row.kind === 'node'">
              App {{ row.node.directionCounts.app }} · 设备 {{ row.node.directionCounts.device }}<br>
              <span class="muted">系统 {{ row.node.directionCounts.system }}</span>
            </template>
            <template v-else>{{ row.file.nodes.length }} 条功能链路</template>
          </template>
        </el-table-column>

        <el-table-column label="联调状态" min-width="130">
          <template #default="{ row }: { row: DashboardTableRow }">
            <el-tag :type="statusTagType(row.status)" effect="light">{{ statusLabel(row.status) }}</el-tag>
          </template>
        </el-table-column>

        <el-table-column label="操作" width="196" fixed="right">
          <template #default="{ row }: { row: DashboardTableRow }">
            <template v-if="row.kind === 'node'">
              <el-button link type="primary" @click="openDetail(row.file, row.node)">查看详情</el-button>
            </template>
            <template v-else>
              <el-button link type="primary" @click="handleFileAction(row.file)">
                {{ fileActionLabel(row.file) }}
              </el-button>
              <el-button v-if="canDownloadServerFile(row.file)" link type="primary" @click="downloadServerFile(row.file)">下载</el-button>
              <el-button v-if="row.file.source === 'local'" link type="danger" @click="removeLocalFile(row.file)">移除</el-button>
            </template>
          </template>
        </el-table-column>
      </el-table>

      <div class="mobile-log-list" aria-label="移动端联调日志">
        <el-empty v-if="visibleRows.length === 0" description="没有匹配的日志或功能链路" />
        <article v-for="row in visibleRows" v-else :key="row.id" class="mobile-log-card">
          <div class="mobile-file-header">
            <div class="mobile-file-title">
              <strong>{{ row.file.filename }}</strong>
              <span>{{ fileParseSummary(row.file) }}</span>
            </div>
            <el-tag :type="statusTagType(row.status)" effect="light">{{ statusLabel(row.status) }}</el-tag>
          </div>

          <dl class="mobile-file-meta">
            <div>
              <dt>会话时间</dt>
              <dd>{{ formatTime(row.file.receivedAt) }}</dd>
            </div>
            <div>
              <dt>设备引用</dt>
              <dd>{{ row.file.deviceRef ?? '-' }}</dd>
            </div>
            <div>
              <dt>功能链路</dt>
              <dd>{{ row.children.length }} 条</dd>
            </div>
            <div v-if="row.file.source === 'server'">
              <dt>服务器状态</dt>
              <dd>{{ serverStatusLabel(row.file.serverStatus) }}</dd>
            </div>
          </dl>

          <div class="mobile-file-actions">
            <el-button type="primary" plain @click="handleFileAction(row.file)">
              {{ fileActionLabel(row.file) }}
            </el-button>
            <el-button v-if="canDownloadServerFile(row.file)" @click="downloadServerFile(row.file)">下载日志</el-button>
            <el-button v-if="row.file.source === 'local'" type="danger" plain @click="removeLocalFile(row.file)">移除日志</el-button>
          </div>

          <div v-if="row.children.length" class="mobile-node-list">
            <p class="mobile-node-list-title">功能链路</p>
            <article v-for="child in row.children" :key="child.id" class="mobile-node-item">
              <div class="mobile-node-header">
                <div>
                  <strong>{{ child.node.title }}</strong>
                  <span>{{ child.node.eventCount }} 条事件 · {{ child.node.operation ?? '未标记操作' }}</span>
                </div>
                <el-tag :type="statusTagType(child.status)" effect="light" size="small">{{ statusLabel(child.status) }}</el-tag>
              </div>
              <p class="mobile-node-conclusion">{{ child.node.conclusion }}</p>
              <div class="mobile-node-footer">
                <span>App {{ child.node.directionCounts.app }} · 设备 {{ child.node.directionCounts.device }} · 系统 {{ child.node.directionCounts.system }}</span>
                <el-button link type="primary" @click="openDetail(child.file, child.node)">查看详情</el-button>
              </div>
            </article>
          </div>
          <p v-else class="mobile-empty-chain">
            {{ row.file.source === 'server' && !row.file.isLoadedFromServer ? '尚未加载服务器日志内容。' : '当前日志没有可展示的结构化功能链路。' }}
          </p>
        </article>
      </div>

      <div v-if="apiBaseUrl && hasLoadedServerList" class="server-pagination" aria-label="服务器日志分页">
        <span>服务器结果：第 {{ serverPage }} 页，共 {{ serverTotal }} 份</span>
        <el-pagination
          v-model:current-page="serverPage"
          v-model:page-size="serverPageSize"
          :total="serverTotal"
          :page-sizes="[20, 50, 100]"
          layout="sizes, prev, pager, next"
          background
          @current-change="changeServerPage"
          @size-change="changeServerPageSize"
        />
      </div>
    </section>

    <section class="safety-band" aria-labelledby="safety-title">
      <h2 id="safety-title">数据边界</h2>
      <p>看板只处理脱敏日志。浏览器不连接 SFTP，不保存主机、账号、目录或私钥；导出内容再次使用白名单字段和敏感值隐藏规则。</p>
    </section>

    <el-drawer v-model="detailOpen" direction="rtl" size="min(620px, 100vw)" class="detail-drawer">
      <template #header>
        <div v-if="detail" class="drawer-title">
          <div>
            <p class="eyebrow">{{ detail.file.filename }}</p>
            <h2>{{ detail.node.title }}</h2>
          </div>
          <el-tag :type="statusTagType(detail.node.status)" effect="light">{{ statusLabel(detail.node.status) }}</el-tag>
        </div>
      </template>

      <template v-if="detail">
        <el-descriptions :column="1" border class="detail-summary">
          <el-descriptions-item label="结论">{{ detail.node.conclusion }}</el-descriptions-item>
          <el-descriptions-item label="会话">{{ formatTime(detail.node.startedAt) }} 至 {{ formatTime(detail.node.endedAt) }}</el-descriptions-item>
          <el-descriptions-item label="交互统计">App {{ detail.node.directionCounts.app }} · 设备 {{ detail.node.directionCounts.device }} · 系统 {{ detail.node.directionCounts.system }}</el-descriptions-item>
          <el-descriptions-item label="Trace">{{ detail.node.traceId ?? '-' }}</el-descriptions-item>
        </el-descriptions>

        <div class="detail-toolbar">
          <h3>事件时间线</h3>
          <el-button @click="exportDetail">导出本链路</el-button>
        </div>
        <p v-if="hiddenDetailEventCount" class="timeline-note">中间 {{ hiddenDetailEventCount }} 条事件已折叠，避免长日志阻塞页面。</p>
        <el-button v-if="hiddenDetailEventCount" link type="primary" @click="showAllDetailEvents = true">显示全部事件</el-button>

        <el-timeline class="event-timeline">
          <el-timeline-item
            v-for="record in activeDetailEvents"
            :key="record.lineNumber"
            :timestamp="formatTime(record.timestamp)"
            :type="record.direction === 'app' ? 'primary' : record.direction === 'device' ? 'success' : 'info'"
          >
            <div class="event-head">
              <strong>{{ record.event }}</strong>
              <span>{{ record.direction === 'app' ? 'App 下发' : record.direction === 'device' ? '设备回包' : '系统事件' }}</span>
            </div>
            <p>{{ record.summary }}</p>
            <div v-if="Object.keys(record.fields).length" class="field-list">
              <span v-for="(value, key) in record.fields" :key="key">{{ key }}={{ value }}</span>
            </div>
          </el-timeline-item>
        </el-timeline>
      </template>
    </el-drawer>
  </main>
</template>

<style scoped>
.dashboard-shell {
  max-width: 1480px;
  margin: 0 auto;
  padding: 24px;
}

.page-header,
.toolbar-band,
.table-band,
.safety-band {
  background: #fff;
  border: 1px solid #d8e0e3;
  border-radius: 8px;
}

.page-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 24px;
  padding: 24px;
}

.eyebrow {
  margin: 0 0 6px;
  color: #0c6d66;
  font-size: 13px;
  font-weight: 700;
  letter-spacing: 0;
}

h1,
h2,
h3,
p {
  margin-top: 0;
}

h1 {
  margin-bottom: 8px;
  font-size: 28px;
  line-height: 1.25;
}

h2 {
  margin-bottom: 6px;
  font-size: 19px;
  line-height: 1.35;
}

h3 {
  margin-bottom: 0;
  font-size: 16px;
}

.page-description,
.section-heading p,
.safety-band p,
.mode-address,
.muted,
.file-cell span,
.node-cell span {
  color: #62717c;
  font-size: 14px;
}

.page-description {
  max-width: 720px;
  margin-bottom: 0;
}

.mode-panel {
  display: grid;
  justify-items: end;
  gap: 8px;
  min-width: 190px;
}

.mode-address {
  max-width: 260px;
  overflow-wrap: anywhere;
  text-align: right;
}

.stat-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
  margin: 16px 0;
}

.stat-item {
  min-height: 88px;
  border: 1px solid #d8e0e3;
  border-top: 3px solid #50616d;
  border-radius: 6px;
  background: #fff;
  padding: 14px 16px;
}

.stat-item span {
  display: block;
  color: #62717c;
  font-size: 14px;
}

.stat-item strong {
  display: block;
  margin-top: 4px;
  color: #17212b;
  font-size: 30px;
  line-height: 1;
}

.stat-item.success { border-top-color: #237546; }
.stat-item.warning { border-top-color: #b15d00; }
.stat-item.danger { border-top-color: #b3261e; }

.toolbar-band {
  display: flex;
  justify-content: space-between;
  gap: 16px;
  padding: 16px;
}

.filter-group,
.action-group {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
}

.filter-group :deep(.el-input) {
  width: min(360px, 100%);
}

.filter-group :deep(.el-select) {
  width: 150px;
}

.server-filter-band {
  margin-top: 16px;
  border: 1px solid #d8e0e3;
  border-radius: 8px;
  background: #fff;
  padding: 16px;
}

.server-filter-heading,
.server-pagination {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
}

.server-filter-heading h2 {
  margin-bottom: 0;
}

.server-filter-controls {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 14px;
}

.server-filter-controls :deep(.el-date-editor) {
  width: min(330px, 100%);
}

.server-filter-controls :deep(.el-input),
.server-filter-controls :deep(.el-select) {
  width: 150px;
}

.table-band {
  margin-top: 16px;
  overflow: hidden;
}

.section-heading {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 20px 20px 14px;
}

.section-heading p {
  margin-bottom: 0;
}

.result-count {
  color: #50616d;
  font-size: 14px;
  white-space: nowrap;
}

.log-table {
  width: 100%;
}

.mobile-log-list {
  display: none;
}

.server-pagination {
  padding: 16px 20px;
  border-top: 1px solid #d8e0e3;
}

.server-pagination > span {
  color: #62717c;
  font-size: 14px;
  white-space: nowrap;
}

.file-cell,
.node-cell {
  display: grid;
  gap: 2px;
  min-width: 0;
}

.file-cell strong,
.node-cell strong {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.node-cell strong {
  color: #0c5e59;
}

.safety-band {
  margin-top: 16px;
  padding: 18px 20px;
  border-left: 4px solid #0c6d66;
}

.safety-band h2,
.safety-band p {
  margin-bottom: 0;
}

.drawer-title {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  width: 100%;
  padding-right: 20px;
}

.drawer-title h2 {
  margin-bottom: 0;
}

.detail-summary {
  margin-bottom: 20px;
}

.detail-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-top: 20px;
}

.timeline-note {
  margin: 8px 0 0;
  color: #8a5100;
  font-size: 14px;
}

.event-timeline {
  margin-top: 16px;
}

.event-head {
  display: flex;
  justify-content: space-between;
  gap: 12px;
}

.event-head span {
  color: #62717c;
  font-size: 13px;
  white-space: nowrap;
}

.event-timeline p {
  margin: 6px 0;
  color: #45545f;
  font-family: Consolas, "Courier New", monospace;
  font-size: 12px;
  line-height: 1.6;
  overflow-wrap: anywhere;
}

.field-list {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.field-list span {
  max-width: 100%;
  overflow-wrap: anywhere;
  border: 1px solid #d8e0e3;
  border-radius: 4px;
  background: #f7f9fa;
  color: #4c5b65;
  padding: 2px 6px;
  font-family: Consolas, "Courier New", monospace;
  font-size: 12px;
}

.visually-hidden {
  position: absolute;
  width: 1px;
  height: 1px;
  overflow: hidden;
  clip: rect(0 0 0 0);
  clip-path: inset(50%);
  white-space: nowrap;
}

@media (max-width: 960px) {
  .dashboard-shell { padding: 16px; }
  .page-header,
  .toolbar-band { flex-direction: column; }
  .mode-panel { justify-items: start; }
  .mode-address { text-align: left; }
  .stat-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .filter-group,
  .action-group { width: 100%; }
  .server-filter-controls :deep(.el-date-editor) { width: 100%; }
}

@media (max-width: 560px) {
  .dashboard-shell { padding: 12px; }
  .page-header { padding: 18px; }
  .stat-grid { grid-template-columns: 1fr 1fr; gap: 8px; }
  .stat-item { min-height: 78px; padding: 12px; }
  .stat-item strong { font-size: 26px; }
  .filter-group :deep(.el-input),
  .filter-group :deep(.el-select) { width: 100%; }
  .server-filter-controls :deep(.el-input),
  .server-filter-controls :deep(.el-select) { width: 100%; }
  .server-filter-heading,
  .server-pagination { align-items: flex-start; flex-direction: column; }
  .server-pagination :deep(.el-pagination) { flex-wrap: wrap; }
  .action-group > :deep(.el-button) { flex: 1 1 calc(50% - 4px); margin-left: 0; }
  .section-heading { align-items: flex-start; flex-direction: column; }
}

@media (max-width: 640px) {
  .log-table {
    display: none;
  }

  .mobile-log-list {
    display: grid;
    gap: 10px;
    padding: 0 12px 12px;
  }

  .mobile-log-card {
    border: 1px solid #d8e0e3;
    border-radius: 6px;
    background: #fbfcfc;
    padding: 14px;
  }

  .mobile-file-header,
  .mobile-node-header,
  .mobile-node-footer {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 10px;
  }

  .mobile-file-title,
  .mobile-node-header > div {
    display: grid;
    min-width: 0;
    gap: 4px;
  }

  .mobile-file-title strong,
  .mobile-node-header strong {
    overflow-wrap: anywhere;
  }

  .mobile-file-title span,
  .mobile-node-header span,
  .mobile-node-footer span,
  .mobile-empty-chain {
    color: #62717c;
    font-size: 13px;
    line-height: 1.5;
    overflow-wrap: anywhere;
  }

  .mobile-file-meta {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 8px 12px;
    margin: 14px 0;
  }

  .mobile-file-meta div {
    min-width: 0;
  }

  .mobile-file-meta dt {
    margin-bottom: 2px;
    color: #62717c;
    font-size: 12px;
  }

  .mobile-file-meta dd {
    margin: 0;
    color: #28343d;
    font-size: 13px;
    line-height: 1.45;
    overflow-wrap: anywhere;
  }

  .mobile-file-actions {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }

  .mobile-file-actions :deep(.el-button) {
    flex: 1 1 130px;
    min-width: 0;
    margin-left: 0;
  }

  .mobile-node-list {
    display: grid;
    gap: 8px;
    margin-top: 16px;
    padding-top: 14px;
    border-top: 1px solid #d8e0e3;
  }

  .mobile-node-list-title {
    margin: 0;
    color: #45545f;
    font-size: 13px;
    font-weight: 700;
  }

  .mobile-node-item {
    display: grid;
    gap: 8px;
    border-left: 3px solid #0c6d66;
    background: #fff;
    padding: 10px;
  }

  .mobile-node-header strong {
    color: #0c5e59;
    font-size: 14px;
    line-height: 1.45;
  }

  .mobile-node-conclusion {
    margin: 0;
    color: #45545f;
    font-size: 13px;
    line-height: 1.55;
    overflow-wrap: anywhere;
  }

  .mobile-node-footer {
    align-items: center;
  }

  .mobile-node-footer :deep(.el-button) {
    flex: 0 0 auto;
    margin-left: 0;
    white-space: nowrap;
  }

  .mobile-empty-chain {
    margin: 14px 0 0;
  }
}
</style>
