# EVT 日志看板

Vue 3 + Element Plus 的 EVT 联调日志看板。它支持本地导入多份脱敏日志，按文件展示功能链路、成功/失败状态、App 下发与设备回包，并可接入日志服务的 HTTPS API。

## 开发

```powershell
npm.cmd install
npm.cmd run dev
```

默认在本地分析模式运行，不会访问网络。配置 `VITE_LOG_API_BASE_URL` 后可使用服务端列表、详情和内容接口；浏览器不会直连 SFTP，也不保存服务器账号或私钥。

本机联调可以让 Vite 读取中间层在服务端读取 `EVT_LOG_DASHBOARD_TOKEN`，Vue 只访问同源的 `/api/v1/diagnostic-logs`。不要把该 token 写成 `VITE_*` 变量。中间层会在服务端过滤空字段，并将当前服务的旧内容格式转为脱敏结构化事件，原始日志行不会进入 Vue 状态。Node 20+ 的启动示例：

```powershell
node --env-file=<受保护的token文件> node_modules/vite/bin/vite.js --host 127.0.0.1 --port 5173
```

`.env.local` 在此模式下应为 `VITE_LOG_API_BASE_URL=http://localhost:5173`。该中间层仅适合本机联调；生产环境仍应使用 SSO/HttpOnly Cookie 或独立 BFF。

服务端环境变量、接口路径、分页和脱敏边界见[服务端对接说明](docs/server-integration.md)。

服务端模式中，列表默认每页 20 份，可按接收时间、App 版本、平台、设备引用、错误码、保存状态和关键字筛选并分页。只有服务端返回 <code>stored</code> 状态且授权读取的日志可以加载链路；下载还需要明确的 <code>download</code> 权限。

服务根地址只使用 HTTPS；开发时只有 <code>localhost</code>、<code>127.0.0.1</code> 可以使用 HTTP。前端固定请求 <code>/api/v1/diagnostic-logs</code>，不会直连 SFTP，也不会保存服务器账号、私钥或安全码。当前工程只实现看板读取和导出，不包含 App 上传服务端的接口实现。

独立看板使用已建立的 HttpOnly Cookie/SSO 会话，通过 <code>credentials: include</code> 读取服务端；当前页面不提供 Bearer Token 配置或输入。列表、详情和内容响应会先按白名单契约校验，JSON、ID、状态、列表/详情时间、分页游标、字段类型或内容 schema 不符合要求时会停止本次加载，避免不完整或错误数据进入联调结论。内容项虽通过结构校验但不符合 EVT 时间或标识符规范时，会转为未解析记录，不会判定为联调成功。

## 验证

```powershell
npm.cmd run test
npm.cmd run build
```
