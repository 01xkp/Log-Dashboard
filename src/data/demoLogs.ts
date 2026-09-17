export interface DemoLogSource {
  readonly id: string;
  readonly filename: string;
  readonly bytes: number;
  readonly content: string;
}

export const demoLogSources: readonly DemoLogSource[] = [
  {
    id: 'demo-success',
    filename: 'aipin-2026-09-17-09-42-15-d45e6a7b.log',
    bytes: 6842,
    content: `【AIPIN联调】【蓝牙】【信息】【阶段：设备扫描】 2026-09-17T01:42:15.010Z | INFO | BLE | - | device_scan | scanning | scan_start_requested | pending | - | action=start platform=android
【AIPIN联调】【蓝牙】【信息】【阶段：设备扫描】 2026-09-17T01:42:17.220Z | INFO | BLE | - | device_scan | scanning | scan_result_accepted | accepted | 2210 | device_suffix=...8423 rssi=-46 service_count=1
【AIPIN联调】【会话】【信息】【阶段：蓝牙连接】 2026-09-17T01:42:18.010Z | INFO | SESSION | - | device_connect | connect | gatt_contract_verified | success | 790 | endpoint=0xfa11
【AIPIN联调】【会话】【发送：App到设备】【信息】【阶段：认证特征写入】 2026-09-17T01:42:18.480Z | INFO | CMD | 5cc41a | device_authenticate | fa19_write | evt_command_transmit_started | pending | - | command=0x09 expected_command=0x89 endpoint=0xfa19
【AIPIN联调】【协议】【接收：设备到App】【信息】【阶段：回包处理】 2026-09-17T01:42:18.604Z | INFO | CMD | 5cc41a | device_authenticate | response | evt_command_response_received | accepted | 124 | actual_command=0x89 endpoint=0xfa19
【AIPIN联调】【会话】【信息】【阶段：状态同步】 2026-09-17T01:42:18.652Z | INFO | SESSION | 5cc41a | device_authenticate | sync | legacy_authentication_completed | success | 172 | granted_permissions=[]
【AIPIN联调】【协议】【发送：App到设备】【信息】【阶段：文件读取】 2026-09-17T01:42:20.010Z | INFO | CMD | 7e991c | device_file_import | request | evt_command_transmit_started | pending | - | command=0x23 expected_command=0xa3
【AIPIN联调】【协议】【接收：设备到App】【信息】【阶段：文件读取】 2026-09-17T01:42:20.472Z | INFO | CMD | 7e991c | device_file_import | download | evt_command_completed | success | 462 | actual_command=0xa3 bytes=4096
【AIPIN联调】【应用】【信息】【阶段：上传】 2026-09-17T01:42:21.009Z | INFO | APP | - | - | upload | app_log_upload_requested | pending | -
【AIPIN联调】【应用】【信息】【阶段：上传】 2026-09-17T01:42:21.598Z | INFO | APP | - | - | upload | app_log_upload_succeeded | success | 589 | bytes=6842`,
  },
  {
    id: 'demo-review',
    filename: 'aipin-2026-09-17-10-06-34-87c1fabc.log',
    bytes: 3278,
    content: `【AIPIN联调】【蓝牙】【信息】【阶段：设备扫描】 2026-09-17T02:06:34.402Z | INFO | BLE | - | device_scan | scanning | scan_start_requested | pending | - | action=start platform=android
【AIPIN联调】【蓝牙】【信息】【阶段：设备扫描】 2026-09-17T02:06:37.107Z | INFO | BLE | - | device_scan | scanning | scan_candidate_selected | accepted | 2705 | device_suffix=...8423 rssi=-53
【AIPIN联调】【协议】【发送：App到设备】【信息】【阶段：认证特征写入】 2026-09-17T02:06:38.003Z | INFO | CMD | 42a5dd | device_authenticate | fa19_write | evt_command_transmit_started | pending | - | command=0x09 expected_command=0x89 endpoint=0xfa19
【AIPIN联调】【协议】【信息】【阶段：回包处理】 2026-09-17T02:06:40.012Z | WARNING | CMD | 42a5dd | device_authenticate | response | evt_response_wait_finished | timeout | 2009 | expected_command=0x89 timeout_ms=2000
【AIPIN联调】【回连】【信息】【阶段：资源关闭】 2026-09-17T02:06:40.300Z | INFO | RECONNECT | - | device_reconnect | idle | reconnect_cycle_started | pending | - | action=retry`,
  },
];
