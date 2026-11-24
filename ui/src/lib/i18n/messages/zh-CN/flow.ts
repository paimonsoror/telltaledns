// REQ: API-011 — flow 页面的中文翻译。键名与 en/flow.ts 一一对应。
// 色块（`<span class="sw">`）嵌在句子中间的地方被拆成 `…bands` 与 `…fail`：前者写到色块之前，
// 后者接着色块之后写。
import type { MessageKey } from '../en';

export const flow: Partial<Record<MessageKey, string>> = {
  // 标题，以及图上方的那排控件。
  'flow.what': '范围',
  'flow.network': '全网',
  'flow.device': '设备',
  'flow.window': '时间范围',
  'flow.window.15m': '15 分钟',
  'flow.window.1h': '1 小时',
  'flow.window.6h': '6 小时',
  'flow.window.24h': '24 小时',
  'flow.window.7d': '7 天',
  'flow.showSmall': '显示小项',
  'flow.live': '实时',

  // 设备地址表单（按设备查看时出现）。
  'flow.devicePlaceholder': '设备地址，例如 192.168.2.14',
  'flow.deviceAddress': '设备地址',
  'flow.show': '查看',

  // 卡片标题：看的是谁、有多少应答，以及图示/表格切换。
  'flow.pickDevice': '请选择设备',
  'flow.answers.one': '· {n} 次应答',
  'flow.answers.other': '· {n} 次应答',
  'flow.fromQueryLog': '，来自查询日志',
  'flow.updated': '· 更新于 {time}，每 15 秒刷新一次',
  'flow.diagram': '图示',
  'flow.table': '表格',

  // 卡片说明这些数字缺了哪些部分。
  'flow.missingNodes': '缺少 {nodes} 的数据：它们没有应答。',
  'flow.partial': '这个时间范围里有一部分是由不支持流量计数的版本统计的：那些应答缺失了。',
  'flow.truncated': '读取查询日志时提前停止：数字只覆盖已读取的部分。',

  // 卡片没有内容时说的话。
  'flow.enterDevice': '请在上方填写。',
  'flow.empty': '这个时间范围内没有应答。',

  // 表格视图：列名（单元格里是数据）。
  'flow.col.from': '来自',
  'flow.col.to': '去向',
  'flow.col.answers': '应答数',
  'flow.col.share': '占比',

  // 图：读屏文字、节点的提示，以及图下方的图例。
  'flow.diagramAria': '查询流向：先是分组，再做判定，然后是上游和响应码；带宽就是应答数。表格视图会列出每一条链路。',
  'flow.nodeEndHere.one': ' · {n} 条在此结束',
  'flow.nodeEndHere.other': ' · {n} 条在此结束',
  'flow.legend.bands': '带宽 = 应答数，每条都恰好计入这一对；',
  'flow.legend.fail': ' 红色的带最终是 SERVFAIL。',
  'flow.legend.folded.one': '{n} 个低于 0.5 % 的节点被折叠进“其他”（打开“显示小项”即可看到）。',
  'flow.legend.folded.other': '{n} 个低于 0.5 % 的节点被折叠进“其他”（打开“显示小项”即可看到）。',
  'flow.legend.select': '点击节点可查看它背后的页面。',
  'flow.stage.status': '决策',
  'flow.stage.upstream': '上游',
  'flow.stage.rcode': '响应',
};
