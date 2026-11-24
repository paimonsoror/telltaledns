// REQ: API-011 — analyze 页面的中文翻译。键名与 en/analyze.ts 一一对应。
// 查询语言自己的关键字（from、where、bucket 等）保持原样，不翻译。
import type { MessageKey } from '../en';

export const analyze: Partial<Record<MessageKey, string>> = {
  // 标题与标签页。
  'analyze.tab.budget': '错误预算',

  // 查询框：它的标签、怎么运行，以及按钮旁边的阶段列表。
  'analyze.queryLabel': '查询语句（vqlog）· Ctrl+Enter 运行',
  'analyze.queryAria': 'vqlog 查询语句',
  'analyze.run': '运行',
  'analyze.estimate': '估算开销',
  'analyze.estimateTitle': '只估算这次查询会读取多少数据',
  'analyze.stages': '阶段：from · where · bucket · by · stats · top · sort · limit',

  // 示例按钮：按钮上显示的文字（实际运行的查询保持原样）。
  'analyze.example.topBlocked': '今天被拦截最多的名称',
  'analyze.example.busiest': '查询最频繁的设备',
  'analyze.example.perHour': '每小时的查询量及延迟',
  'analyze.example.slow': '各上游的慢应答',
  'analyze.example.failed': '失败的解析',

  // 结果的说明：实际理解的语句、读了多少、花了多久，以及哪些部分没算进去。
  'analyze.asUnderstood': '实际理解：',
  // 复数形式：中文只有一种写法，`.one` 与 `.other` 相同。
  'analyze.estimate.one': '预估：最多会读取 {blocks} 个块中的 {n} 条查询日志。',
  'analyze.estimate.other': '预估：最多会读取 {blocks} 个块中的 {n} 条查询日志。',
  'analyze.matched.one': '读取的 {scanned} 条查询中匹配了 {matched} 条（预估最多 {estimated}），耗时 {elapsed} ms · {n} 个分组',
  'analyze.matched.other': '读取的 {scanned} 条查询中匹配了 {matched} 条（预估最多 {estimated}），耗时 {elapsed} ms · {n} 个分组',
  'analyze.partial': '部分结果：{reason}',
  'analyze.notIncluded': '未包含：{nodes}',
  'analyze.rollups': '数据来自汇总表（为较长窗口保留的计数），而不是查询日志。',
  'analyze.nothing': '没有匹配的结果。',
};
