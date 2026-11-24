// REQ: API-011 — heatmap 页面的中文翻译。键名与 en/heatmap.ts 一一对应。
//
// 每一行日期来自网格本身（接口给的数据），不在这里；插值里的 count、when 都是算好的数字与时间。
import type { MessageKey } from '../en';

export const heatmap: Partial<Record<MessageKey, string>> = {
  // 标题，以及分段控件：统计什么、看多长时间。
  'heatmap.what': '统计对象',
  'heatmap.scope.network': '整个网络',
  'heatmap.window.90d': '90 天',
  'heatmap.slot': '时间粒度',
  'heatmap.slot.hour': '小时',
  'heatmap.slot.15m': '15 分钟',
  'heatmap.slot.minute': '分钟',
  'heatmap.count': '计数',
  'heatmap.count.queries': '查询',
  'heatmap.typicalWeek': '典型一周',

  // 设备或名称的输入框：提示文字，以及屏幕阅读器读到的名称。
  'heatmap.keyPlaceholder.name': '名称，例如 pool.ntp.org',
  'heatmap.show': '显示',

  // 卡片头：网格覆盖什么、每段多长，以及两种视图。
  'heatmap.head.all': '整个网络',
  'heatmap.head.pickDevice': '选择一台设备',
  'heatmap.head.pickName': '选择一个名称',
  'heatmap.grain.15m': '15 分钟',
  'heatmap.slots': '每段 {grain}，本地时间',
  'heatmap.dayTimeline': '当天时间线',
  'heatmap.missing': '缺少 {nodes}：它们没有应答。',
  'heatmap.empty': '请在上方输入。',

  // 表格视图，以及网格被读出来时是什么。
  'heatmap.col.day': '日期',
  'heatmap.grid.aria': '热力图：行为日期，列为一天中的时间。用方向键在格子间移动，回车打开查询日志。',
  'heatmap.grid.role': '热力图',

  // 格子上的提示：是哪一段时间，数了多少。
  'heatmap.tip.below': '{when} · 在该小时的前 100 名之外',
  'heatmap.tip.none': '{when} · 无数据',
  'heatmap.measure.blocked': '被拦截的查询',
  'heatmap.tip.value': '{when} · {count} 条{what}',
  'heatmap.tip.average.one': '{when} · {n} 天平均 {count} 条{what}',
  'heatmap.tip.average.other': '{when} · {n} 天平均 {count} 条{what}',

  // 颜色、条形和斜线各是什么意思。
  'heatmap.legend.stronger': '颜色越深表示{what}越多；右侧和底部的条形分别是每行和每列的合计。',
  'heatmap.legend.topListBefore': '计数来自每小时的前 100 名：',
  'heatmap.legend.topListAfter': '带斜线的格子表示这一项排在该小时的列表之外。',
  'heatmap.legend.cell': '选中一个格子可查看它的查询（查询日志保留的天数少于热力图）。',
};
