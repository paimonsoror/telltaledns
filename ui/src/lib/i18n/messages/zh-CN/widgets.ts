// REQ: API-011 — widgets 的中文翻译。键名与 en/widgets.ts 一一对应。
// 标记一行里各个部分的连接符也在这里：部分之间的「 · 」，节点名之间的「、」，以及多条标记之间的「；」。
import type { MessageKey } from '../en';

export const widgets: Partial<Record<MessageKey, string>> = {
  // 图表的视图切换，以及切换后显示的表格。
  'widgets.chart.empty': '还没有数据。',
  'widgets.chart.changed': '变更时间',
  // 光标不在任何一格上时图例里的值：所选范围内的总数。
  'widgets.chart.total': '合计',
  // 单个变更标记的说明（提示以及读屏软件读到的内容），以及多条标记连在一起时的写法。
  'widgets.chart.mark': '{time}：{summary}',
  'widgets.chart.mark.actor': '{time}：{summary}（{actor}）',
  // 标记的提示最多列出五条，这是其余的数量。
  'widgets.chart.more.one': '还有 {n} 条',
  'widgets.chart.more.other': '还有 {n} 条',
  // 标记各部分之间的分隔（以及节点名之间的分隔）；前后各留一个空格，紧跟着的又是英文名字。
  'widgets.chart.sep': ' · ',
  'widgets.chart.list': '、',

  // KPI 卡片：与等长的上一时间段相比的涨跌，衡量的是什么。
  'widgets.kpi.deltaTitle': '与等长的上一时间段相比',

  // 调用方没有给出文字时，环形图中间显示的内容。

  // 「变更」开关、备注表单，以及类型筛选。
  'widgets.changes.noteOpen': '备注…',
  'widgets.changes.what': '发生了什么',
  'widgets.changes.whatHint': '把接入点移到了走廊',
  'widgets.changes.whenHint': '（可选，最多回溯 7 天）',
  'widgets.changes.add': '添加备注',
  'widgets.changes.noteHelp':
    '每个节点上的每张时间图表都会显示它。备注不能修改也不能删除；如有需要，再添加一条更正的备注。',
  'widgets.changes.kinds': '显示哪些类型的变更',
  'widgets.barList.bad': '坏',
  'widgets.barList.uncertain': '± 最多',
  'widgets.changePreview.lead': '这将做什么：',
  'widgets.barList.empty': '这里什么都没有。',
  'widgets.barList.bars': '条形图',
};
