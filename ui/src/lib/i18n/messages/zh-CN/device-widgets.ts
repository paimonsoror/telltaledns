// REQ: API-011 — device-widgets 的中文翻译。键名与 en/device-widgets.ts 一一对应。
// 句子中间夹着标记的地方（“显示已静音”外有 `<b>`，时间线图例里每个圆点）被拆成
// `…Lead`/`…firstContact` 与 `…Tail`/`…anomaly`：前者写到标记之前，后者接着标记之后写。
import type { MessageKey } from '../en';

export const deviceWidgets: Partial<Record<MessageKey, string>> = {
  // 为单台设备静音某类发现：表单的说明、各个字段和按钮。
  'deviceWidgets.mute.introLead':
    '不再为这台设备统计下面这些类型的发现。这些发现仍会被记录和列出（打开',
  'deviceWidgets.mute.introTail': '），其他每台设备仍会照常检查。',
  'deviceWidgets.mute.showMuted': '显示已静音',
  'deviceWidgets.mute.device': '设备（名称、IP 或网段）',
  'deviceWidgets.mute.kinds': '发现的类型',
  'deviceWidgets.mute.for': '持续',
  'deviceWidgets.mute.howLong': '持续多久',
  'deviceWidgets.mute.duration.1w': '1 周',
  'deviceWidgets.mute.notePlaceholder': '原因（可选），例如：每小时的逆向 DNS 扫描',
  // 中文的复数规则只取 `other`；`one` 是英文单数那一条的译文，占位符与英文保持一致。
  'deviceWidgets.mute.similar.one': '所显示时间段内的这条发现本来会被静音。',
  'deviceWidgets.mute.similar.other': '所显示时间段内的这 {n} 条发现本来会被静音。',
  'deviceWidgets.mute.previewLead': '这一操作会做什么：',
  'deviceWidgets.mute.previewFallback': '为这台设备静音这些发现。',
  'deviceWidgets.mute.mute': '静音',

  // 设备的节律：看的是哪个时段、表格视图、坐标轴，以及两个徽标。
  'deviceWidgets.rhythm.hours': '哪段时间',
  'deviceWidgets.rhythm.recent': '最近',
  'deviceWidgets.rhythm.thisHour': '本小时',
  'deviceWidgets.rhythm.empty': '这台设备还没有被跟踪的域名。',
  'deviceWidgets.rhythm.legend':
    '每一列是两次查询之间的间隔：0 表示不到 1 秒，然后是 1–1.5 秒、1.5–2.2 秒……一直到 2 小时及以上。',
  'deviceWidgets.rhythm.openQueries': '查看这些查询',
  'deviceWidgets.rhythm.aria': '{domain}：{period}',
  'deviceWidgets.rhythm.noRhythm': '没有固定节律',
  'deviceWidgets.rhythm.under': '不到 {span}',
  'deviceWidgets.rhythm.andLonger': '{span} 及以上',
  'deviceWidgets.rhythm.range': '{from}–{to}',
  'deviceWidgets.rhythm.unit.s': '{n} 秒',
  'deviceWidgets.rhythm.unit.h': '{n} 小时',
  'deviceWidgets.rhythm.cell': '{gap}：{count}（{pct} %）',
  'deviceWidgets.rhythm.usual': '平时',
  'deviceWidgets.rhythm.newRhythm': '新节律',

  // 设备的一天，画成泳道：时间窗、表格、提示，以及画布上各元素的含义。
  'deviceWidgets.timeline.window.3d': '3 天',
  'deviceWidgets.timeline.loading': '正在读取查询日志…',
  'deviceWidgets.timeline.truncated': '查询日志的读取提前结束了（{reason}）：泳道只覆盖已读取的部分。',
  'deviceWidgets.timeline.coverage': '查询日志从 {day} {time} 开始：灰色的部分没有数据。',
  'deviceWidgets.timeline.empty': '这个时间窗内没有来自这台设备的查询。',
  'deviceWidgets.timeline.hidden': '（已隐藏）',
  'deviceWidgets.timeline.p99Row': 'p99（ms）',
  'deviceWidgets.timeline.laneFallback': '域名 {n}',
  'deviceWidgets.timeline.new': '新',
  'deviceWidgets.timeline.unit.ms': '{n} ms',
  // 悬停在一格上时说的话：间隔、域名，以及这一格里发生了什么。
  // 数量为 1 时英文仍说 “queries”，与英文保持一致：复数类别只为取到数量。
  'deviceWidgets.timeline.tip.anyDomain': '某个域名',
  'deviceWidgets.timeline.tip.lane': '{span} · {domain} · {queries}，{blocked}{slow}',
  'deviceWidgets.timeline.tip.queries.one': '{q} 次查询',
  'deviceWidgets.timeline.tip.queries.other': '{q} 次查询',
  'deviceWidgets.timeline.tip.blocked.one': '{q} 次拦截',
  'deviceWidgets.timeline.tip.blocked.other': '{q} 次拦截',
  'deviceWidgets.timeline.tip.slow.one': '{q} 次较慢',
  'deviceWidgets.timeline.tip.slow.other': '{q} 次较慢',
  'deviceWidgets.timeline.tip.latency': '{span} · {queries} · p99 {p99}',
  // 泳道下面的图例，在每个圆点处断开。
  'deviceWidgets.timeline.legendLead':
    '越暗表示查询越多；红色下划线：被拦截；琥珀色刻度：慢于延迟目标。上方圆点：',
  'deviceWidgets.timeline.legend.firstContact': '首次访问，',
  'deviceWidgets.timeline.legend.anomaly': '异常，',
  'deviceWidgets.timeline.legend.blockedBurst': '拦截高峰，',
  'deviceWidgets.timeline.legend.identity': '设备身份发生变化；灰色刻度是配置变更。',

  // 设备看起来是什么：那一行话、建议的分组，以及按需展开的依据。
  'deviceWidgets.identity.setAs.a': '设置为 {what}',
  'deviceWidgets.identity.setAs.an': '设置为 {what}',
  'deviceWidgets.identity.madeBy': '由 {vendor} 制造',
  'deviceWidgets.identity.looks.a': '看起来是 {product}（{level}）',
  'deviceWidgets.identity.looks.an': '看起来是 {product}（{level}）',
  'deviceWidgets.identity.suggested': '{group}（建议）',
  'deviceWidgets.identity.suggestedTitle':
    '这个分组的设置要求的正是这类设备。请在地址的菜单里添加：加入分组…',
  'deviceWidgets.identity.hideWhy': '隐藏原因',
  'deviceWidgets.identity.talksTo': '会访问 {domains}',
  'deviceWidgets.identity.macVendor': 'MAC 厂商 {vendor}{prefix}',
  'deviceWidgets.identity.callsItself': '自称“{name}”',
  'deviceWidgets.identity.couldBe.a': '也可能是 {product}',
  'deviceWidgets.identity.couldBe.an': '也可能是 {product}',
  'deviceWidgets.identity.notRight': '不对吗？请为设备命名，并设置它是什么（“它是什么”）。',

  // 按看起来是什么分类的设备（高级仪表盘）。
  'deviceWidgets.byType.title': '按类型分类的设备',
  'deviceWidgets.byType.empty': '还没有识别出任何设备。',
};
