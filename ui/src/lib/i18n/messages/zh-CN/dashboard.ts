// REQ: API-011 — dashboard 界面的中文文案。键名与 en/dashboard.ts 一一对应。
import type { MessageKey } from '../en';

export const dashboard: Partial<Record<MessageKey, string>> = {
  // 标题、视图控件、部分结果提示。
  'dashboard.switchBack': '切换到新版仪表盘',

  // 时间范围（标题下的切换按钮）。

  // 各项数字。
  'dashboard.nxdomainLine': '{nxdomain} 个 NXDOMAIN · {servfail} 个 SERVFAIL（最近 {range}）',

  // 与上一周期的变化（数字下方的小字）。
  'dashboard.previousPeriodTitle': '与等长的上一周期相比',

  // 图表：它的视图和标题。
  'dashboard.chartView': '图表视图',
  'dashboard.view.totals': '总量',
  'dashboard.upstreamFailures': '上游故障',
  'dashboard.upstreamQueries': '上游查询',
  'dashboard.failures': '故障',

  // 服务等级（高级视图）：目标与告警的措辞。
  'dashboard.slo.window.one': '最近 {n} 天',
  'dashboard.slo.window.other': '最近 {n} 天',
  'dashboard.slo.availability': '能正常工作的应答',
  'dashboard.slo.latency': '快速的应答',

  // 时间花在哪里（高级视图）：视图切换、表格，以及每种路径的含义。
  // `max` stays as it is, beside p50/p90/p99.
  'dashboard.path.cache': '由缓存应答：重复的问题，没有询问上游服务器。也包括缓存副本刚过期、立即给出答案并在后台刷新的应答（这类答案算陈旧）。通常远低于 1 毫秒。',

  // 上游服务器（高级视图）。
  'dashboard.asThisNode': '以本节点的视角',

  // 热门列表。
  'dashboard.topClients': '热门设备',
  'dashboard.byType': '按类型',
  'dashboard.clients': '设备',
  'dashboard.searchSuffix': '搜索后缀 ×{n}',
  'dashboard.detailsFor': '查看 {name} 的详情',
  'dashboard.podsAskedPre': '设备用各自的 DNS 搜索后缀查询了',
  'dashboard.podsAskedPost': '，因此这其实是同一个问题，看起来却有 {n} 条：',
  'dashboard.queriesCount': '{count} 次查询',
  'dashboard.ofThisList': '占本列表 {pct}',
  'dashboard.showItsQueries': '查看它的查询',
  'dashboard.showInLog': '在查询日志中查看',

  // 图表自身的界面文字。
  'dashboard.chart': '图表',
  'dashboard.noData': '暂无数据。',
  'dashboard.changed': '变更',
  'dashboard.what': '内容',
  'dashboard.total': '合计',
  'dashboard.andMore': '还有 {n} 个',
};
