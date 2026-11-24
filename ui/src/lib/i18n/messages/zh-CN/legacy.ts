// REQ: API-011 — legacy 页面的中文翻译。键名与 en/legacy.ts 一一对应。
import type { MessageKey } from '../en';

export const legacy: Partial<Record<MessageKey, string>> = {
  // 标题，以及数字上方的控件。
  'legacy.title': '仪表盘',
  'legacy.showing': '显示',
  'legacy.nodes': '节点',
  'legacy.everyNode': '全部节点',
  'legacy.nodePod': '{site} 的 Pod {pod}',
  'legacy.nodePrimary': '（主节点）',
  'legacy.thisNode': '本节点',
  'legacy.siteAllNodes': '站点 {site}（全部节点）',
  'legacy.siteLabel': '站点 {site}',
  'legacy.oneNode': '某个节点',
  'legacy.topListsFor': '热门列表统计',
  'legacy.group': '分组',
  'legacy.everyDevice': '全部设备',
  'legacy.timeRange': '时间范围',
  'legacy.partialResults': '部分结果：{nodes} 没有应答，因此这些数字只覆盖集群中的其他节点。',

  // 时间范围（标题下的切换按钮），以及说明卡片覆盖哪几个小时的文字。
  'legacy.range.48h': '48 小时',
  'legacy.range.30d': '30 天',
  'legacy.lastRange': '最近 {range}',
  'legacy.sinceTime': '自 {time} 起',
  'legacy.thisHour': '本小时',

  // 各项数字。
  'legacy.queries': '查询',
  'legacy.blocked': '已拦截',
  'legacy.cacheHits': '缓存命中',
  'legacy.upstreamP90': '上游服务器 p90',
  'legacy.activeClients': '活跃设备',
  'legacy.nxdomainServfail': 'NXDOMAIN / SERVFAIL',
  'legacy.blockedQueries': '{queries} 次查询',
  'legacy.cacheAnswers': '{answers} 个应答',
  'legacy.cacheFreshRefreshed': '新鲜 {fresh} · 已刷新 {refreshed}',
  'legacy.cacheP50': '缓存 p50 {value}',

  // 图表和热门设备图例上的状态词（发给接口的仍然是标识符本身）。
  'legacy.status.cached': '缓存',
  'legacy.status.refreshed': '已刷新',
  'legacy.status.forwarded': '转发',
  'legacy.status.local': '本地',
  'legacy.status.other': '其他',

  // 图表：标题、没有数据时的说明，以及环形图中间的文字。
  'legacy.chartQueriesByStatus': '按状态划分的查询',
  'legacy.answersByStatus': '按状态划分的应答',
  'legacy.noAnswersRange': '这个时间范围内没有应答。',
  'legacy.donutCenter': '应答 · {range}',
  'legacy.chartTrafficByGroup': '按分组划分的流量',
  'legacy.chartUpstreamExchanges': '上游服务器交互',
  'legacy.upstreamQueries': '上游查询',
  'legacy.failures': '故障',

  // 时间花在哪里（高级视图）：视图切换、表格，以及每种路径的含义。
  'legacy.whereTimeGoes': '时间花在哪里',
  'legacy.parenThisHour': '（本小时）',
  'legacy.whereTimeGoesAs': '时间分布的展示方式',
  'legacy.percentiles': '分位数',
  'legacy.noAnswersHour': '本小时还没有应答。',
  'legacy.col.path': '路径',
  // `max` 与 p50/p90/p99 并列，保持原样。
  'legacy.col.max': 'max',
  'legacy.path.cache': '由缓存应答：重复的问题，没有询问上游服务器。也包括缓存副本刚过期、立即给出答案并在后台刷新的应答。通常远低于 1 毫秒。',
  'legacy.path.upstream': '缓存中没有：询问了上游解析器并等待它回答。也包括因为上游服务器变慢或故障而给出陈旧答案，以及 SERVFAIL。通常是耗时最长的一条路径。',
  'legacy.path.local': '由你网络中的名称（本地记录）应答，没有询问任何外部服务器。',
  'legacy.path.synthesized': '没有查询任何地方就给出的应答：已拦截的名称、被拒绝或限速的查询、格式错误的查询，以及特殊名称（例如 Firefox 的 DNS-over-HTTPS 探针）。',
  'legacy.path.fallback': '走这条路径的应答。',
  'legacy.path.waitUpstream': '在上面的上游路径中：等待上游解析器所花的时间（其余时间是本节点自己的工作）。',
  'legacy.path.wait': '等待 {what} 应答所花的时间。',
  'legacy.path.over': '{path}走的是{proto}。',
  'legacy.proto.udp': '基于 UDP 的普通 DNS，大多数设备使用这种方式',
  'legacy.proto.tcp': '基于 TCP 的普通 DNS，用于大应答和部分工具',
  'legacy.proto.dot': 'DNS over TLS（端口 853），例如 Android 的私人 DNS',
  'legacy.proto.doh': 'DNS over HTTPS，例如浏览器或安装了描述文件的 Apple 设备',

  // 上游服务器（高级视图）。
  'legacy.asThisNode': '（以本节点的视角）',
  'legacy.details': '详情',
  'legacy.noUpstreams': '尚未配置上游服务器。',

  // 热门列表。
  'legacy.topDomains': '热门域名',
  'legacy.topBlocked': '拦截最多',
  'legacy.topClients': '热门客户端',
  'legacy.domainsScope': '热门域名：互联网或内网',
  'legacy.internet': '互联网',
  'legacy.internal': '内网',
  'legacy.empty': '暂无数据。',
};
