// REQ: API-011 — cache 页面的中文翻译。键名与 en/cache.ts 一一对应。
// 计数后面跟着名词的地方，名词自成一条键（`.one`/`.other`），句子用占位符把它带进去，
// 于是每种语言都能把数字放在自己习惯的位置。
import type { MessageKey } from '../en';

export const cache: Partial<Record<MessageKey, string>> = {
  // 标题。

  // 节点卡片：缓存工作得如何、存了多少、是怎么启动的。
  'cache.node.answeredHeading': '由缓存应答',
  'cache.node.lastHour': '最近一小时',
  'cache.node.sinceStart': '· 启动以来 {pct}',
  'cache.node.fresh':
    '最近一小时有 {pct} 是新鲜命中；其余是刚过期就立即给出答案、同时在后台刷新的（或上游故障期间继续给出答案的）。',
  'cache.node.answers.one': '{n} 条应答',
  'cache.node.answers.other': '{n} 条应答',
  'cache.node.holdsHeading': '现有内容',
  'cache.node.ofBudget': '（共 {bytes}）',
  'cache.node.shareLabel': '占内存上限的 {pct}',
  'cache.node.lookups.one': '{n} 次查询',
  'cache.node.lookups.other': '{n} 次查询',
  'cache.node.lastHourLine': '{lookups} · 预取 {prefetched} 次 · 给出过期应答 {stale} 次 · 淘汰 {evicted} 次',
  'cache.node.started': '启动状态',
  'cache.node.coldOff': '冷启动（未开启跨重启保留缓存）',
  'cache.node.warm': '热启动：重新载入 {answers}，{date} {time}',
  'cache.node.cold': '冷启动：{note}',
  'cache.node.chartAnswered': '由缓存应答，最近一小时（%）',
  'cache.node.chartLookups': '每 15 秒的查询数',
  'cache.node.chartsFilling': '图表会在最初几分钟内逐步填充（每 15 秒一个采样点）。',

  // 容量建议：结论，以及加大容量能换来什么。
  'cache.sizing.heading': '容量',
  'cache.sizing.grow': '可以更大',
  'cache.sizing.shrink': '可以更小',
  'cache.sizing.ok': '大小合适',
  'cache.sizing.learning': '学习中',
  'cache.sizing.bigger': '更大：',
  'cache.sizing.step': '{size}% → +{hits}% 命中',
  'cache.sizing.peak': '峰值 {bytes}。',

  // “缓存内容”下的两张表：它们的控件，以及每个节点的内容构成表。
  'cache.makeup.title': '缓存内容',
  'cache.makeup.sort': '排序',
  'cache.makeup.sortAria': '排序方式',
  'cache.makeup.sortHits': '命中最多',
  'cache.makeup.sortBytes': '占用最大',
  'cache.makeup.sortExpiring': '最先过期',
  'cache.makeup.refresh': '刷新',
  'cache.makeup.colHolds': '条目',
  'cache.makeup.colStale': '过期',
  'cache.makeup.colValidated': '已验证',
  'cache.makeup.kind.answer.one': '{n} 条应答',
  'cache.makeup.kind.answer.other': '{n} 条应答',
  'cache.makeup.kind.noSuchName.one': '{n} 条域名不存在',
  'cache.makeup.kind.noSuchName.other': '{n} 条域名不存在',
  'cache.makeup.kind.noData.one': '{n} 条无数据',
  'cache.makeup.kind.noData.other': '{n} 条无数据',
  'cache.makeup.kind.servfail.one': '{n} 条 SERVFAIL',
  'cache.makeup.kind.servfail.other': '{n} 条 SERVFAIL',
  'cache.makeup.showFewer': '少显示几个节点',
  'cache.makeup.showAll.one': '显示全部 {n} 个节点',
  'cache.makeup.showAll.other': '显示全部 {n} 个节点',

  // 条目排行：跨节点合并的名称列表，以及一个名称在各节点上的情况。
  'cache.top.empty': '没有缓存。',
  'cache.top.emptyFresh': '没有仍在有效期内的缓存。',
  'cache.top.lookupTitle': '在下方查询',
  'cache.top.ttlLeft': '剩余 {ttl}',
  'cache.top.ttlStale': '已过期 {ttl}',
  'cache.top.ttlRange': '{from} 至 {to}',
  'cache.top.nodesOf': '{shown} / {total}',
  'cache.top.hits.one': '{n} 次命中',
  'cache.top.hits.other': '{n} 次命中',
  'cache.top.merged':
    '已跨节点合并：每个名称只出现一次，命中数来自把它列入各自前 {limit} 名的那些节点。要看单个节点的列表，请在上方选择一个节点。',
  'cache.top.cardTitle': '查询并清除',

  // 节点上生效的设置。
  'cache.settings.maxEntries.one': '，最多 {n} 条应答',
  'cache.settings.maxEntries.other': '，最多 {n} 条应答',
  'cache.settings.ttlLine': '{min} 至 {max}；否定应答最长 {negative}；SERVFAIL {servfail}',
  'cache.settings.serveStale': '提供过期应答',
  'cache.settings.serveStaleAtOnce': '立即给出答案并在后台刷新，过期后最多持续 {duration}',
  'cache.settings.serveStaleWhen': '上游不响应时',
  'cache.settings.serveStaleWithin': '，等待不超过 {seconds} 秒',
  'cache.settings.serveStaleFor': '，过期后最多持续 {duration}',
  'cache.settings.prefetch': '预取',
  'cache.settings.prefetchOn': '开启：TTL 剩余不足 {percent}% 时，在 {hits}之后',
  'cache.settings.prefetchHits.one': '{n} 次命中',
  'cache.settings.prefetchHits.other': '{n} 次命中',
  'cache.settings.acrossRestarts': '跨重启',
  'cache.settings.kept': '保留',
  'cache.settings.notKept': '不保留',
  'cache.settings.changeUnder': '在配置文件的 ',
  'cache.settings.inConfig': ' 中修改这些设置。',
};
