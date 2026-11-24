// REQ: API-011 — upstreams 页面的中文翻译。键名与 en/upstreams.ts 一一对应。
// 句子中间夹着值时（标记里的 <strong>、<code>、<a>）把句子拆开：`…intro` 写到第一个值之前，
// `…before`/`…after` 夹住那个元素。
import type { MessageKey } from '../en';

export const upstreams: Partial<Record<MessageKey, string>> = {
  // 标题，以及表格的列名。
  'upstreams.col.requests': '请求',
  'upstreams.col.failures': '失败',
  'upstreams.col.smoothed': '平滑值',
  'upstreams.col.secondOpinions': '二次征询',
  'upstreams.col.dnssec': 'DNSSEC',
  'upstreams.col.ede': '错误码（EDE）',

  // 行内数字下面那两条比例条是什么。
  'upstreams.share.requests': '占全部上游请求的比例',
  'upstreams.share.failures': '失败率',

  // 失败的原因（一个数量和它的类别），写在失败率下面。
  'upstreams.failure.timeout.one': '{n} 次超时',
  'upstreams.failure.timeout.other': '{n} 次超时',
  'upstreams.failure.network.one': '{n} 次连接错误',
  'upstreams.failure.network.other': '{n} 次连接错误',
  'upstreams.failure.badResponse.one': '{n} 次错误应答',
  'upstreams.failure.badResponse.other': '{n} 次错误应答',
  'upstreams.failure.unresolved.one': '{n} 次域名未解析',
  'upstreams.failure.unresolved.other': '{n} 次域名未解析',
  'upstreams.failure.servfail.one': '{n} 次 SERVFAIL',
  'upstreams.failure.servfail.other': '{n} 次 SERVFAIL',
  'upstreams.failure.refused.one': '{n} 次 REFUSED',
  'upstreams.failure.refused.other': '{n} 次 REFUSED',
  'upstreams.failure.otherRcode.one': '{n} 次其他错误',
  'upstreams.failure.otherRcode.other': '{n} 次其他错误',

  // 健康徽标各是什么意思；这里加粗的三个词就是徽标上显示的那三个词。
  'upstreams.health.intro': '健康：',
  'upstreams.health.answering': ' = 能正常应答，',
  'upstreams.health.stopped': ' = 连续失败后不再向它提问，',
  'upstreams.health.trial':
    ' = 正在用一条试探查询检查它是否已经恢复。百分位数涵盖这一小时。把鼠标停在徽标上，可以看到熔断器自己的说法。',

  // 应答时间的热力图，以及选上游的那个菜单。
  'upstreams.latency.title': '应答时间的变化',

  // 应答质量的检查：标题，以及上游还没应答时的说明。
  'upstreams.quality.title': '应答质量',
  'upstreams.quality.empty': '暂时没有可显示的内容：等上游开始应答后，就会出现 DNSSEC 判定和错误码。',

  // 第二个上游怎么说：带数量的标签，以及说明原因的提示。
  'upstreams.opinion.same.one': '{n} 个相同',
  'upstreams.opinion.same.other': '{n} 个相同',
  'upstreams.opinion.otherAddresses.one': '{n} 个其他地址',
  'upstreams.opinion.otherAddresses.other': '{n} 个其他地址',
  'upstreams.opinion.otherAddressesTip': '两边都有地址，但完全不重合：CDN 和按地理位置应答的 DNS 会针对每个递归服务器给出不同答案，通常没有影响。',
  'upstreams.opinion.otherResponse.one': '{n} 个其他响应',
  'upstreams.opinion.otherResponse.other': '{n} 个其他响应',
  'upstreams.opinion.otherResponseTip': '响应码不同（SERVFAIL、REFUSED……）。',
  'upstreams.opinion.filtered.one': '{n} 个被过滤',
  'upstreams.opinion.filtered.other': '{n} 个被过滤',
  'upstreams.opinion.filteredTip': '一边有地址，另一边没有或只有 0.0.0.0/回环地址：说明其中一个在过滤这个名称。',
  'upstreams.opinion.unanswered.one': '{n} 个没有第二次应答',
  'upstreams.opinion.unanswered.other': '{n} 个没有第二次应答',
  'upstreams.opinion.unansweredTip': '第二个上游没有应答。',

  // 一处分歧的结论（表格下面那个列表里的标签）。
  'upstreams.disagreement.otherAddresses': '其他地址',
  'upstreams.disagreement.otherResponse': '其他响应',
  'upstreams.disagreement.filtered': '被过滤',

  // 一行里数出来的 DNSSEC 判定，以及错误码为空时的说明。
  'upstreams.dnssec.secure.one': '{n} 项安全',
  'upstreams.dnssec.secure.other': '{n} 项安全',
  'upstreams.dnssec.unsigned.one': '{n} 项未签名',
  'upstreams.dnssec.unsigned.other': '{n} 项未签名',
  'upstreams.dnssec.bogus.one': '{n} 项伪造',
  'upstreams.dnssec.bogus.other': '{n} 项伪造',
  'upstreams.dnssec.undecided.one': '{n} 项未判定',
  'upstreams.dnssec.undecided.other': '{n} 项未判定',

  // 二次征询关闭时的说明。
  'upstreams.secondOpinionsOff.before': '二次征询已关闭。设置 ',
  'upstreams.secondOpinionsOff.after':
    ' 后，每 1000 个转发出去的查询中就有 1 个会再向另一个上游提问，并比较两者的应答（那个上游会看到这些名称）。',

  // 最近的分歧，按节点列出。
  'upstreams.disagreements': '最近的分歧',
  'upstreams.disagreements.on': '（节点 {node}）',

  // 两个编辑器：它们的标题，以及句子里用的名词。
  'upstreams.manage.noun': '上游',
  'upstreams.manage.groupTitle': '上游分组',
  'upstreams.manage.groupNoun': '上游分组',

  // 上游编辑器的字段：名称、示例、说明。
  'upstreams.field.addressPlaceholder': 'tls://9.9.9.9 或 https://dns.quad9.net/dns-query',
  'upstreams.field.addressHelp':
    '可用 udp://、tcp://、tls://（DNS over TLS）、https://（DNS over HTTPS）或 quic://。插件类上游（exec://、unix://）在配置文件中定义。',
  'upstreams.field.tlsName': 'TLS 服务器名称',
  'upstreams.field.tlsNamePlaceholder': 'dns.quad9.net',
  'upstreams.field.tlsNameHelp': '服务器证书上的名称，用于以 IP 给出的 tls:// 和 quic:// 地址。',
  'upstreams.field.timeout': '超时（ms）',

  // 上游分组编辑器的字段。
  'upstreams.field.members': '上游',
  'upstreams.field.strategy': '策略',
  'upstreams.field.strategyHelp':
    'failover：按顺序，失败就换下一个。fastest：选最近最快的。parallel：同时问几个，取最先返回的应答。',

  // 保存之前先问一下草稿里的上游到底通不通。
  'upstreams.test.works': '可用：{detail}，用时 {ms} 毫秒。',
  'upstreams.test.fails': '不可用：{error}',

  // 把某个域名交给别处处理。
  'upstreams.forwarded.before': '要把某个域名交给别的服务器处理（例如公司网络、家里的路由器），请在 ',
  'upstreams.forwarded.after': ' 页面添加一个转发域名。',
};
