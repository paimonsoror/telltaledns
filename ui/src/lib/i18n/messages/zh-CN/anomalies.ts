// REQ: API-011 — anomalies 页面的中文翻译。键名与 en/anomalies.ts 一一对应。
// 名字嵌在句子中间的地方（标记里用 `<b>` 包住）被拆成 `…by` 与 `…rest`：前者写到名字之前，
// 后者接着名字之后写。
import type { MessageKey } from '../en';

export const anomalies: Partial<Record<MessageKey, string>> = {
  // 标题，以及页面查看的时间范围。
  'anomalies.range.24h': '最近 24 小时',
  'anomalies.range.7d': '最近 7 天',
  'anomalies.range.30d': '最近 30 天',

  // 静音保存后的提示（被静音的那条发现已经离开了列表）。
  'anomalies.muted.saved': '已静音。',
  'anomalies.dismiss': '关闭',

  // 这个页面是用来做什么的。
  'anomalies.intro':
    '每台设备都会与它自己在最初一周里学到的平时行为作比较。这些发现只是提示；若要处理，请打开该设备的查询，或把它移到更严格的分组。查看过之后请确认该发现：它就不再被算作新发现，并且在所有节点上生效。如果某台设备反复无害地做出同一类行为，可以为它静音这一类发现。',

  // 工具栏：哪些被隐藏了，以及一次性确认全部。
  'anomalies.showAcknowledged': '显示已确认（{n}）',
  'anomalies.showMuted': '显示已静音（{n}）',
  'anomalies.acknowledgeAll': '确认全部 {n}',

  // 列表为空时说的话。
  'anomalies.empty.acknowledged': '没有新发现：这段时间内的每条发现都已确认。',
  'anomalies.empty.muted.one': '没有异常：{n} 条已静音的发现被隐藏。',
  'anomalies.empty.muted.other': '没有异常：{n} 条已静音的发现被隐藏。',
  'anomalies.empty.none': '没有异常。新设备在最初 7 天里不会有动静，TelltaleDNS 在这段时间学习它们。',

  // 发现的类型：徽标和静音表格里的文字（值本身仍是标识符）。
  'anomalies.kind.rateSpike': '查询量远超平时',
  'anomalies.kind.domainVolume': '发往某个域名的流量异常',
  'anomalies.kind.drift': '大量新域名',
  'anomalies.kind.beacon': '规律性回连',
  'anomalies.kind.chattyLoop': '高频循环查询',
  'anomalies.kind.nxdomainStorm': '大量解析失败',
  'anomalies.kind.dga': '看起来由机器生成的域名',
  'anomalies.informational': '仅供参考：不计为异常',

  // 一条被静音的发现：是谁静音的，以及这意味着什么。
  'anomalies.muted.badge': '已静音',
  'anomalies.muted.rest': ' 静音：不计入徽标、告警和指标',

  // 一条已确认的发现：是谁、在什么时候确认的。
  'anomalies.ack.badge': '已确认',
  'anomalies.ack.by': '由',
  'anomalies.ack.sep': '，',

  // 别人留下的备注，用引号括起来。
  'anomalies.note': '：“{note}”',

  // 依据：看到的值、设备的平时值，以及它越过的界线。
  'anomalies.evidence.observed': '实测',
  'anomalies.evidence.usual': '平时',
  'anomalies.evidence.threshold': '阈值',
  'anomalies.evidence.window': '时间窗',

  // 发现的时间窗有多长。
  'anomalies.window.days.one': '{n} 天',
  'anomalies.window.days.other': '{n} 天',
  'anomalies.window.hours.one': '{n} 小时',
  'anomalies.window.hours.other': '{n} 小时',
  'anomalies.window.minutes.one': '{n} 分钟',
  'anomalies.window.minutes.other': '{n} 分钟',

  // 一条发现上的操作。
  'anomalies.showQueries': '查看这些查询',
  'anomalies.seeTheDay': '查看当天情况',
  'anomalies.foundBy': '由 {nodes} 发现',
  'anomalies.removeMute': '取消静音',
  'anomalies.muteForDevice': '为这台设备静音…',
  'anomalies.undoAcknowledge': '撤销确认',
  'anomalies.acknowledge': '确认',

  // 静音表格：标题、说明、列名和行里的文字。
  'anomalies.mutes.title': '静音',
  'anomalies.mutes.intro': '对这些设备不再计数的发现类型。它们仍会被记录：打开“显示已静音”即可看到。',
  'anomalies.mutes.col.kinds': '类型',
  'anomalies.mutes.col.until': '直到',
  'anomalies.mutes.group': '分组 {name}',
  'anomalies.mutes.ended': '已结束',
  'anomalies.mutes.untilRemoved': '直到手动删除',

  // 首次出现的域名：标题、开关和表格。
  'anomalies.newDomains.title': '新域名',
  'anomalies.newDomains.onlySuspicious': '只看疑似机器生成',
  'anomalies.newDomains.intro':
    '每台设备首次访问的域名（不含它的第一天），最新的在前。评分表示这个域名看起来有多像机器生成（0.6 及以上为可疑）。',
  'anomalies.newDomains.empty': '这段时间内没有新域名。',
  'anomalies.newDomains.col.firstSeen': '首次出现',
  'anomalies.newDomains.col.score': '评分',
};
