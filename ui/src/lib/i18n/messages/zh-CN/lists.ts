// REQ: API-011 — lists 页面的中文翻译。键名与 en/lists.ts 一一对应。
// 一句话中间夹着标记元素的地方被拆成两段（`lists.emptyStart` 写到 `<code>` 之前，
// `lists.emptyEnd` 接着它后面写），这样标记里自己的元素能保留下来。
import type { MessageKey } from '../en';

export const lists: Partial<Record<MessageKey, string>> = {
  // 标题、快照里的数量，以及表格为空时说的话。
  'lists.snapshotBlocked.one': '快照 {snapshot} 中有 {n} 个被拦截的名称',
  'lists.snapshotBlocked.other': '快照 {snapshot} 中有 {n} 个被拦截的名称',
  'lists.emptyStart': '还没有配置任何列表。添加 ',
  'lists.emptyEnd': ' 条目（URL、文件或内联规则）。',

  // 表格的列。
  'lists.col.list': '列表',
  'lists.col.kind': '类型',
  'lists.col.state': '状态',
  'lists.col.namesUsed': '使用的名称',
  'lists.col.unique': '独有',
  'lists.col.lines': '行数',
  'lists.col.size': '大小',
  'lists.col.checked': '上次检查',
  'lists.col.changed': '上次更改',

  // 一行：名称旁的徽标、数字下面的说明，以及占比条。
  'lists.badge.off': '关闭',
  'lists.badge.shadowTitle': '从不拦截：它本来会拦截的内容在下面统计',
  'lists.regexSkippedStart.one': '{n} 条正则规则被略过（超过 ',
  'lists.regexSkippedStart.other': '{n} 条正则规则被略过（超过 ',
  'lists.regexSkippedEnd': ' 的上限，或者太大无法编译）',
  'lists.stale.one': '已 {n} 天没有变化',
  'lists.stale.other': '已 {n} 天没有变化',
  'lists.staleTitle': '它的来源可能已经废弃，但仍能应答',
  'lists.shareLabel': '占快照中被拦截名称的比例',
  'lists.overlapShare': '{pct}% 同时也在 {list} 中',
  'lists.noneYet': '还没有',

  // 影子列表本来会拦截什么（OBS-018）。
  'lists.shadow.title': '本来会拦截',
  'lists.shadow.counts': '{queries}，来自 {devices}',
  'lists.shadow.queries.one': '{n} 个查询',
  'lists.shadow.queries.other': '{n} 个查询',
  'lists.shadow.devices.one': '{n} 台设备',
  'lists.shadow.devices.other': '{n} 台设备',
  'lists.shadow.since': '，始于 {when}',
  'lists.shadow.last': ' · 最近 {when}',
  'lists.shadow.empty': '还没有：它没有匹配到你设备查询过的任何名称。',
  'lists.shadow.noteStart': '影子列表从不拦截。如果上面的名字是你希望拦截的，就把该列表改为 ',

  // 有人似乎需要的被拦截名称（OBS-018）。
  'lists.overblocking.title': '可能过度拦截',
  'lists.overblocking.col.blockedBy': '被谁拦截',
  'lists.overblocking.col.allowedAfter': '随后很快放行',
  'lists.overblocking.col.retries': '重试突发',
  'lists.overblocking.col.devices': '设备数',
  'lists.overblocking.col.last': '最近',
  'lists.overblocking.note':
    '“随后很快放行”统计的是在拦截后 10 分钟内又拿到该名称的设备（一次暂停或一次放行）：说明有人需要它。重试突发是指应用每分钟请求 10 次以上；广告库也会这样。',

  // 列表编辑器：标题、名词、一行里对条目的说明，以及它自己的脚注。
  'lists.manage.title': '管理列表',
  'lists.manage.noun': '列表',
  'lists.manage.rules.one': '{n} 条规则',
  'lists.manage.rules.other': '{n} 条规则',
  'lists.manage.summaryOff': ' · 关闭',
  'lists.footNote':
    '“使用的名称”是这个列表放进当前快照的名称数量；“独有”是其他列表都没有的名称（移除它会失去什么）。“命中”是各节点启动以来它决定的查询数，按整个集群统计。',

  // 编辑器的字段（API-002、OBS-018）。
  'lists.field.download': '下载地址',
  'lists.field.downloadPlaceholder': 'https://example.org/hosts.txt',
  'lists.field.downloadHelp': 'hosts 文件、纯域名列表和 Adblock 风格的列表都可以用。也可以留空，改为在下面直接写规则。',
  'lists.field.rulesPlaceholder': 'ads.example.com, ||tracker.example^（每行一条）',
  'lists.field.match': '纯名称的匹配方式',
  'lists.field.matchHelp': 'subtree：该名称及其下面的所有名称。exact：仅该名称本身。',
  'lists.field.enabled': '启用',
  'lists.field.mode': '模式',
  'lists.field.modeHelp': 'enforce：会拦截。shadow：从不拦截；页面会显示它本来会拦截什么，方便你先判断。',
  'lists.field.refresh': '每隔多久检查更新（秒）',
  'lists.field.refreshPlaceholder': '86400',

  // 保存前先试一下草稿列表（T9.12）。
  'lists.test.label': '试一下',
  'lists.test.badLines': ' 无法使用的行：{lines}',
  'lists.test.works': '可用：{detail}，用时 {ms} 毫秒。{notes}',
  'lists.test.fails': '不可用：{detail}。{notes}',
};
