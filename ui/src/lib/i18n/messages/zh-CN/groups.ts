// REQ: API-011 — groups 页面的中文翻译。键名与 en/groups.ts 一一对应。
// 一句话中间夹着值的地方被拆成两段（`groups.dns64OnStart` 写到前缀之前，`groups.dns64OnEnd`
// 接在前缀后面），这样标记里自己的元素能保留下来。
import type { MessageKey } from '../en';

export const groups: Partial<Record<MessageKey, string>> = {
  // 标题，以及分组是什么。
  'groups.intro':
    '分组是一类设备：分组网段上的每台设备都属于它（已命名的设备也可以单独归入一个分组）。分组决定应用哪些列表，并显示每类设备都在做什么。',

  // 卡片：暂停状态、分组里有什么，以及它做了什么。
  'groups.pausedUntil': '暂停至 {time}',
  'groups.devices.default': '不匹配其他任何规则的设备',
  'groups.devices.namedAndWorkloads': '已命名的设备和 Kubernetes 工作负载',
  'groups.devices.namedOnly': '仅已命名的设备',
  'groups.safeSearch': '安全搜索已开启',
  'groups.safeSearch.notYouTube': '（不含 YouTube）',
  'groups.safeSearch.youtubeModerate': '（YouTube 为中等限制）',
  'groups.schedulesLabel': '时间表：',
  'groups.schedules.onNow': '正在生效',
  'groups.blocks': '拦截 {services}',
  'groups.answers.rebinding': '重绑定保护已开启',
  'groups.answers.blockIps': '拦截 {networks} 网段内的应答',
  'groups.rewritesLabel': '重写：',
  'groups.upstreamsLabel': '上游服务器：',
  'groups.dns64OnStart': 'DNS64 已开启（',
  'groups.dns64OnEnd': '）',
  'groups.filterAaaa': '不使用 IPv6 地址（AAAA 查询返回空应答）',

  // 卡片上的数字，以及它被问到的名称。
  'groups.stat.queries': '查询（24 小时）',
  'groups.stat.devices': '设备（本小时）',
  'groups.top.names': '热门名称',
  'groups.top.nothingBlocked': '没有拦截',

  // 分组里的 Kubernetes 工作负载，以及通往它的查询的链接。
  'groups.workloadsLabel': '工作负载：',
  'groups.workloads.more.one': '还有 {n} 个',
  'groups.workloads.more.other': '还有 {n} 个',
  'groups.showQueries': '查看这个分组的查询',

  // 卡片下面的设置表。
  'groups.col.priority': '优先级',
  'groups.col.blocking': '拦截状态',
  'groups.lists.none': '无',
  'groups.lists.everyEnabled': '所有启用的列表',
  'groups.blockTtl': 'TTL {seconds} 秒',

  // 分组编辑器：标题、名词，以及一行里对条目的说明。
  'groups.manage.title': '管理分组',
  'groups.manage.noun': '分组',
  'groups.manage.lists.one': '{n} 个列表',
  'groups.manage.lists.other': '{n} 个列表',

  // 分组编辑器的字段。
  'groups.field.networks': '网段',
  'groups.field.networksHelp': '每行一个。这些网段上的每台设备都属于该分组。',
  'groups.field.listsHelp': '新建分组时全部不勾选，表示使用所有启用的列表。',
  'groups.field.upstreams': '上游服务器',
  'groups.field.upstreamsHelp':
    '这个分组的问题交给哪个上游分组。（default）表示使用默认上游分组；针对某个域名的路由仍然优先。',
  'groups.field.safeSearch': '安全搜索',
  'groups.field.safeSearchHelp':
    'Google、Bing、DuckDuckGo、Yandex 和 Pixabay 只显示安全结果；YouTube 使用受限模式。',
  'groups.field.youtube': 'YouTube 限制',
  'groups.field.blockedServices': '拦截的服务',
  'groups.field.blockedServicesHelp': '为这个分组拦截整个服务（它的所有域名），在它的列表之外额外生效。',
  'groups.field.rebinding': '重绑定保护',
  'groups.field.rebindingHelp': '拦截来自互联网、指向私有网络地址的应答（DNS 重绑定）。',
  'groups.field.blockAnswerIps': '拦截这些网段内的应答',
  'groups.field.blockAnswerIpsHelp': '地址落在这些网段内的应答一律拦截，不管名字是什么。',
  'groups.field.dns64': 'DNS64',
  'groups.field.dns64Help': '为只有 IPv4 的名字生成 IPv6 地址，用于挂 NAT64 的纯 IPv6 网络。',
  'groups.field.dns64Prefix': 'DNS64 前缀',
  'groups.field.dns64Exclude': 'DNS64 排除项',
  'groups.field.dns64ExcludeHelp':
    '这里的 IPv6 地址视为不存在（该名字会得到临时生成的地址）；这里的 IPv4 地址永远不会被合成为 IPv6。',
  'groups.field.filterAaaa': '不使用 IPv6 地址',
  'groups.field.filterAaaaHelp':
    '对 IPv6（AAAA）查询返回空应答，让这些设备改用 IPv4：用于 IPv6 出问题的网络。你自己的名字仍然会应答。不要与 DNS64 同时使用。',
  'groups.field.schedulesHelp': '这个分组遵循的时间表（在下面的“时间表”里创建）。',
  'groups.field.blockMode': '拦截应答',
  'groups.field.priorityHelp': '当一台设备匹配多个分组时，优先级最高的生效。',
  'groups.field.color': '颜色',

  // 分组下面的时间表编辑器：标题、名词、字段，以及时间窗写错时说的话。
  'groups.schedule.title': '时间表',
  'groups.schedule.noun': '时间表',
  'groups.schedule.action': '时间窗内',
  'groups.schedule.actionHelp':
    'block_all：就寝时间（除快捷放行规则和本地名字外全部拦截）。enable_lists：额外应用这些列表。block_services：额外拦截这些服务。',
  'groups.schedule.window': '时间窗（每行一个）',
  'groups.schedule.windowHelp':
    '日期：mon … sun、weekdays、weekends、daily。结束时间早于开始时间表示跨过午夜。',
  'groups.schedule.lists': '列表（enable_lists）',
  'groups.schedule.services': '服务（block_services）',
  'groups.schedule.tz': '时区',
  'groups.schedule.tzHelp': 'IANA 时区。默认：本节点的时区。',
  'groups.schedule.errLine': '“{line}”：日期和时间请写成“weekdays 21:00-07:00”这样',
  'groups.schedule.errEmpty': '至少添加一个时间窗，例如“weekdays 21:00-07:00”。',
};
