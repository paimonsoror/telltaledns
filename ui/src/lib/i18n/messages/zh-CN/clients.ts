// REQ: API-011 — clients 页面的中文翻译。键名与 en/clients.ts 一一对应。
// 句子中间夹着元素（`<code>` 或 `<strong>`）的地方被拆开：`…Lead`/`…Mid` 写到它之前，
// `…Tail`/`…After` 接着它之后写；因为两种语言语序不同，中文这一侧的空格也各自取舍。
import type { MessageKey } from '../en';

export const clients: Partial<Record<MessageKey, string>> = {
  // 页面本身、标题，以及各个标签页（标签页上的数量是数字，由标签页组件显示）。
  'clients.tab.seen': '最近一小时',
  'clients.tab.devices': '设备',
  'clients.tab.workloads': '工作负载',
  'clients.tab.discovered': '已发现',

  // 最近一小时见过的客户端：标题、没有应答的节点，以及空表时的说明。
  'clients.seen.title': '最近一小时内的客户端',
  'clients.seen.missing': '没有 {names} 的数据：它们没有应答，因此未列出它们的客户端。',
  'clients.seen.empty': '最近一小时没有查询。',
  'clients.col.servers': '服务器',
  'clients.col.queries': '查询数',
  'clients.link.when': '时段',
  'clients.link.rhythm': '节律',
  'clients.link.day': '当天',

  // 已配置的设备：标题、空表时的说明，以及列名。
  'clients.devices.emptyLead': '还没有设备。在任意位置（这里、仪表盘或查询日志）点击一个地址并选择“为设备命名…”，或者在配置文件中添加 ',
  'clients.devices.emptyTail': ' 条目。',
  'clients.col.name': '名称',
  'clients.col.recognizedBy': '识别方式',
  'clients.col.definedIn': '定义位置',
  'clients.devices.noGroup': '它所在网络的分组，不论在哪里看到它',
  'clients.from.network': '来自它所在的网络',
  'clients.from.default': '默认：没有匹配的网络分组',
  'clients.forget': '忘记',
  'clients.forgetAria': '忘记 {name}',

  // Kubernetes 工作负载：标题、命名空间筛选、工作负载是什么，以及列名。
  'clients.workloads.title': 'Kubernetes 工作负载',
  'clients.workloads.namespace': '命名空间',
  'clients.workloads.introLead':
    '每个工作负载就是一台设备，无论它运行多少个 Pod：它的查询、异常和时间线在滚动更新后仍然连续。它的分组来自其 Pod 或命名空间上的 ',
  'clients.workloads.introTail': ' 标签、某条规则，或者默认分组。计数覆盖最近 24 小时。',
  'clients.col.workload': '工作负载',
  'clients.col.pods': 'Pod 数',
  'clients.col.blocked': '拦截数',
  'clients.col.lastSeen': '最后出现',
  'clients.col.last24h': '最近 24 小时内',
  'clients.workloads.notInLastDay': '最近一天没有出现',
  'clients.workloads.terminating': '（正在终止）',
  // Kubernetes 的对象类型名是它的 API 名称，中文里也照原样保留。
  'clients.kind.deploy': 'Deployment',
  'clients.kind.sts': 'StatefulSet',
  'clients.kind.ds': 'DaemonSet',
  'clients.kind.job': 'Job',
  'clients.kind.cronjob': 'CronJob',
  'clients.kind.rs': 'ReplicaSet',
  'clients.kind.pod': 'Pod',

  // 由路由器的 DHCP 或 mDNS 发现的设备：标题、它列出什么，以及列名。
  'clients.discovered.title': '在你的网络中发现',
  'clients.discovered.introLead': '来自你路由器 DHCP 的名称（',
  'clients.discovered.introMid': '：UniFi、OPNsense），或者设备通过 mDNS 自报的名称（',
  'clients.discovered.introTail': '）。未命名的设备已经会显示这些名称；点击一个地址即可保留它、修改它，或者把设备放进分组。',
  'clients.discovered.emptyLead': '还没有发现任何设备。请在下方',
  'clients.discovered.emptyMid': '里连接你的路由器，或者设置 ',
  'clients.col.nameItGave': '它自报的名称',
  'clients.col.from': '来源',
  'clients.col.inTelltale': '在 TelltaleDNS 中',
  'clients.discovered.notNamed': '尚未命名',
  // 租约来自哪里（值仍是接口的 `router` 或 `mdns`）。
  'clients.source.mdns': 'mDNS',

  // 路由器：在这里添加和修改（在已发现设备的下方）。
  'clients.router.title': '路由器',
  'clients.router.noun': '路由器',
  'clients.router.urlHelp':
    'UniFi OS 控制台：https://192.168.1.1。经典 Network 应用：https://controller:8443。OPNsense：https://opnsense.lan。粘贴的密钥只会经 https:// 发送。修改地址（或类型、站点、TLS 设置）后需要重新粘贴密钥。',
  'clients.router.apiKeyHelp':
    'UniFi Network 9+：设置 → 控制平面 → 集成。OPNsense：系统 → 访问 → 用户 → API 密钥。它保存在接收配置变更的节点上，不会进入备份。',
  'clients.router.apiSecret': 'API Secret（OPNsense）',
  'clients.router.username': '用户名（UniFi，代替 API 密钥）',
  'clients.router.usernameHelp': '一个本地 UniFi 用户；只读权限就够。',
  'clients.router.password': '密码（UniFi）',
  'clients.router.site': '站点（UniFi）',
  'clients.router.tlsCa': '控制台证书',
  'clients.router.tlsCaHelp': '自签名控制台：提供一个存放其证书的文件，以便校验。',
  'clients.router.tlsName': '证书中的名称',
  'clients.router.tlsNameHelp': 'UniFi 控制台把自己命名为 unifi.local。',
  'clients.router.tlsInsecure': '不校验证书',
  'clients.router.tlsInsecureHelp':
    '对任何控制台都可用，但网络上的任何东西都可能冒充它并拿到密钥。使用粘贴的密钥时，请把地址写成数字（https://192.168.1.1）。',
  'clients.router.interval': '读取间隔（秒）',
  'clients.router.offlineDays': '包含离线设备的天数（UniFi）',
  'clients.router.offlineDaysHelp': '0：只读已连接的客户端。',

  // 密钥已保存时：输入框里提示什么，以及该填什么。
  'clients.keep.apiKey': 'API 密钥',
  'clients.keep.apiSecret': 'API Secret',
  'clients.keep.password': '密码',
  'clients.keep.saved': '已保存。要更换，请输入新的{what}。',
  'clients.keep.missing': '缺少密钥：请重新输入{what}',
  'clients.keep.fileMissing': '密钥文件不存在：请把文件放回原处（或粘贴{what}）',
  'clients.keep.notUsed': '未使用：请重新输入{what}',
  'clients.keep.paste': '粘贴{what}',

  // 路由器那一行对它的密钥怎么说。
  'clients.routerStatus.missing': '缺少密钥：请重新输入',
  'clients.routerStatus.fileMissing': '密钥文件不存在：请把文件放回原处，或粘贴密钥',
  'clients.routerStatus.notUsed': '密钥未使用：请重新输入',
  'clients.routerStatus.saved': '密钥已保存',
  // 从另一台机器经纯 HTTP 打开的页面，粘贴进去的内容会不加密地经过网络。
  'clients.plainHttp': '你正在使用纯 HTTP 页面：粘贴的密钥会以未加密的形式经过网络。请先用 https 打开此页面。',

  // 设备的抽屉：它的视图、它的节律，以及它的一天。
  'clients.device.view': '设备视图',
  'clients.device.timeline': '时间线',
  'clients.device.timelineIntro': '这台设备在查询日志中的一天：它访问的每个域名一条泳道，下方是应答耗时，上方是发生的事件。',
  'clients.device.rhythmIntro':
    '这台设备对它访问最多的每个域名问得有多规律：每一列是两次查询之间的间隔（对数刻度），越暗表示落在这里的次数越多。一格深色代表定时器；一片模糊代表人。',
  'clients.device.anomalyOffLead': '异常引擎已关闭（',
  'clients.device.anomalyOffTail': '），因此没有东西在测量节律。',
  'clients.device.notAnswering': '未应答：{names}。',
};
