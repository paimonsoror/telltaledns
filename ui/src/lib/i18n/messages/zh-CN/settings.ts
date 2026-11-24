// REQ: API-011 — settings 界面的中文文案。键名与 en/settings.ts 一一对应。
// 句子里夹着元素（`<code>` 或链接）的地方被拆成 `…Lead`/`…Mid` 与 `…Tail`：前者写到元素之前，
// 后者接着元素之后写，这样标记里的元素得以保留，中文读起来仍是一句话。
import type { MessageKey } from '../en';

export const settings: Partial<Record<MessageKey, string>> = {
  'settings.tab.account': '账户',
  'settings.tab.tokens': 'API 令牌',
  'settings.tab.users': '用户',
  'settings.tab.audit': '审计日志',
  'settings.tab.queries': '查询处理',

  // 表格里显示的开关的两种状态。
  'settings.value.on': '开启',

  // 我的账户：密码与两步验证。
  'settings.account.changePassword': '修改密码',
  'settings.account.currentPassword': '当前密码',
  'settings.account.newPassword': '新密码（至少 10 个字符）',
  'settings.account.passwordChanged': '密码已修改，你的其他会话已被登出。',
  'settings.twoFactor.title': '两步验证登录',
  'settings.twoFactor.saveCodes': '请立即保存这些恢复码。',
  'settings.twoFactor.saveCodesNote': '手机丢失时每个恢复码可用一次；它们不会再次显示。',
  'settings.twoFactor.codesLeft': '还剩 {n} 个恢复码。',
  'settings.twoFactor.offPassword': '密码，用于关闭此功能',
  'settings.twoFactor.turnOff': '关闭两步验证',
  'settings.twoFactor.stepOneLead': '把这个账户添加到验证器应用：在手机上，',
  'settings.twoFactor.stepOneLink': '在应用中打开',
  'settings.twoFactor.stepOneTail': '，或者手动输入密钥：',
  'settings.twoFactor.stepTwo': '输入它显示的 6 位验证码。',
  'settings.twoFactor.codeLabel': '6 位验证码',
  'settings.twoFactor.turnOn': '开启',
  'settings.twoFactor.about': '登录时在密码之外，再要求验证器应用提供的验证码。',
  'settings.twoFactor.setup': '设置两步验证登录',

  // 域名图标：这个浏览器如何绘制名称左侧的小标记。
  'settings.icons.title': '域名图标',
  'settings.icons.about':
    '仪表盘的列表和查询日志中域名左侧的小标记。它根据 TelltaleDNS 已经掌握的信息绘制，因此关于你查询的任何内容都不会发送出去。只在这个浏览器中为你记住。',
  'settings.icons.style': '样式',
  'settings.icons.brand': '品牌和字母标',
  'settings.icons.mono': '仅字母标',
  'settings.icons.off': '关闭',
  'settings.icons.size': '尺寸',
  'settings.icons.default': '默认',
  'settings.icons.small': '小',

  // API 令牌：表单、代理权限、新建的令牌，以及表格。
  'settings.tokens.aboutLead': '供脚本、仪表盘和 AI 代理使用：发送',
  'settings.tokens.aboutTail': '。令牌的权限永远不会超过你自己。',
  'settings.tokens.nameLabel': '令牌名称',
  'settings.tokens.namePlaceholder': '名称，例如 grafana',
  'settings.tokens.kindUser': '给我的脚本用',
  'settings.tokens.kindAgent': '给 AI 代理用',
  'settings.tokens.scopeRead': '只读（只读用户）',
  'settings.tokens.scopeWrite': '读写（操作员）',
  'settings.tokens.expiresLabel': '有效期',
  'settings.tokens.expiresNever': '永不过期',
  'settings.tokens.expires30': '30 天',
  'settings.tokens.expires90': '90 天',
  'settings.tokens.expiresYear': '1 年',
  'settings.tokens.create': '创建令牌',
  'settings.tokens.agentLegend': '代理可以做什么',
  'settings.tokens.groupOnly': '仅限该分组的设备和查询（可选）：',
  'settings.tokens.groupPlaceholder': '例如 kids',
  'settings.tokens.agentNoteLead': '代理每次变更都必须给出理由，每分钟最多 120 个请求，在审计日志中显示为',
  'settings.tokens.agentNoteMid': '，只要设置',
  'settings.tokens.agentNoteTail': '就会立即停止。',
  'settings.tokens.copyNow': '请立即复制令牌；它不会再次显示。',
  'settings.tokens.empty': '还没有令牌。',
  'settings.tokens.colScope': '权限',
  'settings.tokens.colCreated': '创建时间',
  'settings.tokens.colExpires': '过期时间',
  'settings.tokens.groupSuffix': ' · 分组 {group}',
  // REQ: AGT-004 — 代理令牌可以做什么（发给接口的标识符本身不变）。
  'settings.tokens.scope.analytics': '统计、排行榜、异常、解释',
  'settings.tokens.scope.querylog': '查询日志（谁查询了什么）',
  'settings.tokens.scope.configRead': '列表、分组、设备、名称、上游',
  'settings.tokens.scope.clients': '给设备命名并重新分组',
  'settings.tokens.scope.records': '修改我网络中的名称',
  'settings.tokens.scope.forwards': '把域名发送到其他服务器',
  'settings.tokens.scope.clusterAdmin': '提升节点；灰度发布与固定版本',
  'settings.tokens.scope.upgrade': '在节点上安装更新的 TelltaleDNS 版本',

  // 用户（管理员的）：密码可以在哪里使用、表格，以及表单。
  'settings.users.passwordSignIn': '密码登录',
  'settings.users.limitedTo': '密码登录仅限以下网络中的管理员：',
  'settings.users.wholeNetworks': '包含整个网段',
  'settings.users.wholeNetworksLead':
    '这些网段里的任何人仍然会看到登录表单，而不只是你指定的机器。如果要只限你管理用的机器，请把每一台都写成单个地址，例如',
  'settings.users.onlyListed': '只有列出的机器才会看到登录表单。',
  'settings.users.loopbackLead': '如果本机上有反向代理在提供这个页面，请把',
  'settings.users.loopbackMid': '加入',
  'settings.users.loopbackTail':
    '之下）。在此之前，它转发的一切都看起来来自这台机器，因此可以使用密码。',
  'settings.users.noNetworks':
    '没有任何网络允许用密码登录（管理员也不例外），所以如果你的登录提供方宕机了，没有人能用密码登录。',
  'settings.users.changeLead': '要修改它，请改配置文件中的',
  'settings.users.changeMid': '（位于',
  'settings.users.changeMid2': '之下），然后重启。参见指南中的',
  'settings.users.changeLink': '用户与登录',
  'settings.users.changeTail': '。',
  'settings.users.colUser': '用户',
  'settings.users.colRole': '角色',
  'settings.users.colTwoFactor': '两步验证',
  'settings.users.colBasic': 'HTTP Basic',
  'settings.users.you': '（你）',
  'settings.users.signsInWith': '通过 {provider} 登录',
  'settings.users.roleOf': '{name} 的角色',
  'settings.users.reset': '重置',
  'settings.users.basicFor': '{name} 的 HTTP Basic',
  'settings.users.disabledEnable': '已禁用 · 启用',
  'settings.users.activeDisable': '启用中 · 禁用',
  'settings.users.tokens': '令牌',
  'settings.users.reallyDelete': '确实删除？',
  'settings.users.delete': '删除',
  'settings.users.noTokens': '{name} 没有 API 令牌。',
  'settings.users.tokenOf': '{name} 的令牌',
  'settings.users.addTitle': '添加用户',
  'settings.users.usernamePlaceholder': '用户名',
  'settings.users.passwordPlaceholder': '密码（10 个字符以上）',
  'settings.users.add': '添加',
  'settings.users.rolesNote':
    '只读用户可以查看仪表盘和查询日志；操作员还可以暂停拦截，并管理列表、客户端和分组；管理员可以做任何事。',

  // 审计日志（REQ: API-006）：筛选、链校验和表格。
  'settings.audit.allChanges': '所有变更',
  'settings.audit.signIns': '登录与锁定',
  'settings.audit.verify': '校验链',
  'settings.audit.about':
    '对用户、密码、两步验证和 API 令牌的每一次变更，以及登录、锁定和配置重新加载。记录不能被编辑，每条都与前一条串联在一起，因此篡改可以被发现。',
  'settings.audit.intact': '链完好：共 {n} 条记录。头部',
  'settings.audit.broken': '链在第 {n} 条记录处断裂',
  'settings.audit.brokenTail': '：日志在 TelltaleDNS 之外被改动过。',
  'settings.audit.empty': '没有记录。',
  'settings.audit.colWho': '操作者',
  'settings.audit.colWhat': '操作',
  'settings.audit.reason': '原因：{reason}',

  // REQ: CLU-013 — 灰度发布（管理员的）：节点挑选、观察期与守卫。
  'settings.cluster.standalone': '这个节点独立运行：灰度发布需要集群（见集群页面）。',
  'settings.cluster.rollout.noun': '灰度发布设置',
  'settings.cluster.rollout.summaryOff': '关闭：变更同时到达每个节点',
  'settings.cluster.rollout.summary.one': '{n} 项金丝雀；观察期 {bake} 秒',
  'settings.cluster.rollout.summary.other': '{n} 项金丝雀；观察期 {bake} 秒',
  'settings.cluster.rollout.footnote':
    '对这些设置的变更会同时到达每个节点（它本身从不灰度）。集群页面显示正在观察期的版本、守卫的读数和你可以退回固定的版本。',
  'settings.cluster.rollout.canaries': '金丝雀节点',
  'settings.cluster.rollout.canariesHelp':
    '它们（以及主节点）最先收到每个变更。一个都不选：变更同时到达每个节点。',
  'settings.cluster.rollout.ephemeral': '解析器 Pod（Kubernetes）',
  'settings.cluster.rollout.site': '{site} 站点的所有节点',
  'settings.cluster.rollout.bakeTime': '观察期（秒）',
  'settings.cluster.rollout.bakeTimeHelp': '变更在金丝雀上运行多久后所有人都收到。至少 5。',
  'settings.cluster.rollout.servfail': 'SERVFAIL 比例超过此值即判失败（%）',
  'settings.cluster.rollout.servfailHelp':
    '或者比变更前金丝雀的比例高 2 个百分点，取两者中较高的；根据 50 个应答来判定。',
  'settings.cluster.rollout.requireTraffic': '判定前先等到 50 个应答',
  'settings.cluster.rollout.requireTrafficHelp':
    '关闭：安静的观察期也算通过。开启：一直观察到金丝雀回答了 50 个查询（或达到最长观察期），然后再判定。',
  'settings.cluster.rollout.maxBake': '最长观察期（秒）',
  'settings.cluster.rollout.failOnDisconnect': '金丝雀断连一分钟即判失败',
  'settings.cluster.rollout.failOnDisconnectHelp':
    '它可能因这次变更崩溃了。观察期内被重新调度的 Pod 也会让发布失败；取消固定后再试。',
  'settings.cluster.rollout.history': '保留用于固定的版本数',
  'settings.cluster.rollout.noteNone': '没有金丝雀：变更同时到达每个节点。',
  'settings.cluster.rollout.noteBody':
    '变更先到达 {names}（以及主节点），如果没有失败，其余节点在 {time} 后收到。',
  'settings.cluster.rollout.minutes.one': '{n} 分钟',
  'settings.cluster.rollout.minutes.other': '{n} 分钟',

  // 节点的系统信息（REQ: OBS-002）。
  'settings.system.started': '启动时间',
  'settings.system.startedValue': '{time} · 已运行 {uptime}',
  'settings.system.restarts': '重启次数',
  'settings.system.unclean': '（其中 {n} 次在崩溃或被终止之后）',
  'settings.system.listeners': 'DNS 监听',
  'settings.system.snapshot': '过滤快照',
  'settings.system.names': ' · {names} 个名称',
  'settings.system.apiRef': 'API 参考：',
  'settings.system.apiRefNote': '（OpenAPI 3.1）。',

  // REQ: OBS-020 — 监听检查，以及证书的情况（REQ: API-003, ADR-149）。
  'settings.probes.title': '监听检查',
  'settings.probes.emptyLead': '还没有结果（第一轮在启动几秒后运行），或者探针已关闭（',
  'settings.probes.colAsked': '询问对象',
  'settings.probes.colResult': '结果',
  'settings.probes.colTime': '耗时',
  'settings.probes.webUi': 'Web UI 与 API',
  'settings.probes.extraTarget': '（额外目标）',
  'settings.probes.skipped': '已跳过',
  'settings.probes.answers': '有应答',
  'settings.probes.notAnswering': '无应答',
  'settings.probes.missedOnce': '失败一次',
  'settings.probes.forNames': '用于 {names}',
  'settings.probes.certSelfSigned': '自签名证书（不会过期）',
  'settings.probes.certExpired': '证书已在 {n} 天前过期',
  'settings.probes.certExpires': '证书将在 {n} 天后过期',
  'settings.probes.footnoteLead':
    '每 30 秒，每个节点都会用监听器自己的协议向它的每个监听器问一个问题，就像一台设备那样。Web UI 开启 HTTPS（',
  'settings.probes.footnoteTail':
    '）时也会检查：信任自签名证书之前，请把它的 SHA-256 指纹和浏览器显示的那个对比一下。',

  // REQ: OBS-033 — 最近 90 天的变更标记（所有节点的）。
  'settings.changes.title': '变更',
  'settings.changes.kindLabel': '变更类型',
  'settings.changes.kindAll': '所有类型',
  'settings.changes.kindConfig': '配置已应用',
  'settings.changes.kindNotes': '备注',
  'settings.changes.kindLists': '列表刷新',
  'settings.changes.kindRollouts': '灰度发布',
  'settings.changes.kindBuilds': '构建与重启',
  'settings.changes.kindMaintenance': '维护模式',
  'settings.changes.kindPauses': '暂停',
  'settings.changes.kindCache': '缓存清空',
  'settings.changes.kindUpstreams': '上游被停用或恢复',
  'settings.changes.filterPlaceholder': '筛选',
  'settings.changes.filterLabel': '筛选变更',
  'settings.changes.empty': '过去 90 天没有记录到变更',
  'settings.changes.emptyMatch': '（符合筛选条件）',
  'settings.changes.emptyTail': '。',
  'settings.changes.missing': '无应答：{nodes}。',
  'settings.changes.footnote':
    '来自每个节点的最近 200 条配置版本、构建、重启、列表刷新、灰度发布、维护、暂停、缓存清空、上游停用或恢复以及备注。每个节点保留 90 天。',

  // REQ: OPS-004 — 当前构建，以及用来比较的已发布版本。
  'settings.updates.title': '版本与更新',
  'settings.updates.thisBuild': '当前构建',
  'settings.updates.built': '构建时间',
  'settings.updates.commit': ' · 提交',
  'settings.updates.channel': ' · {channel} 通道',
  'settings.updates.builtValue': '{date} · {target} · {install} 安装',
  'settings.updates.available': '有可用更新',
  'settings.updates.date': '（{date}）',
  'settings.updates.whatsNew': '更新内容',
  'settings.updates.upToDate': '已是最新',
  'settings.updates.newer': '比已发布的 {channel} 构建更新',
  'settings.updates.newerVersion': '（{version}）',
  'settings.updates.notCheckedLead': '未检查（',
  'settings.updates.unknown': '尚不清楚',
  'settings.updates.unknownError': '：{error}',
  'settings.updates.checkNow': '立即检查',

  // REQ: API-007 — 一个文件容纳一切，以及它包含什么。
  'settings.backup.title': '备份',
  'settings.backup.aboutLead':
    '一个文件，包含你的设置、用户和 API 令牌、你在这里添加的设备和名称、审计日志以及统计历史。在新机器上用',
  'settings.backup.aboutTail': '来恢复。',
  'settings.backup.download': '下载备份',
  'settings.backup.privateLead':
    '它含有密码哈希，请妥善保管。查询日志不在其中；要包含它，请在服务器上运行',
  'settings.backup.privateTail': '。',

  // REQ: DNS-006 — 缓存有自己的页面。
  'settings.queries.cacheAboutLead': '命中率、已缓存的内容、设置、查询和清空操作都在',
  'settings.queries.cacheAboutLink': '缓存页面',
  'settings.queries.cacheAboutTail': '上。',

  // REQ: DNS-014 — 每个客户端的速率限制。
  'settings.queries.ratelimit.title': '速率限制',
  'settings.queries.ratelimit.noun': '速率限制',
  'settings.queries.ratelimit.summary':
    '每个客户端每 {window} 秒 {queries} 个查询，超出后 {action}',
  'settings.queries.ratelimit.footnote':
    '一个客户端就是一个地址（IPv6：一个 /64）。为整个网络转发的路由器或代理看起来像一个客户端：把它加入“永不受限”，或者把数字调大。变更立即生效，每个客户端的计数从头开始。',
  'settings.queries.ratelimit.enabled': '限制每个客户端的查询数',
  'settings.queries.ratelimit.queries': '每个窗口允许的查询数',
  'settings.queries.ratelimit.queriesHelp':
    '按客户端计算；不超过它的短时突发没有问题。超过的客户端会得到下面指定的动作，直到额度重新填满。',
  'settings.queries.ratelimit.window': '窗口（秒）',
  'settings.queries.ratelimit.action': '超过限制时',
  'settings.queries.ratelimit.actionHelp': 'refused 回以 REFUSED；drop 不作任何应答。',
  'settings.queries.ratelimit.exempt': '永不受限',
  'settings.queries.ratelimit.exemptHelp':
    '地址或网段，每行一个（比如为整个网络转发的路由器）。它会替换配置文件里的列表，所以请保留 127.0.0.0/8 和 ::1/128。',
  'settings.queries.ratelimit.ipv4': 'IPv4：每 /N 统计一个客户端',
  'settings.queries.ratelimit.ipv4Help': '32 表示每个地址单独计数。',
  'settings.queries.ratelimit.ipv6': 'IPv6：每 /N 统计一个客户端',
  'settings.queries.ratelimit.ipv6Help': '64 会把一台设备轮换的隐私地址归为一组。',

  // REQ: OBS-022 — 不进入查询日志和统计的名称与设备。
  'settings.queries.exclusions.title': '排除在日志之外',
  'settings.queries.exclusions.noun': '排除项',
  'settings.queries.exclusions.summaryOff': '关闭：',
  'settings.queries.exclusions.summaryNone': '没有排除任何内容',
  'settings.queries.exclusions.summary': '{names} 个名称，{clients} 台设备',
  'settings.queries.exclusions.footnoteLead': '它们的查询仍然会被应答，也仍然计入',
  'settings.queries.exclusions.footnoteTail':
    '，但在每个节点上都不会进入查询日志、实时视图、仪表盘和排行榜、异常以及导出。之前已记录的查询会保留。',
  'settings.queries.exclusions.enabled': '把这些排除在日志和统计之外',
  'settings.queries.exclusions.enabledHelp': '关闭后会保留下面的列表，但所有内容又会重新记入日志。',
  'settings.queries.exclusions.namesHelp':
    '每行一个；每个也会覆盖其子域。适合连通性检查、时间服务器或监控探针这类噪声。',
  'settings.queries.exclusions.clientsHelp': '地址或网段，每行一个（比如一台监控主机）。',

  // REQ: OBS-024 — 变更模拟的开关与界限。
  'settings.queries.simulate.title': '变更模拟',
  'settings.queries.simulate.noun': '模拟设置',
  'settings.queries.simulate.summary': '开启，默认 {window}；代理计划{plans}',
  'settings.queries.simulate.always': '总是模拟',
  'settings.queries.simulate.whenAsked': '在要求时模拟',
  'settings.queries.simulate.footnote':
    '模拟会带变更和不带变更各重放一遍查询日志，并显示哪些应答会不一样。它从不影响 DNS 应答，以后台优先级运行；查询日志隐私等级为 1 或更高时无法重放名称。',
  'settings.queries.simulate.enabled': '允许变更模拟',
  'settings.queries.simulate.enabledHelp':
    '“这本来会怎样？”按钮、试运行的 simulate 参数，以及供代理使用的 simulate_change。',
  'settings.queries.simulate.plans': '代理的计划默认模拟',
  'settings.queries.simulate.plansHelp':
    '关闭：只有代理要求时计划才模拟（simulate: "24h"）。开启：每个计划都会重放查询日志，在每个节点上消耗 CPU。',
  'settings.queries.simulate.window': '默认窗口',
  'settings.queries.simulate.windowHelp':
    '没有给出窗口时，模拟会回放多久以前的数据：30m、24h，最多 7d。',
  'settings.queries.simulate.maxSecs': '每个节点的时间上限（秒）',
  'settings.queries.simulate.maxSecsHelp':
    '1 到 300。时间用尽的节点会返回它已读到的内容（部分结果）。',
  'settings.queries.simulate.maxRows': '每个节点读取的最大日志查询数',
  'settings.queries.simulate.maxRowsHelp': '至少 1,000。从最新的开始。',

  // REQ: API-002 (T7.5, ADR-069) — 添加、修改、预览和恢复条目的编辑器。
  'settings.editor.add': '添加{noun}',
  'settings.editor.editTitle': '{noun}：{name}',
  'settings.editor.none': '还没有。',
  'settings.editor.hiddenNote': '未写入配置',
  'settings.editor.revert': '恢复为文件中的设置',
  'settings.editor.done': '完成',
  'settings.editor.testing': '测试中…',
  'settings.editor.sending': '发送中…',
  'settings.editor.what': '这将会做什么：',
  'settings.editor.whatFallback': '按所见修改配置。',
  'settings.editor.changeIt': '修改',
  'settings.editor.check': '检查',
  'settings.editor.badgeAdded': '在此添加',
  'settings.editor.badgeOverride': '覆盖了文件',
  'settings.editor.badgeHidden': '隐藏',

  // REQ: OBS-035 (T14.13, ADR-140) — 大屏显示（管理员的）。
  'settings.wall.title': '大屏显示',
  'settings.wall.about':
    '一个给挂在墙上的屏幕用的链接：在那块屏幕的浏览器里打开一次，它就会保持登录，只显示大屏内容（流量地图、流向、服务等级、热力图和实时查询）。它打不开其他页面，也改不了任何东西。如果可以，请把它限制到那块屏幕的地址；在这里撤销就能让该屏幕登出。',
  'settings.wall.namePlaceholder': '走廊',
  'settings.wall.onlyFrom': '仅限来自',
  'settings.wall.networksPlaceholder': '192.168.2.40, 10.0.0.0/24（可选）',
  'settings.wall.endsAfter': '结束于',
  'settings.wall.daysPlaceholder': '天数（可选）',
  'settings.wall.make': '生成链接',
  'settings.wall.linkNote': '：在那块墙上的浏览器中打开它。它只在现在显示一次。',
  'settings.wall.copyLink': '复制链接',
  'settings.wall.empty': '还没有大屏显示。',
  'settings.wall.colMadeBy': '创建者',
  'settings.wall.colLastUsed': '最近使用',
  'settings.wall.colEnds': '结束时间',
  'settings.wall.anywhere': '任意地址',
  'settings.wall.whenRevoked': '撤销时',
  'settings.wall.revoke': '撤销',

  // REQ: OPS-011 (ADR-156) — 一个可以附在缺陷报告里的打码文件。
  'settings.support.title': '支持包',
  'settings.support.about':
    '一个可以附在缺陷报告里的文件：构建和平台信息、你的设置（不含机密）、集群与健康状态、上游、列表名称和数量、指标快照，以及这个节点最近的日志。不会上传任何内容。',
  'settings.support.howMuch': '隐藏多少',
  'settings.support.strict': '严格（推荐）',
  'settings.support.strictText':
    '地址，设备、分组、节点和 Pod 名称，电子邮件地址和用户主目录路径都会变成化名（device-1、10.4.7.9）。不含查询名称、不含自由文本，日志里只保留警告和错误。',
  'settings.support.standard': '标准',
  'settings.support.standardText':
    '与严格相同，另加日志的 INFO 行、带化名的排行榜，以及（如果你选择的话）一小段最近的查询样本。',
  'settings.support.none': '无',
  'settings.support.noneText':
    '真实的地址、名称和域名。密码、令牌和密钥仍然会被删除。分享之前请自己先看一遍。',
  'settings.support.reveal': '保持这些可读（名称，用逗号分隔）',
  'settings.support.revealPlaceholder': '例如 pi',
  'settings.support.revealLabel': '要保持可读的名称',
  'settings.support.sample': '包含的最近查询数（0 表示不含）',
  'settings.support.sampleLabel': '查询样本',
  'settings.support.cluster':
    '集群中的每个节点（每个节点先隐藏自己的名称和地址，因此不会有真实内容跨网络传输）',
  'settings.support.keepMap': '允许我下载化名对照表（10 分钟内有效，只能一次）',
  'settings.support.preview': '预览它会包含什么',
  'settings.support.working': '处理中…',
  'settings.support.make': '生成支持包',
  'settings.support.saved': '已保存',
  'settings.support.savedSize': '（压缩前 {size}）。',
  'settings.support.savedNote': '附加之前请先看一遍：日志行是按规则打码的，只能尽力而为。',
  'settings.support.downloadMap': '下载化名对照表',
  'settings.support.mapGone': '（已给出；再生成一个支持包才能得到新的）',
  'settings.support.mapLead':
    '它列出了每个化名代表什么，因此包含你真实的名称和地址：请自己保管，只有你愿意时才告诉维护者',
  'settings.support.mapTail': '原来是什么。',
  'settings.support.previewNote': '这是支持包现在会包含的内容；没有保存任何东西。',
  'settings.support.colAnswered': '有应答',
  'settings.support.colFiles': '文件数',
  'settings.support.yes': '是',
  'settings.support.missing': '缺失',
  'settings.support.colFile': '文件',
  'settings.support.colPart': '部分',
  'settings.support.colReplaced': '已替换或删除',
  'settings.support.cut': '已截断',
  'settings.support.removedSecrets': '作为机密被删除的设置：{fields}。',
  'settings.support.report': '请报告',
  'settings.support.unclassified': '这些设置没有匹配的规则，已被删除：{fields}。',
};
