// REQ: API-011 — localdns 页面的中文翻译。键名与 en/localdns.ts 一一对应。
// 句子里嵌着标记的地方按标记拆开：`…Start` 写到标记之前，`…End` 接着标记之后写，
// 这样 `<code>`、`<b>`、`<em>` 都留在原处。
import type { MessageKey } from '../en';

export const localdns: Partial<Record<MessageKey, string>> = {
  // 标题和它的副标题（DNS 术语），以及打开表单的按钮：按钮上的字同时也是抽屉的标题。
  'localdns.subtitle': '本地 DNS',
  'localdns.setUpHomeDomain': '设置我的家庭域名',
  'localdns.addName': '添加名称',
  'localdns.editName': '编辑 {name}',
  'localdns.sendDomain': '把一个域名送到另一台服务器',

  // 还什么都没定义，中间夹着一个示例名称。
  'localdns.emptyStart': '还没有本地名称。“设置我的家庭域名”会给你的 NAS、打印机或服务器起一个名字，比如 ',
  'localdns.emptyEnd': '，任何设备都能用它。',

  // 名称表格：列名、名称来自哪里，以及每一行能做什么。
  'localdns.col.answers': '应答内容',
  'localdns.col.ttl': 'TTL',
  'localdns.ttlDefault': '默认',
  'localdns.source.ui': '界面 / API',
  'localdns.test': '试一下',
  'localdns.removeName': '删除 {name}',

  // 配置文件里声明的区域：它们是什么，以及谁能看到。
  'localdns.zones.title': '区域',
  'localdns.zones.introStart': 'TelltaleDNS 自己应答这些域名下的所有查询，内容来自配置文件（',
  'localdns.zones.introEnd': '）：它没有的名称会得到“无此名称”。限定到分组的区域只有这些分组中的设备能看到。',
  'localdns.zones.col.zone': '区域',
  'localdns.zones.col.records': '记录',
  'localdns.zones.col.seenBy': '可见范围',

  // 送到别处的域名：表格、没有时的说明，以及 stub 区域的标记。
  'localdns.forwards.title': '送到其他服务器的域名',
  'localdns.forwards.empty': '没有：不在本页面上的名称都会向公共 DNS 服务器查询。',
  'localdns.forwards.stub': '(stub 区域)',
  'localdns.forwards.remove': '停止发送 {domain}',

  // 这次变更会做什么，用一句话说清（预览里用的是本页面自己的文字）。
  'localdns.preview.a': '{value} 这个地址',
  'localdns.preview.aaaa': 'IPv6 地址 {value}',
  'localdns.preview.cname': '{value} 的同一个应答',
  'localdns.preview.ptr': '{value} 这个名称（一次反向查询）',
  'localdns.preview.txt': '“{value}” 这段文本',
  'localdns.preview.mx': '{value} 这台邮件服务器',
  'localdns.preview.srv': '{value} 这项服务',
  'localdns.preview.sentence': '每台查询 {name} 的设备都会得到 {what}，由 TelltaleDNS 自己应答。',
  'localdns.preview.sentenceReverse':
    '每台查询 {name} 的设备都会得到 {what}，由 TelltaleDNS 自己应答，并且对该地址做反向查询能找到这个名称。',
  'localdns.preview.anyDevice': '任意设备',

  // “添加名称”表单（也用于向导的第二步）。
  'localdns.form.value': '值',
  'localdns.form.typeA': 'A（IPv4 地址）',
  'localdns.form.typeAAAA': 'AAAA（IPv6 地址）',
  'localdns.form.typeCNAME': 'CNAME（另一个名称的别名）',
  'localdns.form.alsoKeeps': '同时保留：{records}。',
  'localdns.form.back': '上一步',
  'localdns.form.saving': '正在保存…',
  'localdns.form.needName': '请填写名称，例如 nas.home.arpa。',
  'localdns.form.saved': '已保存。{name} 现在在任何设备上都能解析。',

  // 家庭域名向导的第一步：为什么用 home.arpa。
  'localdns.wizard.introStart': '选择设备名称末尾使用的域名。',
  'localdns.wizard.introEnd': ' 就是专门为此保留的（RFC 8375），所以绝不会和互联网冲突；如果你有自己的域名，也可以用它。',
  'localdns.wizard.homeDomain': '家庭域名',
  'localdns.wizard.next': '下一步',
  'localdns.wizard.firstDevice': '现在添加第一台设备。以后可以用“添加名称”继续添加。',
  'localdns.wizard.deviceName': '设备名',
  'localdns.wizard.fullNameStart': '它的完整名称是 ',

  // “把一个域名送到另一台服务器”抽屉：送到哪里，以及 stub 区域的选择。
  'localdns.forward.intro': '用于只有另一台 DNS 服务器才知道的名称：VPN 后面的公司网络、路由器自带的名字、另一个实验室。',
  'localdns.forward.domain': '域名',
  'localdns.forward.servers': '服务器地址',
  'localdns.forward.serversHintStart': '多台服务器：用空格分隔（按顺序尝试）。加密：',
  'localdns.forward.stubLabel': '这些服务器只知道这个域名，并把部分子域名交给其他服务器',
  'localdns.forward.stubBefore': '所谓 ',
  'localdns.forward.stubTerm': 'stub 区域',
  'localdns.forward.stubAfter':
    '：服务器会被直接（按 IP 地址）询问，并且会跟随它们对其他服务器的转交，就像 BIND 的 stub 区域那样。当这些服务器拒绝其他查询时用它。',
  'localdns.forward.sentence': '{domain} 下的所有名称都向 {servers} 查询，而不走公共 DNS 服务器；你的本地名称仍然优先应答。',
  'localdns.forward.sentenceStub':
    '{domain} 下的所有名称都从 {servers} 开始查询，并跟随它们对其他服务器的转交，而不走公共 DNS 服务器；你的本地名称仍然优先应答。',
  'localdns.forward.saved': '已保存。{domain} 下的名称现在交给 {servers}。',
};
