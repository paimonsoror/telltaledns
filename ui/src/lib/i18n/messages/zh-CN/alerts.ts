// REQ: API-011 — alerts 界面的中文文案。键名与 en/alerts.ts 一一对应：告警页本身、“当前”卡片、
// 节点的维护提示、各通知目标最近一次投递，以及两个编辑器（通知目标，含“发送测试”，和规则）。
//
// 名字嵌在句子中间的地方（标记里用 `<strong>` 包住）被拆成 `…lead` 与 `…rest`：前者写到名字
// 之前，后者接着名字之后写。
import type { MessageKey } from '../en';

export const alerts: Partial<Record<MessageKey, string>> = {
  // 页面本身，以及“当前”卡片。
  'alerts.now.title': '当前',
  'alerts.now.elsewhere': '规则由集群的主节点检查（独立运行的节点由自己检查），这里没有需要检查的内容。',
  'alerts.now.empty': '没有正在触发的告警。',
  'alerts.now.about': '对象',

  // 维护中的节点会暂停自己的告警。
  'alerts.maintenance.lead': '维护期间',
  'alerts.maintenance.rest': '的告警暂停，直到 {when}（{reason}）。',

  // 各目标最近一次投递的情况。
  'alerts.deliveries.title': '各通知目标最近一次投递',
  'alerts.deliveries.delivered': '已投递',

  // 通知目标：编辑器的标题与名词、各个字段，以及“发送测试”。
  'alerts.dest.title': '通知目标',
  'alerts.dest.noun': '通知目标',
  'alerts.dest.typeHelp':
    'email（任意服务商的 SMTP）、ntfy 或 Gotify（手机推送）、slack（Slack、Mattermost、Discord），或者一个 JSON webhook。',
  'alerts.dest.addressPlaceholder': 'smtp://smtp.gmail.com:587 或 https://ntfy.sh/my-topic',
  'alerts.dest.addressHelp': '邮件：smtp://host:587（STARTTLS）或 smtps://host:465。其他类型：https:// 地址。',
  'alerts.dest.from': '发件人（邮件）',
  'alerts.dest.to': '收件人（邮件，每行一个）',
  'alerts.dest.account': '账号（邮件）',
  'alerts.dest.passwordFile': '密码文件（邮件）',
  'alerts.dest.passwordFileHelp':
    '节点上保存密码的文件（例如 Gmail 应用专用密码）。密码本身不会经过界面。由管理员设置。请使用 /run/secrets、/etc/telltale-secrets 或数据目录下 secrets 文件夹中的文件。',
  'alerts.dest.tokenFile': '令牌文件（ntfy、Gotify）',
  'alerts.dest.tokenFileHelp':
    '节点上保存访问令牌的文件。由管理员设置。请使用 /run/secrets、/etc/telltale-secrets 或数据目录下 secrets 文件夹中的文件。',
  'alerts.dest.tlsCa': '私有 CA（邮件）',
  'alerts.dest.sendTest': '发送测试',
  'alerts.dest.sent': '已发送。请确认已收到。',
  'alerts.dest.notDelivered': '未送达',

  // 规则：编辑器的标题与名词，以及各个字段。
  'alerts.rule.title': '规则',
  'alerts.rule.noun': '规则',
  'alerts.rule.when': '条件',
  'alerts.rule.sendTo': '发送到',
  'alerts.rule.forSecs': '至少持续（秒）',
  'alerts.rule.forSecsHelp': '条件需要持续多久才会发出告警，这样短暂的抖动就不会打扰。',
  'alerts.rule.threshold': '阈值（%）',
  'alerts.rule.thresholdPlaceholder': '5（servfail_rate）或 90（disk_full）',
  'alerts.rule.on': '开启',
  'alerts.rule.summaryOff': '（已关闭）',
};
