// REQ: API-011 — simulation 的中文翻译。键名与 en/simulation.ts 一一对应。
// 计数后面跟着名词的地方，名词自成一条键（`.one`/`.other`），句子用占位符把它带进去，
// 于是每种语言都能把数字放在自己习惯的位置。服务器给的标识符（原因、提示）在这里是一条键，
// 本文件不认识的标识符仍按原样显示。
import type { MessageKey } from '../en';

export const simulation: Partial<Record<MessageKey, string>> = {
  // “这项改动会有什么影响？”：按钮，以及完全没有结果时说明原因。
  'simulation.preview.button': '这项改动会有什么影响？',
  'simulation.preview.replaying': '正在重放日志中的查询…',
  'simulation.preview.reason.disabled': '此集群已关闭模拟（设置 → 查询处理 → 变更模拟）。',
  'simulation.preview.reason.privacyLevel':
    '本节点的查询日志按隐私级别把名称哈希或隐藏了，因此无法重放这项改动；不过在列表相同的分组之间移动设备仍然可以重放。',
  'simulation.preview.reason.noQueryLog': '本节点已关闭查询日志，没有可重放的内容。',
  'simulation.preview.reason.busy': '本节点上已有另一个模拟在运行，请过几秒钟再试。',
  'simulation.preview.reason.localFile': '这项改动引用了配置文件尚未读取的本地文件，因此只有管理员才能重放。',
  'simulation.preview.reason.downloadLimit':
    '这项改动新增或修改的列表超过了本节点单次模拟能读取的数量（按 URL 或从文件读取最多 4 个，且在其列表大小上限的 4 倍以内）。请一次模拟更少的列表改动。',
  'simulation.preview.notSimulated': '未模拟：{reason}',
  'simulation.preview.notApplicable': '这项改动不会影响查询的应答方式，没有可重放的内容。',

  // 重放了什么：日志里的多少条，以及哪些应答会不同。
  'simulation.preview.over.one': '共 {n} 条日志查询{when}：',
  'simulation.preview.over.other': '共 {n} 条日志查询{when}：',
  'simulation.preview.since': '，自 {time} 起',
  'simulation.preview.noneDifferent': '没有任何查询的应答会改变。',
  'simulation.preview.different': '会有 {n} 条查询的应答改变。',
  'simulation.preview.partialLabel': '部分结果：',
  'simulation.preview.partialNote': '已到达时间或行数上限，更早的查询没有被重放。',

  // 四类差异：各有自己的方块，以及其名称的标题。
  'simulation.preview.newlyBlocked': '新增拦截',
  'simulation.preview.newlyAllowed': '新增放行',
  'simulation.preview.changedRoute': '改走上游',
  'simulation.preview.changedAnswer': '应答改变',
  'simulation.preview.devices.one': '{n} 台设备',
  'simulation.preview.devices.other': '{n} 台设备',

  // 一条名称自己的计数（名称本身来自日志），以及其下方的每台设备标签。
  'simulation.preview.queries.one': '{n} 条查询',
  'simulation.preview.queries.other': '{n} 条查询',
  'simulation.preview.counts': '{queries}，{devices}',
  'simulation.preview.byDevice': '按设备',
  'simulation.preview.chip.blocked': '拦截 {n} 条',
  'simulation.preview.chip.allowed': '放行 {n} 条',
  'simulation.preview.chip.rerouted': '改走上游 {n} 条',
  'simulation.preview.chip.answeredDifferently': '应答改变 {n} 条',

  // 无法重放的部分、近似的部分，以及没有应答的节点。
  'simulation.preview.undetermined.one': '{n} 条查询无法重新判定（日志中的名称已哈希）。',
  'simulation.preview.undetermined.other': '{n} 条查询无法重新判定（日志中的名称已哈希）。',
  'simulation.preview.note.identityFromEvent':
    '有些设备在查询时是通过 MAC 地址或客户端 ID 识别的；它们保留查询被记录时所处的分组。',
  'simulation.preview.note.badfilterCrossSnapshot':
    '被改动的列表带有 $badfilter 规则；在预览中它们不会抵消其他列表的规则。',
  'simulation.preview.note.namesCapped': '改动的名称非常多：计数是完整的，但没有列出每一个名称。',
  'simulation.preview.note.privacyLevel1DevicesOnly':
    '在隐私级别 1，只能检查在分组之间移动的设备：若某台设备的新分组判定不同，它的查询会被计入无法判定的部分。',
  'simulation.preview.missingNodes': '未包含（未应答）：{nodes}。',

  // 保留在 Git 中：标题、复制片段，以及本节点从 Git 构建时还需要补上的内容。
  'simulation.keepInGit.title': '保留在 Git 中',
  'simulation.keepInGit.note':
    '本节点的配置来自 Git。改动已保存在本节点并与集群共享，但在你添加以下内容之前，从 Git 重建不会包含它：',

  // 谁用掉了错误预算：标题、两个目标，以及概况那一行。
  'simulation.budget.title': '谁用掉了错误预算？',
  'simulation.budget.objectiveAria': '目标',
  'simulation.budget.summary': ' 个错误（自 {date} 起共 {answers} 个应答）；目标（{target}%）允许 {allowed} 个：',
  'simulation.budget.summary.overspent': '超支。',
  'simulation.budget.summary.left': '预算剩余 {pct}%。',
  'simulation.budget.partialNodes':
    '在窗口的部分时间里，{nodes} 没有客户端和名称列表（旧版本，或按上线后的分钟数统计的 Pod）；它们的错误应答在其他地方都已计入。',

  // 消耗曲线，以及没有消耗时的说明。
  'simulation.budget.empty': '这个窗口内没有消耗。',
  'simulation.budget.chartLeft': '预算剩余（%）',

  // 各个细分：标题、被隐藏的列表怎么说，以及空列表怎么说。
  'simulation.budget.timelineOnly': '隐私级别只保留了时间线：没有按客户端、名称或其他任何维度的细分。',
  'simulation.budget.hiddenByPrivacy': '已被隐私级别隐藏。',
  'simulation.budget.noClients': '没有记录到客户端。',
  'simulation.budget.namesHidden': '名称（{n} 个，已被隐私级别隐藏）',
  'simulation.budget.noNames': '没有记录到名称。',
  'simulation.budget.rcode': '响应码',
  'simulation.budget.approximate':
    '客户端和名称是近似的排行榜（每个计数最多有各自的 ± 误差）；其他列表是精确的。链接会打开查询日志，它保留的天数比预算窗口更少。',
  'simulation.budget.byNode': '按节点',
};
