// REQ: API-011 — slo 的中文翻译。键名与 en/slo.ts 一一对应。
// 窗口天数后面不再接名词的地方，`.one`/`.other` 两条键保留同一句话：`tn()` 是为计数准备的，
// 不是用来改写句子的。
import type { MessageKey } from '../en';

export const slo: Partial<Record<MessageKey, string>> = {
  // 卡片：标题、窗口有多长，以及还没有数据时说的话。
  'slo.title': '服务等级',
  'slo.window.one': '（最近 {n} 天）',
  'slo.window.other': '（最近 {n} 天）',
  'slo.loading': '正在加载…',
  'slo.off': '目标已关闭（',
  'slo.offEnd': '）。',
  'slo.missing': '缺少 {nodes}：它们没有应答。',

  // 各个目标、正常目标的徽标，以及它的数字从哪来。
  'slo.onTrack': '正常',
  'slo.target': '{means} · 目标 {target}%',
  'slo.ofAnswers': '占 {answers} 个应答',

  // 预算消耗过快的说法，以及每个词悬停时的解释。
  'slo.alert.fast': '消耗极快',
  'slo.alert.fastTip':
    '最近一小时（以及最近 5 分钟）预算的消耗速度超过其可持续速度的 14 倍：照这个速度，一个月的预算大约两天就会用完。',
  'slo.alert.slow': '消耗过快',
  'slo.alert.slowTip': '最近 6 小时（以及最近 30 分钟）预算的消耗速度超过其可持续速度的 6 倍。',
  'slo.alert.ticket': '按此趋势将耗尽',
  'slo.alert.ticketTip': '最近 3 天预算的消耗速度一直快于可持续速度：本周值得看一下。',

  // 剩余的错误预算，以及旁边的消耗速率。
  'slo.budgetTitle': '错误预算余量：窗口内目标仍然允许的错误应答数',
  'slo.budget.none': '还没有应答',
  'slo.budget.overspent': '预算已超支',
  'slo.budget.left': '错误预算剩余 {pct}%',
  'slo.burnRate': '消耗速率',
  'slo.burn.none': '最近 {window} 没有可判断的应答。',
  'slo.burn.some': '最近 {window}：{total} 个应答中有 {bad} 个错误。1× 表示正好在窗口内用掉全部预算。',

  // 谁用掉的。
  'slo.who': '谁用掉的？',
};
