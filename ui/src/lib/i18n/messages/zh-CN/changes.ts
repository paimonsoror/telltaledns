// REQ: API-011 — changes 页面的中文翻译。键名与 en/changes.ts 一一对应。
// 代码片段嵌在句子里的地方被拆成 `…intro` 与 `…introMid`：前者写到 `<code>` 之前，后者接着它之后写；
// 最后一段带尾随空格，因为后面紧跟着一个数量。
import type { MessageKey } from '../en';

export const changes: Partial<Record<MessageKey, string>> = {
  // 标题，以及这个页面是做什么的。
  'changes.title': '代理变更',
  'changes.intro':
    '通过 MCP 连接的 AI 代理不会直接改动任何东西：它们先制定计划，这里会显示计划以及它将会做什么。设置',
  'changes.introMid': '后，计划需要等操作员批准，代理才能应用它。',
  'changes.expires.one': '计划在 {n} 分钟后过期。',
  'changes.expires.other': '计划在 {n} 分钟后过期。',

  // 计划的状态：摘要旁边徽标上的文字（发给接口的仍然是标识符本身）。
  'changes.state.pending': '等待批准',
  'changes.state.ready': '可以应用',
  'changes.state.approved': '已批准',
  'changes.state.rejected': '已拒绝',
  'changes.state.applying': '正在应用',
  'changes.state.applied': '已应用',
  'changes.state.stale': '已失效：配置已更改',
  'changes.state.failed': '失败',
  'changes.state.discarded': '已放弃',

  // 单个计划：它的说明、它会做什么、试运行结果，以及变更前后。
  'changes.plan.why': '原因',
  'changes.plan.askedBy': '请求者',
  'changes.plan.when': '时间',
  'changes.plan.expires': '· {time}后过期',
  'changes.plan.decidedBy': '决定者',
  'changes.plan.change': '变更',
  'changes.plan.impact': '它将会做什么：',
  'changes.plan.beforeAfter': '变更前后',
  'changes.plan.before': '变更前',
  'changes.plan.after': '变更后',
  'changes.plan.approve': '批准',
  'changes.plan.reject': '拒绝',

  // 两个列表：等待操作员处理的，以及已经处理完的。
  'changes.waiting.title': '等待批准',
  'changes.waiting.empty': '没有等待批准的计划。',
  'changes.recent': '最近的计划',
};
