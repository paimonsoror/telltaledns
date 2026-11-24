// REQ: API-011 — help 界面的中文文案：每个“？”面板自己的标签，以及面板里流程图的用词。
// 术语条目本身的中文在 docs/help/topics.zh-CN.json。键名与 en/help.ts 一一对应。
import type { MessageKey } from '../en';

export const help: Partial<Record<MessageKey, string>> = {
  // 按钮和面板的标题，按面板显示的顺序。
  'help.button.aria': '帮助：{title}',
  'help.panel.when': '什么时候会用到',
  'help.panel.example': '例子',
  'help.panel.caution': '注意',
  'help.panel.termBefore': '这个在 DNS 里的术语叫',
  'help.panel.termAfter': '。',
  'help.panel.docs': '完整文档',

  // 流程图：先是方框里的字，再是图下面那句话。
  'help.flow.aDevice': '某台设备',
  'help.flow.aName': '某个名字',
  'help.flow.asks': '查询一个名字',
  'help.flow.decides': '做判定',
  'help.flow.refused': '拒绝',
  'help.flow.fromMemory': '来自记忆',
  'help.flow.cacheSub': '缓存',
  'help.flow.local': '你自己的名字',
  'help.flow.localSub': '本地记录',
  'help.flow.blocked': '已拦截',
  'help.flow.blockedSub': '拦截列表',
  'help.flow.route': '另一台服务器',
  'help.flow.routeSub': '路由',
  'help.flow.upstream': '公共 DNS',
  'help.flow.upstreamSub': '上游服务器',
  'help.flow.sentence': '{device}查询 {name}；TelltaleDNS {outcome}{detail}。',
  'help.flow.answer.cache': '从记忆里回答，因为它最近刚被问过',
  'help.flow.answer.local': '用你自己一个名字来回答',
  'help.flow.answer.blocked': '把它拦掉，所以它永远加载不了',
  'help.flow.answer.route': '去问你为那个域名指定的服务器',
  'help.flow.answer.upstream': '去问一台公共 DNS 服务器，并记住这个应答',
  'help.flow.answer.refused': '拒绝，因为这台设备可能不允许使用这台服务器',
};
