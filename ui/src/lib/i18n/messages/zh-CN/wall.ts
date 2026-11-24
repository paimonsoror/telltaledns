// REQ: API-011 — wall 页面的中文翻译。键名与 en/wall.ts 一一对应。
import type { MessageKey } from '../en';

export const wall: Partial<Record<MessageKey, string>> = {
  // 右上角：轮换已暂停的提示（时钟保持原样）。
  'wall.paused': '已暂停',

  // 面板下方的圆点；读屏软件听到的也只有这个词。
  'wall.panels': '面板',

  // 底部滚动条：第一条实时查询到达之前显示的话。
  'wall.waiting': '正在等待查询…',
  'wall.panel.map': '网络正在访问什么',
  'wall.panel.flow': '查询去了哪里',
  'wall.panel.latency': '应答时间',
  'wall.panel.heat': '这一周',
  'wall.panel.kpi': '此刻',
  'wall.flow.aria': '最近一小时的查询去向',
  'wall.slo.whoSpent': '谁花掉了',
  'wall.slo.off': '服务等级目标已关闭。',
  'wall.slo.noData': '没有数据',
  'wall.slo.budgetLeft': '预算剩余 {pct} %',
  'wall.kpi.qps': '查询 / 秒',
  'wall.kpi.blocked': '已拦截',
  'wall.kpi.fromCache': '来自缓存',
  'wall.kpi.health': '健康状况',
  'wall.slo.answersWork': '可用的应答',
};
