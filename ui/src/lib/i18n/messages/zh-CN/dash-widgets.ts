// REQ: API-011 — dash-widgets 界面的中文文案。键名与 en/dash-widgets.ts 一一对应。
import type { MessageKey } from '../en';

export const dashWidgets: Partial<Record<MessageKey, string>> = {
  // 延迟热力图自身的控件。
  'dashw.window': '时间窗口',
  'dashw.paths': '路径',
  'dashw.path.cache': '缓存',
  'dashw.path.upstream': '上游服务器',
  'dashw.path.local': '本地名称',
  'dashw.path.synthesized': '已拦截与特殊',
  'dashw.showGrid': '网格',
  'dashw.empty': '此时间窗口内还没有应答。',
  'dashw.time': '时间',
  // 格子上的提示，以及样例点。
  'dashw.tipMore': '更多',
  'dashw.tipAnswers.one': '{time} · {range} · {answers} 个应答',
  'dashw.tipAnswers.other': '{time} · {range} · {answers} 个应答',
  'dashw.dot.via': ' 经 {upstream}',
  'dashw.dot.label': '{latency} {path}{via}，{time}：打开这次查询',
  // 颜色、那条线和那些圆点分别是什么意思。
  'dashw.legend.darker': '颜色越深 = 该时间段与该延迟区间内的应答越多。',
  'dashw.legend.threshold': '延迟目标（{ms} ms）。',
  'dashw.legend.dots': '圆点是真实查询：选中一个即可打开它。',
  'dashw.legend.partial': '部分 {step} 数据来自较早的版本，没有延迟区间。',
  'dashw.legend.missing': '不含 {nodes}。',
  // 熔断器徽标：状态用日常说法，提示里给出熔断器模式自己的说法。
  'dashw.breaker.open': '已停用',
  'dashw.breaker.halfOpen': '探测中',
  'dashw.breaker.title': '熔断器：{state}',
  'dashw.rowOver': '> 5 秒',
};
