// REQ: API-011 — traffic 页面的中文翻译。键名与 en/traffic.ts 一一对应。
//
// 瓦片上的名称和状态来自接口本身（状态是接口的标识符，原样显示）；这里只有页面自己的文字。
import type { MessageKey } from '../en';

export const traffic: Partial<Record<MessageKey, string>> = {
  // 标题、两个分段控件，以及小时菜单。
  'traffic.groupBy': '分组依据',
  'traffic.mode.service': '服务',
  'traffic.mode.site': '站点',
  'traffic.mode.name': '名称',
  'traffic.show.allowed': '已放行',
  'traffic.hour': '小时',
  'traffic.hour.previous': '上一小时',

  // 一块瓦片被读出来时：名称和状态的位置，以及它有多少查询。
  'traffic.tile.aria.one': '{label}，{status}，{n} 条查询',
  'traffic.tile.aria.other': '{label}，{status}，{n} 条查询',
  'traffic.empty': '本小时还没有查询。',

  // 地图下面那张卡片：用文字说明这块瓦片、它背后的名称，以及没有选中任何瓦片时的提示。
  'traffic.details.queries.one': '{n} 条查询',
  'traffic.details.queries.other': '{n} 条查询',
  'traffic.details.share': ' · 占当前显示的 {pct}',
  'traffic.details.growth': ' · 最近 {seconds} 秒增加了 {n}',
  'traffic.details.when': '何时',
  'traffic.details.whenTitle': '{name} 在什么时候被查询',
  'traffic.details.andMore.one': '还有 {n} 个',
  'traffic.details.andMore.other': '还有 {n} 个',
  'traffic.details.hint': '把鼠标停在一块瓦片上就能看到它背后的名称。点开其中一块即可在查询日志里查看。',

  // 图例：两种颜色和那圈高亮各是什么意思，以及最繁忙列表覆盖了哪些数据。
  'traffic.legend.size': '面积更大、颜色更深表示查询更多',
  'traffic.legend.ring': '当前增长最快',
  'traffic.legend.foot': '最繁忙的 {names} 个名称和 {blocked} 个被拦截的名称（{when}），覆盖所有节点；计数为近似值',
  'traffic.legend.updated': '。更新于 {time}',
  'traffic.legend.previousHour': '上一小时',
};
