// REQ: API-011 — rules 页面的中文翻译。键名与 en/rules.ts 一一对应。
import type { MessageKey } from '../en';

export const rules: Partial<Record<MessageKey, string>> = {
  // 标题，以及卡片上方关于快捷规则的那段说明。
  'rules.intro':
    '为一台设备、一个分组或所有设备放行或拦截某个站点，可以只持续一段时间，也可以永久生效。快捷规则先于任何列表做出判定：设备自己的规则胜过它所在分组的规则，分组的规则胜过所有设备的规则。',

  // 两张卡片：新建一条，以及正在生效的规则。
  'rules.new': '新建规则',
  'rules.inEffect': '生效中',
  'rules.empty': '还没有快捷规则。可以在这里新建，也可以在查询日志里用“为什么？”新建。',

  // 表格的各列。
  'rules.col.rule': '规则',
  'rules.col.for': '针对',
  'rules.col.ends': '结束',
  'rules.col.note': '备注',
  'rules.col.made': '创建',

  // 规则针对谁（设备名是规则自己的数据）。
  'rules.group': '分组 {groups}',
  'rules.everyone': '所有设备',

  // 规则什么时候结束。
  'rules.ends.never': '永不',
  'rules.ends.expired': '已过期',
  'rules.ends.in': '{when}后',
  'rules.ends.at': '{time} 到期',

  // 规则是从哪来的，以及保存修改后说了什么。
  'rules.source.file': '配置文件',
  'rules.inConfigFile': '在配置文件中',
  'rules.updated': '规则已更新。{message}',

  // 行上的按钮、编辑的标题，以及为什么某条规则要到别处修改。
  'rules.edit': '编辑',
  'rules.remove': '删除',
  'rules.editRule': '编辑规则',
  'rules.manyScopes': '涉及多台设备或多个分组：请通过接口修改。',
};
