// REQ: API-011 — 通用文案的中文翻译。键名与 en/common.ts 一一对应。
import type { MessageKey } from '../en';

export const common: Partial<Record<MessageKey, string>> = {
  'common.loading': '加载中…',
  'common.retry': '重试',
  'common.cancel': '取消',
  'common.save': '保存',
  'common.saved': '已保存。',
  'common.close': '关闭',
  'common.search': '搜索',
  'common.apply': '应用',
  'common.copy': '复制',
  'common.copied': '已复制',
  'common.all': '全部',
  'common.never': '从未',
  'common.ago': '{time}前',
  'common.inFuture': '{time}后',
  'common.switchLanguage': '切换语言',
  'common.unreachable': '无法连接 TelltaleDNS：{error}',
  'common.dayShort': '天',
  'common.hourShort': '小时',
  'common.minuteShort': '分',
  'common.secondShort': '秒',
  'common.role.admin': '管理员',
  'common.role.operator': '操作员',
  'common.role.viewer': '只读用户',
};