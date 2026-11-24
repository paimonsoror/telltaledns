// REQ: API-011 — display 页面的中文翻译。键名与 en/display.ts 一一对应。
import type { MessageKey } from '../en';

export const display: Partial<Record<MessageKey, string>> = {
  'display.noCode': '这个地址没有显示码。请向管理员索取墙屏显示的链接。',
  'display.opening': '正在打开墙屏…',
};
