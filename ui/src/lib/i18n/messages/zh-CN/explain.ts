// REQ: API-011 — explain 页面的中文翻译。键名与 en/explain.ts 一一对应。
// 表单里的两个示例（域名、IP）只是示范该填什么，两种语言写法相同，不翻译。
import type { MessageKey } from '../en';

export const explain: Partial<Record<MessageKey, string>> = {
  // 标题。

  // 表单：每个字段要填什么、输入框里的示例，以及执行按钮。
  'explain.form.namePlaceholder': 'ads.example.com',
  'explain.form.client': '客户端 IP',
  'explain.form.clientPlaceholder': '192.168.1.20',
  'explain.form.submit': '解释',
};
