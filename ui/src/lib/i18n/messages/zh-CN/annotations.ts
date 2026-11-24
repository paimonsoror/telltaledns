// REQ: OBS-033, API-011 — annotations 的中文翻译。键名与 en/annotations.ts 一一对应：
// 类型筛选和标记提示里各种变更的叫法（变更本身仍然是标识符）。
import type { MessageKey } from '../en';

export const annotations: Partial<Record<MessageKey, string>> = {
  'annotations.kind.note': '备注',
  'annotations.kind.buildStarted': '构建',
  'annotations.kind.nodeRestarted': '重启',
  'annotations.kind.blockingPaused': '暂停',
  'annotations.kind.upstreamBreaker': '熔断器',
};
