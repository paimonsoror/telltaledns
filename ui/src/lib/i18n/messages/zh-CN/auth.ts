// REQ: API-011 — 登录、两步验证和首次设置的中文文案。键名与 en/auth.ts 一一对应。
import type { MessageKey } from '../en';

export const auth: Partial<Record<MessageKey, string>> = {
  'auth.signIn': '登录',
  'auth.signingIn': '正在登录…',
  'auth.signInWith': '使用 {provider} 登录',
  'auth.passwordOr': '或使用密码',
  'auth.passwordOrAdmin': '或由受信任网络中的管理员使用密码登录',
  'auth.passwordOff': '此服务器已关闭密码登录。',
  'auth.username': '用户名',
  'auth.password': '密码',
  'auth.code': '验证码',
  'auth.codeHint': '输入身份验证器应用中的 6 位验证码。',
  'auth.codeTitle': '6 位数字',
  'auth.useRecovery': '改用恢复码',
  'auth.useAppCode': '改用应用验证码',
  'auth.recoveryCode': '恢复码',
  'auth.passwordRestricted': '密码登录仅限受信任网络中的管理员使用。登录服务商故障时可用它应急。',

  'auth.setup.title': '欢迎使用 TelltaleDNS',
  'auth.setup.introBefore': '创建第一个管理员。',
  'auth.setup.introAfter': '会打印设置令牌（服务器日志里写明了它保存在哪个文件）。',
  'auth.setup.token': '设置令牌',
  'auth.setup.username': '管理员用户名',
  'auth.setup.password': '密码（至少 10 个字符）',
  'auth.setup.repeat': '重复密码',
  'auth.setup.create': '创建管理员并登录',
  'auth.setup.creating': '正在创建…',
  'auth.setup.mismatch': '两次输入的密码不一致。',
};