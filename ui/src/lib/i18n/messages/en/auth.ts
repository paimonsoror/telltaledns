// REQ: API-003, API-004, API-011 — sign-in, the two-factor step, first-run setup, and the shell
// both forms sit in.
export const auth = {
  'auth.signIn': 'Sign in',
  'auth.signingIn': 'Signing in…',
  'auth.signInWith': 'Sign in with {provider}',
  'auth.passwordOr': 'or with a password',
  'auth.passwordOrAdmin': 'or, as an admin on a trusted network, with a password',
  'auth.passwordOff': 'Password sign-in is turned off on this server.',
  'auth.username': 'Username',
  'auth.password': 'Password',
  'auth.code': 'Code',
  'auth.codeHint': 'Enter the 6-digit code from your authenticator app.',
  'auth.codeTitle': '6 digits',
  'auth.useRecovery': 'Use a recovery code instead',
  'auth.useAppCode': 'Use the app code instead',
  'auth.recoveryCode': 'Recovery code',
  'auth.passwordRestricted':
    'Password sign-in is limited to admins on trusted networks. Use it when your sign-in provider is down.',

  'auth.setup.title': 'Welcome to TelltaleDNS',
  'auth.setup.introBefore': 'Create the first admin.',
  'auth.setup.introAfter': 'prints the setup token (the server log says which file holds it).',
  'auth.setup.token': 'Setup token',
  'auth.setup.username': 'Admin username',
  'auth.setup.password': 'Password (at least 10 characters)',
  'auth.setup.repeat': 'Repeat password',
  'auth.setup.create': 'Create admin and sign in',
  'auth.setup.creating': 'Creating…',
  'auth.setup.mismatch': 'The passwords don’t match.',
} as const;