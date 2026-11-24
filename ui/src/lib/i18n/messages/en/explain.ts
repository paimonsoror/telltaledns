// REQ: API-011 — strings for the explain page, English source of truth.
//
// The form's two placeholders are examples of what to type (a name, an address), not sentences:
// they read the same in every language.
export const explain = {
  // The heading.

  // The form: what each field asks for, its example, and the button that runs it.
  'explain.form.namePlaceholder': 'ads.example.com',
  'explain.form.client': 'Client IP',
  'explain.form.clientPlaceholder': '192.168.1.20',
  'explain.form.submit': 'Explain',
} as const;
