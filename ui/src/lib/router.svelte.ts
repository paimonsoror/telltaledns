// Hash routing (`#/queries?client=1.2.3.4`): the server only ever serves `/`, so deep links
// work without server-side fallbacks, and filters live in the URL for sharing.

function parse() {
  const h = location.hash.replace(/^#/, '') || '/';
  const [path, query = ''] = h.split('?', 2);
  return { path: path || '/', params: new URLSearchParams(query) };
}

export const route = $state(parse());

window.addEventListener('hashchange', () => {
  const r = parse();
  route.path = r.path;
  route.params = r.params;
});

export function href(path: string, params?: Record<string, string | undefined>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params ?? {})) if (v) p.set(k, v);
  const q = p.toString();
  return `#${path}${q ? `?${q}` : ''}`;
}

export function navigate(path: string, params?: Record<string, string | undefined>, replace = false) {
  const h = href(path, params);
  if (replace) {
    history.replaceState(null, '', h);
    const r = parse();
    route.path = r.path;
    route.params = r.params;
  } else {
    location.hash = h;
  }
}
