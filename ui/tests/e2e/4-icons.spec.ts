// REQ: OBS-039 (ADR-167) — domain icons, the parts that need no browser: which brand a name belongs
// to, the colour and letter of a name that has none, the names that wear no icon, the generated
// brand data, and how a stored choice is read back. (The page behaviour is `1-ui.spec.ts`.)
import { expect, test } from '@playwright/test';
import { BRANDS } from '../../src/lib/icons/brands';
import { BRAND_OF, BRAND_TITLE } from '../../src/lib/icons/map.data';
import { brandFor, hueOf, inkFor, isHashed, isInternal, letterOf, registrable } from '../../src/lib/icons/map';
import { DEFAULT_PREFS, ICON_PX, parsePrefs } from '../../src/lib/icons/prefs';

test('obs_039 a brand owns its domains, subdomains and CDNs, on label boundaries only', () => {
  expect(brandFor('www.netflix.com')).toBe('netflix');
  expect(brandFor('occ-0-1.nflxso.net')).toBe('netflix');
  expect(brandFor('API.Spotify.com.')).toBe('spotify');
  expect(brandFor('i.ytimg.com')).toBe('youtube');
  expect(brandFor('fonts.gstatic.com')).toBe('google');
  // A look-alike is not the brand: only whole labels match.
  expect(brandFor('notnetflix.com')).toBeNull();
  expect(brandFor('netflix.com.evil.example')).toBeNull();
  expect(brandFor('cdn.nx.example')).toBeNull();
  expect(brandFor('localhost')).toBeNull();
  // A longer match wins over a shorter one (a Google host that is also under googleapis.com).
  expect(brandFor('firebaselogging-pa.googleapis.com')).toBe('firebase');
});

test('obs_039 the generated data is whole: every mapped brand has a colour, a glyph and a title', () => {
  const slugs = new Set(Object.values(BRAND_OF));
  expect(slugs.size).toBeGreaterThan(80);
  for (const s of slugs) {
    const g = BRANDS[s];
    expect(g, `glyph for ${s}`).toBeTruthy();
    expect(g[0], `colour of ${s}`).toMatch(/^[0-9A-Fa-f]{6}$/);
    expect(g[1].length, `path of ${s}`).toBeGreaterThan(20);
    expect([undefined, 16], `grid of ${s}`).toContain(g[2]);
    expect(BRAND_TITLE[s], `title of ${s}`).toBeTruthy();
  }
  // Nothing in the glyph data that no domain points at (it would ship unused).
  for (const s of Object.keys(BRANDS)) expect(slugs.has(s), `${s} is mapped`).toBe(true);
});

// The second pack: Bootstrap Icons (MIT) for the marks Simple Icons dropped. Its glyphs sit on a 16 grid and
// were given a brand colour by hand; the first pack's stay on 24 (no third element).
test('obs_039 the marks Simple Icons dropped come from the second pack', () => {
  const cases: [string, string][] = [
    ['teams.events.data.microsoft.com', 'microsoftteams'],
    ['vortex.data.microsoft.com', 'microsoft'],
    ['login.microsoftonline.com', 'microsoft'],
    ['www.bing.com', 'bing'],
    ['login.xboxlive.com', 'xbox'],
    ['atlas.skype.com', 'skype'],
    ['www.amazon.com', 'amazon'],
    ['b79c66.us-east-1.prod.service.a2z.com', 'amazon'],
    ['media.licdn.com', 'linkedin'],
    ['edge-chat.slack.com', 'slack'],
    ['api.openai.com', 'openai'],
    ['ctest.nintendo.net', 'nintendo'],
  ];
  for (const [name, slug] of cases) {
    expect(brandFor(name), name).toBe(slug);
    expect(BRANDS[slug][2], `${slug} sits on a 16 grid`).toBe(16);
    expect(BRAND_TITLE[slug], `title of ${slug}`).toBeTruthy();
  }
  expect(BRANDS.netflix[2], 'a Simple Icons glyph has no grid size').toBeUndefined();
  expect(brandFor('notmicrosoft.com')).toBeNull(); // whole labels only
  // A mark neither pack carries is still a monogram, never a guess.
  for (const n of ['www.hulu.com', 'www.disneyplus.com', 'www.bbc.co.uk']) expect(brandFor(n), n).toBeNull();
});

test('obs_039 who owns a name, and the names of the network itself', () => {
  expect(registrable('api.example.com')).toBe('example.com');
  expect(registrable('www.bbc.co.uk')).toBe('bbc.co.uk');
  expect(registrable('Example.COM.')).toBe('example.com');
  expect(registrable('localhost')).toBe('localhost');
  for (const n of ['nas.home.arpa', 'printer.lan', 'hue-bridge.local', 'router', '20.1.168.192.in-addr.arpa', 'web.default.svc.cluster.local']) {
    expect(isInternal(n), n).toBe(true);
  }
  for (const n of ['example.com', 'www.netflix.com', 'a.b.example.org']) expect(isInternal(n), n).toBe(false);
});

test('obs_039 a name the privacy level hid wears no icon, and a look-alike is still a name', () => {
  expect(isHashed('h0123456789abcdef')).toBe(true);
  expect(isHashed('H0123456789ABCDEF')).toBe(true);
  expect(isHashed('h0123456789abcde')).toBe(false); // 15 digits
  expect(isHashed('h0123456789abcdef0')).toBe(false); // 17
  expect(isHashed('h0123456789abcdeg')).toBe(false); // not hex
  expect(isHashed('h0123456789abcdef.example.com')).toBe(false); // a real name that starts that way
  expect(isHashed('hello')).toBe(false);
});

test('obs_039 a name without a brand keeps one colour and one letter', () => {
  // The same owner is always the same colour, whatever the subdomain.
  expect(hueOf(registrable('a.example.org'))).toBe(hueOf(registrable('b.c.example.org')));
  for (const reg of ['example.org', 'nx.example', 'tv-vendor.example', 'bbc.co.uk', 'x.io']) {
    const h = hueOf(reg);
    expect(Number.isInteger(h) && h >= 0 && h < 360, reg).toBe(true);
  }
  // Different owners spread over the wheel (a degenerate hash would put them all together).
  const hues = new Set(['a.com', 'b.com', 'c.com', 'd.com', 'e.com', 'f.com', 'g.com', 'h.com'].map(hueOf));
  expect(hues.size).toBeGreaterThan(4);
  expect(letterOf('bbc.co.uk')).toBe('B');
  expect(letterOf('www.example.com')).toBe('E');
  expect(letterOf(registrable('cdn.nx.example'))).toBe('N');
  expect(letterOf('')).toBe('·');
});

test('obs_039 the glyph colour reads on its tile', () => {
  expect(inkFor('E50914')).toBe('#ffffff'); // red: white glyph
  expect(inkFor('000000')).toBe('#ffffff');
  expect(inkFor('FFFC00')).toBe('#111418'); // yellow: dark glyph
  expect(inkFor('FFFFFF')).toBe('#111418');
});

test('obs_039 a stored choice is read back, and anything else is the default', () => {
  expect(DEFAULT_PREFS).toEqual({ style: 'brand', size: 'default' });
  expect(ICON_PX).toEqual({ default: 20, small: 16 });
  expect(parsePrefs(null)).toEqual(DEFAULT_PREFS);
  expect(parsePrefs('')).toEqual(DEFAULT_PREFS);
  expect(parsePrefs('not json')).toEqual(DEFAULT_PREFS);
  expect(parsePrefs('null')).toEqual(DEFAULT_PREFS);
  expect(parsePrefs('{"style":"mono","size":"small"}')).toEqual({ style: 'mono', size: 'small' });
  expect(parsePrefs('{"style":"off"}')).toEqual({ style: 'off', size: 'default' });
  expect(parsePrefs('{"size":"small"}')).toEqual({ style: 'brand', size: 'small' });
  expect(parsePrefs('{"style":"neon","size":"huge"}')).toEqual(DEFAULT_PREFS);
});
