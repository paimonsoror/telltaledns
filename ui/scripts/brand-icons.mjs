// REQ: OBS-039 (ADR-167) — builds the domain icons' data from two packs:
//   Simple Icons (CC0-1.0), the first choice: colour brand marks on a 24x24 grid;
//   Bootstrap Icons (MIT), for the marks Simple Icons dropped (Microsoft, Amazon, LinkedIn, ...):
//   monochrome glyphs on a 16x16 grid, given a brand colour by hand in BOOTSTRAP below.
//   ui/src/lib/icons/brands.ts    brand colour, glyph path and, when it isn't 24, the glyph's grid
//                                 size per slug (a lazy chunk in the UI)
//   ui/src/lib/icons/map.data.ts  the domains (or hosts) each brand owns, and the brand titles
// Both are committed: a build never needs the network or these packages. Path data is minified
// with svgo to two decimals (a third of the bytes, under 1% difference at 16-20 px). Run it to change
// the curated list below or to move to another pack release (then review the diff):
//   cd ui && npm i --no-save simple-icons@16.38.0 bootstrap-icons@1.13.2 svgo@4.1.0 && node scripts/brand-icons.mjs
// or point SIMPLE_ICONS_DIR and BOOTSTRAP_ICONS_DIR at installed copies (svgo is found beside
// Simple Icons). It reports the brands neither pack carries (those names wear a monogram) and which
// of our service presets (presets/services) still have no icon. docs: site/dev-icons.html.
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';

const PINNED = '16.38.0';
const ROOT = path.resolve(import.meta.dirname, '../..');
const OUT = path.join(ROOT, 'ui/src/lib/icons');
const dir = process.env.SIMPLE_ICONS_DIR ?? path.join(import.meta.dirname, '../node_modules/simple-icons');
const installed = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8')).version;
if (installed !== PINNED) {
  console.error(`simple-icons ${installed} is installed but ${PINNED} is pinned here. Install ${PINNED}, or change PINNED and review the diff.`);
  process.exit(1);
}
const si = await import(pathToFileURL(path.join(dir, 'index.mjs')).href);
const all = Object.values(si).filter((x) => x && typeof x === 'object' && x.slug);
const bySlug = new Map(all.map((x) => [x.slug, x]));

// Bootstrap Icons (MIT): the second pack. Its glyphs have no colour, so each one used gets a brand
// colour here (the mark's well-known colour, chosen to read as a tile with a white or dark glyph).
const BOOTSTRAP_PINNED = '1.13.2';
const SVGO_PINNED = '4.1.0';
const PRECISION = 2;
const bsDir = process.env.BOOTSTRAP_ICONS_DIR ?? path.join(import.meta.dirname, '../node_modules/bootstrap-icons');
const bsInstalled = JSON.parse(fs.readFileSync(path.join(bsDir, 'package.json'), 'utf8')).version;
if (bsInstalled !== BOOTSTRAP_PINNED) {
  console.error(`bootstrap-icons ${bsInstalled} is installed but ${BOOTSTRAP_PINNED} is pinned here. Install ${BOOTSTRAP_PINNED}, or change BOOTSTRAP_PINNED and review the diff.`);
  process.exit(1);
}
const svgoDir = path.join(dir, '../svgo');
const svgoInstalled = JSON.parse(fs.readFileSync(path.join(svgoDir, 'package.json'), 'utf8')).version;
if (svgoInstalled !== SVGO_PINNED) {
  console.error(`svgo ${svgoInstalled} is installed but ${SVGO_PINNED} is pinned here. Install ${SVGO_PINNED}, or change SVGO_PINNED and review the diff.`);
  process.exit(1);
}
const { optimize } = createRequire(path.join(dir, 'package.json'))('svgo');

/** Bootstrap Icons name -> the slug it is stored under, its brand colour, and its title. */
const BOOTSTRAP = {
  microsoft: { slug: 'microsoft', hex: '0078D4', title: 'Microsoft' },
  'microsoft-teams': { slug: 'microsoftteams', hex: '6264A7', title: 'Microsoft Teams' },
  windows: { slug: 'windows', hex: '0078D4', title: 'Windows' },
  xbox: { slug: 'xbox', hex: '107C10', title: 'Xbox' },
  bing: { slug: 'bing', hex: '008373', title: 'Bing' },
  linkedin: { slug: 'linkedin', hex: '0A66C2', title: 'LinkedIn' },
  amazon: { slug: 'amazon', hex: 'FF9900', title: 'Amazon' },
  slack: { slug: 'slack', hex: '4A154B', title: 'Slack' },
  openai: { slug: 'openai', hex: '412991', title: 'OpenAI' },
  'nintendo-switch': { slug: 'nintendo', hex: 'E60012', title: 'Nintendo' },
  skype: { slug: 'skype', hex: '00AFF0', title: 'Skype' },
};

/**
 * A Bootstrap glyph's path data: its `<path>`s as one. A path that starts with a relative `m` (Bing's
 * third) would be read from the end of the one before it, so it is anchored at the origin: `M0 0` then
 * the same `m` (which, after an absolute move to 0 0, is the absolute move it was meant to be).
 */
function bootstrapPath(name) {
  const svg = fs.readFileSync(path.join(bsDir, 'icons', `${name}.svg`), 'utf8');
  if (/evenodd/.test(svg)) throw new Error(`${name}: fill-rule evenodd isn't supported (the tile draws every glyph with the default rule)`);
  const ds = [...svg.matchAll(/<path[^>]*\sd="([^"]+)"/g)].map((m) => m[1]);
  if (ds.length === 0 || ds.some((d) => !/^[Mm]/.test(d))) throw new Error(`${name}: expected paths that start with a move (M or m)`);
  return ds.map((d) => (d.startsWith('m') ? `M0 0${d}` : d)).join(' ');
}

/** Path data minified by svgo to PRECISION decimals (the viewBox is `0 0 size size`). */
function minify(d, size) {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}"><path d="${d}"/></svg>`;
  const out = optimize(svg, {
    multipass: true,
    plugins: [{ name: 'preset-default', params: { overrides: { convertPathData: { floatPrecision: PRECISION } } } }],
  }).data;
  return /<path[^>]*\sd="([^"]+)"/.exec(out)?.[1] ?? d;
}

// [candidate slugs (the first one Simple Icons has wins), the domains the brand owns]. A full host is
// allowed (`teams.microsoft.com`): the longest matching suffix of a name wins.
const LIST = [
  // Google and friends
  [['google'], ['google.com', 'gstatic.com', 'googleapis.com', 'googleusercontent.com', 'gvt1.com', 'gvt2.com', 'ggpht.com', 'withgoogle.com', 'google.co.uk']],
  [['youtube'], ['youtube.com', 'ytimg.com', 'googlevideo.com', 'youtu.be', 'youtube-nocookie.com']],
  [['googleads'], ['doubleclick.net', 'googlesyndication.com', 'googleadservices.com', 'googletagservices.com']],
  [['googleanalytics'], ['google-analytics.com', 'analytics.google.com']],
  [['googletagmanager'], ['googletagmanager.com']],
  [['firebase'], ['firebaseio.com', 'firebaseapp.com', 'app-measurement.com', 'firebaselogging-pa.googleapis.com']],
  [['android'], ['android.com']],
  [['gmail'], ['gmail.com']],
  // Apple
  [['apple'], ['apple.com', 'icloud.com', 'mzstatic.com', 'cdn-apple.com', 'apple-dns.net', 'icloud-content.com', 'aaplimg.com']],
  [['applemusic'], ['music.apple.com']],
  [['appletv'], ['tv.apple.com']],
  // Microsoft (Simple Icons dropped the main logo; the product marks it keeps are used where they exist)
  [['microsoft', 'bi:microsoft'], ['microsoft.com', 'msftconnecttest.com']],
  [['microsoftoffice', 'microsoft365', 'bi:microsoft'], ['office.com', 'office365.com', 'office.net', 'officeapps.live.com', 'microsoftonline.com', 'sharepoint.com']],
  [['microsoftteams', 'bi:microsoft-teams'], ['teams.microsoft.com', 'teams.events.data.microsoft.com']],
  [['skype', 'bi:skype'], ['skype.com', 'skypeassets.com']],
  [['microsoftedge', 'bi:microsoft'], ['edge.microsoft.com', 'msedge.net']],
  [['microsoftazure', 'azure', 'bi:microsoft'], ['azure.com', 'azureedge.net', 'azurewebsites.net', 'windows.net']],
  [['bing', 'bi:bing'], ['bing.com', 'bing.net']],
  [['windows11', 'windows', 'bi:windows'], ['windowsupdate.com', 'windows.com', 'live.com']],
  [['xbox', 'bi:xbox'], ['xbox.com', 'xboxlive.com']],
  [['github'], ['github.com', 'githubusercontent.com', 'githubassets.com', 'github.io', 'githubcopilot.com']],
  [['linkedin', 'bi:linkedin'], ['linkedin.com', 'licdn.com']],
  // Amazon
  [['amazon', 'bi:amazon'], ['amazon.com', 'media-amazon.com', 'ssl-images-amazon.com', 'amazon.co.uk', 'a2z.com']],
  [['amazonwebservices', 'amazonaws'], ['amazonaws.com', 'awsstatic.com', 'aws.amazon.com']],
  [['amazoncloudfront', 'amazonaws'], ['cloudfront.net']],
  [['primevideo'], ['primevideo.com', 'aiv-cdn.net', 'amazonvideo.com', 'pv-cdn.net']],
  [['amazonalexa', 'alexa'], ['alexa.amazon.com', 'alexa.com']],
  [['ring'], ['ring.com']],
  // Social and messaging
  [['facebook'], ['facebook.com', 'fbcdn.net', 'fb.com', 'fbsbx.com', 'facebook.net']],
  [['meta'], ['meta.com']],
  [['instagram'], ['instagram.com', 'cdninstagram.com']],
  [['whatsapp'], ['whatsapp.com', 'whatsapp.net', 'wa.me']],
  [['messenger'], ['messenger.com']],
  [['x'], ['x.com', 'twitter.com', 'twimg.com', 't.co']],
  [['reddit'], ['reddit.com', 'redd.it', 'redditstatic.com', 'redditmedia.com']],
  [['tiktok'], ['tiktok.com', 'tiktokcdn.com', 'tiktokv.com', 'tiktokcdn-us.com', 'ttwstatic.com']],
  [['snapchat'], ['snapchat.com', 'sc-cdn.net', 'snap-dev.net']],
  [['pinterest'], ['pinterest.com', 'pinimg.com']],
  [['tumblr'], ['tumblr.com']],
  [['discord'], ['discord.com', 'discordapp.com', 'discord.gg', 'discordapp.net']],
  [['telegram'], ['telegram.org', 't.me', 'telegram.me']],
  [['signal'], ['signal.org']],
  [['mastodon'], ['mastodon.social', 'joinmastodon.org']],
  [['twitch'], ['twitch.tv', 'ttvnw.net', 'jtvnw.net', 'twitchcdn.net']],
  [['tinder'], ['tinder.com', 'gotinder.com']],
  [['slack', 'bi:slack'], ['slack.com', 'slack-edge.com']],
  [['zoom'], ['zoom.us', 'zoom.com']],
  // Streaming
  [['netflix'], ['netflix.com', 'nflxvideo.net', 'nflximg.net', 'nflxso.net', 'nflxext.com']],
  [['spotify'], ['spotify.com', 'scdn.co', 'spotifycdn.com']],
  [['disneyplus', 'disney'], ['disneyplus.com', 'disney.com', 'bamgrid.com', 'dssott.com']],
  [['hulu'], ['hulu.com', 'hulustream.com']],
  [['hbomax', 'max'], ['max.com', 'hbomax.com']],
  [['paramountplus'], ['paramountplus.com']],
  [['plex'], ['plex.tv', 'plex.direct']],
  [['roku'], ['roku.com']],
  [['soundcloud'], ['soundcloud.com', 'sndcdn.com']],
  [['vimeo'], ['vimeo.com', 'vimeocdn.com']],
  [['crunchyroll'], ['crunchyroll.com']],
  // Gaming
  [['steam'], ['steampowered.com', 'steamcontent.com', 'steamstatic.com', 'steamcommunity.com', 'valvesoftware.com']],
  [['epicgames'], ['epicgames.com', 'unrealengine.com', 'epicgames.dev']],
  [['roblox'], ['roblox.com', 'rbxcdn.com', 'rbx.com', 'robloxlabs.com']],
  [['minecraft'], ['minecraft.net', 'mojang.com']],
  [['playstation'], ['playstation.com', 'playstation.net', 'sonyentertainmentnetwork.com']],
  [['nintendo', 'nintendoswitch', 'bi:nintendo-switch'], ['nintendo.com', 'nintendo.net']],
  [['ea'], ['ea.com']],
  [['battledotnet', 'battlenet'], ['battle.net', 'blizzard.com']],
  // Developer and infrastructure
  [['cloudflare'], ['cloudflare.com', 'cloudflare-dns.com', 'cloudflarestream.com', 'workers.dev', 'pages.dev']],
  [['jsdelivr'], ['jsdelivr.net']],
  [['npm'], ['npmjs.org', 'npmjs.com']],
  [['docker'], ['docker.com', 'docker.io']],
  [['kubernetes'], ['kubernetes.io', 'k8s.io']],
  [['helm'], ['helm.sh']],
  [['grafana'], ['grafana.com', 'grafana.org', 'grafana.net']],
  [['prometheus'], ['prometheus.io']],
  [['gitlab'], ['gitlab.com']],
  [['ubuntu'], ['ubuntu.com', 'canonical.com']],
  [['debian'], ['debian.org']],
  [['fedora'], ['fedoraproject.org']],
  [['archlinux'], ['archlinux.org']],
  [['redhat'], ['redhat.com']],
  [['python'], ['python.org']],
  [['pypi'], ['pypi.org', 'pythonhosted.org']],
  [['rust'], ['rust-lang.org', 'crates.io']],
  [['nodedotjs'], ['nodejs.org']],
  [['letsencrypt'], ['letsencrypt.org']],
  [['homeassistant'], ['home-assistant.io', 'nabucasa.com']],
  [['openai', 'bi:openai'], ['openai.com', 'chatgpt.com', 'oaistatic.com', 'oaiusercontent.com']],
  [['anthropic'], ['anthropic.com']],
  [['claude'], ['claude.ai']],
  [['stackoverflow'], ['stackoverflow.com', 'sstatic.net']],
  [['stackexchange'], ['stackexchange.com']],
  [['ycombinator'], ['ycombinator.com']],
  [['wikipedia'], ['wikipedia.org']],
  [['wikimediacommons', 'wikimedia'], ['wikimedia.org']],
  [['firefox'], ['mozilla.org', 'mozilla.com', 'mozilla.net', 'firefox.com']],
  [['brave'], ['brave.com']],
  [['duckduckgo'], ['duckduckgo.com']],
  [['protonmail', 'proton'], ['proton.me', 'protonmail.com']],
  [['dropbox'], ['dropbox.com', 'dropboxstatic.com']],
  [['atlassian'], ['atlassian.com', 'atlassian.net']],
  [['notion'], ['notion.so', 'notion.com']],
  [['figma'], ['figma.com']],
  [['adobe'], ['adobe.com', 'adobe.io', 'typekit.net']],
  [['datadog'], ['datadoghq.com']],
  [['sentry'], ['sentry.io']],
  [['newrelic'], ['newrelic.com']],
  [['fastly'], ['fastly.net']],
  [['akamai'], ['akamai.net', 'akamaiedge.net', 'akamaihd.net', 'akamaized.net']],
  [['wordpress'], ['wordpress.com', 'wp.com']],
  [['gravatar'], ['gravatar.com']],
  [['medium'], ['medium.com']],
  [['backstage'], ['backstage.io']],
  [['argo'], ['argoproj.io']],
  [['loki', 'grafana'], ['grafana.io']],
  // Devices and the home
  [['samsung'], ['samsung.com', 'samsungcloudsolution.com', 'samsungosp.com', 'samsungapps.com', 'samsungcloudsolution.net']],
  [['lg'], ['lg.com', 'lgtvsdk.com', 'lgsmartad.com']],
  [['sonos'], ['sonos.com']],
  [['philipshue'], ['meethue.com']],
  [['tplink'], ['tp-link.com', 'tplinkcloud.com', 'tplinkra.com']],
  [['ubiquiti'], ['ui.com', 'ubnt.com']],
  [['nest', 'googlenest'], ['nest.com']],
  [['ecobee'], ['ecobee.com']],
  [['tesla'], ['tesla.com']],
  // News, shopping, money
  [['bbc'], ['bbc.co.uk', 'bbc.com', 'bbci.co.uk']],
  [['nytimes', 'newyorktimes'], ['nytimes.com']],
  [['theguardian', 'guardian'], ['theguardian.com']],
  [['paypal'], ['paypal.com', 'paypalobjects.com']],
  [['stripe'], ['stripe.com', 'stripe.network']],
  [['shopify'], ['shopify.com', 'myshopify.com']],
  [['ebay'], ['ebay.com', 'ebaystatic.com']],
  [['walmart'], ['walmart.com']],
  [['airbnb'], ['airbnb.com']],
  [['uber'], ['uber.com']],
  [['webex', 'cisco'], ['webex.com']],
];

const brands = {};
const titles = {};
const map = {};
const dropped = [];
let fromBootstrap = 0;
for (const [cands, domains] of LIST) {
  // Simple Icons first; a `bi:` candidate (a Bootstrap Icons name) only when it has none of the others.
  const si = cands.find((c) => bySlug.has(c));
  const bi = si ? undefined : cands.find((c) => c.startsWith('bi:'))?.slice(3);
  let slug;
  if (si) {
    slug = si;
    if (!brands[slug]) {
      const i = bySlug.get(slug);
      brands[slug] = [i.hex, minify(i.path, 24)];
      titles[slug] = i.title;
    }
  } else if (bi) {
    const b = BOOTSTRAP[bi];
    if (!b) throw new Error(`BOOTSTRAP has no entry for ${bi}`);
    slug = b.slug;
    if (!brands[slug]) {
      brands[slug] = [b.hex, minify(bootstrapPath(bi), 16), 16];
      titles[slug] = b.title;
      fromBootstrap++;
    }
  } else {
    dropped.push(`${cands[0]} (${domains[0]}${domains.length > 1 ? ` +${domains.length - 1}` : ''})`);
    continue;
  }
  for (const d of domains) map[d] = slug;
}
for (const name of Object.keys(BOOTSTRAP)) {
  if (!LIST.some(([cands]) => cands.includes(`bi:${name}`))) throw new Error(`BOOTSTRAP has ${name}, which no LIST entry uses`);
}

const sorted = (o) => Object.fromEntries(Object.entries(o).sort(([a], [b]) => a.localeCompare(b)));
const head = `// GENERATED by ui/scripts/brand-icons.mjs from simple-icons ${PINNED} (CC0-1.0) and bootstrap-icons ${BOOTSTRAP_PINNED} (MIT), path data minified by svgo ${SVGO_PINNED} to ${PRECISION} decimals; do not edit by hand.\n`;
fs.mkdirSync(OUT, { recursive: true });
fs.writeFileSync(
  path.join(OUT, 'brands.ts'),
  `${head}// slug -> [brand colour (hex, no #), SVG path, the glyph's grid size when it isn't 24]. A separate chunk: loaded when the first brand icon is drawn.\nexport const BRANDS: Record<string, [string, string, number?]> = ${JSON.stringify(sorted(brands))};\n`,
);
fs.writeFileSync(
  path.join(OUT, 'map.data.ts'),
  `${head}/** A domain (or host) a brand owns -> its slug. The longest matching suffix of a name wins. */\nexport const BRAND_OF: Record<string, string> = ${JSON.stringify(sorted(map))};\nexport const BRAND_TITLE: Record<string, string> = ${JSON.stringify(sorted(titles))};\n`,
);

const suffixHit = (name) => {
  const parts = name.split('.');
  for (let k = 0; k < parts.length - 1; k++) if (map[parts.slice(k).join('.')]) return map[parts.slice(k).join('.')];
  return null;
};
const uncovered = [];
let services = 0;
const presets = path.join(ROOT, 'presets/services');
for (const f of fs.readdirSync(presets).filter((n) => n.endsWith('.toml'))) {
  for (const block of fs.readFileSync(path.join(presets, f), 'utf8').split('[[service]]').slice(1)) {
    services++;
    const id = /id = "([^"]+)"/.exec(block)?.[1];
    const doms = [...block.matchAll(/"\|\|([a-z0-9.-]+)\^"/g)].map((m) => m[1]);
    if (!doms.map(suffixHit).find(Boolean)) uncovered.push(id);
  }
}
const json = JSON.stringify(sorted(brands));
const kib = (n) => (n / 1024).toFixed(1);
console.log(`${Object.keys(brands).length} brands have an icon (${Object.keys(brands).length - fromBootstrap} from Simple Icons, ${fromBootstrap} from Bootstrap Icons); ${Object.keys(map).length} domains mapped`);
console.log(`glyph data ${kib(json.length)} KiB raw, ${kib(zlib.gzipSync(Buffer.from(json), { level: 9 }).length)} KiB gzip`);
console.log(`in neither pack (${dropped.length}): ${dropped.join('; ')}`);
console.log(`service presets without an icon (${uncovered.length} of ${services}): ${uncovered.join(', ')}`);
