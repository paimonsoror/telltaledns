# Wall display (kiosk mode): design notes (T14.9)

**Requirement:** OBS-035 (new). **ADR:** ADR-135 (new, Proposed). **Spec section:** `07` §3 row
*Wall*. **Owner request:** 2026-10-16. **Build last:** it composes T14.1, T14.3, T14.4, T14.6.

## 1. What it is, in one paragraph
A full-screen, no-navigation route for a wall monitor or a tablet on a shelf: the treemap breathing as
tiles grow, particles flowing along the Sankey, SLO rings, the latency heatmap scrolling, a ticker of
the live tail, rotating on a timer. Zero new data — rendering on top of the APIs and the SSE stream
that exist. Honest about it: highest fun, lowest operational value of the pack, and also the
screenshot that makes people try the project.

## 2. Non-goals
- Any weakening of authentication for the kiosk (§8 is the right place for that conversation).
- New API endpoints, new metrics, new storage.
- A dashboard builder. Panels and their order are a URL parameter, nothing more.

## 3. Composition (decision)
Route `#/wall?panels=map,flow,slo,latency,heat&every=20&scope=` (defaults: all panels, 20 s per
panel, cluster scope). `App.svelte` renders `Wall.svelte` **without** the sidebar, header, or footer
(a `kiosk` layout flag on the route table), on `--bg` with the brand mark small in a corner and a clock.

Panels (each a thin wrapper over an existing component with a `wall` prop that hides controls and
scales type):
| panel | component | live behaviour |
|---|---|---|
| `map` | Traffic map treemap (OBS-026) | refresh every 5 s; tiles **tween** area and position over 600 ms (`treemap.ts` layout is deterministic, so interpolate rects by key); growing tiles pulse once |
| `flow` | Sankey (T14.6), 1 h live window | 10 s refresh; **particles**: small dots travelling along each link path at a rate proportional to its count (cap 60 dots on screen; `requestAnimationFrame`, paused when the tab is hidden) |
| `slo` | Service level (OBS-016) as two large **rings** (remaining budget) with the 1 h burn rate as a needle, plus "who spent it" top 3 (T14.1) | 30 s |
| `latency` | Latency heatmap (T14.4), last 60 minutes, minute step | 30 s; new column slides in from the right |
| `heat` | Rhythm heatmap (T14.3), network, 7 d × 15 m | 5 min |
| `tail` | always on, bottom strip: the live tail (`/queries/stream`, 500 ev/s cap) as a ticker of `client → name · status` with status colours | continuous; the ticker drops frames, never queues (keep the newest 50) |

`prefers-reduced-motion`: no tweens, no particles, no slide; panels still rotate (with a fade of 0 ms).
A `?motion=off` parameter does the same. Battery/CPU: all animation stops when
`document.visibilityState !== 'visible'`; the page targets < 10 % of one core on a Pi 4's Chromium
(measure on the Pi's desktop image or a Pi Zero 2 W if the owner has one; record the number).

## 4. Auth (decision)
The wall needs a signed-in session like any page. Document the supported pattern: sign in on the
kiosk's browser once; session lifetime is the existing setting. Nothing in this task extends session
lifetimes or adds unauthenticated routes. See §8 for the follow-up.

## 5. UI details (decision)
- Type scales with `vmin`; a 1080p wall at 3 m reads the big numbers from the sofa.
- Each panel announces itself with a title that fades after 3 s; a progress hairline at the bottom
  shows the rotation.
- `Esc` or any click exits to the dashboard. `Space` pauses rotation. `←`/`→` move panels.
- A **Wall** button in the dashboard header (Advanced view) opens the route; `docs/running.md`
  describes the URL parameters.
- Tests cannot see motion; the Playwright test checks the route renders each panel's `data-testid`,
  that controls are hidden, that `?panels=` is honoured, and that `motion=off` sets no animation
  classes.

## 6. Grafana
None. (The Grafana dashboard *is* the other wall; say so in the docs.)

## 7. Acceptance criteria
1. `#/wall` renders without nav; `?panels=slo,flow` shows only those two in order; `every=5` rotates in
   5 s (fake timers in the test).
2. Tween correctness: given two treemap layouts with the same keys, the interpolated rects at t=0 and
   t=1 equal the layouts exactly (unit test on the interpolation helper).
3. Particle cap: with 200 links the animation keeps ≤ 60 dots (unit test on the scheduler).
4. `prefers-reduced-motion` and `?motion=off` → no animation classes, no rAF loop started (spy).
5. Hidden tab → rAF loop stops within one frame; visible again → resumes.
6. Live tail ticker under a 1,000 ev/s synthetic stream keeps the newest 50 and never grows (memory
   assertion in the test).
7. Bundle growth for the pack measured and reported (target < 60 KB gz total across T14.x).
8. Playwright `obs_035 wall`; docs (`running.md` *Wall display*), site page with a demo-network
   screenshot and a short GIF (from the demo network only).

## 8. Open
- A **viewer role** or a long-lived, read-only, IP-restricted kiosk session would make a real wall
  practical. It is an auth change (AUTH requirements, OIDC implications), so it is its own ADR and the
  owner's call. Propose it in the task report; don't build it here.

## 9. Decided at the start of the task (owner: accept all defaults, 2026-10-16)
Recorded in ADR-135:
- **Panels:** the traffic map, the flow, and the rhythm heatmap are pages, not components, so the
  wall has its own small panels (`ui/src/lib/components/wall/`) drawing with the same layout
  modules (`treemap.ts`, `sankey.ts`, `heatmap.ts`); the latency heatmap is the existing component
  with a `wall` prop (the last hour, no controls, every 30 s). The map shows this hour's busiest
  names (no service or site grouping on the wall).
- One panel at a time, full screen, with the tail ticker always along the bottom (12 shown of the
  50 kept). A click anywhere exits, as §5 says (on a touch screen, a tap exits).
- **SLO:** two rings (budget left), a needle on a log scale from 0 to 14.4 (a fast burn) for the 1 h
  burn rate, and the three devices with the most bad answers of the availability budget.
- **Tests:** the UI has no unit-test runner, so `ui/src/lib/wall.ts` (panels, tweens, the particle
  budget, the ticker, the loop) is imported by the Playwright spec and checked there; the rotation
  is checked with a real 5 s timer (the suite shares one page, so no fake clock).
- **Not done here:** the Pi 4 Chromium CPU figure (no Pi desktop to measure on, and the live Pi is
  off limits); the demo screenshot and GIF; the viewer / kiosk session (§8: proposed to the owner).
- A **Wall** link on the dashboard in the Advanced view. Auth unchanged. (Moved on 2026-10-17, owner request: an icon button at the top right between pause and the theme, styled like them.)
