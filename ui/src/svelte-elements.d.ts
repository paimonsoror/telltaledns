// REQ: API-012 — `translate` is a global attribute; browsers honour it on SVG text too, and the pages mark
// an SVG label that holds a server's word with it. Svelte's SVG element typings do not list it.
import 'svelte/elements';

declare module 'svelte/elements' {
  interface SVGAttributes<T extends EventTarget> {
    translate?: 'yes' | 'no' | undefined | null;
  }
}
