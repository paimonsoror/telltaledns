// REQ: API-013 (ADR-190) — what the first load knows about testing a language pack: the one storage
// key, the address of the build's pair-file template (from the URL table, which only `main.ts`
// imports), and the hooks the pack's code sets when it runs. The pack's own code loads later, and only
// when it is used (it reads this web UI's build, the entry module's path, from the page itself).

/** The browser storage key of a test pack (or of the notice that it was removed). */
export const DEVPACK_KEY = 'telltale.devpack';

export const devpack: {
  /** The build's pair-file template (`/assets/locales/template-<sha8>.json`), or null. */
  template: string | null;
  /** A pack or a notice about one is in this browser (the Settings card then shows in Simple too). */
  active: boolean;
  /** Set by the pack's code: the app's build poll calls it with the server's build commit. */
  onBuild?: (commit: string | undefined) => void;
  /** Set by the pack's code: the page failed to draw with the pack (true: handled, it reloads). */
  failed?: () => boolean;
  /** Set by the pack's code: the app calls it with who is signed in (null: nobody, or the display page),
   * whenever that changes, so the pack follows a sign-out, a session that ends and the next sign-in. */
  seen?: (who: string | null) => void;
  /** Set by the app's sign-out: true while it waits for the server's answer, then while the page leaves for the
   * provider's sign-out (OIDC), which the pack's code must not cancel by reloading the page. */
  leaving?: boolean;
  /** Set by the pack's code: the app's sign-out calls it when the page does not leave for the provider, so that a
   * reload held back while it waited happens now. */
  settled?: () => void;
} = { template: null, active: false };
