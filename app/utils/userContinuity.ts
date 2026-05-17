// oxlint-disable-next-line import/no-unresolved
import { getCookie, removeCookie, setCookie } from "tiny-cookie";
import { deleteAllDatabases } from "~/utils/developer";
import Logger from "~/utils/Logger";

const LAST_USER_KEY = "outline_last_user_id";
const POST_SWITCH_REDIRECT_HOME_ONCE_KEY =
  "outline_post_switch_redirect_home_once";

function markPostSwitchRedirectHome(): void {
  try {
    sessionStorage.setItem(POST_SWITCH_REDIRECT_HOME_ONCE_KEY, "true");
  } catch {
    // best effort
  }
  setCookie(POST_SWITCH_REDIRECT_HOME_ONCE_KEY, "true", { expires: 1 / 24 });
}

/**
 * Consume and clear the one-time post-user-switch redirect marker.
 *
 * @returns true if the caller should force a redirect to the home route.
 */
export function consumePostSwitchRedirectHome(): boolean {
  try {
    const shouldRedirect =
      sessionStorage.getItem(POST_SWITCH_REDIRECT_HOME_ONCE_KEY) === "true" ||
      getCookie(POST_SWITCH_REDIRECT_HOME_ONCE_KEY) === "true";
    if (shouldRedirect) {
      sessionStorage.removeItem(POST_SWITCH_REDIRECT_HOME_ONCE_KEY);
      removeCookie(POST_SWITCH_REDIRECT_HOME_ONCE_KEY);
      return true;
    }
  } catch {
    // best effort
  }

  removeCookie(POST_SWITCH_REDIRECT_HOME_ONCE_KEY);

  return false;
}

/**
 * Storage keys + cookie names that carry user-tied state OUTSIDE
 * the localStorage AUTH_STORE. Without clearing these, post-wipe
 * the SPA still redirects to the previous user's URL via the
 * AuthenticatedLayout's postLoginRedirectPath handling.
 *
 * - sessionStorage `postLoginRedirectPath` + cookie of the same
 *   name: set by `setPostLoginPath` in `useLastVisitedPath.tsx`
 *   when a logged-in user is bounced off an authenticated route.
 *   AuthenticatedLayout consumes it on mount via `usePostLoginPath`
 *   → `<Redirect to={postLoginPath} />`. Survives a localStorage
 *   wipe because it lives in sessionStorage (and a cookie); if we
 *   don't drop it, the wiped SPA re-mounts at /home, layout reads
 *   the stale path, and redirects the new user to the previous
 *   user's URL (e.g. a Collection they have no access to).
 *
 * - cookie `lastSignedIn`: set by `auth()` middleware alongside
 *   `accessToken`. Surfaces "logged in via X" hints in the UI.
 *   The server's stale-session 302 already clears it, but the
 *   boot-time wipe path (cookie absent + marker present) needs
 *   to clear it too — otherwise the UI may show the previous
 *   provider on the login screen.
 */
function clearAuxiliaryUserState(): void {
  try {
    sessionStorage.removeItem("postLoginRedirectPath");
  } catch {
    // best effort
  }
  removeCookie("postLoginRedirectPath");
  removeCookie("lastSignedIn");
}

/**
 * Decode the `accessToken` JWT cookie's payload to extract the
 * authenticated user's id. The cookie is set with `httpOnly: false`
 * specifically so the SPA can read it for this kind of client-side
 * identity check; see auth-issuing path in
 * `server/middlewares/authentication.ts:60-63`. Returns null if the
 * cookie is absent or the JWT is malformed.
 *
 * JWT payload shape (from `User.getJwtToken` in server/models/User.ts):
 *   { id, expiresAt, type, service }
 *
 * No signature verification here — we're using the id as a *change
 * detector*, not as a trust anchor. Any tampering only triggers an
 * unnecessary localStorage wipe; it can't grant access.
 */
function getCurrentUserIdFromCookie(): string | null {
  const token = getCookie("accessToken");
  if (!token) {
    return null;
  }
  try {
    const segments = token.split(".");
    if (segments.length < 2) {
      return null;
    }
    // Convert base64url → base64 then decode.
    const payload = JSON.parse(
      atob(segments[1].replace(/-/g, "+").replace(/_/g, "/"))
    );
    return typeof payload?.id === "string" ? payload.id : null;
  } catch {
    return null;
  }
}

/**
 * Wrap `deleteAllDatabases` to swallow errors. If anything goes wrong
 * we still want the navigation to proceed — the new session's API
 * calls will backfill correct data even if some stale rows linger.
 */
export async function cleanupIndexedDB(): Promise<void> {
  try {
    await deleteAllDatabases();
  } catch {
    // best effort
  }
}

/**
 * Clear the Cache API entries (used by Outline's service worker to
 * cache /api responses) and unregister all service workers.
 *
 * Why both:
 *   - caches.delete() removes the cached responses already on disk.
 *     Without this, the next /api/auth.info from the freshly-mounted
 *     SPA would still be served from the previous user's cached
 *     response.
 *   - serviceWorker.unregister() prevents the now-stale SW script
 *     from re-caching while the new session boots. The SW will
 *     re-register naturally on the new page load.
 */
export async function cleanupCachesAndServiceWorkers(): Promise<void> {
  if ("caches" in window) {
    try {
      const keys = await caches.keys();
      await Promise.all(keys.map((k) => caches.delete(k)));
    } catch {
      // best effort
    }
  }
  if ("serviceWorker" in navigator) {
    try {
      const regs = await navigator.serviceWorker.getRegistrations();
      await Promise.all(regs.map((r) => r.unregister()));
    } catch {
      // best effort
    }
  }
}

/**
 * Detect whether the authenticated user has changed since the last
 * session in this browser, and wipe all browser-local state if so.
 *
 * The bundle's SSO flow allows multiple users to authenticate in the
 * same Chrome browser in sequence (portal "Log out of all apps" + login
 * as a different user, shared-workstation scenarios, etc.). Outline
 * persists user-tied state in several places: AuthStore's localStorage
 * entry, `lastVisitedPath`, IndexedDB document/team caches, and any
 * other mobx-store that uses `usePersistedState`. None of those are
 * keyed by user-id; on a user switch, the new user inherits the
 * previous user's cached state until the next API call backfills.
 *
 * The visible symptom is e.g. the account-menu avatar showing alice's
 * initials immediately after bob logs in (until /api/auth.info
 * resolves). Other symptoms hide indefinitely behind cached IndexedDB
 * rows.
 *
 * One central cleanup at SPA boot — before any store rehydrates from
 * localStorage — covers every cache without needing per-key
 * invalidation in each store. Compare-and-wipe is keyed off the JWT
 * `id` claim, decoded from the (non-HttpOnly) accessToken cookie.
 *
 * MUST be invoked before `new RootStore()` in `app/stores/index.ts`.
 */
export function checkUserContinuity(): void {
  const currentUserId = getCurrentUserIdFromCookie();
  const lastUserId = localStorage.getItem(LAST_USER_KEY);

  if (!currentUserId) {
    // No accessToken cookie. Two sub-cases:
    //
    // (a) No prior marker either — fresh browser, genuinely
    //     unauthenticated boot. Nothing to do.
    //
    // (b) Marker exists from a prior authenticated session, but the
    //     cookie is gone. This is the portal-logout-then-login-as-
    //     different-user case: oauth2-proxy clears the upstream
    //     session cookie + (depending on flow) the accessToken
    //     cookie, the user re-authenticates via Cognito as a
    //     different user, and the browser lands back on a URL that
    //     used to belong to the previous user (e.g. the collection
    //     they were viewing). At this point AUTH_STORE in
    //     localStorage still holds the previous user's data; without
    //     a wipe the SPA rehydrates that and the new fetchAuth
    //     response races against it.
    //
    // For (b) we wipe and redirect to /home — same destination as
    // the JWT-mismatch path. For (a) we just return.
    if (lastUserId) {
      Logger.info(
        "lifecycle",
        "Cookie cleared but prior-session marker present — wiping browser-local state"
      );
      try {
        localStorage.clear();
      } catch {
        // best effort
      }
      clearAuxiliaryUserState();
      Promise.all([
        cleanupIndexedDB(),
        cleanupCachesAndServiceWorkers(),
      ]).finally(() => {
        markPostSwitchRedirectHome();
        window.location.replace("/home");
      });
    }
    return;
  }

  if (lastUserId && lastUserId !== currentUserId) {
    Logger.info(
      "lifecycle",
      "User identity changed since last session — wiping browser-local state"
    );
    try {
      localStorage.clear();
    } catch {
      // localStorage can throw on quota / disabled — best effort.
    }
    // Set the marker BEFORE the navigation so the post-navigation
    // re-boot of this function doesn't fire the wipe again.
    try {
      localStorage.setItem(LAST_USER_KEY, currentUserId);
    } catch {
      // best effort
    }

    // Block the redirect on async cleanup completing. Without this,
    // window.location.replace fires immediately while deleteAllDatabases
    // + caches.delete are still in-flight. The new page load then
    // mounts AuthStore, fires `fetchAuth → /api/auth.info`, and the
    // service worker (which we just told to clear but hasn't finished
    // yet) intercepts with a CACHED response for the previous user.
    // Result: avatar shows the previous user's name even though
    // localStorage was wiped. Awaiting the cleanup promises before
    // navigating closes that race.
    //
    // The cleanups are belt-and-suspenders, covering every browser-
    // local store Outline uses:
    //   - localStorage   → handled above by localStorage.clear()
    //   - IndexedDB      → deleteAllDatabases() (Outline's own helper)
    //   - Cache API      → caches.delete() per cache key
    //                       (service workers cache /api responses here)
    //   - Service Worker → unregister all (forces re-registration on
    //                       the new session so SW state is per-user)
    clearAuxiliaryUserState();
    Promise.all([
      cleanupIndexedDB(),
      cleanupCachesAndServiceWorkers(),
    ]).finally(() => {
      markPostSwitchRedirectHome();
      window.location.replace("/home");
    });
    return;
  }

  try {
    localStorage.setItem(LAST_USER_KEY, currentUserId);
  } catch {
    // localStorage quota / disabled — best effort. Same-user re-boots
    // will work since the marker survives; cross-user wipes won't fire,
    // but the failure mode is "stale state" which the user can fix
    // with an explicit logout. Not a regression vs. pre-fix.
  }
}

/**
 * Wipe all browser-local state and navigate to `/home` so the SPA
 * re-mounts on a clean slate. Used when we detect a stale session
 * mid-flight (e.g. an /api/* response was 302'd to HTML because the
 * cookie's identity differs from the proxy's identity).
 *
 * At call time the accessToken cookie has already been cleared by the
 * server's 302 response. We can't rely on `checkUserContinuity`'s
 * cookie-vs-marker comparison on the next boot — that compares a
 * non-existent cookie against the marker and returns early. So we
 * do the wipe inline here and then reload.
 *
 * Idempotent guard: if multiple parallel /api calls all get bounced
 * (the SPA fires several auth.* requests concurrently on boot), only
 * the first should kick off the wipe + reload. Subsequent callers
 * short-circuit.
 */
let wipeInFlight = false;
export async function wipeAndReload(): Promise<void> {
  if (wipeInFlight) {
    return;
  }
  wipeInFlight = true;
  Logger.info(
    "lifecycle",
    "Stale session detected via redirect — wiping browser-local state"
  );
  // The LAST_USER_KEY marker is deliberately NOT written here. On the
  // post-reload boot the accessToken cookie is absent (the server's
  // 302 cleared it), so `checkUserContinuity` returns early — it has
  // no `currentUserId` to write. Once AuthStore.fetchAuth provisions
  // the new user and the server issues a fresh JWT cookie, the marker
  // gets written on the *next* full boot when cookie+marker are both
  // present and aligned. The transient "marker missing, cookie
  // present" state in between is benign: same-user behaviour falls
  // into the "set marker, no wipe" branch of checkUserContinuity.
  try {
    localStorage.clear();
  } catch {
    // best effort
  }
  clearAuxiliaryUserState();
  try {
    await Promise.race([
      Promise.all([
        cleanupIndexedDB(),
        cleanupCachesAndServiceWorkers(),
      ]),
      // Hard ceiling so a hung IDB / SW operation doesn't strand the
      // user staring at the previous user's avatar indefinitely. 1.5s
      // is well above typical p99 for these APIs on healthy browsers.
      new Promise((resolve) => setTimeout(resolve, 1500)),
    ]);
  } catch {
    // best effort
  }
  markPostSwitchRedirectHome();
  window.location.replace("/home");
}
