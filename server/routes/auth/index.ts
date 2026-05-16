import passport from "@outlinewiki/koa-passport";
import { addDays } from "date-fns";
import Koa from "koa";
import bodyParser from "koa-body";
import Router from "koa-router";
import env from "@server/env";
import { AuthenticationError } from "@server/errors";
import authMiddleware from "@server/middlewares/authentication";
import coalesceBody from "@server/middlewares/coaleseBody";
import { verifyCSRFToken } from "@server/middlewares/csrf";
import { Collection, Team, View } from "@server/models";
import AuthenticationHelper from "@server/models/helpers/AuthenticationHelper";
import type { AppState, AppContext, APIContext } from "@server/types";
import { JWT_COOKIE_TTL_DAYS } from "@server/utils/authentication";
import { getJWTPayload } from "@server/utils/jwt";

const app = new Koa<AppState, AppContext>();
const router = new Router();

router.use(passport.initialize());

// dynamically register available authentication provider routes
void (async () => {
  for (const provider of AuthenticationHelper.providers) {
    const resolvedRouter = await provider.value.router;
    if (resolvedRouter) {
      router.use(
        "/",
        authMiddleware({ optional: true }),
        resolvedRouter.routes()
      );
    }
  }
})();

router.get("/redirect", authMiddleware(), async (ctx: APIContext) => {
  const { user, service } = ctx.state.auth;

  // This route is only for exchanging a short-lived transfer token for a
  // session cookie. Reject anything else (in particular session JWTs being
  // replayed to extend their own life). The previous heuristic relied on
  // a quirk where session JWTs were deterministic; with proper `expiresAt`
  // claims they no longer are, so check the token type directly.
  if (getJWTPayload(ctx.state.auth.token).type !== "transfer") {
    throw AuthenticationError("Cannot extend token");
  }

  // Mint the JWT with the same expiry the cookie will carry so the token
  // and the cookie die together. Without an `expiresAt` claim the
  // validator at `utils/jwt.ts:47` skips the expiry check, leaving the
  // token replayable indefinitely if it ever leaves the cookie.
  const expires = addDays(new Date(), JWT_COOKIE_TTL_DAYS);
  const jwtToken = user.getJwtToken(expires, service);

  // ensure that the lastActiveAt on user is updated to prevent replay requests
  await user.updateActiveAt(ctx, true);

  ctx.cookies.set("accessToken", jwtToken, {
    sameSite: "lax",
    expires,
  });
  const [team, collection, view] = await Promise.all([
    Team.findByPk(user.teamId),
    Collection.findFirstCollectionForUser(user),
    View.findOne({
      where: {
        userId: user.id,
      },
    }),
  ]);

  const defaultCollectionId = team?.defaultCollectionId;

  if (defaultCollectionId) {
    const collection = await Collection.findOne({
      where: {
        id: defaultCollectionId,
        teamId: team.id,
      },
    });

    if (collection) {
      ctx.redirect(`${team.url}${collection.path}`);
      return;
    }
  }

  const hasViewedDocuments = !!view;

  ctx.redirect(
    !hasViewedDocuments && collection
      ? `${team?.url}${collection.path}/recent`
      : `${team?.url}/home`
  );
});

/**
 * Returns true iff `url` is a safe redirect target:
 *   - scheme is http or https (rejects javascript:, data:, etc.)
 *   - hostname matches an entry in `MPASS_SIGNOUT_NEXT_ALLOWED_HOSTS`
 *
 * Suffix match enforces a dot boundary: `foss.arbisoft.com` matches
 * `foss.arbisoft.com` and `*.foss.arbisoft.com` but NOT
 * `foss.arbisoft.com.evil.example`. Closes the obvious open-redirect
 * surface the endpoint would otherwise expose.
 */
function isAllowedSignOutNext(url: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  // Reject non-http(s) schemes outright — javascript: and data: parse fine
  // but should never be a valid next-hop. https is required in production;
  // http is allowed for dev/localhost flows.
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    return false;
  }
  const host = parsed.hostname.toLowerCase();
  if (!host) {
    return false;
  }
  for (const entry of env.MPASS_SIGNOUT_NEXT_ALLOWED_HOSTS) {
    if (host === entry || host.endsWith("." + entry)) {
      return true;
    }
  }
  return false;
}

/**
 * GET /auth/portal-logout?next=<absolute_url>
 *
 * Clears the accessToken + lastSignedIn cookies and 302-redirects to
 * `next`. Designed for the foss-server-bundle portal's "Log out of all
 * apps" redirect chain — the portal navigates the browser through each
 * app's logout URL, each step clearing its own cookies while the browser
 * is on that app's own domain (so the Set-Cookie scope is correct).
 *
 * CSRF-exempt by design: the portal cannot share Outline's CSRF token
 * cross-origin, so the existing POST + CSRF flow isn't usable here. The
 * residual risk is force-logout (an attacker embeds an `<img>` and the
 * victim's session ends). Low impact — the only state lost is the
 * cookie, and ForwardAuth re-auths on the next request.
 *
 * Open-redirect protection: `next` is validated against
 * `MPASS_SIGNOUT_NEXT_ALLOWED_HOSTS` (suffix-match on a dot boundary).
 * Empty allowlist rejects every `next` — cookies are still cleared, the
 * endpoint just returns 200 instead of 302.
 */
router.get("/portal-logout", async (ctx: APIContext) => {
  const epoch = new Date(0);
  // path:/ is load-bearing — without it Koa defaults the Set-Cookie path
  // to the request URL (`/auth/portal-logout`), which doesn't shadow the
  // original `accessToken` cookie's path:/ scope. The browser keeps the
  // JWT. Matches the cookie-clear shape used by the auth() catch block
  // at server/middlewares/authentication.ts:114-117.
  ctx.cookies.set("accessToken", "", {
    sameSite: "lax",
    expires: epoch,
    path: "/",
  });
  // lastSignedIn is non-HttpOnly because the frontend reads it.
  ctx.cookies.set("lastSignedIn", "", {
    httpOnly: false,
    sameSite: "lax",
    expires: epoch,
    path: "/",
  });

  const nextRaw = String(ctx.query.next ?? "").trim();
  if (nextRaw && isAllowedSignOutNext(nextRaw)) {
    ctx.redirect(nextRaw);
    return;
  }

  ctx.body = { ok: true };
});

app.use(bodyParser());
app.use(coalesceBody());
app.use(verifyCSRFToken());
app.use(router.routes());

export default app;
