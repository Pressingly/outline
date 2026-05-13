import passport from "@outlinewiki/koa-passport";
import { addDays } from "date-fns";
import Koa from "koa";
import bodyParser from "koa-body";
import Router from "koa-router";
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

app.use(bodyParser());
app.use(coalesceBody());
app.use(verifyCSRFToken());
app.use(router.routes());

export default app;
