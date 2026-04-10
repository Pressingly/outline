import { addMonths } from "date-fns";
import type { Next } from "koa";
import { Op } from "sequelize";
import Logger from "@server/logging/Logger";
import { Team, User } from "@server/models";
import { sequelize } from "@server/storage/database";
import type { AppContext } from "@server/types";

/** Paths that should never trigger proxy-auth session creation. */
const BYPASS_PATHS = ["/_health", "/api/hooks"];

/** Throttle window (ms) — skip DB writes if user was active recently. */
const ACTIVE_THROTTLE_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Koa middleware that reads the `X-Auth-Request-Email` header injected by
 * Traefik ForwardAuth (oauth2-proxy) and transparently creates an Outline
 * session (JWT `accessToken` cookie) for the identified user.
 *
 * - If a valid `accessToken` cookie already exists the middleware is a no-op.
 * - On first visit the user and team are provisioned if they don't exist.
 * - Gated on the `PROXY_AUTH_ENABLED` env var (must be "true").
 */
export default function proxyAuth() {
  const enabled = process.env.PROXY_AUTH_ENABLED === "true";

  return async function proxyAuthMiddleware(ctx: AppContext, next: Next) {
    if (!enabled) {
      return next();
    }

    // Skip bypass paths
    if (BYPASS_PATHS.some((p) => ctx.path.startsWith(p))) {
      return next();
    }

    // Skip if user already has a valid session cookie
    const existingToken = ctx.cookies.get("accessToken");
    if (existingToken) {
      return next();
    }

    const email = ctx.get("x-auth-request-email");
    if (!email) {
      return next();
    }

    try {
      // Self-hosted Outline: single team, grab the first (and only) one
      const team = await Team.findOne({
        order: [["createdAt", "ASC"]],
      });

      if (!team) {
        Logger.warn("proxyAuth: no team found — creating default team");
        await createSessionForEmail(ctx, email, null);
      } else {
        await createSessionForEmail(ctx, email, team);
      }
    } catch (err) {
      Logger.error("proxyAuth: session creation failed", err as Error, {
        email,
      });
      // Don't block the request — fall through to normal auth which will
      // show the login page
    }

    return next();
  };
}

async function createSessionForEmail(
  ctx: AppContext,
  email: string,
  existingTeam: Team | null
) {
  const displayName = ctx.get("x-auth-request-user") || email.split("@")[0];

  await sequelize.transaction(async (transaction) => {
    let team = existingTeam;

    // Create team if none exists (first-ever login on fresh install)
    if (!team) {
      team = await Team.create(
        {
          name: "Wiki",
        },
        { transaction }
      );
      Logger.info("proxyAuth: created default team", { teamId: team.id });
    }

    // Find or create user
    let user = await User.findOne({
      where: {
        email: { [Op.iLike]: email },
        teamId: team.id,
      },
      transaction,
    });

    const isNewUser = !user;

    if (!user) {
      user = await User.create(
        {
          email,
          name: displayName,
          teamId: team.id,
        },
        { transaction }
      );
      Logger.info("proxyAuth: created user", {
        userId: user.id,
        email,
        teamId: team.id,
      });
    }

    if (user.isSuspended) {
      Logger.warn("proxyAuth: suspended user attempted login", {
        userId: user.id,
        email,
      });
      return;
    }

    // Throttle lastActiveAt updates
    const now = new Date();
    if (
      !user.lastActiveAt ||
      now.getTime() - user.lastActiveAt.getTime() > ACTIVE_THROTTLE_MS
    ) {
      await user.update(
        {
          lastActiveAt: now,
          lastActiveIp: ctx.ip,
          lastSignedInAt: isNewUser ? now : user.lastSignedInAt || now,
        },
        { transaction }
      );
    }

    // Issue JWT and set cookie
    const expires = addMonths(new Date(), 3);
    const jwtToken = user.getJwtToken(expires, "proxy-auth");

    ctx.cookies.set("accessToken", jwtToken, {
      sameSite: "lax",
      expires,
    });

    ctx.cookies.set("lastSignedIn", "proxy-auth", {
      httpOnly: false,
      sameSite: true,
      expires: new Date("2100"),
    });

    Logger.info("proxyAuth: session created", {
      userId: user.id,
      email,
      isNewUser,
    });
  });
}
