import { addDays } from "date-fns";
import type { Next } from "koa";
import capitalize from "lodash/capitalize";
import { UserRole } from "@shared/types";
import { slugifyDomain } from "@shared/utils/domains";
import { parseEmail } from "@shared/utils/email";
import { UserRoleHelper } from "@shared/utils/UserRoleHelper";
import tracer, {
  addTags,
  getRootSpanFromRequestContext,
} from "@server/logging/tracer";
import teamCreator from "@server/commands/teamCreator";
import { createContext } from "@server/context";
import env from "@server/env";
import Logger from "@server/logging/Logger";
import { User, Team, ApiKey, OAuthAuthentication } from "@server/models";
import { sequelize } from "@server/storage/database";
import type { AppContext } from "@server/types";
import { AuthenticationType } from "@server/types";
import { JWT_COOKIE_TTL_DAYS } from "@server/utils/authentication";
import { getUserForJWT } from "@server/utils/jwt";
import {
  AuthenticationError,
  AuthorizationError,
  StaleSessionRedirect,
  UserSuspendedError,
} from "../errors";

/** Service identifier used by the ForwardAuth authentication flow. */
export const FORWARDAUTH_SERVICE = "forwardauth";

/** The {@link env.AUTH_TYPE} value that activates ForwardAuth/SSO mode. */
const AUTH_TYPE_SSO = "SSO";

type AuthenticationOptions = {
  /** Role required to access the route. */
  role?: UserRole;
  /** Type of authentication required to access the route. */
  type?: AuthenticationType | AuthenticationType[];
  /** Authentication is parsed, but optional. */
  optional?: boolean;
};

type AuthTransport = "cookie" | "header" | "body" | "query";

type AuthInput = {
  /** The authentication token extracted from the request, if any. */
  token?: string;
  /** The method used to receive the authentication token. */
  transport?: AuthTransport;
};

export default function auth(options: AuthenticationOptions = {}) {
  return async function authMiddleware(ctx: AppContext, next: Next) {
    try {
      const { type, token, user, service, scope } =
        await validateAuthentication(ctx, options);

      // On the first ForwardAuth-authenticated request, issue a JWT cookie so
      // that subsequent requests and cookie-dependent services (WebSocket,
      // collaboration) use the fast JWT path instead of the header DB path.
      if (service === FORWARDAUTH_SERVICE && !ctx.cookies.get("accessToken")) {
        const expires = addDays(new Date(), JWT_COOKIE_TTL_DAYS);
        ctx.cookies.set("accessToken", user.getJwtToken(expires, service), {
          sameSite: "lax",
          expires,
        });
        ctx.cookies.set("lastSignedIn", FORWARDAUTH_SERVICE, {
          httpOnly: false,
          sameSite: "lax",
          expires: new Date("2100"),
        });
      }

      await Promise.all([
        user.updateActiveAt(ctx),
        user.team?.updateActiveAt(),
      ]);

      ctx.state.auth = {
        user,
        token,
        type,
        service,
        scope,
      };

      if (tracer) {
        addTags(
          {
            "request.userId": user.id,
            "request.teamId": user.teamId,
            "request.authType": type,
          },
          getRootSpanFromRequestContext(ctx)
        );
      }
    } catch (err) {
      const epoch = "Thu, 01 Jan 1970 00:00:00 GMT";

      // Stale-session redirect. Convert into a 302 with Location
      // pointing to /home, plus Set-Cookie headers expiring the stale
      // accessToken + lastSignedIn cookies. Browser / fetch auto-
      // follow the redirect with the cleared cookies, which lands on
      // the ForwardAuth `fwd:` header path and issues a fresh JWT —
      // no 401 surfaces to the SPA.
      //
      // err.headers is the only way to carry Set-Cookie + Location
      // through Koa's onerror handler (see Koa's context.js:139-146 —
      // response headers are stripped on error, then only err.headers
      // are re-applied).
      if (err.status === 302 && err.redirectTo) {
        err.headers = {
          ...err.headers,
          "set-cookie": [
            `accessToken=; expires=${epoch}; path=/`,
            `lastSignedIn=; expires=${epoch}; path=/`,
          ],
          Location: err.redirectTo,
        };
        throw err;
      }

      // If a cookie-transported JWT caused the 401, clear it so the browser
      // stops sending it. On the next request ForwardAuth headers take over
      // and a fresh session is issued. Only clear when the cookie was the
      // active transport (no Authorization: Bearer header present).
      //
      // IMPORTANT: ctx.cookies.set() cannot be used here — Koa's onerror
      // handler strips all response headers before sending the error response,
      // then re-applies only err.headers (context.js:139-146). Attaching the
      // Set-Cookie directives to the error object is the only way they survive.
      const authInput = parseAuthentication(ctx);
      if (
        err.status === 401 &&
        authInput.transport === "cookie" &&
        !ctx.request.get("authorization") &&
        ctx.cookies.get("accessToken")
      ) {
        err.headers = {
          ...err.headers,
          "set-cookie": [
            `accessToken=; expires=${epoch}; path=/`,
            `lastSignedIn=; expires=${epoch}; path=/`,
          ],
        };
      }
      if (options.optional) {
        ctx.state.auth = {};
      } else {
        throw err;
      }
    }

    return next();
  };
}

/**
 * Parses the authentication token from the request context.
 *
 * @param ctx The application context containing the request information.
 * @returns An object containing the token and its transport method.
 */
export function parseAuthentication(ctx: AppContext): AuthInput {
  const authorizationHeader = ctx.request.get("authorization");

  if (authorizationHeader) {
    const parts = authorizationHeader.split(" ");

    if (parts.length === 2) {
      const scheme = parts[0];
      const credentials = parts[1];

      if (/^Bearer$/i.test(scheme)) {
        return {
          token: credentials,
          transport: "header",
        };
      }
    } else {
      throw AuthenticationError(
        `Bad Authorization header format. Format is "Authorization: Bearer <token>"`
      );
    }
  } else if (
    ctx.request.body &&
    typeof ctx.request.body === "object" &&
    "token" in ctx.request.body
  ) {
    return {
      token: String(ctx.request.body.token),
      transport: "body",
    };
  } else if (ctx.request.query?.token) {
    return {
      token: String(ctx.request.query.token),
      transport: "query",
    };
  } else {
    const accessToken = ctx.cookies.get("accessToken");
    if (accessToken) {
      return {
        token: accessToken,
        transport: "cookie",
      };
    }
  }

  // Check proxy-injected identity headers last — after all conventional
  // credentials — so an existing session cookie (or Bearer token) is always
  // preferred. This means once the JWT cookie has been issued the header path
  // is bypassed entirely, avoiding a DB round-trip on every request.
  if (env.AUTH_TYPE === AUTH_TYPE_SSO) {
    const authRequestEmail = ctx.request.get("x-auth-request-email");
    if (authRequestEmail) {
      return {
        token: `fwd:${authRequestEmail}`,
        transport: "header",
      };
    }
  }

  return {
    token: undefined,
    transport: undefined,
  };
}

/**
 * Normalises a raw `x-auth-request-email` header value into the canonical
 * email used for User lookup.
 *
 * - Lowercased and whitespace-trimmed.
 * - If it doesn't pass the email-shape regex (e.g. oauth2-proxy is forwarding
 *   a bare username like a numeric Cognito ID), synthesise
 *   `<local>@${env.DEFAULT_EMAIL_DOMAIN}` so the resulting key is the same
 *   one the User row was created under.
 *
 * Kept in sync with the synthesis logic in the `fwd:` branch of
 * `validateAuthentication` and reused by the stale-session mismatch check.
 */
function normalizeProxyEmail(raw: string): string {
  const trimmed = raw.toLowerCase().trim();
  // Use indexOf instead of a regex to avoid polynomial backtracking on
  // uncontrolled input while preserving the original regex's semantics:
  // (a) local part exists, (b) exactly one "@", (c) at least one char
  // between "@" and the dot, and (d) at least one char after the dot.
  // Embedded whitespace is also rejected (matching [^\s@]+ behaviour).
  const atIdx = trimmed.indexOf("@");
  const dotIdx = trimmed.indexOf(".", atIdx + 1);
  const isEmailShaped =
    atIdx > 0 &&
    trimmed.indexOf("@", atIdx + 1) === -1 &&
    !/\s/.test(trimmed) &&
    dotIdx > atIdx + 1 &&
    dotIdx < trimmed.length - 1;
  return isEmailShaped
    ? trimmed
    : `${trimmed.split("@")[0]}@${env.DEFAULT_EMAIL_DOMAIN}`;
}

async function validateAuthentication(
  ctx: AppContext,
  options: AuthenticationOptions
): Promise<{
  user: User;
  token: string;
  type: AuthenticationType;
  service?: string;
  scope?: string[];
}> {
  const { token, transport } = parseAuthentication(ctx);

  if (!token) {
    throw AuthenticationError("Authentication required");
  }

  let user: User | null;
  let type: AuthenticationType;
  let service: string | undefined;
  let scope: string[] | undefined;

  if (OAuthAuthentication.match(token)) {
    if (transport !== "header") {
      throw AuthenticationError(
        "OAuth access token must be passed in the Authorization header"
      );
    }

    type = AuthenticationType.OAUTH;

    let authentication;
    try {
      authentication = await OAuthAuthentication.findByAccessToken(token, {
        rejectOnEmpty: true,
      });
    } catch (_err) {
      throw AuthenticationError("Invalid access token");
    }
    if (!authentication) {
      throw AuthenticationError("Invalid access token");
    }
    if (authentication.accessTokenExpiresAt < new Date()) {
      throw AuthenticationError("Access token is expired");
    }
    if (!authentication.canAccess(ctx.originalUrl)) {
      throw AuthenticationError(
        "Access token does not have access to this resource"
      );
    }

    user = await User.findByPk(authentication.userId, {
      include: [
        {
          model: Team,
          as: "team",
          required: true,
        },
      ],
    });
    if (!user) {
      throw AuthenticationError("Invalid access token");
    }

    scope = authentication.scope;
    await authentication.updateActiveAt();
  } else if (ApiKey.match(token)) {
    if (transport === "cookie") {
      throw AuthenticationError("API key must not be passed in the cookie");
    }

    type = AuthenticationType.API;
    let apiKey;

    try {
      apiKey = await ApiKey.findByToken(token);
    } catch (_err) {
      throw AuthenticationError("Invalid API key");
    }

    if (!apiKey) {
      throw AuthenticationError("Invalid API key");
    }

    if (apiKey.expiresAt && apiKey.expiresAt < new Date()) {
      throw AuthenticationError("API key is expired");
    }

    if (!apiKey.canAccess(ctx.originalUrl)) {
      throw AuthenticationError(
        "API key does not have access to this resource"
      );
    }

    user = await User.findByPk(apiKey.userId, {
      include: [
        {
          model: Team,
          as: "team",
          required: true,
        },
      ],
    });

    if (!user) {
      throw AuthenticationError("Invalid API key");
    }

    scope = apiKey.scope ?? ["*"];
    await apiKey.updateActiveAt();
  } else if (token.startsWith("fwd:") && env.AUTH_TYPE === AUTH_TYPE_SSO) {
    type = AuthenticationType.APP;
    service = FORWARDAUTH_SERVICE;

    const email = normalizeProxyEmail(token.slice(4));
    const localPart = email.split("@")[0];
    const { domain } = parseEmail(email);

    // Concurrent-creation race guard. The SPA on first-ever login fires
    // multiple parallel API requests (docs, team, access tokens, …) with
    // no accessToken cookie set yet — so every request takes the `fwd:`
    // header path, every request hits the find-then-create below, and
    // before the row is committed the others have already passed the
    // findOne miss. Without a serialisation point, N parallel requests
    // create N duplicate rows for the same email.
    //
    // Outline's User table intentionally does NOT have a unique constraint
    // on email (server/migrations/20170712055148-non-unique-email.js
    // removed it to support the same email across multiple teams). So
    // ON CONFLICT can't save us at the DB level; we serialise the
    // find+create on a Postgres advisory lock keyed by the email hash.
    // Advisory locks are per-session, transaction-scoped here, and have
    // no schema cost. Different emails take different lock keys so
    // concurrent first-logins for distinct users don't contend.
    user = await sequelize.transaction(async (transaction) => {
      // pg_advisory_xact_lock takes a bigint; hash the email to a stable
      // 64-bit signed int. hashtext is built-in to Postgres and returns
      // an int4 — widen to bigint to feed the function's bigint overload.
      await sequelize.query(
        "SELECT pg_advisory_xact_lock(hashtext($email)::bigint)",
        { bind: { email }, transaction }
      );

      // Re-check inside the lock. If another concurrent request beat us
      // to the create, we'll see its row here and skip provisioning.
      // Exact match on the canonical lowercased email — never LIKE.
      // Using LIKE here would let SQL wildcard metacharacters (%, _) in
      // the supplied value match arbitrary users (e.g. "%@%.%" matches
      // the first row, often the bootstrap admin).
      let existing = await User.scope("withTeam").findOne({
        where: { email },
        transaction,
      });

      if (existing) {
        return existing;
      }

      // Self-hosted deployments have a single team. When none exists yet
      // the first arriving user bootstraps the installation. Team
      // provisioning happens inside this same transaction so the lock
      // also serialises the team bootstrap path.
      let team = await Team.findOne({ transaction });
      let isNewTeam = false;

      if (!team) {
        Logger.info("authentication", "Provisioning new team via ForwardAuth", {
          domain,
        });
        const subdomain = slugifyDomain(domain ?? "team");
        team = await teamCreator(createContext({ ip: ctx.ip, transaction }), {
          name: env.APP_NAME,
          subdomain,
          authenticationProviders: [
            {
              name: FORWARDAUTH_SERVICE,
              providerId: domain ?? FORWARDAUTH_SERVICE,
            },
          ],
        });
        isNewTeam = true;
      }

      Logger.info("authentication", "Provisioning new user via ForwardAuth", {
        email,
      });
      const created = await User.create(
        {
          name: localPart,
          email,
          teamId: team.id,
          // First user into a brand-new team becomes admin.
          role: isNewTeam ? UserRole.Admin : team.defaultUserRole,
          lastActiveAt: new Date(),
          lastActiveIp: ctx.ip,
        },
        { transaction }
      );

      // Reload with associations so downstream middleware sees a full User.
      const full = await User.scope("withTeam").findByPk(created.id, {
        transaction,
      });
      if (!full) {
        throw AuthenticationError("Failed to provision ForwardAuth user");
      }
      return full;
    });
  } else {
    type = AuthenticationType.APP;
    const result = await getUserForJWT(token);
    user = result.user;
    service = result.service;

    // SSO stale-session detection: if oauth2-proxy is asserting a different
    // identity than what's in this JWT cookie, the cookie is stale. Typical
    // repro: portal "log out of all apps" clears the shared _oauth2_proxy
    // cookie + Cognito session but NOT Outline's accessToken cookie on its
    // own subdomain; a different user then logs in. Without this check we'd
    // keep serving the previous user from the cookie JWT.
    //
    // Throwing 401 here triggers the cookie-cleanup branch in the outer
    // auth() catch block: the accessToken + lastSignedIn cookies are
    // expired via err.headers, and the client's next request takes the
    // ForwardAuth header path → new JWT for the new user.
    if (env.AUTH_TYPE === AUTH_TYPE_SSO && transport === "cookie") {
      const headerRaw = ctx.request.get("x-auth-request-email");
      // Bidirectional normalisation: both sides MUST be lowercased AND
      // whitespace-trimmed before comparison. Asymmetric normalisation
      // (e.g. trimming the header but not user.email) is observationally
      // equivalent to no normalisation — any whitespace-padded value in
      // the DB (legacy rows, fixtures, non-proxy provisioning paths) would
      // spuriously trigger 401 → cookie clear → re-auth loops on every
      // request. Required by openspec/specs/proxy-auth-middleware/spec.md
      // "Match is case- and whitespace-insensitive".
      //
      // Header absence is NOT treated as stale here — per the same spec
      // ("Header absence is NOT a logout signal"), absent header means
      // internal / non-proxy paths (background jobs, OPTIONS preflight,
      // direct backend hits) that legitimately carry the cookie. Treating
      // it as logout would break those.
      if (
        headerRaw &&
        normalizeProxyEmail(headerRaw) !==
          (user.email ?? "").toLowerCase().trim()
      ) {
        // Redirect to /home (302) with the stale cookie cleared. The
        // browser / fetch auto-follow the redirect, which lands on
        // Outline's home — by then the cookie is gone, ForwardAuth
        // adds the new user's X-Auth-Request-Email header, and the
        // fwd: path issues a fresh JWT. No 401 surfaces to the SPA,
        // no "no access to this doc" toast, no manual reload.
        //
        // We deliberately do NOT redirect to ctx.originalUrl:
        //   - The previous user may have had access to a doc the new
        //     user can't see → retry would 404/403, equally confusing.
        //   - For XHR fetches expecting JSON, /home returns HTML; the
        //     SPA's mismatch handler will route to /home cleanly while
        //     a same-URL retry of an inaccessible doc would error.
        // /home is a known-good landing page for any authenticated
        // user.
        throw StaleSessionRedirect("/home");
      }
    }
  }

  if (user.isSuspended) {
    const suspendingAdmin = user.suspendedById
      ? await User.findByPk(user.suspendedById)
      : undefined;
    throw UserSuspendedError({
      adminEmail: suspendingAdmin?.email || undefined,
    });
  }

  if (options.role && UserRoleHelper.isRoleLower(user.role, options.role)) {
    throw AuthorizationError(`${capitalize(options.role)} role required`);
  }

  if (
    options.type &&
    (Array.isArray(options.type)
      ? !options.type.includes(type)
      : type !== options.type)
  ) {
    throw AuthorizationError(`Invalid authentication type`);
  }

  return {
    user,
    type,
    token,
    service,
    scope,
  };
}
