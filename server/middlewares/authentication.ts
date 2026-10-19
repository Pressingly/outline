import { addDays } from "date-fns";
import type { Next } from "koa";
import { capitalize } from "es-toolkit/compat";
import httpErrors from "http-errors";
import type { HttpError } from "http-errors";
import { AUTH_TYPE_SSO } from "@shared/constants";
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
import { getJWTPayload, getUserForJWT } from "@server/utils/jwt";
import {
  AuthenticationError,
  AuthorizationError,
  StaleSessionRedirect,
  UserSuspendedError,
} from "../errors";

/** Service identifier used by the ForwardAuth authentication flow. */
export const FORWARDAUTH_SERVICE = "forwardauth";

type BaseAuthenticationOptions = {
  /** Role required to access the route. */
  role?: UserRole;
  /** Type of authentication required to access the route. */
  type?: AuthenticationType | AuthenticationType[];
};

type AuthenticationOptions =
  | (BaseAuthenticationOptions & {
      /** Authentication is required. */
      optional?: false;
      skip?: never;
    })
  | (BaseAuthenticationOptions & {
      /** Authentication is parsed, but optional. */
      optional: true;
      /**
       * Returns true when the request is authorized by other means, in which
       * case any credentials on the request are ignored rather than parsed.
       */
      skip?: (ctx: AppContext) => boolean;
    });

type AuthTransport = "cookie" | "header" | "body" | "query" | "proxy";

const FORWARDED_TOKEN_PREFIX = "fwd:";

type AuthInput = {
  /** The authentication token extracted from the request, if any. */
  token?: string;
  /** The method used to receive the authentication token. */
  transport?: AuthTransport;
};

export default function auth(options: AuthenticationOptions = {}) {
  return async function authMiddleware(ctx: AppContext, next: Next) {
    if (options.skip?.(ctx)) {
      ctx.state.auth = {};
      return next();
    }

    try {
      const { type, token, user, service, scope } =
        await validateAuthentication(ctx, options);

      // On the first ForwardAuth-authenticated request, issue a JWT cookie so
      // that subsequent requests and cookie-dependent services (WebSocket,
      // collaboration) use the fast JWT path instead of the header DB path.
      if (service === FORWARDAUTH_SERVICE && !ctx.cookies.get("accessToken")) {
        const expires = addDays(new Date(), JWT_COOKIE_TTL_DAYS);
        ctx.cookies.set("accessToken", user.getSessionToken(expires, service), {
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
      if (httpErrors.isHttpError(err)) {
        // Stale-session redirect. Convert into a 302 with Location pointing
        // to /home and expire the stale session cookies. Browser / fetch
        // auto-follow the redirect with the cleared cookies, which lands on
        // the ForwardAuth proxy transport and issues a fresh JWT, so no
        // 401 surfaces to the SPA.
        //
        // err.headers is the only way to carry Set-Cookie + Location through
        // Koa's onerror handler: response headers are stripped on error, then
        // only err.headers are re-applied. ctx.cookies.set() cannot be used.
        if (err.status === 302 && err.redirectTo) {
          throw withExpiredSessionCookies(err, { Location: err.redirectTo });
        }

        // If a cookie-transported JWT caused the 401, clear it so the browser
        // stops sending it. On the next request ForwardAuth headers take over
        // and a fresh session is issued.
        if (
          err.status === 401 &&
          parseAuthentication(ctx).transport === "cookie" &&
          !ctx.request.get("authorization") &&
          ctx.cookies.get("accessToken")
        ) {
          withExpiredSessionCookies(err);
        }
      }

      // Credentials that are valid but insufficient are always surfaced,
      // otherwise the request would be silently downgraded to anonymous.
      if (options.optional && !(err instanceof httpErrors.Forbidden)) {
        ctx.state.auth = {};
      } else {
        throw err;
      }
    }

    return next();
  };
}

const EXPIRED_SESSION_COOKIES = [
  "accessToken=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/",
  "lastSignedIn=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/",
];

/**
 * Attaches Set-Cookie directives expiring the session cookies to an error, so
 * they survive Koa's error handler. Object.assign is used because the
 * http-errors typings only allow string header values, while Koa accepts the
 * string array needed for multiple Set-Cookie headers.
 *
 * @param err the error being thrown from the middleware.
 * @param extraHeaders additional headers to attach.
 * @returns the same error, carrying the extra headers.
 */
function withExpiredSessionCookies(
  err: HttpError,
  extraHeaders: Record<string, string> = {}
) {
  return Object.assign(err, {
    headers: {
      ...err.headers,
      "set-cookie": EXPIRED_SESSION_COOKIES,
      ...extraHeaders,
    },
  });
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
        token: `${FORWARDED_TOKEN_PREFIX}${authRequestEmail}`,
        transport: "proxy",
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
 * Kept in sync with the synthesis logic in the proxy-transport branch of
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

/**
 * A forwarded identity is only trustworthy when it was built from the proxy
 * header. The same prefix arriving in a client-controlled transport is a
 * forgery attempt.
 *
 * @param token the raw token parsed from the request.
 * @param transport the transport the token arrived through.
 * @returns true when the token claims a forwarded identity it did not earn.
 */
function isClientSuppliedForwardedToken(
  token: string,
  transport?: AuthTransport
): boolean {
  return token.startsWith(FORWARDED_TOKEN_PREFIX) && transport !== "proxy";
}

/**
 * Verify that the caller's mPass access token carries a `custom:corporate_id`
 * matching this deployment's `SMB_CORPORATE_ID`. When the env var is empty the
 * check is skipped entirely (backward-compatible default).
 *
 * @param ctx - koa request context forwarded by oauth2-proxy.
 */
function checkCorporateId(ctx: AppContext): void {
  const expectedCorporateId = env.SMB_CORPORATE_ID;
  if (!expectedCorporateId) {
    return;
  }

  const accessToken = ctx.request.get("x-auth-request-access-token");
  if (!accessToken) {
    throw AuthenticationError("Access denied: missing access token");
  }

  try {
    // Decode JWT payload without verification — oauth2-proxy already verified
    // the signature before forwarding the request.
    const payloadB64 = accessToken.split(".")[1];
    const payload = JSON.parse(
      Buffer.from(payloadB64, "base64url").toString()
    );

    if (payload["custom:is_corporate"] !== "true") {
      throw AuthenticationError("Access denied: not a corporate account");
    }
    if (payload["custom:corporate_id"] !== expectedCorporateId) {
      throw AuthenticationError("Access denied: corporate ID mismatch");
    }
  } catch (e) {
    if (e instanceof Error && "statusCode" in e) {
      throw e;
    }
    throw AuthenticationError("Access denied: invalid access token");
  }
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

  if (isClientSuppliedForwardedToken(token, transport)) {
    throw AuthenticationError("Invalid token");
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
      throw AuthorizationError(
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
      throw AuthorizationError("API key does not have access to this resource");
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
  } else if (transport === "proxy" && env.AUTH_TYPE === AUTH_TYPE_SSO) {
    type = AuthenticationType.APP;
    service = FORWARDAUTH_SERVICE;

    const email = normalizeProxyEmail(
      token.slice(FORWARDED_TOKEN_PREFIX.length)
    );
    checkCorporateId(ctx);
    const { local: localPart, domain } = parseEmail(email);

    // A malformed forwarded email with no local part (e.g. "@example.com")
    // normalises to "@<DEFAULT_EMAIL_DOMAIN>" and yields an empty localPart.
    // User.name enforces a min length of 1, so provisioning would otherwise
    // fail with an opaque validation error — reject explicitly so the failure
    // mode is deterministic.
    if (!localPart) {
      throw AuthenticationError("Invalid forwarded email: missing local part");
    }

    // Concurrent-creation race guard. The SPA on first-ever login fires
    // multiple parallel API requests (docs, team, access tokens, …) with
    // no accessToken cookie set yet — so every request takes the proxy
    // transport, every request hits the find-then-create below, and
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
    // Session tokens are long-lived, so keep them out of transports that end up
    // in browser history, referrers, and request logs. Short-lived single-use
    // tokens such as transfer are still accepted from anywhere.
    if (transport !== "cookie" && transport !== "header") {
      const payload = getJWTPayload(token);

      if (payload.type === "session") {
        throw AuthenticationError(
          "Session token must be passed in the cookie or Authorization header"
        );
      }
    }

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
    // ForwardAuth proxy transport → new JWT for the new user.
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
        // proxy transport issues a fresh JWT. No 401 surfaces to the SPA,
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
