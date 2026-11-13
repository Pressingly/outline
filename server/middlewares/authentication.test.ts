import { generateKeyPairSync } from "node:crypto";
import jwt from "jsonwebtoken";
import type { DefaultState } from "koa";
import { HttpResponse, http } from "msw";
import { AUTH_TYPE_SSO } from "@shared/constants";
import { errToString } from "@shared/utils/error";
import { randomString } from "@shared/random";
import { Scope } from "@shared/types";
import env from "@server/env";
import Logger from "@server/logging/Logger";
import {
  buildUser,
  buildTeam,
  buildAdmin,
  buildApiKey,
  buildOAuthAuthentication,
} from "@server/test/factories";
import { User } from "@server/models";
import { sequelize } from "@server/storage/database";
import { server } from "@server/test/msw";
import { buildMockContext } from "@server/test/support";
import { AuthenticationType } from "@server/types";
import { JWT_COOKIE_TTL_DAYS } from "@server/utils/authentication";
import { EDGE_SECRET_HEADER } from "@server/utils/mpassEdgeTrust";
import auth, { FORWARDAUTH_SERVICE } from "./authentication";

const EDGE_SECRET = "e".repeat(64);

interface CtxOverrides {
  originalUrl?: string;
  request?: {
    headers?: Record<string, string>;
    body?: Record<string, unknown>;
    url?: string;
  };
}

interface MiddlewareError {
  status?: number;
  message?: string;
  id?: string;
  headers?: Record<string, string | string[]>;
  errorData?: Record<string, unknown>;
}

function createCtx(overrides: CtxOverrides = {}) {
  const headers = {
    ...(overrides.request?.headers || {}),
  };

  const get = vi.fn((key: string) => headers[key.toLowerCase()]);

  return {
    state: {},
    cache: {},

    originalUrl: overrides.originalUrl || "/",

    get,

    cookies: {
      get: vi.fn(() => undefined), // 👈 THIS was missing
    },

    request: {
      url: "/",
      headers,
      header: headers,
      body: {},
      get,

      ...(overrides.request || {}),
    },
  };
}

describe("Authentication middleware", () => {
  describe("with session JWT", () => {
    it("should authenticate with correct session token", async () => {
      const state = {} as DefaultState;
      const user = await buildUser();
      const authMiddleware = auth();
      await authMiddleware(
        buildMockContext({
          request: {
            get: vi.fn(() => `Bearer ${user.getSessionToken()}`),
          },
          state,
          cache: {},
        }),
        vi.fn()
      );
      expect(state.auth.user.id).toEqual(user.id);
    });

    it("should return error with invalid session token", async () => {
      const state = {} as DefaultState;
      const user = await buildUser();
      const authMiddleware = auth();

      try {
        await authMiddleware(
          buildMockContext({
            request: {
              get: vi.fn(() => `Bearer ${user.getSessionToken()}error`),
            },
            state,
            cache: {},
          }),
          vi.fn()
        );
      } catch (e) {
        expect(errToString(e)).toBe("Invalid token");
      }
    });

    it("should return error if AuthenticationType mismatches", async () => {
      const state = {} as DefaultState;
      const user = await buildUser();
      const authMiddleware = auth({
        type: AuthenticationType.API,
      });

      try {
        await authMiddleware(
          buildMockContext({
            request: {
              get: vi.fn(() => `Bearer ${user.getSessionToken()}`),
            },
            state,
            cache: {},
          }),
          vi.fn()
        );
      } catch (e) {
        expect(errToString(e)).toBe("Invalid authentication type");
      }
    });
  });

  describe("with API key", () => {
    it("should authenticate user with valid API key", async () => {
      const state = {} as DefaultState;
      const user = await buildUser();
      const authMiddleware = auth();
      const key = await buildApiKey({ userId: user.id });
      await authMiddleware(
        buildMockContext({
          request: {
            get: vi.fn(() => `Bearer ${key.value}`),
          },
          state,
          cache: {},
        }),
        vi.fn()
      );
      expect(state.auth.user.id).toEqual(user.id);
    });
    it("should authenticate with global read scope on read endpoints", async () => {
      const state = {} as DefaultState;
      const user = await buildUser();
      const authMiddleware = auth();
      const key = await buildApiKey({
        userId: user.id,
        scope: [Scope.Read],
      });

      await authMiddleware(
        buildMockContext({
          originalUrl: "/api/auth.info",
          request: {
            url: "/auth.info",
            get: vi.fn(() => `Bearer ${key.value}`),
          },
          state,
          cache: {},
        }),
        vi.fn()
      );
      expect(state.auth.user.id).toEqual(user.id);
    });

    it("should return 403 authorization error when scope does not match", async () => {
      const state = {} as DefaultState;
      const user = await buildUser();
      const authMiddleware = auth();
      const key = await buildApiKey({
        userId: user.id,
        scope: [Scope.Read],
      });

      try {
        await authMiddleware(
          buildMockContext({
            originalUrl: "/api/documents.create",
            request: {
              url: "/documents.create",
              get: vi.fn(() => `Bearer ${key.value}`),
            },
            state,
            cache: {},
          }),
          vi.fn()
        );
        throw new Error("Expected error to be thrown");
      } catch (e) {
        expect(e).toHaveProperty("status", 403);
        expect(e).toHaveProperty("id", "authorization_error");
        expect(errToString(e)).toContain(
          "does not have access to this resource"
        );
      }
    });

    it("should return error with invalid API key", async () => {
      const state = {} as DefaultState;
      const authMiddleware = auth();

      try {
        await authMiddleware(
          buildMockContext({
            request: {
              get: vi.fn(() => `Bearer ${randomString(38)}`),
            },
            state,
            cache: {},
          }),
          vi.fn()
        );
      } catch (e) {
        expect(errToString(e)).toBe("Invalid API key");
      }
    });
  });

  describe("with OAuth access token", () => {
    it("should authenticate user with valid OAuth access token", async () => {
      const state = {} as DefaultState;
      const user = await buildUser();
      const authMiddleware = auth();
      const authentication = await buildOAuthAuthentication({
        user,
        scope: [Scope.Read],
      });

      await authMiddleware(
        buildMockContext({
          originalUrl: "/api/users.info",
          request: {
            url: "/users.info",
            get: vi.fn(() => `Bearer ${authentication.accessToken}`),
          },
          state,
          cache: {},
        }),
        vi.fn()
      );
      expect(state.auth.user.id).toEqual(user.id);
    });

    it("should return error with invalid scope", async () => {
      const state = {} as DefaultState;
      const user = await buildUser();
      const authMiddleware = auth();
      const authentication = await buildOAuthAuthentication({
        user,
        scope: [Scope.Read],
      });

      try {
        await authMiddleware(
          buildMockContext({
            originalUrl: "/api/documents.create",
            request: {
              url: "/documents.create",
              get: vi.fn(() => `Bearer ${authentication.accessToken}`),
            },
            state,
            cache: {},
          }),
          vi.fn()
        );
      } catch (e) {
        expect(errToString(e)).toContain(
          "does not have access to this resource"
        );
      }
    });

    it("should return error with OAuth access token in body", async () => {
      const user = await buildUser();

      const authentication = await buildOAuthAuthentication({
        user,
        scope: [Scope.Read],
      });

      const ctx = createCtx({
        originalUrl: "/api/users.info",
        request: {
          body: {
            token: authentication.accessToken,
          },
        },
      });

      const authMiddleware = auth();

      let error: MiddlewareError | undefined;

      try {
        // @ts-expect-error mock context
        await authMiddleware(ctx, vi.fn());
        throw new Error("Expected middleware to throw");
      } catch (e) {
        error = e as MiddlewareError;
      }

      expect(error).toBeDefined();
      expect(error.status).toBe(401);
      expect(error.message).toBe(
        "OAuth access token must be passed in the Authorization header"
      );
    });
  });

  it("should return error message if no auth token is available", async () => {
    const state = {} as DefaultState;
    const authMiddleware = auth();

    try {
      await authMiddleware(
        buildMockContext({
          request: {
            get: vi.fn(() => "error"),
          },
          state,
          cache: {},
        }),
        vi.fn()
      );
    } catch (e) {
      expect(errToString(e)).toBe(
        'Bad Authorization header format. Format is "Authorization: Bearer <token>"'
      );
    }
  });

  it("should allow passing session token in a cookie", async () => {
    const state = {} as DefaultState;
    const user = await buildUser();
    const authMiddleware = auth();
    await authMiddleware(
      buildMockContext({
        request: {
          get: vi.fn(() => null),
        },
        cookies: {
          get: vi.fn(() => user.getSessionToken()),
        },
        state,
        cache: {},
      }),
      vi.fn()
    );
    expect(state.auth.user.id).toEqual(user.id);
  });

  it("should return error with session token as a GET param", async () => {
    const state = {} as DefaultState;
    const user = await buildUser();
    const authMiddleware = auth();

    await expect(
      authMiddleware(
        buildMockContext({
          request: {
            get: vi.fn(() => null),
            query: {
              token: user.getSessionToken(),
            },
          },
          state,
          cache: {},
        }),
        vi.fn()
      )
    ).rejects.toThrow(
      "Session token must be passed in the cookie or Authorization header"
    );
  });

  it("should return error with session token in body params", async () => {
    const state = {} as DefaultState;
    const user = await buildUser();
    const authMiddleware = auth();

    await expect(
      authMiddleware(
        buildMockContext({
          request: {
            get: vi.fn(() => null),
            body: {
              token: user.getSessionToken(),
            },
          },
          state,
          cache: {},
        }),
        vi.fn()
      )
    ).rejects.toThrow(
      "Session token must be passed in the cookie or Authorization header"
    );
  });

  it("should allow passing transfer token as a GET param", async () => {
    const state = {} as DefaultState;
    const user = await buildUser();
    const authMiddleware = auth();
    await authMiddleware(
      buildMockContext({
        request: {
          get: vi.fn(() => null),
          query: {
            token: user.getTransferToken(),
          },
        },
        state,
        cache: {},
      }),
      vi.fn()
    );
    expect(state.auth.user.id).toEqual(user.id);
  });

  it("should return an error for suspended users", async () => {
    const state = {} as DefaultState;
    const admin = await buildAdmin();
    const user = await buildUser({
      suspendedAt: new Date(),
      suspendedById: admin.id,
    });
    const authMiddleware = auth();
    let error;

    try {
      await authMiddleware(
        buildMockContext({
          request: {
            get: vi.fn(() => `Bearer ${user.getSessionToken()}`),
          },
          state,
          cache: {},
        }),
        vi.fn()
      );
    } catch (err) {
      error = err;
    }

    expect(errToString(error)).toEqual(
      "Your access has been suspended by a workspace admin"
    );
    expect(error).toHaveProperty("errorData.adminEmail", admin.email);
  });

  describe("with ForwardAuth headers", () => {
    beforeEach(() => {
      env.AUTH_TYPE = AUTH_TYPE_SSO;
      env.MPASS_EDGE_SECRET = EDGE_SECRET;
    });

    afterEach(() => {
      env.AUTH_TYPE = undefined;
      env.MPASS_EDGE_SECRET = "";
    });

    it("should authenticate an existing user via X-Auth-Request-Email", async () => {
      const team = await buildTeam();
      const user = await buildUser({ teamId: team.id });
      const state = {} as DefaultState;
      const authMiddleware = auth();

      await authMiddleware(
        {
          // @ts-expect-error mock request
          request: {
            get: vi.fn((header: string) => {
              if (header === EDGE_SECRET_HEADER) {
return EDGE_SECRET;
}
if (header === "x-auth-request-email") {
                return user.email!;
              }
              return "";
            }),
          },
          // @ts-expect-error mock cookies
          cookies: { get: vi.fn(() => undefined), set: vi.fn() },
          state,
          ip: "127.0.0.1",
          cache: {},
        },
        vi.fn()
      );

      expect(state.auth.user.id).toEqual(user.id);
      expect(state.auth.service).toEqual(FORWARDAUTH_SERVICE);
      expect(state.auth.type).toEqual(AuthenticationType.APP);
    });

    it("should issue the accessToken cookie with a 7-day expiry", async () => {
      const team = await buildTeam();
      const user = await buildUser({ teamId: team.id });
      const state = {} as DefaultState;
      const authMiddleware = auth();
      const cookiesSet = vi.fn();
      const before = Date.now();

      await authMiddleware(
        {
          // @ts-expect-error mock request
          request: {
            get: vi.fn((header: string) => {
              if (header === EDGE_SECRET_HEADER) {
return EDGE_SECRET;
}
if (header === "x-auth-request-email") {
                return user.email!;
              }
              return "";
            }),
          },
          // @ts-expect-error mock cookies
          cookies: { get: vi.fn(() => undefined), set: cookiesSet },
          state,
          ip: "127.0.0.1",
          cache: {},
        },
        vi.fn()
      );

      const accessTokenCall = cookiesSet.mock.calls.find(
        (call) => call[0] === "accessToken"
      );
      expect(accessTokenCall).toBeDefined();

      const expires: Date = accessTokenCall![2].expires;
      const ageMs = expires.getTime() - before;
      const expectedMs = JWT_COOKIE_TTL_DAYS * 24 * 60 * 60 * 1000;
      // Allow ±60s skew for test runtime.
      expect(ageMs).toBeGreaterThan(expectedMs - 60_000);
      expect(ageMs).toBeLessThan(expectedMs + 60_000);
    });

    describe("session cookie issuance", () => {
      async function authenticateWithHeaders(headers: Record<string, string>) {
        const state = {} as DefaultState;
        const cookiesSet = vi.fn();

        await auth()(
          buildMockContext({
            request: {
              get: vi.fn(
                (header: string) => headers[header.toLowerCase()] ?? ""
              ),
            },
            cookies: { get: vi.fn(() => undefined), set: cookiesSet },
            state,
            ip: "127.0.0.1",
            cache: {},
          }),
          vi.fn()
        );

        const cookieNames = cookiesSet.mock.calls.map((call) => call[0]);
        return { state, cookieNames };
      }

      it("should issue session cookies on the proxy transport", async () => {
        const user = await buildUser();

        const { state, cookieNames } = await authenticateWithHeaders({
          "x-auth-request-email": user.email!,
          [EDGE_SECRET_HEADER]: EDGE_SECRET,
        });

        expect(state.auth.user.id).toEqual(user.id);
        expect(cookieNames).toEqual(
          expect.arrayContaining(["accessToken", "lastSignedIn"])
        );
      });

      it("should not issue a cookie for a forwardauth session JWT sent as Bearer", async () => {
        const user = await buildUser();
        const expiresSoon = new Date(Date.now() + 60 * 60 * 1000);
        const forwardAuthJwt = user.getSessionToken(
          expiresSoon,
          FORWARDAUTH_SERVICE
        );

        const { state, cookieNames } = await authenticateWithHeaders({
          authorization: `Bearer ${forwardAuthJwt}`,
          "x-auth-request-email": user.email!,
          [EDGE_SECRET_HEADER]: EDGE_SECRET,
        });

        expect(state.auth.user.id).toEqual(user.id);
        expect(state.auth.service).toEqual(FORWARDAUTH_SERVICE);
        expect(cookieNames).toEqual([]);
      });
    });

    it("should provision a new user when X-Auth-Request-Email is unknown", async () => {
      await buildTeam();
      const state = {} as DefaultState;
      const authMiddleware = auth();
      const newEmail = `newuser-${randomString(6)}@example.com`;

      await authMiddleware(
        {
          // @ts-expect-error mock request
          request: {
            get: vi.fn((header: string) => {
              if (header === EDGE_SECRET_HEADER) {
return EDGE_SECRET;
}
if (header === "x-auth-request-email") {
                return newEmail;
              }
              return "";
            }),
          },
          // @ts-expect-error mock cookies
          cookies: { get: vi.fn(() => undefined), set: vi.fn() },
          state,
          ip: "127.0.0.1",
          cache: {},
        },
        vi.fn()
      );

      const provisioned = await User.findOne({
        where: { email: newEmail.toLowerCase() },
      });
      expect(provisioned).not.toBeNull();
      expect(state.auth.user.email).toEqual(newEmail.toLowerCase());
      expect(state.auth.user.name).toEqual(
        newEmail.toLowerCase().split("@")[0]
      );
    });

    it("should use askii.ai domain when X-Auth-Request-Email is not a valid email and DEFAULT_EMAIL_DOMAIN is unset", async () => {
      await buildTeam();
      const state = {} as DefaultState;
      const authMiddleware = auth();
      const localPart = `user-${randomString(6)}`;
      const savedDomain = env.DEFAULT_EMAIL_DOMAIN;
      env.DEFAULT_EMAIL_DOMAIN = "askii.ai";

      try {
        await authMiddleware(
          {
            // @ts-expect-error mock request
            request: {
              get: vi.fn((header: string) => {
                if (header === EDGE_SECRET_HEADER) {
return EDGE_SECRET;
}
if (header === "x-auth-request-email") {
                  return localPart;
                }
                return "";
              }),
            },
            // @ts-expect-error mock cookies
            cookies: { get: vi.fn(() => undefined), set: vi.fn() },
            state,
            ip: "127.0.0.1",
            cache: {},
          },
          vi.fn()
        );

        expect(state.auth.user.email).toEqual(`${localPart.toLowerCase()}@askii.ai`);
      } finally {
        env.DEFAULT_EMAIL_DOMAIN = savedDomain;
      }
    });

    it("should reject a forwarded email with no local part", async () => {
      await buildTeam();
      const state = {} as DefaultState;
      const authMiddleware = auth();

      // "@example.com" normalises to "@<DEFAULT_EMAIL_DOMAIN>" with an empty
      // local part. User.name enforces min length 1, so we reject up front
      // rather than letting provisioning fail with an opaque validation error.
      await expect(
        authMiddleware(
          {
            // @ts-expect-error mock request
            request: {
              get: vi.fn((header: string) => {
                if (header === EDGE_SECRET_HEADER) {
return EDGE_SECRET;
}
if (header === "x-auth-request-email") {
                  return "@example.com";
                }
                return "";
              }),
            },
            // @ts-expect-error mock cookies
            cookies: { get: vi.fn(() => undefined), set: vi.fn() },
            state,
            ip: "127.0.0.1",
            cache: {},
          },
          vi.fn()
        )
      ).rejects.toThrow("Invalid forwarded email: missing local part");
    });

    it("should not match existing users via SQL LIKE wildcard characters", async () => {
      const team = await buildTeam();
      const existingUser = await buildUser({ teamId: team.id });
      const state = {} as DefaultState;
      const authMiddleware = auth();

      // RFC-5321 allows `%` and `_` in the local part, so this is a
      // syntactically valid email that Sequelize's isEmail validator
      // accepts. The `%` would be a SQL LIKE wildcard — under Op.iLike
      // a clause like `email ILIKE 'attacker%@evil.com'` would match
      // any existing email starting with `attacker` (e.g. the bootstrap
      // admin). With exact-match the lookup misses; a separate (junk)
      // account is provisioned instead. The existing user is never
      // impersonated either way.
      const wildcardEmail = "attacker%_@evil.example.com";

      await authMiddleware(
        {
          // @ts-expect-error mock request
          request: {
            get: vi.fn((header: string) => {
              if (header === EDGE_SECRET_HEADER) {
return EDGE_SECRET;
}
if (header === "x-auth-request-email") {
                return wildcardEmail;
              }
              return "";
            }),
          },
          // @ts-expect-error mock cookies
          cookies: { get: vi.fn(() => undefined), set: vi.fn() },
          state,
          ip: "127.0.0.1",
          cache: {},
        },
        vi.fn()
      );

      expect(state.auth.user.id).not.toEqual(existingUser.id);
      expect(state.auth.user.email).not.toEqual(existingUser.email);
      // Provisioned user's email is the exact wildcard string, not a
      // value resolved by pattern matching against existingUser.
      expect(state.auth.user.email).toEqual(wildcardEmail);
    });

    it("should take the advisory lock before creating the ForwardAuth user", async () => {
      // Race-protection regression guard. The pg_advisory_xact_lock MUST be
      // taken before User.create — otherwise N parallel first-login
      // requests for the same email could each pass the findOne miss and
      // each insert a duplicate row (Outline has no unique constraint on
      // users.email; see server/migrations/20170712055148-non-unique-email).
      //
      // If a future refactor moves User.create above the lock, or removes
      // the lock entirely, this test fails.
      await buildTeam();
      const newEmail = `racetest-${randomString(6)}@example.com`;
      const querySpy = vi.spyOn(sequelize, "query");
      const createSpy = vi.spyOn(User, "create");

      try {
        const state = {} as DefaultState;
        const authMiddleware = auth();

        await authMiddleware(
          {
            // @ts-expect-error mock request
            request: {
              get: vi.fn((header: string) => {
                if (header === EDGE_SECRET_HEADER) {
return EDGE_SECRET;
}
if (header === "x-auth-request-email") {
                  return newEmail;
                }
                return "";
              }),
            },
            // @ts-expect-error mock cookies
            cookies: { get: vi.fn(() => undefined), set: vi.fn() },
            state,
            ip: "127.0.0.1",
            cache: {},
          },
          vi.fn()
        );

        // 1. The advisory lock was acquired at least once with the
        //    email-keyed hash. Any sequelize.query() call whose first
        //    arg contains "pg_advisory_xact_lock" counts.
        const lockCallIndex = querySpy.mock.calls.findIndex(
          ([sql]) =>
            typeof sql === "string" && sql.includes("pg_advisory_xact_lock")
        );
        expect(lockCallIndex).toBeGreaterThanOrEqual(0);

        // 2. The lock was acquired BEFORE User.create. Jest's
        //    invocationCallOrder is a monotonically-increasing number
        //    assigned across all spies in a test, so a strict
        //    lower-than relationship means strict before-then-after.
        expect(createSpy.mock.invocationCallOrder.length).toBeGreaterThan(0);
        const lockOrder = querySpy.mock.invocationCallOrder[lockCallIndex];
        const firstCreateOrder = createSpy.mock.invocationCallOrder[0];
        expect(lockOrder).toBeLessThan(firstCreateOrder);
      } finally {
        querySpy.mockRestore();
        createSpy.mockRestore();
      }
    });

    it("should 302 to /home and clear stale cookie when proxy identity changes", async () => {
      // Repro: alice logged in (issued an accessToken JWT cookie), portal
      // "log out of all apps" cleared oauth2-proxy + Cognito but not this
      // app's cookie, bob then logged in. On refresh, the cookie carries
      // alice's JWT while the X-Auth-Request-Email header says bob.
      // Expect: 302 to /home + Set-Cookie clearing the stale accessToken
      // and lastSignedIn cookies. Browser / fetch auto-follow the
      // redirect with the cookies cleared, landing on the ForwardAuth
      // fwd: path that issues a fresh JWT for bob — no 401 surfaces to
      // the SPA, no "no access to this doc" toast, no manual reload.
      const team = await buildTeam();
      const alice = await buildUser({ teamId: team.id });
      const bob = await buildUser({ teamId: team.id });
      const state = {} as DefaultState;
      const authMiddleware = auth();

      let err: MiddlewareError | undefined;

      const aliceJwt = alice.getSessionToken();

      try {
        await authMiddleware(
          {
            // @ts-expect-error mock request
            request: {
              get: vi.fn((header: string) => {
                if (header === EDGE_SECRET_HEADER) {
return EDGE_SECRET;
}
if (header === "x-auth-request-email") {
                  return bob.email!;
                }
                return "";
              }),
            },
            // @ts-expect-error mock cookies
            cookies: {
              get: vi.fn((key: string) => {
                if (key === "accessToken") {
                  return aliceJwt;
                }
                return undefined;
              }),
            },
            state,
            ip: "127.0.0.1",
            cache: {},
          },
          vi.fn()
        );
      } catch (e) {
        err = e as MiddlewareError;
      }

      expect(err).toBeDefined();
      expect(err?.status).toBe(302);
      expect(err?.headers?.Location).toBe("/home");
      expect(err?.headers?.["set-cookie"]).toEqual(
        expect.arrayContaining([
          expect.stringContaining("accessToken="),
          expect.stringContaining("lastSignedIn="),
        ])
      );
    });

    it("should NOT clear cookie when proxy email matches JWT user", async () => {
      // Steady-state: the same user as the JWT cookie. Header presence
      // should not cause a forced re-auth.
      const team = await buildTeam();
      const user = await buildUser({ teamId: team.id });
      const state = {} as DefaultState;
      const authMiddleware = auth();
      const userJwt = user.getSessionToken();
      const cookiesSet = vi.fn();

      await authMiddleware(
        {
          // @ts-expect-error mock request
          request: {
            get: vi.fn((header: string) => {
              if (header === EDGE_SECRET_HEADER) {
return EDGE_SECRET;
}
if (header === "x-auth-request-email") {
                return user.email!;
              }
              return "";
            }),
          },
          // @ts-expect-error mock cookies
          cookies: {
            get: vi.fn((key: string) => {
              if (key === "accessToken") {
                return userJwt;
              }
              return undefined;
            }),
            set: cookiesSet,
          },
          state,
          ip: "127.0.0.1",
          cache: {},
        },
        vi.fn()
      );

      expect(state.auth.user.id).toEqual(user.id);
      expect(cookiesSet).not.toHaveBeenCalled();
    });

    it("should treat case- and whitespace-variant proxy email as matching the JWT user", async () => {
      // Regression guard for normalizeProxyEmail: oauth2-proxy may forward
      // a header value with different case or surrounding whitespace than
      // the lowercase canonical user.email stored at registration time.
      // The mismatch check must normalise both sides before comparing,
      // otherwise the steady-state path silently kicks every cookie-authed
      // request back to ForwardAuth on case-variant headers.
      const team = await buildTeam();
      const user = await buildUser({ teamId: team.id });
      const state = {} as DefaultState;
      const authMiddleware = auth();
      const userJwt = user.getSessionToken();
      // user.email is canonical lowercase; header is uppercase + whitespace-padded.
      const variantHeader = `  ${user.email!.toUpperCase()}  `;

      await authMiddleware(
        {
          // @ts-expect-error mock request
          request: {
            get: vi.fn((header: string) => {
              if (header === EDGE_SECRET_HEADER) {
return EDGE_SECRET;
}
if (header === "x-auth-request-email") {
                return variantHeader;
              }
              return "";
            }),
          },
          // @ts-expect-error mock cookies
          cookies: {
            get: vi.fn((key: string) => {
              if (key === "accessToken") {
                return userJwt;
              }
              return undefined;
            }),
            set: vi.fn(),
          },
          state,
          ip: "127.0.0.1",
          cache: {},
        },
        vi.fn()
      );

      // No 401 thrown, no cookie cleared — request is authenticated as
      // the same user the JWT carries.
      expect(state.auth.user.id).toEqual(user.id);
    });

    describe("with a client-supplied fwd: token", () => {
      interface ForgedRequest {
        headers?: Record<string, string>;
        body?: Record<string, unknown>;
        query?: Record<string, string>;
        cookie?: string;
      }

      async function authenticateForged({
        headers = {},
        body = {},
        query = {},
        cookie,
      }: ForgedRequest) {
        const state = {} as DefaultState;
        let error: unknown;

        try {
          await auth()(
            buildMockContext({
              request: {
                get: vi.fn(
                  (header: string) =>
                    ({ [EDGE_SECRET_HEADER]: EDGE_SECRET, ...headers })[
                      header.toLowerCase()
                    ] ?? ""
                ),
                body,
                query,
              },
              cookies: {
                get: vi.fn((key: string) =>
                  key === "accessToken" ? cookie : undefined
                ),
                set: vi.fn(),
              },
              state,
              ip: "127.0.0.1",
              cache: {},
            }),
            vi.fn()
          );
        } catch (e) {
          error = e;
        }

        return { state, error };
      }

      const uniqueEmail = () => `${randomString(10).toLowerCase()}@example.com`;

      async function buildAttackerAndVictim() {
        const team = await buildTeam();
        const attackerEmail = uniqueEmail();
        const victimEmail = uniqueEmail();
        await buildUser({ teamId: team.id, email: attackerEmail });
        await buildAdmin({ teamId: team.id, email: victimEmail });
        return { attackerEmail, victimEmail };
      }

      it("should reject a forged fwd: Bearer token even with a valid proxy header", async () => {
        const { attackerEmail, victimEmail } = await buildAttackerAndVictim();

        const { state, error } = await authenticateForged({
          headers: {
            authorization: `Bearer fwd:${victimEmail}`,
            "x-auth-request-email": attackerEmail,
          },
        });

        expect(error).toHaveProperty("status", 401);
        expect(state.auth).toBeUndefined();
      });

      it("should reject a forged fwd: token in the query string", async () => {
        const { attackerEmail, victimEmail } = await buildAttackerAndVictim();

        const { state, error } = await authenticateForged({
          headers: { "x-auth-request-email": attackerEmail },
          query: { token: `fwd:${victimEmail}` },
        });

        expect(error).toHaveProperty("status", 401);
        expect(state.auth).toBeUndefined();
      });

      it("should reject a forged fwd: token in the request body", async () => {
        const { attackerEmail, victimEmail } = await buildAttackerAndVictim();

        const { state, error } = await authenticateForged({
          headers: { "x-auth-request-email": attackerEmail },
          body: { token: `fwd:${victimEmail}` },
        });

        expect(error).toHaveProperty("status", 401);
        expect(state.auth).toBeUndefined();
      });

      it("should reject a forged fwd: accessToken cookie and clear it", async () => {
        const { attackerEmail, victimEmail } = await buildAttackerAndVictim();

        const { state, error } = await authenticateForged({
          headers: { "x-auth-request-email": attackerEmail },
          cookie: `fwd:${victimEmail}`,
        });

        expect(error).toHaveProperty("status", 401);
        expect(error).toHaveProperty(
          ["headers", "set-cookie"],
          expect.arrayContaining([expect.stringContaining("accessToken=;")])
        );
        expect(state.auth).toBeUndefined();
      });

      it("should not provision a user for a forged fwd: token", async () => {
        const forgedEmail = uniqueEmail();

        const { error } = await authenticateForged({
          body: { token: `fwd:${forgedEmail}` },
        });

        expect(error).toHaveProperty("status", 401);
        expect(await User.count({ where: { email: forgedEmail } })).toBe(0);
      });
    });

    it("should not honour ForwardAuth headers when AUTH_TYPE is not SSO", async () => {
      env.AUTH_TYPE = undefined;
      const state = {} as DefaultState;
      const authMiddleware = auth();

      try {
        await authMiddleware(
          {
            // @ts-expect-error mock request
            request: {
              get: vi.fn((header: string) => {
                if (header === EDGE_SECRET_HEADER) {
return EDGE_SECRET;
}
if (header === "x-auth-request-email") {
                  return "attacker@example.com";
                }
                return "";
              }),
              query: {},
            },
            // @ts-expect-error mock cookies
            cookies: { get: vi.fn(() => undefined) },
            state,
            cache: {},
          },
          vi.fn()
        );
        expect(true).toBe(false); // should not reach here
      } catch (e) {
        expect(errToString(e)).toEqual("Authentication required");
      }
    });
  });

  it("should return an error for deleted team", async () => {
    const state = {} as DefaultState;
    const team = await buildTeam();
    const user = await buildUser({ teamId: team.id });
    await team.destroy();
    const authMiddleware = auth();
    let error;

    try {
      await authMiddleware(
        buildMockContext({
          request: {
            get: vi.fn(() => `Bearer ${user.getSessionToken()}`),
          },
          state,
          cache: {},
        }),
        vi.fn()
      );
    } catch (err) {
      error = err;
    }

    expect(errToString(error)).toEqual("Invalid token");
  });
  describe("with skip", () => {
    it("should ignore credentials when skip returns true", async () => {
      const state = {} as DefaultState;
      const user = await buildUser();
      const apiKey = await buildApiKey({
        userId: user.id,
        scope: ["/api/documents.info"],
      });
      const next = vi.fn();
      const authMiddleware = auth({
        optional: true,
        skip: (ctx) => !!ctx.query.sig,
      });
      await authMiddleware(
        buildMockContext({
          request: {
            get: vi.fn(() => `Bearer ${apiKey.value}`),
          },
          query: { sig: "signature" },
          originalUrl: "/api/files.get?sig=signature",
          state,
          cache: {},
        }),
        next
      );
      expect(next).toHaveBeenCalled();
      expect(state.auth).toEqual({});
    });

    it("should authenticate when skip returns false", async () => {
      const state = {} as DefaultState;
      const user = await buildUser();
      const next = vi.fn();
      const authMiddleware = auth({
        optional: true,
        skip: (ctx) => !!ctx.query.sig,
      });
      await authMiddleware(
        buildMockContext({
          request: {
            get: vi.fn(() => `Bearer ${user.getSessionToken()}`),
          },
          query: {},
          state,
          cache: {},
        }),
        next
      );
      expect(next).toHaveBeenCalled();
      expect(state.auth.user.id).toEqual(user.id);
    });
  });
});

describe("Authentication middleware - cookie cleanup regression", () => {
  it("clears auth cookies on 401 when using cookie JWT (no Authorization header)", async () => {
    const state = {} as DefaultState;

    const ctx = {
      state,
      cache: {},
      request: {
        get: vi.fn(() => undefined),
      },
      cookies: {
        get: vi.fn((key: string) => {
          if (key === "accessToken") {
            return "cookie-token";
          }
          return undefined;
        }),
      },
    };

    const authMiddleware = auth();

    let err: MiddlewareError | undefined;

    try {
      // @ts-expect-error mock context
      await authMiddleware(ctx, async () => {
        throw Object.assign(new Error("fail"), { status: 401 });
      });
    } catch (e) {
      err = e as MiddlewareError;
    }

    expect(err).toBeDefined();

    expect(err?.headers?.["set-cookie"]).toEqual(
      expect.arrayContaining([
        expect.stringContaining("accessToken="),
        expect.stringContaining("lastSignedIn="),
      ])
    );
  });

  it("does NOT clear cookies when Authorization header is present", async () => {
    const state = {} as DefaultState;

    const ctx = {
      state,
      cache: {},
      request: {
        get: vi.fn((header: string) => {
          if (header === "authorization") {
            return "Bearer fake.jwt.token";
          }
          return undefined;
        }),
      },
      cookies: {
        get: vi.fn(() => "cookie-token"),
      },
    };

    const authMiddleware = auth();

    let err: MiddlewareError | undefined;

    try {
      // @ts-expect-error mock context
      await authMiddleware(ctx, async () => {
        throw Object.assign(new Error("fail"), { status: 401 });
      });
    } catch (e) {
      err = e as MiddlewareError;
    }

    expect(err).toBeDefined();

    // 🔥 core regression assertion
    expect(err?.headers?.["set-cookie"]).toBeUndefined();
  });
});

describe("Authentication middleware - mPass edge trust", () => {
  interface EdgeRequest {
    headers?: Record<string, string>;
    cookie?: string;
    remoteAddress?: string;
  }

  const uniqueEmail = () => `${randomString(10).toLowerCase()}@example.com`;

  async function authenticate({
    headers = {},
    cookie,
    remoteAddress = "172.18.0.9",
  }: EdgeRequest) {
    const state = {} as DefaultState;
    let error: unknown;

    try {
      await auth()(
        {
          // @ts-expect-error mock request
          request: {
            get: vi.fn((header: string) => headers[header.toLowerCase()] ?? ""),
            body: {},
            query: {},
          },
          // @ts-expect-error mock cookies
          cookies: {
            get: vi.fn((key: string) =>
              key === "accessToken" ? cookie : undefined
            ),
            set: vi.fn(),
          },
          // @ts-expect-error mock node request
          req: { socket: { remoteAddress } },
          path: "/api/auth.info",
          state,
          ip: "127.0.0.1",
          cache: {},
        },
        vi.fn()
      );
    } catch (e) {
      error = e;
    }

    return { state, error };
  }

  beforeEach(() => {
    env.AUTH_TYPE = AUTH_TYPE_SSO;
    env.MPASS_EDGE_SECRET = EDGE_SECRET;
  });

  afterEach(() => {
    env.AUTH_TYPE = undefined;
    env.MPASS_EDGE_SECRET = "";
    vi.restoreAllMocks();
  });

  describe("identity headers", () => {
    it("logs in a request that came through the edge", async () => {
      const user = await buildUser({ email: uniqueEmail() });

      const { state, error } = await authenticate({
        headers: {
          "x-auth-request-email": user.email!,
          [EDGE_SECRET_HEADER]: EDGE_SECRET,
        },
      });

      expect(error).toBeUndefined();
      expect(state.auth.user.id).toEqual(user.id);
      expect(state.auth.service).toEqual(FORWARDAUTH_SERVICE);
    });

    it.each([
      ["without the edge secret", {}],
      ["with a wrong edge secret", { [EDGE_SECRET_HEADER]: "x".repeat(64) }],
    ])(
      "ignores a forged header %s and neither logs in nor provisions",
      async (_label, edgeHeaders) => {
        const victim = await buildAdmin({ email: uniqueEmail() });
        const stranger = uniqueEmail();

        const forgedVictim = await authenticate({
          headers: { "x-auth-request-email": victim.email!, ...edgeHeaders },
        });
        const forgedStranger = await authenticate({
          headers: { "x-auth-request-email": stranger, ...edgeHeaders },
        });

        expect(forgedVictim.error).toHaveProperty("status", 401);
        expect(forgedVictim.state.auth).toBeUndefined();
        expect(forgedStranger.error).toHaveProperty("status", 401);
        expect(await User.count({ where: { email: stranger } })).toBe(0);
      }
    );

    it.each([
      ["unset", ""],
      ["shorter than 32 characters", "s".repeat(31)],
    ])(
      "trusts no identity header when the configured secret is %s",
      async (_label, secret) => {
        env.MPASS_EDGE_SECRET = secret;
        const user = await buildUser({ email: uniqueEmail() });

        const { error } = await authenticate({
          headers: {
            "x-auth-request-email": user.email!,
            [EDGE_SECRET_HEADER]: secret,
          },
        });

        expect(error).toHaveProperty("status", 401);
      }
    );

    it("warns with the mPass id, path and socket address but never the email", async () => {
      const warn = vi.spyOn(Logger, "warn");
      const email = uniqueEmail();

      const remoteAddress = `172.20.${randomString(4)}`;

      await authenticate({
        headers: {
          "x-auth-request-email": email,
          "x-auth-request-user": email,
          "x-auth-request-preferred-username": "mpass-123",
          "x-forwarded-for": "10.9.9.9",
        },
        remoteAddress,
      });

      expect(warn).toHaveBeenCalledWith(
        "mPass identity headers ignored: request lacks the edge secret",
        {
          mpassId: "mpass-123",
          path: "/api/auth.info",
          remoteAddr: remoteAddress,
        }
      );
      expect(JSON.stringify(warn.mock.calls)).not.toContain(email);
    });

    it("caps the logged mPass id at 64 characters", async () => {
      const warn = vi.spyOn(Logger, "warn");

      await authenticate({
        headers: {
          "x-auth-request-email": uniqueEmail(),
          "x-auth-request-preferred-username": "m".repeat(500),
        },
        remoteAddress: `172.21.${randomString(4)}`,
      });

      expect(warn).toHaveBeenCalledWith(
        "mPass identity headers ignored: request lacks the edge secret",
        expect.objectContaining({ mpassId: "m".repeat(64) })
      );
    });

    it("warns once per remote address within a minute", async () => {
      const warn = vi.spyOn(Logger, "warn");
      const remoteAddress = `172.22.${randomString(4)}`;
      const forged = {
        headers: { "x-auth-request-email": uniqueEmail() },
        remoteAddress,
      };

      await authenticate(forged);
      await authenticate(forged);

      expect(
        warn.mock.calls.filter(([message]) =>
          message.startsWith("mPass identity headers ignored")
        )
      ).toHaveLength(1);
    });

    it("does not end a session on a forged identity switch", async () => {
      const user = await buildUser({ email: uniqueEmail() });
      const other = await buildUser({ email: uniqueEmail() });

      const { state, error } = await authenticate({
        headers: { "x-auth-request-email": other.email! },
        cookie: user.getSessionToken(),
      });

      expect(error).toBeUndefined();
      expect(state.auth.user.id).toEqual(user.id);
    });

    it("still redirects a stale session on an edge-vouched identity switch", async () => {
      const user = await buildUser({ email: uniqueEmail() });
      const other = await buildUser({ email: uniqueEmail() });

      const { error } = await authenticate({
        headers: {
          "x-auth-request-email": other.email!,
          [EDGE_SECRET_HEADER]: EDGE_SECRET,
        },
        cookie: user.getSessionToken(),
      });

      expect(error).toHaveProperty("status", 302);
    });

    it("authenticates an API key even when forged identity headers are present", async () => {
      const user = await buildUser();
      const apiKey = await buildApiKey({ userId: user.id });
      const victim = await buildAdmin({ teamId: user.teamId });

      const { state, error } = await authenticate({
        headers: {
          authorization: `Bearer ${apiKey.value}`,
          "x-auth-request-email": victim.email!,
        },
      });

      expect(error).toBeUndefined();
      expect(state.auth.user.id).toEqual(user.id);
      expect(state.auth.type).toEqual(AuthenticationType.API);
    });
  });

  describe("corporate gate", () => {
    const CLIENT_ID = "outline-client";
    const CORPORATE_ID = "corp-42";
    const KID = "kid-1";
    const keyPair = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const otherKeyPair = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const jwks = {
      keys: [{ ...keyPair.publicKey.export({ format: "jwk" }), kid: KID }],
    };
    let issuer: string;

    function token(
      overrides: Record<string, unknown> = {},
      privateKey = keyPair.privateKey
    ) {
      return jwt.sign(
        {
          iss: issuer,
          token_use: "access",
          client_id: CLIENT_ID,
          "custom:is_corporate": "true",
          "custom:corporate_id": CORPORATE_ID,
          exp: Math.floor(Date.now() / 1000) + 300,
          ...overrides,
        },
        privateKey.export({ type: "pkcs8", format: "pem" }),
        { algorithm: "RS256", keyid: KID }
      );
    }

    function serveJwks(respond: () => Response) {
      const jwksHandler = vi.fn(respond);
      server.use(http.get(`${issuer}/.well-known/jwks.json`, jwksHandler));
      return jwksHandler;
    }

    async function edgeLogin(accessToken?: string) {
      const user = await buildUser({ email: uniqueEmail() });
      const headers: Record<string, string> = {
        "x-auth-request-email": user.email!,
        [EDGE_SECRET_HEADER]: EDGE_SECRET,
      };
      if (accessToken) {
        headers["x-auth-request-access-token"] = accessToken;
      }
      return { user, ...(await authenticate({ headers })) };
    }

    beforeEach(() => {
      issuer = `https://issuer-${randomString(8).toLowerCase()}.example.test/pool`;
      env.SMB_CORPORATE_ID = CORPORATE_ID;
      env.MPASS_COGNITO_ISSUER_URL = issuer;
      env.MPASS_OIDC_CLIENT_ID = CLIENT_ID;
    });

    afterEach(() => {
      env.SMB_CORPORATE_ID = "";
      env.MPASS_COGNITO_ISSUER_URL = "";
      env.MPASS_OIDC_CLIENT_ID = "";
    });

    it("logs in a member of this corporation with a verified token", async () => {
      serveJwks(() => HttpResponse.json(jwks));

      const { user, state, error } = await edgeLogin(token());

      expect(error).toBeUndefined();
      expect(state.auth.user.id).toEqual(user.id);
    });

    it.each([
      ["missing_token", () => undefined],
      ["bad_signature", () => token({}, otherKeyPair.privateKey)],
      ["expired", () => token({ exp: Math.floor(Date.now() / 1000) - 600 })],
      [
        "untrusted_issuer",
        () => token({ iss: "https://evil.example.test/pool" }),
      ],
      ["wrong_audience", () => token({ client_id: "another-client" })],
      ["not_corporate", () => token({ "custom:is_corporate": "false" })],
      ["wrong_organization", () => token({ "custom:corporate_id": "corp-7" })],
    ])("refuses with %s", async (reason, accessToken) => {
      serveJwks(() => HttpResponse.json(jwks));
      const warn = vi.spyOn(Logger, "warn");

      const { state, error } = await edgeLogin(accessToken());

      expect(error).toHaveProperty("status", 401);
      expect(state.auth).toBeUndefined();
      expect(warn).toHaveBeenCalledWith(
        "mPass proxy login refused",
        expect.objectContaining({ reason })
      );
    });

    it("refuses an unsigned token it used to accept from a forged decode", async () => {
      serveJwks(() => HttpResponse.json(jwks));
      const unsigned = jwt.sign(
        {
          iss: issuer,
          token_use: "access",
          client_id: CLIENT_ID,
          "custom:is_corporate": "true",
          "custom:corporate_id": CORPORATE_ID,
        },
        "",
        { algorithm: "none" }
      );

      const { error } = await edgeLogin(unsigned);

      expect(error).toHaveProperty("status", 401);
    });

    it.each([
      ["a network error", () => HttpResponse.error()],
      ["a server error", () => new HttpResponse(null, { status: 503 })],
      ["a non-JSON body", () => new HttpResponse("<html>", { status: 200 })],
    ])(
      "fails closed with jwks_unavailable and no 500 on %s",
      async (_label, respond) => {
        serveJwks(respond);
        const warn = vi.spyOn(Logger, "warn");

        const { error } = await edgeLogin(token());

        expect(error).toHaveProperty("status", 401);
        expect(warn).toHaveBeenCalledWith(
          "mPass proxy login refused",
          expect.objectContaining({ reason: "jwks_unavailable" })
        );
      }
    );

    it("refuses every login when the gate is on but no issuer is configured", async () => {
      env.MPASS_COGNITO_ISSUER_URL = "";
      const warn = vi.spyOn(Logger, "warn");

      const { error } = await edgeLogin(token());

      expect(error).toHaveProperty("status", 401);
      expect(warn).toHaveBeenCalledWith(
        "mPass proxy login refused",
        expect.objectContaining({ reason: "verifier_unconfigured" })
      );
    });

    async function establishedRequest(accessToken?: string) {
      const user = await buildUser({ email: uniqueEmail() });
      const headers: Record<string, string> = {
        "x-auth-request-email": user.email!,
        [EDGE_SECRET_HEADER]: EDGE_SECRET,
      };
      if (accessToken) {
        headers["x-auth-request-access-token"] = accessToken;
      }
      return {
        user,
        ...(await authenticate({ headers, cookie: user.getSessionToken() })),
      };
    }

    describe("on an established session", () => {
      it.each([
        ["jwks_unavailable", () => new HttpResponse(null, { status: 503 })],
        ["expired", () => HttpResponse.json(jwks)],
      ])(
        "keeps the session when the check is inconclusive (%s)",
        async (reason, respond) => {
          serveJwks(respond);
          const info = vi.spyOn(Logger, "info");
          const accessToken =
            reason === "expired"
              ? token({ exp: Math.floor(Date.now() / 1000) - 600 })
              : token();

          const { user, state, error } = await establishedRequest(accessToken);

          expect(error).toBeUndefined();
          expect(state.auth.user.id).toEqual(user.id);
          expect(info).toHaveBeenCalledWith(
            "authentication",
            "mPass corporate check inconclusive: established session kept",
            expect.objectContaining({ reason })
          );
        }
      );

      it("keeps the session when no token is forwarded", async () => {
        const { user, state, error } = await establishedRequest();

        expect(error).toBeUndefined();
        expect(state.auth.user.id).toEqual(user.id);
      });

      it.each([
        ["not_corporate", { "custom:is_corporate": "false" }],
        ["wrong_organization", { "custom:corporate_id": "corp-7" }],
      ])(
        "ends the session when a valid token says %s",
        async (reason, claims) => {
          serveJwks(() => HttpResponse.json(jwks));
          const warn = vi.spyOn(Logger, "warn");

          const { state, error } = await establishedRequest(token(claims));

          expect(error).toHaveProperty("status", 401);
          expect(error).toHaveProperty(
            ["headers", "set-cookie"],
            expect.arrayContaining([expect.stringContaining("accessToken=;")])
          );
          expect(state.auth).toBeUndefined();
          expect(warn).toHaveBeenCalledWith(
            "mPass proxy login refused",
            expect.objectContaining({ reason })
          );
        }
      );

      it("verifies each forwarded token once until it expires", async () => {
        const jwksHandler = serveJwks(() => HttpResponse.json(jwks));
        const accessToken = token();

        await establishedRequest(accessToken);
        await establishedRequest(accessToken);

        expect(jwksHandler).toHaveBeenCalledTimes(1);
      });

      it("does not run the gate on a session request that bypassed the edge", async () => {
        const jwksHandler = serveJwks(() => HttpResponse.json(jwks));
        const user = await buildUser({ email: uniqueEmail() });

        const { state, error } = await authenticate({
          headers: {
            "x-auth-request-access-token": token({
              "custom:corporate_id": "corp-7",
            }),
          },
          cookie: user.getSessionToken(),
        });

        expect(error).toBeUndefined();
        expect(state.auth.user.id).toEqual(user.id);
        expect(jwksHandler).not.toHaveBeenCalled();
      });
    });

    it("trims SMB_CORPORATE_ID before comparing", async () => {
      env.SMB_CORPORATE_ID = `  ${CORPORATE_ID} `;
      serveJwks(() => HttpResponse.json(jwks));

      const { error } = await edgeLogin(token());

      expect(error).toBeUndefined();
    });

    describe("with a CHANGE_ME_ SMB_CORPORATE_ID", () => {
      beforeEach(() => {
        env.SMB_CORPORATE_ID = " CHANGE_ME_SMB_CORPORATE_ID ";
      });

      it("refuses a new login with placeholder_config, even with a valid token", async () => {
        const jwksHandler = serveJwks(() => HttpResponse.json(jwks));
        const warn = vi.spyOn(Logger, "warn");

        const { state, error } = await edgeLogin(token());

        expect(error).toHaveProperty("status", 401);
        expect(state.auth).toBeUndefined();
        expect(jwksHandler).not.toHaveBeenCalled();
        expect(warn).toHaveBeenCalledWith(
          "mPass proxy login refused",
          expect.objectContaining({ reason: "placeholder_config" })
        );
      });

      it("ends an established session", async () => {
        serveJwks(() => HttpResponse.json(jwks));

        const { state, error } = await establishedRequest(token());

        expect(error).toHaveProperty("status", 401);
        expect(state.auth).toBeUndefined();
      });
    });

    it("treats a whitespace-only SMB_CORPORATE_ID as unset", async () => {
      env.SMB_CORPORATE_ID = "   ";
      const jwksHandler = serveJwks(() => HttpResponse.json(jwks));

      const { error } = await edgeLogin();

      expect(error).toBeUndefined();
      expect(jwksHandler).not.toHaveBeenCalled();
    });

    it("reads no token and fetches no JWKS when SMB_CORPORATE_ID is unset", async () => {
      env.SMB_CORPORATE_ID = "";
      const jwksHandler = serveJwks(() => HttpResponse.json(jwks));

      const { user, state, error } = await edgeLogin("not-a-jwt");

      expect(error).toBeUndefined();
      expect(state.auth.user.id).toEqual(user.id);
      expect(jwksHandler).not.toHaveBeenCalled();
    });
  });
});
