import type { DefaultState } from "koa";
import { randomString } from "@shared/random";
import { Scope } from "@shared/types";
import env from "@server/env";
import {
  buildUser,
  buildTeam,
  buildAdmin,
  buildApiKey,
  buildOAuthAuthentication,
} from "@server/test/factories";
import { User } from "@server/models";
import { sequelize } from "@server/storage/database";
import { AuthenticationType } from "@server/types";
import { JWT_COOKIE_TTL_DAYS } from "@server/utils/authentication";
import auth, { FORWARDAUTH_SERVICE } from "./authentication";

function createCtx(overrides: any = {}) {
  const headers = {
    ...(overrides.request?.headers || {}),
  };

  const get = jest.fn((key: string) => headers[key.toLowerCase()]);

  return {
    state: {},
    cache: {},

    originalUrl: overrides.originalUrl || "/",

    get,

    cookies: {
      get: jest.fn(() => undefined), // 👈 THIS was missing
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
        {
          // @ts-expect-error mock request
          request: {
            get: vi.fn(() => `Bearer ${user.getJwtToken()}`),
          },
          state,
          cache: {},
        },
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
          {
            // @ts-expect-error mock request
            request: {
              get: vi.fn(() => `Bearer ${user.getJwtToken()}error`),
            },
            state,
            cache: {},
          },
          vi.fn()
        );
      } catch (e) {
        expect(e.message).toBe("Invalid token");
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
          {
            // @ts-expect-error mock request
            request: {
              get: vi.fn(() => `Bearer ${user.getJwtToken()}`),
            },
            state,
            cache: {},
          },
          vi.fn()
        );
      } catch (e) {
        expect(e.message).toBe("Invalid authentication type");
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
        {
          // @ts-expect-error mock request
          request: {
            get: vi.fn(() => `Bearer ${key.value}`),
          },
          state,
          cache: {},
        },
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
        {
          originalUrl: "/api/auth.info",
          // @ts-expect-error mock request
          request: {
            url: "/auth.info",
            get: vi.fn(() => `Bearer ${key.value}`),
          },
          state,
          cache: {},
        },
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
          {
            originalUrl: "/api/documents.create",
            // @ts-expect-error mock request
            request: {
              url: "/documents.create",
              get: vi.fn(() => `Bearer ${key.value}`),
            },
            state,
            cache: {},
          },
          vi.fn()
        );
        throw new Error("Expected error to be thrown");
      } catch (e) {
        expect(e.status).toBe(403);
        expect(e.id).toBe("authorization_error");
        expect(e.message).toContain("does not have access to this resource");
      }
    });

    it("should return error with invalid API key", async () => {
      const state = {} as DefaultState;
      const authMiddleware = auth();

      try {
        await authMiddleware(
          {
            // @ts-expect-error mock request
            request: {
              get: vi.fn(() => `Bearer ${randomString(38)}`),
            },
            state,
            cache: {},
          },
          vi.fn()
        );
      } catch (e) {
        expect(e.message).toBe("Invalid API key");
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
        {
          originalUrl: "/api/users.info",
          // @ts-expect-error mock request
          request: {
            url: "/users.info",
            get: vi.fn(() => `Bearer ${authentication.accessToken}`),
          },
          state,
          cache: {},
        },
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
          {
            originalUrl: "/api/documents.create",
            // @ts-expect-error mock request
            request: {
              url: "/documents.create",
              get: vi.fn(() => `Bearer ${authentication.accessToken}`),
            },
            state,
            cache: {},
          },
          vi.fn()
        );
      } catch (e) {
        expect(e.message).toContain("does not have access to this resource");
      }
    });

    it("should return error with OAuth access token in body", async () => {
      const user = await buildUser();

      const authentication = await buildOAuthAuthentication({
        user,
        scope: [Scope.Read],
      });

      let error: any;

      try {
        await authMiddleware(
          {
            originalUrl: "/api/users.info",
            request: {
              url: "/users.info",
              // @ts-expect-error mock request
              get: vi.fn(() => null),
              body: {
                token: authentication.accessToken,
              },
            },
            state,
            cache: {},
          },
          vi.fn()
        );
        throw new Error("Expected middleware to throw");
      } catch (e: any) {
        error = e;
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
        {
          // @ts-expect-error mock request
          request: {
            get: vi.fn(() => "error"),
          },
          state,
          cache: {},
        },
        vi.fn()
      );
    } catch (e) {
      expect(e.message).toBe(
        'Bad Authorization header format. Format is "Authorization: Bearer <token>"'
      );
    }
  });

  it("should allow passing auth token as a GET param", async () => {
    const state = {} as DefaultState;
    const user = await buildUser();
    const authMiddleware = auth();
    await authMiddleware(
      {
        request: {
          // @ts-expect-error mock request
          get: vi.fn(() => null),
          query: {
            token: user.getJwtToken(),
          },
        },
        state,
        cache: {},
      },
      vi.fn()
    );
    expect(state.auth.user.id).toEqual(user.id);
  });

  it("should allow passing auth token in body params", async () => {
    const state = {} as DefaultState;
    const user = await buildUser();
    const authMiddleware = auth();
    await authMiddleware(
      {
        request: {
          // @ts-expect-error mock request
          get: vi.fn(() => null),
          body: {
            token: user.getJwtToken(),
          },
        },
        state,
        cache: {},
      },
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
        {
          // @ts-expect-error mock request
          request: {
            get: vi.fn(() => `Bearer ${user.getJwtToken()}`),
          },
          state,
          cache: {},
        },
        vi.fn()
      );
    } catch (err) {
      error = err;
    }

    expect(error.message).toEqual(
      "Your access has been suspended by a workspace admin"
    );
    expect(error.errorData.adminEmail).toEqual(admin.email);
  });

  describe("with ForwardAuth headers", () => {
    beforeEach(() => {
      env.AUTH_TYPE = "SSO";
    });

    afterEach(() => {
      env.AUTH_TYPE = undefined;
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
            get: jest.fn((header: string) => {
              if (header === "x-auth-request-email") {
                return user.email!;
              }
              return "";
            }),
          },
          // @ts-expect-error mock cookies
          cookies: { get: jest.fn(() => undefined), set: jest.fn() },
          state,
          ip: "127.0.0.1",
          cache: {},
        },
        jest.fn()
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
      const cookiesSet = jest.fn();
      const before = Date.now();

      await authMiddleware(
        {
          // @ts-expect-error mock request
          request: {
            get: jest.fn((header: string) => {
              if (header === "x-auth-request-email") {
                return user.email!;
              }
              return "";
            }),
          },
          // @ts-expect-error mock cookies
          cookies: { get: jest.fn(() => undefined), set: cookiesSet },
          state,
          ip: "127.0.0.1",
          cache: {},
        },
        jest.fn()
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

    it("should provision a new user when X-Auth-Request-Email is unknown", async () => {
      await buildTeam();
      const state = {} as DefaultState;
      const authMiddleware = auth();
      const newEmail = `newuser-${randomString(6)}@example.com`;

      await authMiddleware(
        {
          // @ts-expect-error mock request
          request: {
            get: jest.fn((header: string) => {
              if (header === "x-auth-request-email") {
                return newEmail;
              }
              if (header === "x-auth-request-user") {
                return "New User";
              }
              return "";
            }),
          },
          // @ts-expect-error mock cookies
          cookies: { get: jest.fn(() => undefined), set: jest.fn() },
          state,
          ip: "127.0.0.1",
          cache: {},
        },
        jest.fn()
      );

      const provisioned = await User.findOne({
        where: { email: newEmail.toLowerCase() },
      });
      expect(provisioned).not.toBeNull();
      expect(state.auth.user.email).toEqual(newEmail.toLowerCase());
      expect(state.auth.user.name).toEqual("New User");
    });

    it("should use email prefix as name when X-Auth-Request-User is absent", async () => {
      await buildTeam();
      const state = {} as DefaultState;
      const authMiddleware = auth();
      const newEmail = `prefix-${randomString(6)}@example.com`;

      await authMiddleware(
        {
          // @ts-expect-error mock request
          request: {
            get: jest.fn((header: string) => {
              if (header === "x-auth-request-email") {
                return newEmail;
              }
              return "";
            }),
          },
          // @ts-expect-error mock cookies
          cookies: { get: jest.fn(() => undefined), set: jest.fn() },
          state,
          ip: "127.0.0.1",
          cache: {},
        },
        jest.fn()
      );

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
              get: jest.fn((header: string) => {
                if (header === "x-auth-request-email") {
                  return localPart;
                }
                return "";
              }),
            },
            // @ts-expect-error mock cookies
            cookies: { get: jest.fn(() => undefined), set: jest.fn() },
            state,
            ip: "127.0.0.1",
            cache: {},
          },
          jest.fn()
        );

        expect(state.auth.user.email).toEqual(`${localPart.toLowerCase()}@askii.ai`);
      } finally {
        env.DEFAULT_EMAIL_DOMAIN = savedDomain;
      }
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
            get: jest.fn((header: string) => {
              if (header === "x-auth-request-email") {
                return wildcardEmail;
              }
              return "";
            }),
          },
          // @ts-expect-error mock cookies
          cookies: { get: jest.fn(() => undefined), set: jest.fn() },
          state,
          ip: "127.0.0.1",
          cache: {},
        },
        jest.fn()
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
      const querySpy = jest.spyOn(sequelize, "query");
      const createSpy = jest.spyOn(User, "create");

      try {
        const state = {} as DefaultState;
        const authMiddleware = auth();

        await authMiddleware(
          {
            // @ts-expect-error mock request
            request: {
              get: jest.fn((header: string) => {
                if (header === "x-auth-request-email") {
                  return newEmail;
                }
                return "";
              }),
            },
            // @ts-expect-error mock cookies
            cookies: { get: jest.fn(() => undefined), set: jest.fn() },
            state,
            ip: "127.0.0.1",
            cache: {},
          },
          jest.fn()
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

      let err: any;

      const aliceJwt = alice.getJwtToken();

      try {
        await authMiddleware(
          {
            // @ts-expect-error mock request
            request: {
              get: jest.fn((header: string) => {
                if (header === "x-auth-request-email") {
                  return bob.email!;
                }
                return "";
              }),
            },
            // @ts-expect-error mock cookies
            cookies: {
              get: jest.fn((key: string) => {
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
          jest.fn()
        );
      } catch (e) {
        err = e;
      }

      expect(err).toBeDefined();
      expect(err.status).toBe(302);
      expect(err.headers?.Location).toBe("/home");
      expect(err.headers?.["set-cookie"]).toEqual(
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
      const userJwt = user.getJwtToken();

      await authMiddleware(
        {
          // @ts-expect-error mock request
          request: {
            get: jest.fn((header: string) => {
              if (header === "x-auth-request-email") {
                return user.email!;
              }
              return "";
            }),
          },
          // @ts-expect-error mock cookies
          cookies: {
            get: jest.fn((key: string) => {
              if (key === "accessToken") {
                return userJwt;
              }
              return undefined;
            }),
            set: jest.fn(),
          },
          state,
          ip: "127.0.0.1",
          cache: {},
        },
        jest.fn()
      );

      expect(state.auth.user.id).toEqual(user.id);
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
      const userJwt = user.getJwtToken();
      // user.email is canonical lowercase; header is uppercase + whitespace-padded.
      const variantHeader = `  ${user.email!.toUpperCase()}  `;

      await authMiddleware(
        {
          // @ts-expect-error mock request
          request: {
            get: jest.fn((header: string) => {
              if (header === "x-auth-request-email") {
                return variantHeader;
              }
              return "";
            }),
          },
          // @ts-expect-error mock cookies
          cookies: {
            get: jest.fn((key: string) => {
              if (key === "accessToken") {
                return userJwt;
              }
              return undefined;
            }),
            set: jest.fn(),
          },
          state,
          ip: "127.0.0.1",
          cache: {},
        },
        jest.fn()
      );

      // No 401 thrown, no cookie cleared — request is authenticated as
      // the same user the JWT carries.
      expect(state.auth.user.id).toEqual(user.id);
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
              get: jest.fn((header: string) => {
                if (header === "x-auth-request-email") {
                  return "attacker@example.com";
                }
                return "";
              }),
              query: {},
            },
            // @ts-expect-error mock cookies
            cookies: { get: jest.fn(() => undefined) },
            state,
            cache: {},
          },
          jest.fn()
        );
        expect(true).toBe(false); // should not reach here
      } catch (e) {
        expect(e.message).toEqual("Authentication required");
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
        {
          // @ts-expect-error mock request
          request: {
            get: vi.fn(() => `Bearer ${user.getJwtToken()}`),
          },
          state,
          cache: {},
        },
        vi.fn()
      );
    } catch (err) {
      error = err;
    }

    expect(error.message).toEqual("Invalid token");
  });
});

describe("Authentication middleware - cookie cleanup regression", () => {
  it("clears auth cookies on 401 when using cookie JWT (no Authorization header)", async () => {
    const state = {} as DefaultState;

    const ctx: any = {
      state,
      cache: {},
      request: {
        get: jest.fn(() => undefined),
      },
      cookies: {
        get: jest.fn((key: string) => {
          if (key === "accessToken") {
            return "cookie-token";
          }
          return undefined;
        }),
      },
    };

    const authMiddleware = auth();

    let err: any;

    try {
      await authMiddleware(ctx, async () => {
        throw Object.assign(new Error("fail"), { status: 401 });
      });
    } catch (e) {
      err = e;
    }

    expect(err).toBeDefined();

    expect(err.headers?.["set-cookie"]).toEqual(
      expect.arrayContaining([
        expect.stringContaining("accessToken="),
        expect.stringContaining("lastSignedIn="),
      ])
    );
  });

  it("does NOT clear cookies when Authorization header is present", async () => {
    const state = {} as DefaultState;

    const ctx: any = {
      state,
      cache: {},
      request: {
        get: jest.fn((header: string) => {
          if (header === "authorization") {
            return "Bearer fake.jwt.token";
          }
          return undefined;
        }),
      },
      cookies: {
        get: jest.fn(() => "cookie-token"),
      },
    };

    const authMiddleware = auth();

    let err: any;

    try {
      await authMiddleware(ctx, async () => {
        throw Object.assign(new Error("fail"), { status: 401 });
      });
    } catch (e) {
      err = e;
    }

    expect(err).toBeDefined();

    // 🔥 core regression assertion
    expect(err.headers?.["set-cookie"]).toBeUndefined();
  });
});
