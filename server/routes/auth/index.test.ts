import env from "@server/env";
import { buildUser, buildCollection } from "@server/test/factories";
import { getTestServer } from "@server/test/support";
import { JWT_COOKIE_TTL_DAYS } from "@server/utils/authentication";

const server = getTestServer();

describe("auth/redirect", () => {
  it("should redirect to home", async () => {
    const user = await buildUser();
    const res = await server.get(
      `/auth/redirect?token=${user.getTransferToken()}`,
      {
        redirect: "manual",
      }
    );
    expect(res.status).toEqual(302);
    expect(res.headers.get("location")).not.toBeNull();
    expect(res.headers.get("location")!.endsWith("/home")).toBeTruthy();
  });

  it("should redirect to first collection", async () => {
    const collection = await buildCollection();
    const user = await buildUser({
      teamId: collection.teamId,
    });
    const res = await server.get(
      `/auth/redirect?token=${user.getTransferToken()}`,
      {
        redirect: "manual",
      }
    );
    expect(res.status).toEqual(302);
    expect(res.headers.get("location")).not.toBeNull();
    expect(res.headers.get("location")!.includes(collection.path)).toBeTruthy();
  });

  it("should prevent token extension by rejecting JWT tokens", async () => {
    const user = await buildUser();
    const jwtToken = user.getJwtToken();

    const res = await server.get(`/auth/redirect?token=${jwtToken}`, {
      redirect: "manual",
    });

    expect(res.status).toEqual(401);
  });

  it("should mint an accessToken JWT carrying an expiresAt claim ~JWT_COOKIE_TTL_DAYS out", async () => {
    const user = await buildUser();
    const before = Date.now();

    const res = await server.get(
      `/auth/redirect?token=${user.getTransferToken()}`,
      {
        redirect: "manual",
      }
    );

    expect(res.status).toEqual(302);

    // Pull the `accessToken` cookie out of the Set-Cookie header(s).
    const setCookie = res.headers.get("set-cookie") || "";
    const match = setCookie.match(/accessToken=([^;,]+)/);
    expect(match).not.toBeNull();
    const jwt = match![1];

    // Decode the JWT payload directly — no signature check needed, we're
    // only inspecting the claim. JWT payload is the base64url middle segment.
    const payload = JSON.parse(
      Buffer.from(jwt.split(".")[1], "base64url").toString()
    );

    // Without the fix, getJwtToken(undefined, ...) would omit this claim
    // entirely and the validator at utils/jwt.ts:47 would skip the check.
    expect(payload.expiresAt).toBeDefined();

    const ageMs = new Date(payload.expiresAt).getTime() - before;
    const expectedMs = JWT_COOKIE_TTL_DAYS * 24 * 60 * 60 * 1000;
    // Allow ±60s skew for test runtime.
    expect(ageMs).toBeGreaterThan(expectedMs - 60_000);
    expect(ageMs).toBeLessThan(expectedMs + 60_000);
  });
});

describe("auth/portal-logout", () => {
  let originalAllowlist: string[];

  beforeEach(() => {
    originalAllowlist = env.MPASS_SIGNOUT_NEXT_ALLOWED_HOSTS;
  });

  afterEach(() => {
    env.MPASS_SIGNOUT_NEXT_ALLOWED_HOSTS = originalAllowlist;
  });

  const setAllowlist = (entries: string[]) => {
    env.MPASS_SIGNOUT_NEXT_ALLOWED_HOSTS = entries;
  };

  it("should clear accessToken and lastSignedIn cookies on every call", async () => {
    setAllowlist([]);
    const res = await server.get("/auth/portal-logout", { redirect: "manual" });
    expect(res.status).toEqual(200);
    const setCookie = res.headers.get("set-cookie") ?? "";
    expect(setCookie).toMatch(/accessToken=;/);
    expect(setCookie).toMatch(/lastSignedIn=;/);
  });

  it("should 302 to next when host is in the allowlist", async () => {
    setAllowlist(["foss.arbisoft.com"]);
    const target = "https://pm.foss.arbisoft.com/auth/portal-sign-out/";
    const res = await server.get(
      `/auth/portal-logout?next=${encodeURIComponent(target)}`,
      { redirect: "manual" }
    );
    expect(res.status).toEqual(302);
    expect(res.headers.get("location")).toEqual(target);
    // cookies still cleared
    const setCookie = res.headers.get("set-cookie") ?? "";
    expect(setCookie).toMatch(/accessToken=;/);
  });

  it("should match subdomains of allowlist entries", async () => {
    setAllowlist(["foss.arbisoft.com"]);
    const target = "https://docs.foss.arbisoft.com/done";
    const res = await server.get(
      `/auth/portal-logout?next=${encodeURIComponent(target)}`,
      { redirect: "manual" }
    );
    expect(res.status).toEqual(302);
    expect(res.headers.get("location")).toEqual(target);
  });

  it("should reject next on a host outside the allowlist", async () => {
    setAllowlist(["foss.arbisoft.com"]);
    const target = "https://evil.example/steal";
    const res = await server.get(
      `/auth/portal-logout?next=${encodeURIComponent(target)}`,
      { redirect: "manual" }
    );
    expect(res.status).toEqual(200);
    // still clears cookies — non-redirect rejection isn't an error path
    const setCookie = res.headers.get("set-cookie") ?? "";
    expect(setCookie).toMatch(/accessToken=;/);
  });

  it("should enforce dot-boundary on suffix matches", async () => {
    // "foss.arbisoft.com.evil" must NOT match "foss.arbisoft.com".
    setAllowlist(["foss.arbisoft.com"]);
    const target = "https://foss.arbisoft.com.evil.example/x";
    const res = await server.get(
      `/auth/portal-logout?next=${encodeURIComponent(target)}`,
      { redirect: "manual" }
    );
    expect(res.status).toEqual(200);
  });

  it("should reject every next when the allowlist is empty", async () => {
    setAllowlist([]);
    const res = await server.get(
      "/auth/portal-logout?next=https%3A%2F%2Ffoss.arbisoft.com%2F",
      { redirect: "manual" }
    );
    expect(res.status).toEqual(200);
  });

  it("should reject malformed next values", async () => {
    setAllowlist(["foss.arbisoft.com"]);
    const res = await server.get(
      "/auth/portal-logout?next=not-a-url",
      { redirect: "manual" }
    );
    expect(res.status).toEqual(200);
  });

  it("should not 302 when next is missing", async () => {
    setAllowlist(["foss.arbisoft.com"]);
    const res = await server.get("/auth/portal-logout", { redirect: "manual" });
    expect(res.status).toEqual(200);
    // cookies still cleared
    const setCookie = res.headers.get("set-cookie") ?? "";
    expect(setCookie).toMatch(/accessToken=;/);
  });
});
