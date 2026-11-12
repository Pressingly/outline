import { createHmac, generateKeyPairSync } from "node:crypto";
import jwt from "jsonwebtoken";
import type { JwksFetcher } from "./MpassTokenVerifier";
import {
  InvalidMpassTokenError,
  JWKS_FAILURE_BACKOFF_MS,
  JWKS_LIFESPAN_MS,
  MpassTokenVerifier,
  audienceMatches,
  cognitoIssuer,
  configured,
  jwksUrl,
} from "./MpassTokenVerifier";

const COGNITO = "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_pool";
const PROXY = "https://auth.example.test";
const CLIENT_ID = "client-123";
const KID = "kid-1";

const signingPair = generateKeyPairSync("rsa", { modulusLength: 2048 });
const otherPair = generateKeyPairSync("rsa", { modulusLength: 2048 });
const privatePem = signingPair.privateKey
  .export({ type: "pkcs8", format: "pem" })
  .toString();
const otherPrivatePem = otherPair.privateKey
  .export({ type: "pkcs8", format: "pem" })
  .toString();
const publicPem = signingPair.publicKey
  .export({ type: "spki", format: "pem" })
  .toString();

const jwks = {
  keys: [
    { ...signingPair.publicKey.export({ format: "jwk" }), kid: KID, use: "sig" },
  ],
};

const nowSeconds = () => Math.floor(Date.now() / 1000);

function accessClaims(overrides: Record<string, unknown> = {}) {
  return {
    iss: COGNITO,
    token_use: "access",
    client_id: CLIENT_ID,
    iat: nowSeconds(),
    exp: nowSeconds() + 300,
    sub: "mpass-sub",
    ...overrides,
  };
}

function sign(
  claims: Record<string, unknown>,
  { key = privatePem, kid = KID }: { key?: string; kid?: string } = {}
) {
  const present = Object.fromEntries(
    Object.entries(claims).filter(([, value]) => value !== undefined)
  );
  return jwt.sign(present, key, {
    algorithm: "RS256",
    keyid: kid,
    noTimestamp: !("iat" in present),
  });
}

function hs256WithPublicKey(claims: Record<string, unknown>) {
  const encode = (part: object) =>
    Buffer.from(JSON.stringify(part)).toString("base64url");
  const input = `${encode({ alg: "HS256", typ: "JWT", kid: KID })}.${encode(claims)}`;
  const signature = createHmac("sha256", publicPem)
    .update(input)
    .digest("base64url");
  return `${input}.${signature}`;
}

function buildVerifier(
  fetchJwks = vi.fn<JwksFetcher>(async () => jwks),
  clock = () => 0
) {
  const verifier = new MpassTokenVerifier({
    issuers: [COGNITO, PROXY],
    clientId: CLIENT_ID,
    fetchJwks,
    clock,
  });
  return { verifier, fetchJwks };
}

async function rejectionOf(promise: Promise<unknown>) {
  try {
    await promise;
  } catch (err) {
    if (err instanceof InvalidMpassTokenError) {
      return err.reason;
    }
    throw err;
  }
  return undefined;
}

describe("MpassTokenVerifier", () => {
  it("accepts a Cognito access token issued to the client", async () => {
    const { verifier, fetchJwks } = buildVerifier();

    const claims = await verifier.verify(sign(accessClaims()));

    expect(claims.sub).toEqual("mpass-sub");
    expect(fetchJwks).toHaveBeenCalledWith(jwksUrl(COGNITO));
  });

  it("accepts an mpass-auth-proxy id_token whose aud lists the client", async () => {
    const { verifier, fetchJwks } = buildVerifier();
    const token = sign({
      iss: PROXY,
      token_use: "id",
      aud: ["other", CLIENT_ID],
      iat: nowSeconds(),
      exp: nowSeconds() + 300,
    });

    await expect(verifier.verify(token)).resolves.toBeDefined();
    expect(fetchJwks).toHaveBeenCalledWith(`${PROXY}/.well-known/jwks.json`);
  });

  it("accepts a token that expired within the clock-skew leeway", async () => {
    const { verifier } = buildVerifier();
    const token = sign(accessClaims({ exp: nowSeconds() - 30 }));

    await expect(verifier.verify(token)).resolves.toBeDefined();
  });

  it.each([
    [
      "bad_signature",
      () => sign(accessClaims(), { key: otherPrivatePem }),
    ],
    ["expired", () => sign(accessClaims({ exp: nowSeconds() - 120 }))],
    [
      "untrusted_issuer",
      () => sign(accessClaims({ iss: "https://evil.example.test" })),
    ],
    [
      "wrong_audience",
      () => sign(accessClaims({ client_id: "someone-else" })),
    ],
    [
      "wrong_audience",
      () =>
        sign(
          accessClaims({ token_use: "id", client_id: undefined, aud: "x" })
        ),
    ],
    [
      "wrong_audience",
      () => sign(accessClaims({ token_use: "refresh" })),
    ],
    [
      "missing_claims",
      () => sign(accessClaims({ token_use: undefined })),
    ],
    ["missing_claims", () => sign(accessClaims({ iat: undefined }))],
    ["missing_claims", () => sign(accessClaims({ exp: undefined }))],
    ["unknown_signing_key", () => sign(accessClaims(), { kid: "rotated" })],
    [
      "unsupported_algorithm",
      () => jwt.sign(accessClaims(), "", { algorithm: "none" }),
    ],
    [
      "unsupported_algorithm",
      () => hs256WithPublicKey(accessClaims()),
    ],
    ["malformed", () => "not-a-jwt"],
  ])("rejects with %s", async (reason, token) => {
    const { verifier } = buildVerifier();

    expect(await rejectionOf(verifier.verify(token()))).toEqual(reason);
  });

  it("rejects an untrusted issuer without fetching its JWKS", async () => {
    const { verifier, fetchJwks } = buildVerifier();

    await rejectionOf(
      verifier.verify(sign(accessClaims({ iss: "https://evil.example.test" })))
    );

    expect(fetchJwks).not.toHaveBeenCalled();
  });

  it("refuses everything when no issuer or client id is configured", async () => {
    const verifier = new MpassTokenVerifier({ issuers: [""], clientId: "" });

    expect(verifier.isConfigured).toBe(false);
    expect(await rejectionOf(verifier.verify(sign(accessClaims())))).toEqual(
      "verifier_unconfigured"
    );
  });

  it("caches the JWKS per issuer", async () => {
    const { verifier, fetchJwks } = buildVerifier();

    await verifier.verify(sign(accessClaims()));
    await verifier.verify(sign(accessClaims()));

    expect(fetchJwks).toHaveBeenCalledTimes(1);
  });

  it("refetches the JWKS once its lifespan has passed", async () => {
    let now = 0;
    const { verifier, fetchJwks } = buildVerifier(undefined, () => now);

    await verifier.verify(sign(accessClaims()));
    now = JWKS_LIFESPAN_MS;
    await verifier.verify(sign(accessClaims()));

    expect(fetchJwks).toHaveBeenCalledTimes(2);
  });

  it("fails closed with jwks_unavailable and backs off after a failed fetch", async () => {
    let now = 0;
    const fetchJwks = vi.fn<JwksFetcher>(async () => {
      throw new Error("connect ETIMEDOUT");
    });
    const { verifier } = buildVerifier(fetchJwks, () => now);

    expect(await rejectionOf(verifier.verify(sign(accessClaims())))).toEqual(
      "jwks_unavailable"
    );
    expect(await rejectionOf(verifier.verify(sign(accessClaims())))).toEqual(
      "jwks_unavailable"
    );
    expect(fetchJwks).toHaveBeenCalledTimes(1);

    now = JWKS_FAILURE_BACKOFF_MS;
    fetchJwks.mockImplementation(async () => jwks);

    await expect(verifier.verify(sign(accessClaims()))).resolves.toBeDefined();
    expect(fetchJwks).toHaveBeenCalledTimes(2);
  });

  it("backs off per issuer, so one failing issuer does not block the other", async () => {
    const fetchJwks = vi.fn<JwksFetcher>(async (url: string) => {
      if (url.startsWith(PROXY)) {
        throw new Error("down");
      }
      return jwks;
    });
    const { verifier } = buildVerifier(fetchJwks);
    const proxyToken = sign(accessClaims({ iss: PROXY }));

    expect(await rejectionOf(verifier.verify(proxyToken))).toEqual(
      "jwks_unavailable"
    );
    await expect(verifier.verify(sign(accessClaims()))).resolves.toBeDefined();
  });

  it.each([
    ["no keys array", { nope: true }],
    ["a non-object", "<html>"],
  ])("rejects with jwks_unavailable on %s", async (_label, document) => {
    const { verifier } = buildVerifier(vi.fn<JwksFetcher>(async () => document));

    expect(await rejectionOf(verifier.verify(sign(accessClaims())))).toEqual(
      "jwks_unavailable"
    );
  });

  it("does not refetch on an unknown kid more than once per backoff window", async () => {
    const { verifier, fetchJwks } = buildVerifier();

    await verifier.verify(sign(accessClaims()));
    await rejectionOf(verifier.verify(sign(accessClaims(), { kid: "a" })));
    await rejectionOf(verifier.verify(sign(accessClaims(), { kid: "b" })));

    expect(fetchJwks).toHaveBeenCalledTimes(1);
  });
});

describe("audienceMatches", () => {
  it.each([
    [{ token_use: "access", client_id: CLIENT_ID }, true],
    [{ token_use: "access", aud: CLIENT_ID }, false],
    [{ token_use: "id", aud: CLIENT_ID }, true],
    [{ token_use: "id", aud: [CLIENT_ID] }, true],
    [{ token_use: "id", client_id: CLIENT_ID }, false],
    [{ client_id: CLIENT_ID, aud: CLIENT_ID }, false],
  ])("%j matches=%s", (claims, expected) => {
    expect(audienceMatches(claims, CLIENT_ID)).toBe(expected);
  });
});

describe("cognitoIssuer", () => {
  const base = {
    MPASS_COGNITO_ISSUER_URL: "",
    COGNITO_AWS_REGION: "",
    COGNITO_USER_POOL_ID: "",
    MPASS_TOKEN_ISSUER_URL: "",
    MPASS_OIDC_CLIENT_ID: "",
  };

  it("prefers the explicit issuer without its trailing slash", () => {
    expect(
      cognitoIssuer({ ...base, MPASS_COGNITO_ISSUER_URL: `${COGNITO}/` })
    ).toEqual(COGNITO);
  });

  it("falls back to the region and pool id", () => {
    expect(
      cognitoIssuer({
        ...base,
        COGNITO_AWS_REGION: "eu-west-1",
        COGNITO_USER_POOL_ID: "eu-west-1_pool",
      })
    ).toEqual(COGNITO);
  });

  it("treats CHANGE_ME_ placeholders as unset", () => {
    expect(
      cognitoIssuer({
        ...base,
        MPASS_COGNITO_ISSUER_URL: "CHANGE_ME_ISSUER",
        COGNITO_AWS_REGION: "CHANGE_ME_REGION",
        COGNITO_USER_POOL_ID: "eu-west-1_pool",
      })
    ).toEqual("");
  });

  it("builds a verifier trusting only the configured issuers", () => {
    const verifier = MpassTokenVerifier.fromSettings({
      ...base,
      MPASS_COGNITO_ISSUER_URL: COGNITO,
      MPASS_TOKEN_ISSUER_URL: "CHANGE_ME_PROXY",
      MPASS_OIDC_CLIENT_ID: CLIENT_ID,
    });

    expect(verifier.isConfigured).toBe(true);
    expect(verifier.configurationKey).toEqual(`${COGNITO}|${CLIENT_ID}`);
  });
});

describe("configured", () => {
  it.each([
    [undefined, ""],
    ["  value ", "value"],
    ["CHANGE_ME_X", ""],
  ])("%j -> %j", (value, expected) => {
    expect(configured(value)).toEqual(expected);
  });
});
