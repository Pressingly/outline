import { createHash, createPublicKey } from "node:crypto";
import type { Algorithm, JwtPayload } from "jsonwebtoken";
import jwt from "jsonwebtoken";
import Logger from "@server/logging/Logger";

/** Why a forwarded mPass token was refused. */
export type MpassTokenRejection =
  | "verifier_unconfigured"
  | "malformed"
  | "unsupported_algorithm"
  | "untrusted_issuer"
  | "unknown_signing_key"
  | "jwks_unavailable"
  | "bad_signature"
  | "expired"
  | "missing_claims"
  | "invalid"
  | "wrong_audience";

/** Fetches and parses a JWKS document. Rejects on any transport failure. */
export type JwksFetcher = (url: string) => Promise<unknown>;

/** Settings the verifier reads, matching the server env names. */
export interface MpassTokenSettings {
  MPASS_COGNITO_ISSUER_URL: string;
  COGNITO_AWS_REGION: string;
  COGNITO_USER_POOL_ID: string;
  MPASS_TOKEN_ISSUER_URL: string;
  MPASS_OIDC_CLIENT_ID: string;
}

export interface MpassTokenVerifierOptions {
  /** Issuers whose tokens are trusted, each verified against its own JWKS. */
  issuers: string[];
  /** OIDC client id the token must have been issued to. */
  clientId: string;
  /** Fetches a JWKS document; defaults to an HTTP GET with a short timeout. */
  fetchJwks?: JwksFetcher;
  /** Monotonic clock in milliseconds, for JWKS cache ages; injectable for tests. */
  clock?: () => number;
  /** Wall clock in milliseconds, compared with token expiry; injectable for tests. */
  wallClock?: () => number;
}

/** Thrown when a forwarded token fails verification, carrying the reason. */
export class InvalidMpassTokenError extends Error {
  public readonly reason: MpassTokenRejection;

  constructor(reason: MpassTokenRejection) {
    super(`Invalid mPass token: ${reason}`);
    this.reason = reason;
  }
}

export const JWKS_FETCH_TIMEOUT_MS = 2000;
export const JWKS_LIFESPAN_MS = 60 * 60 * 1000;
export const JWKS_FAILURE_BACKOFF_MS = 30 * 1000;
export const JWKS_MAX_STALE_MS = 24 * 60 * 60 * 1000;
export const CLOCK_SKEW_LEEWAY_SECONDS = 60;
export const VERIFIED_TOKEN_CACHE_SIZE = 1000;

const PLACEHOLDER_PREFIX = "CHANGE_ME_";
const ALGORITHM: Algorithm = "RS256";
const MIN_RSA_MODULUS_BITS = 2048;
const REQUIRED_CLAIMS = ["exp", "iat", "iss", "token_use"];

/**
 * Whether a setting still holds an .env.example CHANGE_ME_ placeholder.
 *
 * @param value the raw setting.
 * @returns true for a placeholder value.
 */
export function isPlaceholder(value: string | undefined): boolean {
  return (value ?? "").trim().startsWith(PLACEHOLDER_PREFIX);
}

/**
 * A setting's value, or "" when it is unset or still an .env.example
 * placeholder.
 *
 * @param value the raw setting.
 * @returns the trimmed value, or "".
 */
export function configured(value: string | undefined): string {
  const text = (value ?? "").trim();
  return text.startsWith(PLACEHOLDER_PREFIX) ? "" : text;
}

/**
 * The Cognito issuer oauth2-proxy validates, falling back to the region and
 * user pool variables when no explicit issuer is set.
 *
 * @param settings the verifier settings.
 * @returns the issuer URL without a trailing slash, or "".
 */
export function cognitoIssuer(settings: MpassTokenSettings): string {
  const explicit = withoutTrailingSlash(
    configured(settings.MPASS_COGNITO_ISSUER_URL)
  );
  if (explicit) {
    return explicit;
  }
  const region = configured(settings.COGNITO_AWS_REGION);
  const poolId = configured(settings.COGNITO_USER_POOL_ID);
  if (!region || !poolId) {
    return "";
  }
  return `https://cognito-idp.${region}.amazonaws.com/${poolId}`;
}

/**
 * The JWKS URL published by an issuer.
 *
 * @param issuer the issuer URL.
 * @returns the issuer's well-known JWKS URL.
 */
export function jwksUrl(issuer: string): string {
  return `${withoutTrailingSlash(issuer)}/.well-known/jwks.json`;
}

/**
 * Whether verified claims name the expected client: Cognito access tokens
 * carry it in `client_id`, id_tokens in `aud`.
 *
 * @param claims the verified token claims.
 * @param clientId the expected OIDC client id.
 * @returns true when the token was issued to the client.
 */
export function audienceMatches(claims: JwtPayload, clientId: string): boolean {
  if (claims.token_use === "access") {
    return claims.client_id === clientId;
  }
  if (claims.token_use === "id") {
    const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    return audiences.includes(clientId);
  }
  return false;
}

/**
 * Fetches a JWKS document over HTTP with a short timeout.
 *
 * @param url the JWKS URL.
 * @returns the parsed JSON body.
 */
export async function fetchJwksOverHttp(url: string): Promise<unknown> {
  const response = await fetch(url, {
    redirect: "error",
    signal: AbortSignal.timeout(JWKS_FETCH_TIMEOUT_MS),
  });
  if (!response.ok) {
    throw new Error(`JWKS fetch failed with status ${response.status}`);
  }
  return response.json();
}

type PemPublicKey = string;

interface VerifiedToken {
  claims: JwtPayload;
  expiresAt: number;
}

interface CachedKeySet {
  keys: Map<string, PemPublicKey>;
  fetchedAt: number;
}

/**
 * Verifies the mPass token oauth2-proxy forwards in
 * X-Auth-Request-Access-Token. A browser session forwards the Cognito access
 * token; a Bearer caller forwards its id_token, which mpass-auth-proxy re-signs
 * under its own issuer when email capture is on. Both issuers are trusted, each
 * against its own JWKS, and nothing else is.
 */
export class MpassTokenVerifier {
  /**
   * Builds a verifier from server settings.
   *
   * @param settings the verifier settings.
   * @returns a verifier for the configured issuers and client id.
   */
  public static fromSettings(settings: MpassTokenSettings): MpassTokenVerifier {
    return new MpassTokenVerifier({
      issuers: [
        cognitoIssuer(settings),
        withoutTrailingSlash(configured(settings.MPASS_TOKEN_ISSUER_URL)),
      ],
      clientId: configured(settings.MPASS_OIDC_CLIENT_ID),
    });
  }

  private readonly issuers: Set<string>;
  private readonly clientId: string;
  private readonly fetchJwks: JwksFetcher;
  private readonly clock: () => number;
  private readonly wallClock: () => number;
  private readonly verified = new Map<string, VerifiedToken>();
  private readonly keySets = new Map<string, CachedKeySet>();
  private readonly failedAt = new Map<string, number>();
  private readonly lastFetchAt = new Map<string, number>();
  private readonly inFlight = new Map<string, Promise<CachedKeySet>>();

  constructor({
    issuers,
    clientId,
    fetchJwks = fetchJwksOverHttp,
    clock = () => performance.now(),
    wallClock = () => Date.now(),
  }: MpassTokenVerifierOptions) {
    this.issuers = new Set(issuers.filter(Boolean));
    this.clientId = clientId;
    this.fetchJwks = fetchJwks;
    this.clock = clock;
    this.wallClock = wallClock;
  }

  public get isConfigured(): boolean {
    return this.issuers.size > 0 && this.clientId.length > 0;
  }

  /** A stable key identifying this verifier's trust configuration. */
  public get configurationKey(): string {
    return [...this.issuers].sort().concat(this.clientId).join("|");
  }

  /**
   * Verifies a forwarded token's signature, issuer, lifetime and audience.
   * A verified token is remembered until it expires, so later requests of the
   * same session skip the JWKS lookup.
   *
   * @param token the raw JWT.
   * @returns the verified claims.
   * @throws InvalidMpassTokenError with the reason the token was refused.
   */
  public async verify(token: string): Promise<JwtPayload> {
    if (!this.isConfigured) {
      throw new InvalidMpassTokenError("verifier_unconfigured");
    }
    const cacheKey = tokenDigest(token);
    const remembered = this.rememberedClaims(cacheKey);
    if (remembered) {
      return remembered;
    }
    const { kid, issuer } = this.unverifiedHeaderAndIssuer(token);
    const key = await this.signingKey(issuer, kid);
    const claims = this.decode(token, key, issuer);
    if (!audienceMatches(claims, this.clientId)) {
      throw new InvalidMpassTokenError("wrong_audience");
    }
    this.remember(cacheKey, claims);
    return claims;
  }

  private rememberedClaims(cacheKey: string): JwtPayload | undefined {
    const entry = this.verified.get(cacheKey);
    if (!entry) {
      return undefined;
    }
    this.verified.delete(cacheKey);
    if (this.wallClock() >= entry.expiresAt) {
      return undefined;
    }
    this.verified.set(cacheKey, entry);
    return entry.claims;
  }

  private remember(cacheKey: string, claims: JwtPayload): void {
    if (typeof claims.exp !== "number") {
      return;
    }
    this.verified.set(cacheKey, { claims, expiresAt: claims.exp * 1000 });
    if (this.verified.size > VERIFIED_TOKEN_CACHE_SIZE) {
      const oldest = this.verified.keys().next().value;
      if (oldest !== undefined) {
        this.verified.delete(oldest);
      }
    }
  }

  private unverifiedHeaderAndIssuer(token: string): {
    kid: string;
    issuer: string;
  } {
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded || typeof decoded.payload === "string") {
      throw new InvalidMpassTokenError("malformed");
    }
    if (decoded.header.alg !== ALGORITHM) {
      throw new InvalidMpassTokenError("unsupported_algorithm");
    }
    const issuer = decoded.payload.iss ?? "";
    if (!this.issuers.has(issuer)) {
      throw new InvalidMpassTokenError("untrusted_issuer");
    }
    if (!decoded.header.kid) {
      throw new InvalidMpassTokenError("unknown_signing_key");
    }
    return { kid: decoded.header.kid, issuer };
  }

  private decode(token: string, key: PemPublicKey, issuer: string): JwtPayload {
    let claims: string | JwtPayload;
    try {
      claims = jwt.verify(token, key, {
        algorithms: [ALGORITHM],
        issuer,
        clockTolerance: CLOCK_SKEW_LEEWAY_SECONDS,
      });
    } catch (err) {
      throw new InvalidMpassTokenError(rejectionFor(err));
    }
    if (typeof claims === "string" || !hasRequiredClaims(claims)) {
      throw new InvalidMpassTokenError("missing_claims");
    }
    return claims;
  }

  private async signingKey(issuer: string, kid: string): Promise<PemPublicKey> {
    const keySet = await this.keySetFor(issuer, kid);
    const key = keySet.keys.get(kid);
    if (!key) {
      throw new InvalidMpassTokenError("unknown_signing_key");
    }
    return key;
  }

  private async keySetFor(issuer: string, kid: string): Promise<CachedKeySet> {
    const cached = this.keySets.get(issuer);
    if (
      cached &&
      !this.isStale(cached) &&
      (cached.keys.has(kid) || !this.mayRefetch(issuer))
    ) {
      return cached;
    }
    try {
      return await this.refreshKeySet(issuer);
    } catch (err) {
      if (!cached || this.isExpired(cached)) {
        throw err;
      }
      Logger.warn("mPass JWKS refresh failed: serving the last good key set", {
        issuer,
        ageSeconds: Math.round((this.clock() - cached.fetchedAt) / 1000),
      });
      return cached;
    }
  }

  private async refreshKeySet(issuer: string): Promise<CachedKeySet> {
    if (this.recentlyFailed(issuer)) {
      throw new InvalidMpassTokenError("jwks_unavailable");
    }
    const pending = this.inFlight.get(issuer) ?? this.startLoad(issuer);
    return pending;
  }

  private startLoad(issuer: string): Promise<CachedKeySet> {
    const pending = this.loadKeySet(issuer).finally(() =>
      this.inFlight.delete(issuer)
    );
    this.inFlight.set(issuer, pending);
    return pending;
  }

  private async loadKeySet(issuer: string): Promise<CachedKeySet> {
    this.lastFetchAt.set(issuer, this.clock());
    try {
      const keySet = {
        keys: parseJwks(await this.fetchJwks(jwksUrl(issuer)), issuer),
        fetchedAt: this.clock(),
      };
      this.keySets.set(issuer, keySet);
      this.failedAt.delete(issuer);
      return keySet;
    } catch {
      this.failedAt.set(issuer, this.clock());
      throw new InvalidMpassTokenError("jwks_unavailable");
    }
  }

  private isStale(keySet: CachedKeySet): boolean {
    return this.clock() - keySet.fetchedAt >= JWKS_LIFESPAN_MS;
  }

  private isExpired(keySet: CachedKeySet): boolean {
    return this.clock() - keySet.fetchedAt >= JWKS_MAX_STALE_MS;
  }

  private mayRefetch(issuer: string): boolean {
    const last = this.lastFetchAt.get(issuer);
    return last === undefined || this.clock() - last >= JWKS_FAILURE_BACKOFF_MS;
  }

  private recentlyFailed(issuer: string): boolean {
    const failed = this.failedAt.get(issuer);
    return (
      failed !== undefined && this.clock() - failed < JWKS_FAILURE_BACKOFF_MS
    );
  }
}

function withoutTrailingSlash(value: string): string {
  return value.replace(/\/+$/, "");
}

function hasRequiredClaims(claims: JwtPayload): boolean {
  return REQUIRED_CLAIMS.every(
    (claim) => claims[claim] !== undefined && claims[claim] !== null
  );
}

function rejectionFor(err: unknown): MpassTokenRejection {
  if (err instanceof jwt.TokenExpiredError) {
    return "expired";
  }
  if (err instanceof jwt.JsonWebTokenError) {
    if (err.message === "invalid signature") {
      return "bad_signature";
    }
    if (err.message.startsWith("jwt issuer invalid")) {
      return "untrusted_issuer";
    }
  }
  return "invalid";
}

function parseJwks(
  document: unknown,
  issuer: string
): Map<string, PemPublicKey> {
  if (!isRecord(document) || !Array.isArray(document.keys)) {
    throw new Error("JWKS document has no keys array");
  }
  return new Map(
    document.keys
      .filter(isUsableRsaKey)
      .flatMap((jwk) => importedKey(jwk, issuer))
  );
}

function importedKey(
  jwk: RsaJwk,
  issuer: string
): Array<[string, PemPublicKey]> {
  try {
    return [[jwk.kid, toKey(jwk)]];
  } catch {
    Logger.warn("mPass JWKS key skipped: it could not be imported", {
      issuer,
      kid: jwk.kid,
    });
    return [];
  }
}

function tokenDigest(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

interface RsaJwk {
  kty: "RSA";
  kid: string;
  n: string;
  e: string;
  use?: string;
}

function isUsableRsaKey(value: unknown): value is RsaJwk {
  return (
    isRecord(value) &&
    value.kty === "RSA" &&
    typeof value.kid === "string" &&
    typeof value.n === "string" &&
    typeof value.e === "string" &&
    (value.use === undefined || value.use === "sig")
  );
}

function toKey(jwk: RsaJwk): PemPublicKey {
  const key = createPublicKey({
    key: { kty: jwk.kty, n: jwk.n, e: jwk.e },
    format: "jwk",
  });
  const modulusLength = key.asymmetricKeyDetails?.modulusLength ?? 0;
  if (modulusLength < MIN_RSA_MODULUS_BITS) {
    throw new Error(`RSA key ${jwk.kid} is ${modulusLength} bits`);
  }
  return key.export({ type: "spki", format: "pem" }).toString();
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
