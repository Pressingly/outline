import type { JwtPayload } from "jsonwebtoken";

/** Why a forwarded identity is not bound to its verified token. */
export type IdentityBindingRejection =
  | "missing_username"
  | "username_headers_disagree"
  | "token_without_username"
  | "username_mismatch"
  | "email_mismatch"
  | "synthetic_mismatch";

/** The forwarded identity headers, raw, as the edge or a minting caller sent them. */
export interface ForwardedIdentityHeaders {
  /** X-Auth-Request-Email. */
  email: string;
  /** X-Auth-Request-Preferred-Username: the mPass id with email capture on. */
  preferredUsername: string;
  /** X-Auth-Request-User: the mPass id with email capture off, an email with it on. */
  user: string;
}

export interface IdentityBindingInput {
  /** Claims of the verified X-Auth-Request-Access-Token. */
  claims: JwtPayload;
  /** The forwarded identity headers. */
  headers: ForwardedIdentityHeaders;
  /** The domain synthetic `<mPass id>@<domain>` emails are built on. */
  syntheticDomain: string;
  /** Normalises a forwarded email exactly as the User lookup does. */
  normalizeEmail: (raw: string) => string;
}

/**
 * The mPass id the forwarded headers name. Preferred-Username carries it with
 * email capture on; with capture off oauth2-proxy sends none and the id is in
 * X-Auth-Request-User instead, which carries the email once capture is on and
 * is then ignored. When both name an id they must agree.
 *
 * @param headers the forwarded identity headers.
 * @returns the mPass id, or the reason none can be trusted.
 */
export function forwardedMpassId(
  headers: ForwardedIdentityHeaders
): { mpassId: string } | { rejection: IdentityBindingRejection } {
  const preferred = headers.preferredUsername.trim();
  const user = mpassIdOrEmpty(headers.user);
  if (preferred && user && preferred !== user) {
    return { rejection: "username_headers_disagree" };
  }
  const mpassId = preferred || user;
  return mpassId ? { mpassId } : { rejection: "missing_username" };
}

/**
 * The username a verified token names: `cognito:username` on an id token,
 * `username` on a Cognito access token.
 *
 * @param claims the verified token claims.
 * @returns the username, or "".
 */
export function tokenUsername(claims: JwtPayload): string {
  const candidates = [claims["cognito:username"], claims.username];
  const username = candidates.find(
    (value): value is string => typeof value === "string" && !!value.trim()
  );
  return username?.trim() ?? "";
}

/**
 * Why the forwarded email is not bound to the verified token, or undefined
 * when it is. The checks run in order and the first failure wins:
 *
 * 1. the forwarded mPass id equals the token's username;
 * 2. when the token carries an `email` claim (an id token), the forwarded
 *    email equals it;
 * 3. a forwarded email on the synthetic domain is `<username>@<domain>`.
 *
 * A real email forwarded with an access token, which has no email claim, is
 * bound only through the username: Outline still trusts the proxy overlay to
 * have paired that email with that user.
 *
 * @param input the verified claims, the forwarded headers and the email rules.
 * @returns the rejection reason, or undefined.
 */
export function identityBindingRejection({
  claims,
  headers,
  syntheticDomain,
  normalizeEmail,
}: IdentityBindingInput): IdentityBindingRejection | undefined {
  const forwarded = forwardedMpassId(headers);
  if ("rejection" in forwarded) {
    return forwarded.rejection;
  }
  const username = tokenUsername(claims);
  if (!username) {
    return "token_without_username";
  }
  if (forwarded.mpassId !== username) {
    return "username_mismatch";
  }
  const email = normalizeEmail(headers.email);
  if (hasEmailClaim(claims) && normalizeEmail(claims.email) !== email) {
    return "email_mismatch";
  }
  if (
    isSyntheticFor(email, syntheticDomain) &&
    !isSyntheticEmailOf(email, username)
  ) {
    return "synthetic_mismatch";
  }
  return undefined;
}

function mpassIdOrEmpty(value: string): string {
  const trimmed = value.trim();
  return trimmed.includes("@") ? "" : trimmed;
}

function hasEmailClaim(
  claims: JwtPayload
): claims is JwtPayload & { email: string } {
  return typeof claims.email === "string" && !!claims.email.trim();
}

function domainOf(email: string): string {
  return email.slice(email.lastIndexOf("@") + 1);
}

function isSyntheticFor(email: string, syntheticDomain: string): boolean {
  const domain = syntheticDomain.trim().toLowerCase();
  return !!domain && domainOf(email) === domain;
}

function isSyntheticEmailOf(email: string, username: string): boolean {
  return email.slice(0, email.lastIndexOf("@")) === username.toLowerCase();
}
