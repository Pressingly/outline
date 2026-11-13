import { createHash, timingSafeEqual } from "node:crypto";
import { configured } from "@server/utils/MpassTokenVerifier";

/** Header Traefik sets on the mPass SSO router to vouch for the request. */
export const EDGE_SECRET_HEADER = "x-mpass-edge-secret";

/** Shortest edge secret that is trusted at all. */
export const MIN_EDGE_SECRET_LENGTH = 32;

/**
 * Whether the configured edge secret is long enough to be trusted. A
 * CHANGE_ME_ placeholder is never trusted, whatever its length.
 *
 * @param secret the configured edge secret.
 * @returns true when identity headers may be trusted with this secret.
 */
export function edgeSecretIsUsable(secret: string): boolean {
  return configured(secret).length >= MIN_EDGE_SECRET_LENGTH;
}

/**
 * Whether a request carries the edge secret, compared in constant time.
 * An unusable secret trusts nothing, because without it a direct call on the
 * backend network is indistinguishable from one that passed mPass ForwardAuth.
 *
 * @param presented the X-Mpass-Edge-Secret value on the request, if any.
 * @param secret the configured edge secret.
 * @returns true only when the request came through the SSO router.
 */
export function requestIsFromEdge(
  presented: string | undefined,
  secret: string
): boolean {
  if (!edgeSecretIsUsable(secret) || !presented) {
    return false;
  }
  return timingSafeEqual(digest(presented), digest(configured(secret)));
}

function digest(value: string): Buffer {
  return createHash("sha256").update(value).digest();
}
