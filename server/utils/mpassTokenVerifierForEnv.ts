import { AUTH_TYPE_SSO } from "@shared/constants";
import env from "@server/env";
import Logger from "@server/logging/Logger";
import { edgeSecretIsUsable } from "@server/utils/mpassEdgeTrust";
import {
  MpassTokenVerifier,
  configured,
} from "@server/utils/MpassTokenVerifier";

let current: { key: string; verifier: MpassTokenVerifier } | undefined;

function settingsKey(): string {
  return JSON.stringify([
    env.MPASS_COGNITO_ISSUER_URL,
    env.COGNITO_AWS_REGION,
    env.COGNITO_USER_POOL_ID,
    env.MPASS_TOKEN_ISSUER_URL,
    env.MPASS_OIDC_CLIENT_ID,
  ]);
}

/**
 * The verifier for the current env. A new one is built only when the token
 * settings change, so its JWKS and verified-token caches survive across
 * requests and a gated request allocates nothing.
 *
 * @returns the shared token verifier.
 */
export function mpassTokenVerifier(): MpassTokenVerifier {
  const key = settingsKey();
  if (current?.key !== key) {
    current = { key, verifier: MpassTokenVerifier.fromSettings(env) };
  }
  return current.verifier;
}

/**
 * This deployment's SMB corporate id, or "" when the gate is off. A
 * CHANGE_ME_ placeholder counts as unset.
 *
 * @returns the trimmed corporate id, or "".
 */
export function expectedCorporateId(): string {
  return configured(env.SMB_CORPORATE_ID);
}

/**
 * Logs an error at boot for an mPass configuration that fails closed: no
 * usable edge secret disables SSO login, and a corporate gate without a
 * token issuer or client id refuses every login.
 */
export function reportMpassMisconfiguration(): void {
  if (env.AUTH_TYPE !== AUTH_TYPE_SSO) {
    return;
  }
  if (!edgeSecretIsUsable(env.MPASS_EDGE_SECRET)) {
    Logger.error(
      "MPASS_EDGE_SECRET is unset or shorter than 32 characters: mPass identity headers will be ignored and SSO login is disabled",
      new Error("mPass edge secret unusable")
    );
  }
  if (expectedCorporateId() && !mpassTokenVerifier().isConfigured) {
    Logger.error(
      "SMB_CORPORATE_ID is set but no token issuer or client id is configured (MPASS_COGNITO_ISSUER_URL, MPASS_OIDC_CLIENT_ID): every mPass login will be refused",
      new Error("mPass token verifier unconfigured")
    );
  }
}
