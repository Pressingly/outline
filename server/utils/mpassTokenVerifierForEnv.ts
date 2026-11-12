import { AUTH_TYPE_SSO } from "@shared/constants";
import env from "@server/env";
import Logger from "@server/logging/Logger";
import { edgeSecretIsUsable } from "@server/utils/mpassEdgeTrust";
import {
  MpassTokenVerifier,
  configured,
} from "@server/utils/MpassTokenVerifier";

let current: MpassTokenVerifier | undefined;

/**
 * The verifier for the current env. It is rebuilt only when the trusted
 * issuers or client id change, so its JWKS cache survives across requests.
 *
 * @returns the shared token verifier.
 */
export function mpassTokenVerifier(): MpassTokenVerifier {
  const candidate = MpassTokenVerifier.fromSettings(env);
  if (current?.configurationKey !== candidate.configurationKey) {
    current = candidate;
  }
  return current;
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
