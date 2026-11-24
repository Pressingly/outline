import { generateKeyPairSync } from "node:crypto";
import jwt from "jsonwebtoken";
import { HttpResponse, http } from "msw";
import { randomString } from "@shared/random";
import env from "@server/env";
import { server } from "@server/test/msw";

const KID = "test-kid";
const CLIENT_ID = "outline-client";
const keyPair = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwks = {
  keys: [{ ...keyPair.publicKey.export({ format: "jwk" }), kid: KID }],
};

/**
 * The mPass id a test derives from a forwarded email: its local part, which is
 * also what makes a synthetic `<mPass id>@<domain>` email bind.
 *
 * @param email the forwarded email, or a bare mPass id.
 * @returns the mPass id.
 */
export function mpassIdFor(email: string): string {
  return email.split("@")[0];
}

/**
 * A Cognito-shaped issuer whose JWKS msw serves, so the real verifier accepts
 * the tokens it signs. Install it in a beforeEach: msw handlers reset after
 * every test.
 */
export class MpassTestIssuer {
  public readonly clientId = CLIENT_ID;
  public issuer = "";

  /** Points the verifier env at a fresh issuer and serves its JWKS. */
  public install(): void {
    this.issuer = `https://issuer-${randomString(8).toLowerCase()}.example.test/pool`;
    env.MPASS_COGNITO_ISSUER_URL = this.issuer;
    env.MPASS_OIDC_CLIENT_ID = this.clientId;
    server.use(
      http.get(`${this.issuer}/.well-known/jwks.json`, () =>
        HttpResponse.json(jwks)
      )
    );
  }

  /** Clears the verifier env this issuer set. */
  public uninstall(): void {
    env.MPASS_COGNITO_ISSUER_URL = "";
    env.MPASS_OIDC_CLIENT_ID = "";
  }

  /**
   * A signed Cognito access token: `username`, no email claim.
   *
   * @param username the mPass id.
   * @param claims extra or overriding claims.
   * @returns the signed JWT.
   */
  public accessToken(
    username: string,
    claims: Record<string, unknown> = {}
  ): string {
    return this.sign({
      token_use: "access",
      client_id: this.clientId,
      username,
      ...claims,
    });
  }

  /**
   * A signed mpass-auth-proxy id token: `cognito:username` and the overlay email.
   *
   * @param username the mPass id.
   * @param email the overlay email.
   * @param claims extra or overriding claims.
   * @returns the signed JWT.
   */
  public idToken(
    username: string,
    email: string,
    claims: Record<string, unknown> = {}
  ): string {
    return this.sign({
      token_use: "id",
      aud: this.clientId,
      "cognito:username": username,
      email,
      ...claims,
    });
  }

  /**
   * The headers oauth2-proxy adds beside X-Auth-Request-Email on a browser
   * login: the access token and the preferred username it names.
   *
   * @param email the forwarded email.
   * @param username the mPass id; defaults to the email's local part.
   * @returns the token and username headers.
   */
  public proofHeaders(
    email: string,
    username = mpassIdFor(email)
  ): Record<string, string> {
    return {
      "x-auth-request-access-token": this.accessToken(username),
      "x-auth-request-preferred-username": username,
    };
  }

  private sign(claims: Record<string, unknown>): string {
    const now = Math.floor(Date.now() / 1000);
    return jwt.sign(
      { iss: this.issuer, iat: now, exp: now + 300, ...claims },
      keyPair.privateKey.export({ type: "pkcs8", format: "pem" }),
      { algorithm: "RS256", keyid: KID }
    );
  }
}
