import { AUTH_TYPE_SSO } from "@shared/constants";
import env from "@server/env";
import Logger from "@server/logging/Logger";
import {
  corporateIdIsPlaceholder,
  expectedCorporateId,
  reportMpassMisconfiguration,
} from "./mpassTokenVerifierForEnv";

const USABLE_SECRET = "e".repeat(64);

describe("reportMpassMisconfiguration", () => {
  beforeEach(() => {
    env.AUTH_TYPE = AUTH_TYPE_SSO;
    env.MPASS_EDGE_SECRET = USABLE_SECRET;
    env.SMB_CORPORATE_ID = "";
    env.MPASS_COGNITO_ISSUER_URL = "";
    env.MPASS_OIDC_CLIENT_ID = "";
  });

  afterEach(() => {
    env.AUTH_TYPE = undefined;
    env.MPASS_EDGE_SECRET = "";
    env.SMB_CORPORATE_ID = "";
    env.MPASS_COGNITO_ISSUER_URL = "";
    env.MPASS_OIDC_CLIENT_ID = "";
    vi.restoreAllMocks();
  });

  function errorMessages() {
    const error = vi.spyOn(Logger, "error").mockImplementation(() => undefined);
    reportMpassMisconfiguration();
    return error.mock.calls.map(([message]) => message);
  }

  it.each([
    ["unset", ""],
    ["shorter than 32 characters", "s".repeat(31)],
  ])("logs an error when the edge secret is %s", (_label, secret) => {
    env.MPASS_EDGE_SECRET = secret;

    expect(errorMessages()).toEqual([
      expect.stringContaining("MPASS_EDGE_SECRET is unset or shorter than 32"),
    ]);
  });

  it("logs an error when the corporate gate is on without an issuer or client id", () => {
    env.SMB_CORPORATE_ID = "corp-42";

    expect(errorMessages()).toEqual([
      expect.stringContaining("SMB_CORPORATE_ID is set but no token issuer"),
    ]);
  });

  it("logs nothing for a complete configuration", () => {
    env.SMB_CORPORATE_ID = "corp-42";
    env.MPASS_COGNITO_ISSUER_URL = "https://issuer.example.test/pool";
    env.MPASS_OIDC_CLIENT_ID = "client";

    expect(errorMessages()).toEqual([]);
  });

  it("logs nothing when SSO is off", () => {
    env.AUTH_TYPE = undefined;
    env.MPASS_EDGE_SECRET = "";
    env.SMB_CORPORATE_ID = "corp-42";

    expect(errorMessages()).toEqual([]);
  });

  it("logs an error and keeps the gate on for a placeholder corporate id", () => {
    env.SMB_CORPORATE_ID = " CHANGE_ME_SMB_CORPORATE_ID ";

    expect(errorMessages()).toEqual([
      "SMB_CORPORATE_ID is a CHANGE_ME_ placeholder: every mPass login is refused",
    ]);
    expect(expectedCorporateId()).toEqual("CHANGE_ME_SMB_CORPORATE_ID");
    expect(corporateIdIsPlaceholder()).toBe(true);
  });

  it("treats a whitespace-only corporate id as unset", () => {
    env.SMB_CORPORATE_ID = "  ";

    expect(errorMessages()).toEqual([]);
    expect(expectedCorporateId()).toEqual("");
    expect(corporateIdIsPlaceholder()).toBe(false);
  });
});
