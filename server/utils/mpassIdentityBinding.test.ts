import {
  forwardedMpassId,
  identityBindingRejection,
  tokenUsername,
} from "./mpassIdentityBinding";

const lower = (raw: string) => raw.trim().toLowerCase();

function rejection(
  claims: Record<string, unknown>,
  headers: Partial<{ email: string; preferredUsername: string; user: string }>
) {
  return identityBindingRejection({
    claims,
    headers: { email: "", preferredUsername: "", user: "", ...headers },
    syntheticDomain: "Synthetic.Test",
    normalizeEmail: lower,
  });
}

describe("forwardedMpassId", () => {
  it.each([
    [{ preferredUsername: " 123 ", user: "" }, { mpassId: "123" }],
    [{ preferredUsername: "", user: "123" }, { mpassId: "123" }],
    [{ preferredUsername: "123", user: "a@example.com" }, { mpassId: "123" }],
    [{ preferredUsername: "123", user: "123" }, { mpassId: "123" }],
    [
      { preferredUsername: "123", user: "456" },
      { rejection: "username_headers_disagree" },
    ],
    [
      { preferredUsername: "", user: "a@example.com" },
      { rejection: "missing_username" },
    ],
    [{ preferredUsername: " ", user: "" }, { rejection: "missing_username" }],
  ])("reads %j as %j", (headers, expected) => {
    expect(forwardedMpassId({ email: "", ...headers })).toEqual(expected);
  });
});

describe("tokenUsername", () => {
  it("prefers cognito:username, then username", () => {
    expect(tokenUsername({ "cognito:username": "a", username: "b" })).toBe("a");
    expect(tokenUsername({ username: "b" })).toBe("b");
    expect(tokenUsername({ username: " " })).toBe("");
    expect(tokenUsername({})).toBe("");
  });
});

describe("identityBindingRejection", () => {
  it("binds a real email to an access token through the username alone", () => {
    expect(
      rejection(
        { username: "123" },
        { email: "Jane@Example.com", preferredUsername: "123" }
      )
    ).toBeUndefined();
  });

  it("requires an id token's email to match", () => {
    const claims = { "cognito:username": "123", email: "jane@example.com" };
    expect(
      rejection(claims, { email: "JANE@example.com", preferredUsername: "123" })
    ).toBeUndefined();
    expect(
      rejection(claims, { email: "boss@example.com", preferredUsername: "123" })
    ).toBe("email_mismatch");
  });

  it("requires a synthetic email to be the token user's own", () => {
    const claims = { username: "123" };
    expect(
      rejection(claims, {
        email: "123@synthetic.test",
        preferredUsername: "123",
      })
    ).toBeUndefined();
    expect(
      rejection(claims, {
        email: "456@synthetic.test",
        preferredUsername: "123",
      })
    ).toBe("synthetic_mismatch");
  });

  it("checks the username before the email", () => {
    expect(
      rejection(
        { username: "123", email: "x@example.com" },
        { email: "y@example.com", preferredUsername: "456" }
      )
    ).toBe("username_mismatch");
  });

  it("refuses a token without a username", () => {
    expect(
      rejection({}, { email: "a@example.com", preferredUsername: "123" })
    ).toBe("token_without_username");
  });

  it("skips the synthetic rule when no synthetic domain is configured", () => {
    expect(
      identityBindingRejection({
        claims: { username: "123" },
        headers: {
          email: "456@synthetic.test",
          preferredUsername: "123",
          user: "",
        },
        syntheticDomain: "",
        normalizeEmail: lower,
      })
    ).toBeUndefined();
  });
});
