import {
  MIN_EDGE_SECRET_LENGTH,
  edgeSecretIsUsable,
  requestIsFromEdge,
} from "./mpassEdgeTrust";

const SECRET = "s".repeat(64);

describe("edgeSecretIsUsable", () => {
  it.each([
    ["", false],
    ["   ", false],
    ["s".repeat(MIN_EDGE_SECRET_LENGTH - 1), false],
    [` ${"s".repeat(MIN_EDGE_SECRET_LENGTH - 1)} `, false],
    ["s".repeat(MIN_EDGE_SECRET_LENGTH), true],
    [SECRET, true],
  ])("treats %j as usable=%s", (secret, usable) => {
    expect(edgeSecretIsUsable(secret)).toBe(usable);
  });
});

describe("requestIsFromEdge", () => {
  it("trusts a request carrying the configured secret", () => {
    expect(requestIsFromEdge(SECRET, SECRET)).toBe(true);
  });

  it("trusts the secret when the configured value has stray whitespace", () => {
    expect(requestIsFromEdge(SECRET, `${SECRET}\n`)).toBe(true);
  });

  it.each([
    ["missing", undefined],
    ["empty", ""],
    ["wrong", "x".repeat(64)],
    ["prefix", SECRET.slice(0, 40)],
    ["longer", `${SECRET}x`],
  ])("rejects a %s secret", (_label, presented) => {
    expect(requestIsFromEdge(presented, SECRET)).toBe(false);
  });

  it("trusts nothing when the configured secret is too short, even on a match", () => {
    const short = "s".repeat(MIN_EDGE_SECRET_LENGTH - 1);
    expect(requestIsFromEdge(short, short)).toBe(false);
  });

  it("trusts nothing when the configured secret is a CHANGE_ME_ placeholder", () => {
    const placeholder = `CHANGE_ME_${"x".repeat(40)}`;

    expect(edgeSecretIsUsable(placeholder)).toBe(false);
    expect(requestIsFromEdge(placeholder, placeholder)).toBe(false);
  });

  it("trusts nothing when no secret is configured", () => {
    expect(requestIsFromEdge("", "")).toBe(false);
  });
});
