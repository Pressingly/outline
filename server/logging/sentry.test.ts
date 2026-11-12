import { withRedactedHeaders } from "./sentry";

describe("withRedactedHeaders", () => {
  it("redacts the edge secret and forwarded token, keeping other headers", () => {
    const event = {
      type: undefined,
      request: {
        url: "https://docs.example.test/api/auth.info",
        headers: {
          "X-Mpass-Edge-Secret": "secret",
          "x-auth-request-access-token": "token",
          "x-request-id": "req-1",
        },
      },
    };

    const redacted = withRedactedHeaders(event);

    expect(redacted.request?.headers).toEqual({
      "X-Mpass-Edge-Secret": "[Filtered]",
      "x-auth-request-access-token": "[Filtered]",
      "x-request-id": "req-1",
    });
    expect(redacted.request?.url).toEqual(event.request.url);
    expect(event.request.headers["X-Mpass-Edge-Secret"]).toEqual("secret");
  });

  it("returns an event without request headers unchanged", () => {
    const event = { type: undefined, message: "boom" };

    expect(withRedactedHeaders(event)).toBe(event);
  });
});
