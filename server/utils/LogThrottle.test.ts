import { LogThrottle } from "./LogThrottle";

describe("LogThrottle", () => {
  it("logs a key at most once per interval", () => {
    let now = 0;
    const throttle = new LogThrottle({ intervalMs: 60_000, clock: () => now });

    expect(throttle.shouldLog("10.0.0.1")).toBe(true);
    expect(throttle.shouldLog("10.0.0.1")).toBe(false);
    expect(throttle.shouldLog("10.0.0.2")).toBe(true);

    now = 59_999;
    expect(throttle.shouldLog("10.0.0.1")).toBe(false);
    now = 60_000;
    expect(throttle.shouldLog("10.0.0.1")).toBe(true);
  });

  it("forgets the least recently logged key beyond its bound", () => {
    const throttle = new LogThrottle({
      intervalMs: 60_000,
      maxKeys: 2,
      clock: () => 0,
    });

    throttle.shouldLog("a");
    throttle.shouldLog("b");
    throttle.shouldLog("c");

    expect(throttle.shouldLog("a")).toBe(true);
    expect(throttle.shouldLog("c")).toBe(false);
  });
});
