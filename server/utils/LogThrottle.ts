export interface LogThrottleOptions {
  /** Minimum time between two log lines for the same key. */
  intervalMs: number;
  /** Most keys remembered; the least recently logged are forgotten first. */
  maxKeys?: number;
  /** Clock in milliseconds; injectable for tests. */
  clock?: () => number;
}

/**
 * Lets a log line through at most once per interval for each key, so a caller
 * repeating the same bad request cannot flood the logs.
 */
export class LogThrottle {
  public constructor({
    intervalMs,
    maxKeys = 1000,
    clock = () => Date.now(),
  }: LogThrottleOptions) {
    this.intervalMs = intervalMs;
    this.maxKeys = maxKeys;
    this.clock = clock;
  }

  /**
   * Whether a log line for this key may be written now; records it when so.
   *
   * @param key what the log line is about, such as a remote address.
   * @returns true when the key has not been logged within the interval.
   */
  public shouldLog(key: string): boolean {
    const now = this.clock();
    const last = this.loggedAt.get(key);
    if (last !== undefined && now - last < this.intervalMs) {
      return false;
    }
    this.loggedAt.delete(key);
    this.loggedAt.set(key, now);
    if (this.loggedAt.size > this.maxKeys) {
      const oldest = this.loggedAt.keys().next().value;
      if (oldest !== undefined) {
        this.loggedAt.delete(oldest);
      }
    }
    return true;
  }

  private readonly intervalMs: number;
  private readonly maxKeys: number;
  private readonly clock: () => number;
  private readonly loggedAt = new Map<string, number>();
}
