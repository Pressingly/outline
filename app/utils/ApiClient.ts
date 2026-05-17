import retry from "fetch-retry";
import trim from "lodash/trim";
import queryString from "query-string";
import EDITOR_VERSION from "@shared/editor/version";
import type { JSONObject } from "@shared/types";
import { Scope } from "@shared/types";
import { version } from "../../package.json";
import env from "~/env";
import stores from "~/stores";
import Logger from "./Logger";
import download from "./download";
import {
  AuthorizationError,
  BadGatewayError,
  BadRequestError,
  NetworkError,
  NotFoundError,
  OfflineError,
  PaymentRequiredError,
  RateLimitExceededError,
  RequestError,
  ServiceUnavailableError,
  UnprocessableEntityError,
  UpdateRequiredError,
} from "./errors";
import { getCookie } from "tiny-cookie";
import { CSRF } from "@shared/constants";
import AuthenticationHelper from "@shared/helpers/AuthenticationHelper";
import { wipeAndReload } from "./userContinuity";

type Options = {
  baseUrl?: string;
};

interface FetchOptions {
  download?: boolean;
  retry?: boolean;
  credentials?: "omit" | "same-origin" | "include";
  headers?: Record<string, string>;
  baseUrl?: string;
}

const fetchWithRetry = retry(fetch);

class ApiClient {
  baseUrl: string;

  shareId?: string;

  /** Map of in-flight POST requests for deduplication, keyed by path + body. */
  private inflightRequests = new Map<string, Promise<any>>();

  constructor(options: Options = {}) {
    this.baseUrl = options.baseUrl || "/api";
  }

  setShareId = (shareId: string | undefined) => {
    this.shareId = shareId;
  };

  fetch = async <T = any>(
    path: string,
    method: string,
    data: JSONObject | FormData | undefined,
    options: FetchOptions = {}
  ): Promise<T> => {
    let body: string | FormData | undefined;
    let modifiedPath;
    let urlToFetch;
    let isJson;

    if (this.shareId) {
      // add to data
      data = {
        ...(data || {}),
        shareId: this.shareId,
      };
    }

    if (method === "GET") {
      if (data) {
        modifiedPath = `${path}?${data && queryString.stringify(data)}`;
      } else {
        modifiedPath = path;
      }
    } else if (method === "POST" || method === "PUT") {
      if (data instanceof FormData || typeof data === "string") {
        body = data;
      } else {
        isJson = true;

        // Only stringify data if its a normal object and
        // not if it's [object FormData], in addition to
        // toggling Content-Type to application/json
        if (
          typeof data === "object" &&
          (data || "").toString() === "[object Object]"
        ) {
          body = JSON.stringify(data);
        }
      }
    }

    if (path.match(/^http/)) {
      urlToFetch = modifiedPath || path;
    } else {
      urlToFetch = (options.baseUrl ?? this.baseUrl) + (modifiedPath || path);
    }

    const headerOptions: Record<string, string> = {
      Accept: "application/json",
      "cache-control": "no-cache",
      "x-editor-version": EDITOR_VERSION,
      "x-api-version": "4",
      "x-client-version": env.VERSION ? `${version}-${env.VERSION}` : version,
      pragma: "no-cache",
      ...options?.headers,
    };

    // Add CSRF token to headers for mutating requests
    const isModifyingRequest = ["POST", "PUT", "PATCH", "DELETE"].includes(
      method
    );
    const canAccessWithReadOnly = AuthenticationHelper.canAccess(path, [
      Scope.Read,
    ]);
    if (isModifyingRequest && !canAccessWithReadOnly) {
      const csrfToken = getCookie(CSRF.cookieName);
      if (csrfToken) {
        headerOptions[CSRF.headerName] = csrfToken;
      }
    }

    // for multipart forms or other non JSON requests fetch
    // populates the Content-Type without needing to explicitly
    // set it.
    if (isJson) {
      headerOptions["Content-Type"] = "application/json";
    }

    const headers = new Headers(headerOptions);
    const timeStart = window.performance.now();
    let response;

    try {
      response = await (options?.retry === false ? fetch : fetchWithRetry)(
        urlToFetch,
        {
          method,
          body,
          headers,
          redirect: "follow",
          credentials: "same-origin",
          cache: "no-cache",
        }
      );
    } catch (_err) {
      if (window.navigator.onLine) {
        throw new NetworkError("A network error occurred, try again?");
      } else {
        throw new OfflineError("No internet connection available");
      }
    }

    const timeEnd = window.performance.now();
    const success = response.status >= 200 && response.status < 300;

    // Stale-session redirect detection. Outline's auth middleware only
    // runs on /api/* routes — so on a user switch, the SPA HTML at /
    // is served WITHOUT the middleware noticing the cookie/header
    // mismatch. The mismatch is only detected on the first /api call
    // after boot (typically auth.info). The server responds with 302
    // + Set-Cookie clearing accessToken + Location: /home. Fetch
    // auto-follows (redirect: "follow"), lands on /home which serves
    // HTML — so `response.redirected` is true and `response.url`
    // points at /home (or some other non-/api path).
    //
    // Without this hook the SPA keeps showing the previous user's
    // data from the rehydrated AUTH_STORE until a full hard nav
    // triggers checkUserContinuity. Symptom: bottom-left avatar
    // shows the previous user immediately after a user switch.
    //
    // We trigger the same wipe checkUserContinuity does, then
    // hard-navigate to /home so the SPA re-mounts on a clean slate
    // (localStorage empty → fresh AuthStore → fresh fetchAuth →
    // correct user).
    //
    // Only trigger in SSO mode where the redirect is part of the
    // expected stale-session flow. In non-SSO deployments, any
    // /api redirect is unexpected and shouldn't trigger a wipe.
    //
    // Detection signals (any of):
    //   - response.redirected is true and final URL is not under /api
    //     (definitive: fetch followed at least one redirect off the
    //     /api namespace)
    //   - Content-Type is text/html for an /api request (the SPA
    //     HTML fallback handler caught it — happens when the redirect
    //     target served HTML, or when some intermediary stripped the
    //     302 and returned HTML directly)
    //
    // Either signal is sufficient. Both can be true together but only
    // the first qualifying detection matters since wipeAndReload is
    // idempotent.
    if (env.AUTH_TYPE === "SSO") {
      const contentType = response.headers.get("content-type") || "";
      const finalUrlOffApi = !response.url.includes("/api/");
      const wasRedirected = response.redirected && finalUrlOffApi;
      // Only treat HTML-on-API as a stale-session signal when the
      // response is a SUCCESS (the 302→/home bounce ends up as 200
      // HTML after fetch follows). A 502/503/4xx HTML error page —
      // Traefik gateway error, oauth2-proxy expiry redirect, etc. —
      // means the user has to re-auth via the normal channels but
      // their browser-local state should NOT be wiped on a transient
      // infrastructure hiccup. Gating on `success` keeps the wipe
      // tightly scoped to the actual stale-session flow.
      const gotHtmlOnApiCall = success && contentType.includes("text/html");
      if (wasRedirected || gotHtmlOnApiCall) {
        Logger.info("lifecycle", "Stale-session redirect detected", {
          redirected: response.redirected,
          finalUrl: response.url,
          contentType,
          status: response.status,
        });
        await wipeAndReload();
        throw new AuthorizationError();
      }
    }

    if (options.download && success) {
      const blob = await response.blob();
      const fileName = (
        response.headers.get("content-disposition") || ""
      ).split("filename=")[1];
      download(blob, trim(fileName, '"'));
      return undefined as T;
    } else if (success && response.status === 204) {
      return undefined as T;
    } else if (success) {
      return response.json();
    }

    // Handle 401, log out user
    if (response.status === 401) {
      if (!this.shareId) {
        if (env.AUTH_TYPE === "SSO") {
          // In ForwardAuth mode, the stale JWT cookie has been cleared by the
          // server. Navigate to the current URL so the browser makes a fresh
          // HTTP request — the proxy will inject new identity headers and a new
          // session will be issued automatically.
          //
          // We skip auth.logout() here: clearing MobX state would cause
          // <Authenticated> to render <Redirect to="/" /> and land the user on
          // the login page instead of their original document.
          window.location.replace(window.location.href);
          throw new AuthorizationError();
        }
        await stores.auth.logout({
          savePath: true,
          clearCache: false,
          revokeToken: false,
        });
      }
      throw new AuthorizationError();
    }

    if (response.status === 502) {
      const text = await response.text();
      const err = new BadGatewayError(text);

      Logger.error("BadGatewayError", err, {
        url: urlToFetch,
        requestTime: Math.round(timeEnd - timeStart),
        responseText: text,
        responseHeaders: Object.fromEntries(response.headers.entries()),
      });
      throw err;
    }

    // Handle failed responses
    const error: {
      message?: string;
      error?: string;
      data?: Record<string, any>;
    } = {};

    try {
      const parsed = await response.json();
      error.message = parsed.message || "";
      error.error = parsed.error;
      error.data = parsed.data;
    } catch (_err) {
      // we're trying to parse an error so JSON may not be valid
    }

    if (response.status === 400 && error.error === "editor_update_required") {
      window.location.reload();
      throw new UpdateRequiredError(error.message);
    }

    if (response.status === 400) {
      throw new BadRequestError(error.message);
    }

    if (response.status === 402) {
      throw new PaymentRequiredError(error.message);
    }

    if (response.status === 403) {
      if (error.error === "user_suspended") {
        await stores.auth.logout({
          savePath: false,
          revokeToken: false,
        });
      }

      if (error.error === "csrf_error") {
        throw new AuthorizationError(
          "CSRF token invalid, please try reloading."
        );
      }

      throw new AuthorizationError(error.message);
    }

    if (response.status === 404) {
      throw new NotFoundError(error.message);
    }

    if (response.status === 503) {
      throw new ServiceUnavailableError(error.message);
    }

    if (response.status === 422) {
      throw new UnprocessableEntityError(error.message);
    }

    if (response.status === 429) {
      throw new RateLimitExceededError(
        `Too many requests, try again in a minute.`
      );
    }

    const err = new RequestError(`Error ${response.status}`);
    Logger.error("Request failed", err, {
      ...error,
      url: urlToFetch,
    });

    // Still need to throw to trigger retry
    throw err;
  };

  get = <T = any>(
    path: string,
    data: JSONObject | undefined,
    options?: FetchOptions
  ) => this.fetch<T>(path, "GET", data, options);

  post = <T = any>(
    path: string,
    data?: JSONObject | FormData | undefined,
    options?: FetchOptions
  ): Promise<T> => {
    if (data instanceof FormData) {
      return this.fetch<T>(path, "POST", data, options);
    }

    const key = `${path}:${JSON.stringify(data)}:${JSON.stringify(options)}`;
    const inflight = this.inflightRequests.get(key);
    if (inflight) {
      return inflight;
    }

    const promise = this.fetch<T>(path, "POST", data, options).finally(() => {
      this.inflightRequests.delete(key);
    });
    this.inflightRequests.set(key, promise);
    return promise;
  };
}

export const client = new ApiClient();
