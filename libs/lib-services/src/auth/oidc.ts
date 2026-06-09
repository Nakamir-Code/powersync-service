export interface OidcToken {
  /** The access token (JWT) to present to the resource. */
  accessToken: string;
  /**
   * Seconds until the token expires, if the endpoint reported it. Used for proactive refresh; when
   * absent, the consumer is limited to reactive re-auth (refresh only after an auth failure).
   */
  expiresInSeconds?: number;
}

/**
 * Description of where and how a token endpoint reports its expiry. See {@link makeExpiryParser}.
 */
export interface ExpirySpec {
  /** JSON field on the token response that carries the expiry, e.g. `expires_in` or `expires_on`. */
  field: string;
  /**
   * How to read `field`. `relative` (the default) is a lifetime in seconds, like the standard OAuth2
   * `expires_in`. `absolute` is a point in time from which the remaining lifetime is computed.
   */
  kind?: 'relative' | 'absolute';
}

export interface FetchOidcTokenOptions {
  /**
   * Derive the token lifetime (seconds from now) from the response body.
   */
  parseExpiry?: (body: any) => number | undefined;
  /**
   * Abort the request after this many milliseconds. Defaults to {@link DEFAULT_TOKEN_REQUEST_TIMEOUT_MS}.
   */
  timeoutMs?: number;
}

/**
 * Epoch timestamps below this are seconds; above, they're already milliseconds.
 */
const MAX_EPOCH_SECONDS = 1e11;

/**
 * Default request timeout, so a hung metadata service can't stall the OIDC callback indefinitely.
 */
const DEFAULT_TOKEN_REQUEST_TIMEOUT_MS = 30_000;

/**
 * Build a parser that extracts a token's remaining lifetime from a response body.
 *
 * @returns a function giving seconds from now, or undefined if the field is missing or unparseable.
 */
export function makeExpiryParser(spec: ExpirySpec): (body: any) => number | undefined {
  return (body) => {
    const raw = body?.[spec.field];
    if (raw == null) {
      // Field not present on this response - no expiry to report.
      return undefined;
    }
    if ((spec.kind ?? 'relative') === 'relative') {
      // Relative: already a lifetime in seconds, so used as-is.
      const seconds = Number(raw);
      return Number.isFinite(seconds) && seconds > 0 ? Math.floor(seconds) : undefined;
    }
    // Absolute: a timestamp to convert to remaining seconds. Auto-detect the encoding.
    const numeric = Number(raw);
    let absoluteMs: number;
    if (!Number.isFinite(numeric)) {
      absoluteMs = Date.parse(raw); // Date string.
    } else if (numeric > MAX_EPOCH_SECONDS) {
      absoluteMs = numeric; // Epoch milliseconds.
    } else {
      absoluteMs = numeric * 1000; // Epoch seconds.
    }
    if (!Number.isFinite(absoluteMs)) {
      return undefined;
    }
    const seconds = Math.floor((absoluteMs - Date.now()) / 1000);
    return seconds > 0 ? seconds : undefined;
  };
}

/**
 * Fetch an OAuth2/OIDC access token from a bring-your-own HTTP token endpoint - e.g. a cloud
 * managed-identity or instance-metadata service.
 *
 * @throws if the request times out, the endpoint returns a non-2xx status, or the body has no string `access_token`.
 * @returns the access token and, if `options.parseExpiry` resolves one, its remaining lifetime.
 */
export async function fetchOidcToken(
  tokenUrl: string,
  tokenHeaders?: Record<string, string>,
  options?: FetchOidcTokenOptions
): Promise<OidcToken> {
  const timeoutMs = options?.timeoutMs ?? DEFAULT_TOKEN_REQUEST_TIMEOUT_MS;
  const abortController = new AbortController();
  const timeout = setTimeout(() => abortController.abort(), timeoutMs);

  try {
    const response = await fetch(tokenUrl, {
      headers: tokenHeaders ?? {},
      signal: abortController.signal
    });
    if (!response.ok) {
      throw new Error(`OIDC token endpoint returned HTTP ${response.status}`);
    }
    const body: any = await response.json();
    if (typeof body?.access_token !== 'string') {
      throw new Error('OIDC token endpoint returned no access_token');
    }
    // Lifetime comes entirely from the caller-supplied (config-driven) parser.
    const expiresInSeconds = options?.parseExpiry?.(body);
    return { accessToken: body.access_token, expiresInSeconds };
  } catch (e) {
    if (e instanceof Error && e.name === 'AbortError') {
      throw new Error(`OIDC token endpoint timed out after ${timeoutMs}ms`);
    }
    throw e;
  } finally {
    clearTimeout(timeout);
  }
}
