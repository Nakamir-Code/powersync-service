import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';

import { fetchOidcToken, makeExpiryParser } from '../../../src/auth/oidc.js';

describe('makeExpiryParser', () => {
  test('reads a relative lifetime in seconds', () => {
    expect(makeExpiryParser({ field: 'expires_in' })({ expires_in: 3600 })).toEqual(3600);
  });

  test('returns undefined for a non-positive relative value', () => {
    expect(makeExpiryParser({ field: 'expires_in' })({ expires_in: 0 })).toBeUndefined();
  });

  test('returns undefined when the field is absent', () => {
    expect(makeExpiryParser({ field: 'expires_in' })({})).toBeUndefined();
  });

  describe('absolute', () => {
    // 2026-01-01T00:00:00Z = 1767225600 epoch seconds.
    const NOW_SECONDS = 1767225600;

    beforeEach(() => {
      vi.useFakeTimers();
      vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    test('reads an epoch-seconds timestamp', () => {
      const parse = makeExpiryParser({ field: 'expires_on', kind: 'absolute' });
      expect(parse({ expires_on: NOW_SECONDS + 3600 })).toEqual(3600);
    });

    test('reads an epoch-milliseconds timestamp', () => {
      const parse = makeExpiryParser({ field: 'expires_on', kind: 'absolute' });
      expect(parse({ expires_on: (NOW_SECONDS + 3600) * 1000 })).toEqual(3600);
    });

    test('reads a date string', () => {
      const parse = makeExpiryParser({ field: 'expires_on', kind: 'absolute' });
      expect(parse({ expires_on: '2026-01-01T01:00:00Z' })).toEqual(3600);
    });

    test('returns undefined for an already-past timestamp', () => {
      const parse = makeExpiryParser({ field: 'expires_on', kind: 'absolute' });
      expect(parse({ expires_on: NOW_SECONDS - 60 })).toBeUndefined();
    });
  });
});

describe('fetchOidcToken', () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock);
  });

  afterEach(() => {
    vi.useRealTimers();
    fetchMock.mockReset();
    vi.unstubAllGlobals();
  });

  test('returns the access token and parsed lifetime', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ access_token: 'abc', expires_in: 3600 }), { status: 200 }));

    const token = await fetchOidcToken('https://idp.example/token', undefined, {
      parseExpiry: makeExpiryParser({ field: 'expires_in' })
    });

    expect(token).toEqual({ accessToken: 'abc', expiresInSeconds: 3600 });
  });

  test('throws on a non-2xx response', async () => {
    fetchMock.mockResolvedValue(new Response('nope', { status: 401 }));

    await expect(fetchOidcToken('https://idp.example/token')).rejects.toThrow('HTTP 401');
  });

  test('throws when the body has no string access_token', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ token: 'abc' }), { status: 200 }));

    await expect(fetchOidcToken('https://idp.example/token')).rejects.toThrow('no access_token');
  });

  test('throws a timeout error when the request exceeds timeoutMs', async () => {
    vi.useFakeTimers();
    fetchMock.mockImplementation(
      (_url: any, init: any) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => reject(init.signal.reason));
        })
    );

    const request = expect(
      fetchOidcToken('https://idp.example/token', undefined, { timeoutMs: 25 })
    ).rejects.toThrow('timed out after 25ms');

    await vi.advanceTimersByTimeAsync(25);
    await request;
  });
});
