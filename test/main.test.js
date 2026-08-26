import assert from 'node:assert/strict';
import test from 'node:test';

import {
  __testables,
  connectionRowId,
  createHandler,
  oauthStateRowId,
} from '../src/main.js';

const NOW = new Date('2026-08-25T12:00:00.000Z');
const OWNER_ID = 'user_keepflip_123';
const ENCRYPTION_KEY = Buffer.alloc(32, 7);

function jsonResponse(status, body = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => JSON.stringify(body),
  };
}

function responseSink() {
  let response;
  return {
    res: {
      json(body, statusCode = 200) {
        response = { body, kind: 'json', statusCode };
        return response;
      },
    },
    response: () => response,
  };
}

function configureEnvironment() {
  process.env.APPWRITE_FUNCTION_API_ENDPOINT = 'https://appwrite.example/v1';
  process.env.APPWRITE_FUNCTION_PROJECT_ID = 'keepflip';
  process.env.EBAY_SANDBOX_CLIENT_ID = 'sandbox-client-id';
  process.env.EBAY_SANDBOX_CLIENT_SECRET = 'sandbox-client-secret';
  process.env.EBAY_SANDBOX_RUNAME = 'KeepFlip-TheJa-SBX-123';
  process.env.EBAY_PRODUCTION_CLIENT_ID = 'production-client-id';
  process.env.EBAY_PRODUCTION_CLIENT_SECRET = 'production-client-secret';
  process.env.EBAY_PRODUCTION_RUNAME = 'KeepFlip-TheJa-PRD-123';
  process.env.EBAY_TOKEN_ENCRYPTION_KEY = ENCRYPTION_KEY.toString('base64');
}

function authenticatedHeaders() {
  return {
    'x-appwrite-key': 'dynamic-function-key',
    'x-appwrite-user-id': OWNER_ID,
    'x-appwrite-user-jwt': 'user-jwt',
  };
}

function tokenCiphertext(tokenBundle) {
  return __testables.encryptSecret(
    JSON.stringify(tokenBundle),
    ENCRYPTION_KEY,
    (size) => Buffer.alloc(size, 3),
  );
}

test('creates a server-owned state and the matching eBay consent URL', async () => {
  configureEnvironment();
  const calls = [];
  const handler = createHandler({
    fetchImpl: async (url, options = {}) => {
      const request = { options, url: String(url) };
      calls.push(request);

      if (request.url.endsWith('/account')) {
        return jsonResponse(200, { $id: OWNER_ID });
      }
      if (
        request.url.endsWith(
          '/tablesdb/keepflip/tables/ebay_oauth_states/rows',
        ) &&
        options.method === 'POST'
      ) {
        return jsonResponse(201, { $id: 'state-row' });
      }

      throw new Error('Unexpected request: ' + request.url);
    },
    now: () => NOW,
    randomBytesImpl: (size) => Buffer.alloc(size, 4),
  });
  const sink = responseSink();

  await handler({
    req: {
      bodyJson: { environment: 'sandbox' },
      headers: authenticatedHeaders(),
      method: 'POST',
      path: '/connect',
    },
    res: sink.res,
  });

  const result = sink.response();
  assert.equal(result.kind, 'json');
  assert.equal(result.statusCode, 200);
  assert.equal(result.body.ok, true);
  assert.equal(result.body.environment, 'sandbox');

  const authorizationUrl = new URL(result.body.authorizationUrl);
  const state = authorizationUrl.searchParams.get('state');
  assert.equal(authorizationUrl.origin, 'https://auth.sandbox.ebay.com');
  assert.equal(authorizationUrl.pathname, '/oauth2/authorize');
  assert.equal(authorizationUrl.searchParams.get('client_id'), 'sandbox-client-id');
  assert.equal(
    authorizationUrl.searchParams.get('redirect_uri'),
    'KeepFlip-TheJa-SBX-123',
  );
  assert.equal(authorizationUrl.searchParams.get('response_type'), 'code');
  assert.equal(
    authorizationUrl.searchParams.get('scope'),
    'https://api.ebay.com/oauth/api_scope https://api.ebay.com/oauth/api_scope/commerce.identity.readonly',
  );
  assert.match(state, /^[A-Za-z0-9_-]{43}$/);

  const stateWrite = calls.find(
    (call) =>
      call.url.endsWith(
        '/tablesdb/keepflip/tables/ebay_oauth_states/rows',
      ) && call.options.method === 'POST',
  );
  const payload = JSON.parse(stateWrite.options.body);
  assert.equal(payload.rowId, oauthStateRowId(state));
  assert.equal(payload.data.ownerId, OWNER_ID);
  assert.equal(payload.data.environment, 'sandbox');
  assert.equal(payload.data.status, 'pending');
  assert.equal(JSON.stringify(payload.data).includes(state), false);

  const accountRequest = calls.find((call) => call.url.endsWith('/account'));
  assert.equal(accountRequest.options.headers['X-Appwrite-JWT'], 'user-jwt');
});

test('returns only safe connection status for an authenticated user', async () => {
  configureEnvironment();
  const accessToken = 'access-token-that-must-not-leak';
  const refreshToken = 'refresh-token-that-must-not-leak';
  const handler = createHandler({
    fetchImpl: async (url) => {
      const requestUrl = String(url);
      if (requestUrl.endsWith('/account')) {
        return jsonResponse(200, { $id: OWNER_ID });
      }
      if (
        requestUrl.endsWith(
          '/rows/' + connectionRowId(OWNER_ID, 'sandbox'),
        )
      ) {
        return jsonResponse(200, {
          ownerId: OWNER_ID,
          ebayUsername: 'keepflip.ebay',
          encryptedTokens: tokenCiphertext({
            accessToken,
            accessTokenExpiresAt: '2026-08-25T13:00:00.000Z',
            refreshToken,
            refreshTokenExpiresAt: '2027-08-25T12:00:00.000Z',
          }),
          revokedAt: null,
        });
      }

      throw new Error('Unexpected request: ' + requestUrl);
    },
    now: () => NOW,
  });
  const sink = responseSink();

  await handler({
    req: {
      bodyJson: { environment: 'sandbox' },
      headers: authenticatedHeaders(),
      method: 'POST',
      path: '/status',
    },
    res: sink.res,
  });

  assert.deepEqual(sink.response().body, {
    connected: true,
    environment: 'sandbox',
    ebayUsername: 'keepflip.ebay',
    accessTokenExpiresAt: '2026-08-25T13:00:00.000Z',
    refreshTokenExpiresAt: '2027-08-25T12:00:00.000Z',
    accessTokenExpired: false,
    needsReconnect: false,
  });
  assert.equal(JSON.stringify(sink.response().body).includes(accessToken), false);
  assert.equal(JSON.stringify(sink.response().body).includes(refreshToken), false);
});

test('refreshes the stored token without exposing it to the app', async () => {
  configureEnvironment();
  const previousAccessToken = 'previous-access-token';
  const previousRefreshToken = 'previous-refresh-token';
  const refreshedAccessToken = 'refreshed-access-token';
  const calls = [];
  const handler = createHandler({
    fetchImpl: async (url, options = {}) => {
      const request = { options, url: String(url) };
      calls.push(request);

      if (request.url.endsWith('/account')) {
        return jsonResponse(200, { $id: OWNER_ID });
      }
      if (
        request.url.endsWith(
          '/rows/' + connectionRowId(OWNER_ID, 'sandbox'),
        ) &&
        options.method === 'GET'
      ) {
        return jsonResponse(200, {
          ownerId: OWNER_ID,
          encryptedTokens: tokenCiphertext({
            accessToken: previousAccessToken,
            accessTokenExpiresAt: '2026-08-25T12:30:00.000Z',
            refreshToken: previousRefreshToken,
            refreshTokenExpiresAt: '2027-08-25T12:00:00.000Z',
          }),
          revokedAt: null,
        });
      }
      if (
        request.url ===
        'https://api.sandbox.ebay.com/identity/v1/oauth2/token'
      ) {
        return jsonResponse(200, {
          access_token: refreshedAccessToken,
          expires_in: 7200,
          token_type: 'User Access Token',
        });
      }
      if (
        request.url.endsWith(
          '/rows/' + connectionRowId(OWNER_ID, 'sandbox'),
        ) &&
        options.method === 'PATCH'
      ) {
        return jsonResponse(200, { $id: 'connection-row' });
      }

      throw new Error('Unexpected request: ' + request.url);
    },
    now: () => NOW,
    randomBytesImpl: (size) => Buffer.alloc(size, 9),
  });
  const sink = responseSink();

  await handler({
    req: {
      bodyJson: { environment: 'sandbox' },
      headers: authenticatedHeaders(),
      method: 'POST',
      path: '/refresh',
    },
    res: sink.res,
  });

  assert.deepEqual(sink.response().body, {
    refreshed: true,
    connected: true,
    environment: 'sandbox',
    accessTokenExpiresAt: '2026-08-25T14:00:00.000Z',
    needsReconnect: false,
  });

  const connectionWrite = calls.find(
    (call) =>
      call.url.endsWith(
        '/rows/' + connectionRowId(OWNER_ID, 'sandbox'),
      ) && call.options.method === 'PATCH',
  );
  const payload = JSON.parse(connectionWrite.options.body);
  assert.match(
    payload.data.encryptedTokens,
    /^v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/,
  );
  assert.equal(payload.data.encryptedTokens.includes(refreshedAccessToken), false);
  assert.equal(payload.data.encryptedTokens.includes(previousRefreshToken), false);
  assert.equal(
    new URLSearchParams(
      calls.find(
        (call) =>
          call.url ===
          'https://api.sandbox.ebay.com/identity/v1/oauth2/token',
      ).options.body,
    ).get('refresh_token'),
    previousRefreshToken,
  );
});

test('rejects app calls that do not carry an Appwrite user session', async () => {
  configureEnvironment();
  const handler = createHandler({
    fetchImpl: async () => {
      throw new Error('The backend must not be called without a JWT.');
    },
    now: () => NOW,
  });
  const sink = responseSink();

  await handler({
    req: {
      bodyJson: { environment: 'sandbox' },
      headers: { 'x-appwrite-key': 'dynamic-function-key' },
      method: 'POST',
      path: '/connect',
    },
    res: sink.res,
  });

  assert.equal(sink.response().statusCode, 401);
  assert.equal(
    sink.response().body.error,
    'You must be signed in to KeepFlip to connect eBay.',
  );
});
