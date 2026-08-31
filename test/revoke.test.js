import assert from 'node:assert/strict';
import test from 'node:test';

import {
  __testables,
  connectionRowId,
  createHandler,
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
        response = { body, statusCode };
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

test('revokes the owner eBay refresh token and clears local credentials without returning them', async () => {
  configureEnvironment();
  const accessToken = 'access-token-that-must-not-leak';
  const refreshToken = 'refresh-token-that-must-not-leak';
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
          ebayUsername: 'keepflip.ebay',
          encryptedTokens: __testables.encryptSecret(
            JSON.stringify({
              accessToken,
              accessTokenExpiresAt: '2026-08-25T13:00:00.000Z',
              refreshToken,
              refreshTokenExpiresAt: '2027-08-25T12:00:00.000Z',
            }),
            ENCRYPTION_KEY,
            (size) => Buffer.alloc(size, 3),
          ),
          revokedAt: null,
        });
      }
      if (
        request.url ===
        'https://api.sandbox.ebay.com/identity/v1/oauth2/token/revoke'
      ) {
        const form = new URLSearchParams(options.body);
        assert.equal(form.get('token'), refreshToken);
        assert.equal(form.get('token_type_hint'), 'refresh_token');
        assert.equal(
          options.headers.Authorization,
          'Basic ' +
            Buffer.from(
              'sandbox-client-id:sandbox-client-secret',
              'utf8',
            ).toString('base64'),
        );
        return jsonResponse(200);
      }
      if (
        request.url.endsWith(
          '/rows/' + connectionRowId(OWNER_ID, 'sandbox'),
        ) &&
        options.method === 'DELETE'
      ) {
        return jsonResponse(204);
      }

      throw new Error('Unexpected request: ' + request.url);
    },
    now: () => NOW,
  });
  const sink = responseSink();

  await handler({
    req: {
      bodyJson: { environment: 'sandbox' },
      headers: authenticatedHeaders(),
      method: 'POST',
      path: '/revoke',
    },
    res: sink.res,
  });

  assert.deepEqual(sink.response(), {
    body: { revoked: true, connected: false, environment: 'sandbox' },
    statusCode: 200,
  });
  assert.equal(JSON.stringify(sink.response()).includes(accessToken), false);
  assert.equal(JSON.stringify(sink.response()).includes(refreshToken), false);

  const localDelete = calls.find(
    (call) =>
      call.url.endsWith(
        '/rows/' + connectionRowId(OWNER_ID, 'sandbox'),
      ) &&
      call.options.method === 'DELETE',
  );
  
  assert.ok(
    localDelete,
    'Expected the eBay connection row to be deleted.',
  );
  
  assert.equal(
    localDelete.options.body,
    undefined,
  );
});
