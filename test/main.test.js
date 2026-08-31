import assert from 'node:assert/strict';
import test from 'node:test';

import {
  __testables,
  connectionRowId,
  createHandler,
  sellerBusinessPolicyRowId,
  sellerInventoryLocationRowId,
  sellerListingDefaultsRowId,
  sellerProfileRowId,
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

test('creates a server-owned state for the app-owned eBay consent URL', async () => {
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

  assert.match(result.body.state, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(typeof result.body.expiresAt, 'string');
  assert.equal('authorizationUrl' in result.body, false);
  const state = result.body.state;

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

test('returns a reconnect state when a saved connection cannot be decrypted', async () => {
  configureEnvironment();
  const logs = [];
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
          encryptedTokens: 'v1.not-a-valid-encrypted-token',
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
    error: (message) => logs.push(message),
  });

  assert.deepEqual(sink.response(), {
    body: {
      connected: false,
      environment: 'sandbox',
      needsReconnect: true,
    },
    kind: 'json',
    statusCode: 200,
  });
  assert.deepEqual(logs, [
    'KeepFlip eBay OAuth backend request failed. route=/status status=500 reason=STORED_CONNECTION_UNREADABLE',
  ]);
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
        'https://apiz.sandbox.ebay.com/identity/v1/oauth2/token'
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
        options.method === 'DELETE'
      ) {
        return jsonResponse(204);
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


test('syncs an allowlisted seller profile and returns only safe cached listing data', async () => {
  configureEnvironment();
  const accessToken = 'access-token-that-must-not-leak';
  const refreshToken = 'refresh-token-that-must-not-leak';
  const ebayUserId = 'ebay-user-id-that-must-not-leak';
  const privateEmail = 'seller-private@example.test';
  const privatePhone = '+15550123';
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
            accessToken,
            accessTokenExpiresAt: '2026-08-25T13:00:00.000Z',
            refreshToken,
            refreshTokenExpiresAt: '2027-08-25T12:00:00.000Z',
          }),
          revokedAt: null,
        });
      }
      if (
        request.url.endsWith(
          '/rows/' + sellerProfileRowId(OWNER_ID, 'sandbox'),
        ) &&
        options.method === 'GET'
      ) {
        return jsonResponse(404);
      }
      if (
        request.url ===
        'https://apiz.sandbox.ebay.com/commerce/identity/v1/user/'
      ) {
        return jsonResponse(200, {
          userId: ebayUserId,
          username: 'keepflip.ebay',
          accountType: 'BUSINESS',
          accountStatus: 'CONFIRMED',
          registrationMarketplaceId: 'EBAY_US',
          email: privateEmail,
          phone: privatePhone,
          businessAccount: {
            legalName: 'KeepFlip Resale LLC',
            doingBusinessAs: 'KeepFlip Vintage',
            website: 'https://keepflip.example/seller',
            primaryPhone: privatePhone,
          },
        });
      }
      if (
        request.url.endsWith(
          '/rows/' + sellerProfileRowId(OWNER_ID, 'sandbox'),
        ) &&
        options.method === 'PATCH'
      ) {
        return jsonResponse(404);
      }
      if (
        request.url.endsWith(
          '/tablesdb/keepflip/tables/ebay_seller_profiles/rows',
        ) &&
        options.method === 'POST'
      ) {
        return jsonResponse(201, { $id: 'seller-profile-row' });
      }
      if (
        request.url.startsWith(
          'https://appwrite.example/v1/tablesdb/keepflip/tables/ebay_seller_listings/rows?',
        ) &&
        options.method === 'GET'
      ) {
        return jsonResponse(200, {
          total: 1,
          rows: [
            {
              ebayListingId: '123456789',
              ebayOfferId: 'offer-123',
              ebaySku: 'KF-123',
              listingTitle: 'Vintage jacket',
              listingStatus: 'PUBLISHED',
              listingUrl: 'https://www.ebay.com/itm/123456789',
              currentPriceCents: 5000,
              currency: 'USD',
              quantityAvailable: 1,
              lastSyncedAt: NOW.toISOString(),
              buyerEmail: privateEmail,
            },
          ],
        });
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
      path: '/seller-account',
    },
    res: sink.res,
  });

  assert.equal(sink.response().statusCode, 200);
  assert.equal(sink.response().body.connected, true);
  assert.equal(sink.response().body.environment, 'sandbox');
  assert.equal(sink.response().body.profileFreshness, 'current');
  assert.deepEqual(sink.response().body.profile, {
    username: 'keepflip.ebay',
    accountType: 'BUSINESS',
    accountStatus: 'CONFIRMED',
    registrationMarketplaceId: 'EBAY_US',
    businessName: 'KeepFlip Resale LLC',
    doingBusinessAs: 'KeepFlip Vintage',
    businessWebsiteUrl: 'https://keepflip.example/seller',
    lastSyncedAt: NOW.toISOString(),
  });
  assert.equal(sink.response().body.listingCount, 1);
  assert.equal(sink.response().body.listings.length, 1);
  assert.equal(sink.response().body.listings[0].title, 'Vintage jacket');
  assert.equal(sink.response().body.listings[0].currentPriceCents, 5000);
  assert.equal('buyerEmail' in sink.response().body.listings[0], false);

  const serial = JSON.stringify(sink.response().body);
  assert.equal(serial.includes(accessToken), false);
  assert.equal(serial.includes(refreshToken), false);
  assert.equal(serial.includes(ebayUserId), false);
  assert.equal(serial.includes(privateEmail), false);
  assert.equal(serial.includes(privatePhone), false);

  const identityRequest = calls.find(
    (call) =>
      call.url ===
      'https://api.sandbox.ebay.com/commerce/identity/v1/user/',
  );
  assert.equal(
    identityRequest.options.headers.Authorization,
    'Bearer ' + accessToken,
  );

  const profileWrite = calls.find(
    (call) =>
      call.url.endsWith(
        '/tablesdb/keepflip/tables/ebay_seller_profiles/rows',
      ) && call.options.method === 'POST',
  );
  const profileData = JSON.parse(profileWrite.options.body).data;
  assert.equal(profileData.ownerId, OWNER_ID);
  assert.equal(profileData.environment, 'sandbox');
  assert.equal(profileData.ebayUsername, 'keepflip.ebay');
  assert.equal(profileData.ebayProfileSnapshotJson.includes(ebayUserId), false);
  assert.equal(profileData.ebayProfileSnapshotJson.includes(privateEmail), false);
  assert.equal(profileData.ebayProfileSnapshotJson.includes(privatePhone), false);
});
test('syncs safe eBay policies, locations, and unambiguous listing defaults', async () => {
  configureEnvironment();
  const accessToken = 'access-token-that-must-not-leak';
  const refreshToken = 'refresh-token-that-must-not-leak';
  const privateEmail = 'private-seller@example.test';
  const privateAddress = '123 Private Warehouse Lane';
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
            accessToken,
            accessTokenExpiresAt: '2026-08-25T13:00:00.000Z',
            refreshToken,
            refreshTokenExpiresAt: '2027-08-25T12:00:00.000Z',
          }),
          revokedAt: null,
        });
      }
      if (
        request.url.endsWith(
          '/rows/' + sellerProfileRowId(OWNER_ID, 'sandbox'),
        ) &&
        options.method === 'GET'
      ) {
        return jsonResponse(404);
      }
      if (
        request.url ===
        'https://apiz.sandbox.ebay.com/commerce/identity/v1/user/'
      ) {
        return jsonResponse(200, {
          userId: 'raw-ebay-user-id-must-not-persist',
          username: 'keepflip.ebay',
          accountType: 'BUSINESS',
          accountStatus: 'CONFIRMED',
          registrationMarketplaceId: 'EBAY_US',
          email: privateEmail,
        });
      }
      if (
        request.url ===
        'https://api.sandbox.ebay.com/sell/account/v1/payment_policy?marketplace_id=EBAY_US'
      ) {
        return jsonResponse(200, {
          paymentPolicies: [
            {
              paymentPolicyId: 'payment-policy-one',
              marketplaceId: 'EBAY_US',
              name: 'Standard payments',
              categoryTypes: ['ALL_EXCLUDING_MOTORS_VEHICLES'],
              privatePaymentInstructions: 'Never store this text.',
            },
          ],
        });
      }
      if (
        request.url ===
        'https://api.sandbox.ebay.com/sell/account/v1/fulfillment_policy?marketplace_id=EBAY_US'
      ) {
        return jsonResponse(200, {
          fulfillmentPolicies: [
            {
              fulfillmentPolicyId: 'fulfillment-policy-one',
              marketplaceId: 'EBAY_US',
              name: 'One-day handling',
              handlingTime: { value: 1, unit: 'DAY' },
              shippingOptions: [
                {
                  shippingServiceCode: 'USPSPriority',
                  privateCarrierAccount: 'do-not-store',
                },
              ],
            },
          ],
        });
      }
      if (
        request.url ===
        'https://api.sandbox.ebay.com/sell/account/v1/return_policy?marketplace_id=EBAY_US'
      ) {
        return jsonResponse(200, {
          returnPolicies: [
            {
              returnPolicyId: 'return-policy-one',
              marketplaceId: 'EBAY_US',
              name: 'Thirty-day returns',
              returnsAccepted: true,
              returnPeriod: { value: 30, unit: 'DAY' },
              returnShippingCostPayer: 'BUYER',
              refundMethod: 'MONEY_BACK',
            },
          ],
        });
      }
      if (
        request.url ===
        'https://api.sandbox.ebay.com/sell/inventory/v1/location?limit=100&offset=0'
      ) {
        return jsonResponse(200, {
          total: 1,
          locations: [
            {
              merchantLocationKey: 'warehouse-main',
              name: 'Main inventory',
              merchantLocationStatus: 'ENABLED',
              locationTypes: ['WAREHOUSE'],
              address: {
                addressLine1: privateAddress,
                city: 'Portland',
                country: 'US',
                postalCode: '97205',
              },
            },
          ],
        });
      }
      if (
        request.url.endsWith(
          '/rows/' + sellerListingDefaultsRowId(OWNER_ID, 'sandbox', 'EBAY_US'),
        ) &&
        options.method === 'GET'
      ) {
        return jsonResponse(404);
      }
      if (
        request.url.endsWith('/rows/' + sellerProfileRowId(OWNER_ID, 'sandbox')) ||
        request.url.endsWith(
          '/rows/' +
            sellerBusinessPolicyRowId(
              OWNER_ID,
              'sandbox',
              'payment:payment-policy-one',
            ),
        ) ||
        request.url.endsWith(
          '/rows/' +
            sellerBusinessPolicyRowId(
              OWNER_ID,
              'sandbox',
              'fulfillment:fulfillment-policy-one',
            ),
        ) ||
        request.url.endsWith(
          '/rows/' +
            sellerBusinessPolicyRowId(
              OWNER_ID,
              'sandbox',
              'return:return-policy-one',
            ),
        ) ||
        request.url.endsWith(
          '/rows/' +
            sellerInventoryLocationRowId(
              OWNER_ID,
              'sandbox',
              'warehouse-main',
            ),
        ) ||
        request.url.endsWith(
          '/rows/' + sellerListingDefaultsRowId(OWNER_ID, 'sandbox', 'EBAY_US'),
        )
      ) {
        if (options.method === 'PATCH') return jsonResponse(404);
      }
      if (
        request.url.endsWith(
          '/tablesdb/keepflip/tables/ebay_seller_profiles/rows',
        ) ||
        request.url.endsWith(
          '/tablesdb/keepflip/tables/ebay_seller_business_policies/rows',
        ) ||
        request.url.endsWith(
          '/tablesdb/keepflip/tables/ebay_seller_inventory_locations/rows',
        ) ||
        request.url.endsWith(
          '/tablesdb/keepflip/tables/ebay_seller_listing_defaults/rows',
        )
      ) {
        if (options.method === 'POST') return jsonResponse(201, { $id: 'saved-row' });
      }
      if (
        request.url.startsWith(
          'https://appwrite.example/v1/tablesdb/keepflip/tables/ebay_seller_listings/rows?',
        ) &&
        options.method === 'GET'
      ) {
        return jsonResponse(200, { total: 0, rows: [] });
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
      path: '/seller-account',
    },
    res: sink.res,
  });

  assert.equal(sink.response().statusCode, 200);
  assert.deepEqual(sink.response().body.listingSetup, {
    state: 'ready',
    marketplaceId: 'EBAY_US',
    policyCounts: { payment: 1, fulfillment: 1, return: 1 },
    locationCount: 1,
    defaultSelection: {
      hasMerchantLocation: true,
      hasPaymentPolicy: true,
      hasFulfillmentPolicy: true,
      hasReturnPolicy: true,
    },
    lastCheckedAt: NOW.toISOString(),
  });

  const policyWrites = calls
    .filter(
      (call) =>
        call.options.method === 'POST' &&
        call.url.endsWith(
          '/tablesdb/keepflip/tables/ebay_seller_business_policies/rows',
        ),
    )
    .map((call) => JSON.parse(call.options.body).data);
  assert.equal(policyWrites.length, 3);
  assert.equal(
    policyWrites.some(
      (row) =>
        row.policyId === 'fulfillment-policy-one' &&
        row.handlingTimeDays === 1 &&
        row.shippingSummary === 'Handling: 1 business day',
    ),
    true,
  );
  assert.equal(
    policyWrites.some(
      (row) =>
        row.policyId === 'return-policy-one' &&
        row.returnsAccepted === true &&
        row.returnPeriodDays === 30,
    ),
    true,
  );

  const locationWrite = calls.find(
    (call) =>
      call.options.method === 'POST' &&
      call.url.endsWith(
        '/tablesdb/keepflip/tables/ebay_seller_inventory_locations/rows',
      ),
  );
  const locationData = JSON.parse(locationWrite.options.body).data;
  assert.deepEqual(locationData, {
    ownerId: OWNER_ID,
    environment: 'sandbox',
    merchantLocationKey: 'warehouse-main',
    locationName: 'Main inventory',
    locationType: 'WAREHOUSE',
    countryCode: 'US',
    locationStatus: 'ENABLED',
    lastSyncedAt: NOW.toISOString(),
    isArchived: false,
  });

  const defaultsWrite = calls.find(
    (call) =>
      call.options.method === 'POST' &&
      call.url.endsWith(
        '/tablesdb/keepflip/tables/ebay_seller_listing_defaults/rows',
      ),
  );
  const defaultsData = JSON.parse(defaultsWrite.options.body).data;
  assert.deepEqual(defaultsData, {
    ownerId: OWNER_ID,
    environment: 'sandbox',
    marketplaceId: 'EBAY_US',
    defaultMerchantLocationKey: 'warehouse-main',
    defaultPaymentPolicyId: 'payment-policy-one',
    defaultFulfillmentPolicyId: 'fulfillment-policy-one',
    defaultReturnPolicyId: 'return-policy-one',
    defaultListingDuration: 'GTC',
    defaultFormat: 'FIXED_PRICE',
    defaultCurrency: 'USD',
    defaultQuantity: 1,
    defaultCategoryId: null,
    defaultCondition: null,
    defaultStoreCategoryId: null,
    selectionSource: 'ebay_import',
    updatedAt: NOW.toISOString(),
  });

  const storedData = JSON.stringify([
    ...policyWrites,
    locationData,
    defaultsData,
  ]);
  assert.equal(storedData.includes(accessToken), false);
  assert.equal(storedData.includes(refreshToken), false);
  assert.equal(storedData.includes(privateEmail), false);
  assert.equal(storedData.includes(privateAddress), false);
  assert.equal(storedData.includes('Never store this text.'), false);
  assert.equal(storedData.includes('do-not-store'), false);

  const setupRequests = calls.filter((call) =>
    call.url.startsWith('https://api.sandbox.ebay.com/sell/'),
  );
  assert.equal(setupRequests.length, 4);
  for (const request of setupRequests) {
    assert.equal(request.options.headers.Authorization, 'Bearer ' + accessToken);
  }
});
test('publishes with saved listing defaults when the request does not override them', async () => {
  configureEnvironment();
  const accessToken = 'access-token-that-must-not-leak';
  const refreshToken = 'refresh-token-that-must-not-leak';
  const itemId = 'item-defaults-001';
  const calls = [];
  const errors = [];
  const handler = createHandler({
    fetchImpl: async (url, options = {}) => {
      const request = { options, url: String(url) };
      calls.push(request);

      if (request.url.endsWith('/account')) {
        return jsonResponse(200, { $id: OWNER_ID });
      }
      if (
        request.url.endsWith('/rows/' + itemId) &&
        options.method === 'GET'
      ) {
        return jsonResponse(200, {
          $id: itemId,
          ownerId: OWNER_ID,
          title: 'Vintage wool jacket',
          description: 'A clean vintage wool jacket with a classic fit.',
          condition: 'USED_GOOD',
          coverPhotoId: 'photo-file-one',
        });
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
            accessToken,
            accessTokenExpiresAt: '2026-08-25T13:00:00.000Z',
            refreshToken,
            refreshTokenExpiresAt: '2027-08-25T12:00:00.000Z',
          }),
          revokedAt: null,
        });
      }
      if (
        request.url.endsWith(
          '/rows/' + sellerListingDefaultsRowId(OWNER_ID, 'sandbox', 'EBAY_US'),
        ) &&
        options.method === 'GET'
      ) {
        return jsonResponse(200, {
          ownerId: OWNER_ID,
          environment: 'sandbox',
          marketplaceId: 'EBAY_US',
          defaultMerchantLocationKey: 'warehouse-main',
          defaultPaymentPolicyId: 'payment-policy-one',
          defaultFulfillmentPolicyId: 'fulfillment-policy-one',
          defaultReturnPolicyId: 'return-policy-one',
          defaultListingDuration: 'GTC',
          defaultCurrency: 'USD',
          defaultQuantity: 2,
        });
      }
      if (
        request.url ===
          'https://api.sandbox.ebay.com/sell/inventory/v1/inventory_item/KF-item-defaults-001' &&
        options.method === 'PUT'
      ) {
        return jsonResponse(204);
      }
      if (
        request.url ===
          'https://api.sandbox.ebay.com/sell/inventory/v1/offer?sku=KF-item-defaults-001&marketplace_id=EBAY_US' &&
        options.method === 'GET'
      ) {
        return jsonResponse(200, { offers: [] });
      }
      if (
        request.url === 'https://api.sandbox.ebay.com/sell/inventory/v1/offer' &&
        options.method === 'POST'
      ) {
        return jsonResponse(201, { offerId: 'offer-defaults-001' });
      }
      if (
        request.url ===
          'https://api.sandbox.ebay.com/sell/inventory/v1/offer/offer-defaults-001/publish' &&
        options.method === 'POST'
      ) {
        return jsonResponse(200, { listingId: 'listing-defaults-001' });
      }
      if (
        request.url.startsWith(
          'https://appwrite.example/v1/tablesdb/keepflip/tables/ebay_seller_listings/rows/',
        ) &&
        options.method === 'PATCH'
      ) {
        return jsonResponse(200, { $id: 'listing-cache-row' });
      }

      throw new Error('Unexpected request: ' + request.url);
    },
    now: () => NOW,
  });
  const sink = responseSink();

  await handler({
    req: {
      bodyJson: {
        environment: 'sandbox',
        itemId,
        price: 50,
        categoryId: '11450',
      },
      headers: authenticatedHeaders(),
      method: 'POST',
      path: '/listing',
    },
    res: sink.res,
    error: (message) => errors.push(message),
  });

  assert.deepEqual(errors, []);
  assert.equal(sink.response().statusCode, 200);
  assert.equal(sink.response().body.status, 'published');

  const offerRequest = calls.find(
    (call) =>
      call.url === 'https://api.sandbox.ebay.com/sell/inventory/v1/offer' &&
      call.options.method === 'POST',
  );
  const offer = JSON.parse(offerRequest.options.body);
  assert.deepEqual(offer.listingPolicies, {
    paymentPolicyId: 'payment-policy-one',
    fulfillmentPolicyId: 'fulfillment-policy-one',
    returnPolicyId: 'return-policy-one',
  });
  assert.equal(offer.merchantLocationKey, 'warehouse-main');
  assert.equal(offer.availableQuantity, 2);
  assert.equal(offer.listingDuration, 'GTC');
  assert.equal(offer.pricingSummary.price.currency, 'USD');

  const inventoryRequest = calls.find(
    (call) =>
      call.url ===
        'https://api.sandbox.ebay.com/sell/inventory/v1/inventory_item/KF-item-defaults-001' &&
      call.options.method === 'PUT',
  );
  const inventory = JSON.parse(inventoryRequest.options.body);
  assert.equal(
    inventory.availability.shipToLocationAvailability.quantity,
    2,
  );
  assert.equal(
    JSON.stringify(sink.response().body).includes(accessToken),
    false,
  );
  assert.equal(
    JSON.stringify(sink.response().body).includes(refreshToken),
    false,
  );
});