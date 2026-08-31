import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from 'node:crypto';

export const KEEPFLIP_EBAY_USER_SCOPES = Object.freeze([
  'https://api.ebay.com/oauth/api_scope',
  'https://api.ebay.com/oauth/api_scope/commerce.identity.readonly',
  'https://api.ebay.com/oauth/api_scope/sell.inventory',
  'https://api.ebay.com/oauth/api_scope/sell.account.readonly',
  'https://api.ebay.com/oauth/api_scope/sell.finances',
]);

const STATE_TTL_MS = 10 * 60 * 1000;

class HttpError extends Error {
  constructor(status, message, diagnosticCode = 'OAUTH_REQUEST_FAILED') {
    super(message);
    this.name = 'HttpError';
    this.status = status;
    this.diagnosticCode = diagnosticCode;
  }
}

class UpstreamError extends Error {
  constructor(status, message) {
    super(message);
    this.name = 'UpstreamError';
    this.status = status;
  }
}

function error(statusOrMessage, message, diagnosticCode) {
  const status = typeof statusOrMessage === 'number' ? statusOrMessage : 500;
  const detail = typeof statusOrMessage === 'number' ? message : statusOrMessage;
  throw new HttpError(
    status,
    cleanText(detail) || 'KeepFlip could not complete the eBay OAuth request.',
    cleanText(diagnosticCode, 80) || 'OAUTH_REQUEST_FAILED',
  );
}

function cleanText(value, maxLength = 8_000) {
  if (typeof value !== 'string') return '';
  const cleaned = value.trim();
  return cleaned.length <= maxLength ? cleaned : cleaned.slice(0, maxLength);
}

function requestHeader(headers, name) {
  if (!headers || typeof headers !== 'object') return '';

  if (typeof headers.get === 'function') {
    return cleanText(headers.get(name));
  }

  const expected = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() !== expected) continue;
    return cleanText(Array.isArray(value) ? value[0] : value);
  }

  return '';
}

function firstEnvironmentValue(names, fallback = '') {
  for (const name of names) {
    const value = cleanText(process.env[name]);
    if (value) return value;
  }

  return fallback;
}

function requiredEnvironmentValue(names) {
  const value = firstEnvironmentValue(names);
  if (!value) {
    error('Missing required eBay OAuth Function configuration.');
  }

  return value;
}

function normalizeEnvironment(value, label = 'OAuth environment') {
  const environment = cleanText(String(value ?? '')).toLowerCase();
  if (environment === 'sandbox' || environment === 'production') {
    return environment;
  }

  error(400, label + ' must be "sandbox" or "production".');
}

function functionRuntime() {
  const endpoint = requiredEnvironmentValue(['APPWRITE_FUNCTION_API_ENDPOINT'])
    .replace(/\/+$/, '');
  const projectId = requiredEnvironmentValue(['APPWRITE_FUNCTION_PROJECT_ID']);

  return { endpoint, projectId };
}

function functionDynamicKey(req) {
  const key =
    requestHeader(req?.headers, 'x-appwrite-key') ||
    cleanText(process.env.APPWRITE_FUNCTION_API_KEY);

  if (!key) {
    error('Appwrite did not provide this Function a dynamic API key.');
  }

  return key;
}

function tableConfiguration() {
  return {
    databaseId: firstEnvironmentValue(
      ['APPWRITE_EBAY_DATABASE_ID', 'APPWRITE_DATABASE_ID'],
      'keepflip',
    ),
    connectionsTableId: firstEnvironmentValue(
      [
        'APPWRITE_EBAY_CONNECTIONS_TABLE_ID',
        'APPWRITE_EBAY_CONNECTIONS_COLLECTION_ID',
        'APPWRITE_CONNECTIONS_TABLE_ID',
        'APPWRITE_CONNECTIONS_COLLECTION_ID',
      ],
      'ebay_connections',
    ),
    statesTableId: firstEnvironmentValue(
      [
        'APPWRITE_EBAY_OAUTH_STATES_TABLE_ID',
        'APPWRITE_EBAY_OAUTH_STATES_COLLECTION_ID',
        'APPWRITE_EBAY_STATES_TABLE_ID',
        'APPWRITE_EBAY_STATES_COLLECTION_ID',
      ],
      'ebay_oauth_states',
    ),
    itemsTableId: firstEnvironmentValue(
      [
        'APPWRITE_EBAY_ITEMS_TABLE_ID',
        'APPWRITE_EBAY_ITEMS_COLLECTION_ID',
        'APPWRITE_ITEMS_TABLE_ID',
        'APPWRITE_ITEMS_COLLECTION_ID',
      ],
      'items',
    ),
    itemPhotosTableId: firstEnvironmentValue(
      [
        'APPWRITE_EBAY_ITEM_PHOTOS_TABLE_ID',
        'APPWRITE_EBAY_ITEM_PHOTOS_COLLECTION_ID',
        'APPWRITE_ITEM_PHOTOS_TABLE_ID',
        'APPWRITE_ITEM_PHOTOS_COLLECTION_ID',
      ],
      'item_photos',
    ),
    itemImagesBucketId: firstEnvironmentValue(
      [
        'APPWRITE_EBAY_ITEM_IMAGES_BUCKET_ID',
        'APPWRITE_ITEM_IMAGES_BUCKET_ID',
      ],
      'item_images',
    ),
    sellerProfilesTableId: firstEnvironmentValue(
      [
        'APPWRITE_EBAY_SELLER_PROFILES_TABLE_ID',
        'APPWRITE_EBAY_SELLER_PROFILES_COLLECTION_ID',
      ],
      'ebay_seller_profiles',
    ),
    sellerListingsTableId: firstEnvironmentValue(
      [
        'APPWRITE_EBAY_SELLER_LISTINGS_TABLE_ID',
        'APPWRITE_EBAY_SELLER_LISTINGS_COLLECTION_ID',
      ],
      'ebay_seller_listings',
    ),
    sellerBusinessPoliciesTableId: firstEnvironmentValue(
      [
        'APPWRITE_EBAY_SELLER_BUSINESS_POLICIES_TABLE_ID',
        'APPWRITE_EBAY_SELLER_BUSINESS_POLICIES_COLLECTION_ID',
      ],
      'ebay_seller_business_policies',
    ),
    sellerInventoryLocationsTableId: firstEnvironmentValue(
      [
        'APPWRITE_EBAY_SELLER_INVENTORY_LOCATIONS_TABLE_ID',
        'APPWRITE_EBAY_SELLER_INVENTORY_LOCATIONS_COLLECTION_ID',
      ],
      'ebay_seller_inventory_locations',
    ),
    sellerListingDefaultsTableId: firstEnvironmentValue(
      [
        'APPWRITE_EBAY_SELLER_LISTING_DEFAULTS_TABLE_ID',
        'APPWRITE_EBAY_SELLER_LISTING_DEFAULTS_COLLECTION_ID',
      ],
      'ebay_seller_listing_defaults',
    ),
  };
}

function decodeEncryptionKey() {
  const text = requiredEnvironmentValue(['EBAY_TOKEN_ENCRYPTION_KEY']);
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(text)) {
    error('EBAY_TOKEN_ENCRYPTION_KEY must be a Base64 32-byte key.');
  }

  const key = Buffer.from(text, 'base64');
  if (key.length !== 32) {
    error('EBAY_TOKEN_ENCRYPTION_KEY must decode to exactly 32 bytes.');
  }

  return key;
}

function configurationFor(environment) {
  const normalized = normalizeEnvironment(environment);
  const prefix =
    normalized === 'production' ? 'EBAY_PRODUCTION' : 'EBAY_SANDBOX';

  return {
    ...tableConfiguration(),
    environment: normalized,
    clientId: requiredEnvironmentValue([prefix + '_CLIENT_ID']),
    clientSecret: requiredEnvironmentValue([prefix + '_CLIENT_SECRET']),
    ruName: requiredEnvironmentValue([
      prefix + '_RU_NAME',
      prefix + '_RUNAME',
    ]),
    scopes: KEEPFLIP_EBAY_USER_SCOPES,
    scopeText: KEEPFLIP_EBAY_USER_SCOPES.join(' '),
    encryptionKey: decodeEncryptionKey(),
  };
}

function appwriteHeaders(runtime, options = {}) {
  const headers = {
    Accept: 'application/json',
    'Content-Type': 'application/json',
    'X-Appwrite-Project': runtime.projectId,
  };

  if (options.apiKey) headers['X-Appwrite-Key'] = options.apiKey;
  if (options.jwt) headers['X-Appwrite-JWT'] = options.jwt;

  return headers;
}

async function parseResponseBody(response) {
  try {
    const text = await response.text();
    return text ? JSON.parse(text) : {};
  } catch {
    return {};
  }
}

async function appwriteJson({
  fetchImpl,
  runtime,
  path,
  method = 'GET',
  apiKey,
  jwt,
  body,
  failureMessage,
}) {
  let response;

  try {
    response = await fetchImpl(runtime.endpoint + path, {
      method,
      headers: appwriteHeaders(runtime, { apiKey, jwt }),
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  } catch {
    throw new UpstreamError(0, failureMessage);
  }

  const payload = await parseResponseBody(response);
  if (!response.ok) {
    throw new UpstreamError(Number(response.status) || 0, failureMessage);
  }

  return payload;
}

function tableRowsPath(configuration, tableId) {
  return (
    '/tablesdb/' +
    encodeURIComponent(configuration.databaseId) +
    '/tables/' +
    encodeURIComponent(tableId) +
    '/rows'
  );
}

function rowPath(configuration, tableId, rowId) {
  return tableRowsPath(configuration, tableId) + '/' + encodeURIComponent(rowId);
}

async function authenticatedUserId({ req, fetchImpl, runtime }) {
  const jwt = requestHeader(req?.headers, 'x-appwrite-user-jwt');
  if (!jwt) {
    error(
      401,
      'You must be signed in to KeepFlip to connect eBay.',
    );
  }

  let account;
  try {
    account = await appwriteJson({
      fetchImpl,
      runtime,
      path: '/account',
      jwt,
      failureMessage: 'KeepFlip could not verify your signed-in session.',
    });
  } catch {
    error(
      401,
      'You must be signed in to KeepFlip to connect eBay.',
    );
  }

  const userId = cleanText(account?.$id, 64);
  const executionUserId = requestHeader(
    req?.headers,
    'x-appwrite-user-id',
  );

  if (!userId || (executionUserId && executionUserId !== userId)) {
    error(
      401,
      'You must be signed in to KeepFlip to connect eBay.',
    );
  }

  return userId;
}

function requestBody(req) {
  const body = req?.bodyJson;
  return body && typeof body === 'object' && !Array.isArray(body) ? body : {};
}

function requestPath(req) {
  const raw = cleanText(req?.path || req?.url || '/') || '/';
  return new URL(raw, 'https://keepflip.invalid').pathname;
}

function currentDate(now) {
  const value = now();
  const date = value instanceof Date ? new Date(value.getTime()) : new Date(value);
  if (Number.isNaN(date.getTime())) {
    error('The OAuth Function clock is invalid.');
  }

  return date;
}

function addSeconds(date, seconds) {
  const numeric = Number(seconds);
  if (!Number.isFinite(numeric) || numeric <= 0) {
    error('eBay did not return a valid token expiration.');
  }

  return new Date(date.getTime() + numeric * 1000).toISOString();
}

export function oauthStateRowId(state) {
  return createHash('sha256')
    .update('keepflip|ebay-oauth-state|v1|' + state, 'utf8')
    .digest('hex')
    .slice(0, 36);
}

export function connectionRowId(userId, environment) {
  return (
    'e' +
    createHash('sha256')
      .update(String(userId) + ':' + String(environment), 'utf8')
      .digest('hex')
      .slice(0, 35)
  );
}

export function sellerProfileRowId(userId, environment) {
  return (
    'p' +
    createHash('sha256')
      .update(
        'keepflip|ebay-seller-profile|v1|' +
          String(userId) +
          ':' +
          String(environment),
        'utf8',
      )
      .digest('hex')
      .slice(0, 35)
  );
}

export function sellerListingRowId(userId, environment, sourceRecordKey) {
  return (
    'l' +
    createHash('sha256')
      .update(
        'keepflip|ebay-seller-listing|v1|' +
          String(userId) +
          ':' +
          String(environment) +
          ':' +
          String(sourceRecordKey),
        'utf8',
      )
      .digest('hex')
      .slice(0, 35)
  );
}

function sellerSetupRowId(prefix, kind, userId, environment, recordKey) {
  return (
    prefix +
    createHash('sha256')
      .update(
        'keepflip|ebay-seller-' +
          kind +
          '|v1|' +
          String(userId) +
          ':' +
          String(environment) +
          ':' +
          String(recordKey),
        'utf8',
      )
      .digest('hex')
      .slice(0, 35)
  );
}

export function sellerBusinessPolicyRowId(
  userId,
  environment,
  sourceRecordKey,
) {
  return sellerSetupRowId('b', 'business-policy', userId, environment, sourceRecordKey);
}

export function sellerInventoryLocationRowId(
  userId,
  environment,
  merchantLocationKey,
) {
  return sellerSetupRowId('i', 'inventory-location', userId, environment, merchantLocationKey);
}

export function sellerListingDefaultsRowId(userId, environment, marketplaceId) {
  return sellerSetupRowId('d', 'listing-defaults', userId, environment, marketplaceId);
}

function createOpaqueState(randomBytesImpl) {
  return randomBytesImpl(32).toString('base64url');
}

async function createStateRecord({
  fetchImpl,
  req,
  runtime,
  configuration,
  userId,
  state,
  now,
}) {
  const createdAt = currentDate(now);
  const expiresAt = new Date(createdAt.getTime() + STATE_TTL_MS).toISOString();

  try {
    await appwriteJson({
      fetchImpl,
      runtime,
      apiKey: functionDynamicKey(req),
      method: 'POST',
      path: tableRowsPath(configuration, configuration.statesTableId),
      body: {
        rowId: oauthStateRowId(state),
        data: {
          ownerId: userId,
          environment: configuration.environment,
          status: 'pending',
          scopeText: configuration.scopeText,
          createdAt: createdAt.toISOString(),
          expiresAt,
        },
      },
      failureMessage: 'KeepFlip could not save the eBay authorization request.',
    });
  } catch (caught) {
    if (caught instanceof HttpError) throw caught;
    error(
      500,
      'KeepFlip could not start the eBay authorization flow.',
    );
  }

  return { expiresAt };
}

async function getConnection({
  fetchImpl,
  req,
  runtime,
  configuration,
  userId,
}) {
  try {
    return await appwriteJson({
      fetchImpl,
      runtime,
      apiKey: functionDynamicKey(req),
      path: rowPath(
        configuration,
        configuration.connectionsTableId,
        connectionRowId(userId, configuration.environment),
      ),
      failureMessage: 'KeepFlip could not read the eBay connection.',
    });
  } catch (caught) {
    if (caught instanceof UpstreamError && caught.status === 404) return null;
    error(
      502,
      'KeepFlip could not read the eBay connection.',
      caught instanceof UpstreamError
        ? 'CONNECTION_ROW_REQUEST_' + (caught.status || 'NETWORK')
        : 'CONNECTION_ROW_REQUEST_FAILED',
    );
  }
}

async function getServerRowOrNull({
  fetchImpl,
  req,
  runtime,
  configuration,
  tableId,
  rowId,
  failureMessage,
}) {
  try {
    return await appwriteJson({
      fetchImpl,
      runtime,
      apiKey: functionDynamicKey(req),
      path: rowPath(configuration, tableId, rowId),
      failureMessage,
    });
  } catch (caught) {
    if (caught instanceof UpstreamError && caught.status === 404) return null;
    throw caught;
  }
}

async function upsertServerRow({
  fetchImpl,
  req,
  runtime,
  configuration,
  tableId,
  rowId,
  data,
  failureMessage,
}) {
  const path = rowPath(configuration, tableId, rowId);
  const apiKey = functionDynamicKey(req);

  try {
    return await appwriteJson({
      fetchImpl,
      runtime,
      apiKey,
      method: 'PATCH',
      path,
      body: { data },
      failureMessage,
    });
  } catch (caught) {
    if (!(caught instanceof UpstreamError) || caught.status !== 404) {
      throw caught;
    }
  }

  try {
    return await appwriteJson({
      fetchImpl,
      runtime,
      apiKey,
      method: 'POST',
      path: tableRowsPath(configuration, tableId),
      body: { rowId, data },
      failureMessage,
    });
  } catch (caught) {
    if (!(caught instanceof UpstreamError) || caught.status !== 409) {
      throw caught;
    }
  }

  return appwriteJson({
    fetchImpl,
    runtime,
    apiKey,
    method: 'PATCH',
    path,
    body: { data },
    failureMessage,
  });
}

function encryptSecret(value, key, randomBytesImpl = randomBytes) {
  const iv = randomBytesImpl(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(value, 'utf8'),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();

  return [
    'v1',
    iv.toString('base64url'),
    tag.toString('base64url'),
    ciphertext.toString('base64url'),
  ].join('.');
}

function decryptSecret(value, key) {
  const [version, ivText, tagText, ciphertextText, ...extra] = String(
    value ?? '',
  ).split('.');

  if (
    version !== 'v1' ||
    !ivText ||
    !tagText ||
    !ciphertextText ||
    extra.length > 0
  ) {
    error('Stored eBay token data is invalid.');
  }

  const decipher = createDecipheriv(
    'aes-256-gcm',
    key,
    Buffer.from(ivText, 'base64url'),
  );
  decipher.setAuthTag(Buffer.from(tagText, 'base64url'));

  return Buffer.concat([
    decipher.update(Buffer.from(ciphertextText, 'base64url')),
    decipher.final(),
  ]).toString('utf8');
}

function readTokenBundle(connection, configuration) {
  const ciphertext =
    typeof connection?.tokenCiphertext === 'string' && connection.tokenCiphertext
      ? connection.tokenCiphertext
      : connection?.encryptedTokens;

  let tokenBundle;
  try {
    tokenBundle = JSON.parse(
      decryptSecret(ciphertext, configuration.encryptionKey),
    );
  } catch {
    error(
      500,
      'KeepFlip could not read the stored eBay connection.',
      'STORED_CONNECTION_UNREADABLE',
    );
  }

  if (
    !tokenBundle ||
    typeof tokenBundle.accessToken !== 'string' ||
    typeof tokenBundle.refreshToken !== 'string' ||
    typeof tokenBundle.accessTokenExpiresAt !== 'string' ||
    typeof tokenBundle.refreshTokenExpiresAt !== 'string'
  ) {
    error(
      500,
      'KeepFlip could not read the stored eBay connection.',
      'STORED_CONNECTION_INVALID',
    );
  }

  return tokenBundle;
}

function connectionStatus(connection, tokenBundle, configuration, now) {
  if (
    !connection ||
    !connection.ownerId ||
    (connection.environment &&
      connection.environment !== configuration.environment) ||
    connection.revokedAt ||
    connection.status === 'revoked'
  ) {
    return {
      connected: false,
      environment: configuration.environment,
    };
  }

  const clock = currentDate(now).getTime();
  const accessExpiry = Date.parse(tokenBundle.accessTokenExpiresAt);
  const refreshExpiry = Date.parse(tokenBundle.refreshTokenExpiresAt);
  const refreshExpired =
    !Number.isFinite(refreshExpiry) || refreshExpiry <= clock;

  const ebayUsername = cleanText(connection?.ebayUsername, 128);

  return {
    connected: !refreshExpired,
    environment: configuration.environment,
    ...(ebayUsername ? { ebayUsername } : {}),
    accessTokenExpiresAt: tokenBundle.accessTokenExpiresAt,
    refreshTokenExpiresAt: tokenBundle.refreshTokenExpiresAt,
    accessTokenExpired:
      !Number.isFinite(accessExpiry) || accessExpiry <= clock,
    needsReconnect: refreshExpired,
  };
}

function ebayTokenEndpoint(environment) {
  return environment === 'production'
    ? 'https://api.ebay.com/identity/v1/oauth2/token'
    : 'https://api.sandbox.ebay.com/identity/v1/oauth2/token';
}

function ebayRevokeEndpoint(environment) {
  return ebayTokenEndpoint(environment) + '/revoke';
}

async function refreshToken({
  fetchImpl,
  configuration,
  tokenBundle,
  now,
}) {
  const clock = currentDate(now);
  const refreshExpiry = Date.parse(tokenBundle.refreshTokenExpiresAt);

  if (
    !Number.isFinite(refreshExpiry) ||
    refreshExpiry <= clock.getTime()
  ) {
    error(
      401,
      'Your eBay authorization has expired. Reconnect your eBay account.',
      'TOKEN_REFRESH_RECONNECT_REQUIRED',
    );
  }

  const form = new URLSearchParams();

  form.set('grant_type', 'refresh_token');
  form.set('refresh_token', tokenBundle.refreshToken);

  /*
   * IMPORTANT:
   *
   * Do NOT send configuration.scopeText here.
   *
   * eBay only allows a refresh request to contain scopes that were
   * originally granted when this refresh token was created.
   *
   * configuration.scopeText represents KeepFlip's CURRENT requested
   * scopes, which may contain permissions that did not exist when an
   * older user connected their eBay account.
   *
   * When the scope parameter is omitted, eBay automatically uses the
   * scopes associated with the existing refresh token.
   */
  let response;

  try {
    response = await fetchImpl(
      ebayTokenEndpoint(configuration.environment),
      {
        method: 'POST',
        headers: {
          Accept: 'application/json',

          Authorization:
            'Basic ' +
            Buffer.from(
              configuration.clientId +
                ':' +
                configuration.clientSecret,
              'utf8',
            ).toString('base64'),

          'Content-Type':
            'application/x-www-form-urlencoded',
        },

        body: form.toString(),
      },
    );
  } catch {
    error(
      502,
      'KeepFlip could not reach eBay to refresh the authorization.',
      'TOKEN_REFRESH_NETWORK',
    );
  }

  const payload = await parseResponseBody(response);

  if (!response.ok) {
    const ebayError = cleanText(payload?.error, 80);

    /*
     * These errors mean the existing user authorization can no longer
     * be used. The correct recovery is a new authorization-code /
     * consent flow.
     */
    if (
      ebayError === 'invalid_grant' ||
      ebayError === 'invalid_token' ||
      ebayError === 'invalid_scope'
    ) {
      error(
        401,
        'Your eBay authorization needs to be reconnected.',
        'TOKEN_REFRESH_RECONNECT_REQUIRED',
      );
    }

    error(
      502,
      'KeepFlip could not refresh the eBay authorization.',
      'TOKEN_REFRESH_HTTP_' + String(response.status || 'UNKNOWN'),
    );
  }

  if (
    typeof payload?.access_token !== 'string' ||
    !payload.access_token
  ) {
    error(
      502,
      'eBay returned an invalid authorization refresh response.',
      'TOKEN_REFRESH_RESPONSE_INVALID',
    );
  }

  const nextRefreshToken =
    typeof payload.refresh_token === 'string' &&
    payload.refresh_token
      ? payload.refresh_token
      : tokenBundle.refreshToken;

  const nextRefreshExpiresAt =
    payload.refresh_token_expires_in
      ? addSeconds(clock, payload.refresh_token_expires_in)
      : tokenBundle.refreshTokenExpiresAt;

  return {
    ...tokenBundle,

    accessToken: payload.access_token,

    accessTokenExpiresAt: addSeconds(
      clock,
      payload.expires_in,
    ),

    refreshToken: nextRefreshToken,

    refreshTokenExpiresAt: nextRefreshExpiresAt,

    /*
     * Do NOT set:
     *
     * scopeText: configuration.scopeText
     *
     * Doing so would falsely claim an older authorization possesses
     * permissions that were added to KeepFlip later.
     */

    updatedAt: clock.toISOString(),
  };
}

async function saveRefreshedConnection({
  fetchImpl,
  req,
  runtime,
  configuration,
  connection,
  tokenBundle,
  randomBytesImpl,
}) {
  const field =
    typeof connection?.tokenCiphertext === 'string' && connection.tokenCiphertext
      ? 'tokenCiphertext'
      : 'encryptedTokens';
  const data = {
    [field]: encryptSecret(
      JSON.stringify(tokenBundle),
      configuration.encryptionKey,
      randomBytesImpl,
    ),
    updatedAt: tokenBundle.updatedAt,
    revokedAt: null,
  };

  try {
    await appwriteJson({
      fetchImpl,
      runtime,
      apiKey: functionDynamicKey(req),
      method: 'PATCH',
      path: rowPath(
        configuration,
        configuration.connectionsTableId,
        connectionRowId(connection.ownerId, configuration.environment),
      ),
      body: { data },
      failureMessage: 'KeepFlip could not save the refreshed eBay authorization.',
    });
  } catch {
    error(
      500,
      'KeepFlip could not save the refreshed eBay authorization.',
    );
  }
}

function ebayClientAuthorization(configuration) {
  return (
    'Basic ' +
    Buffer.from(
      configuration.clientId + ':' + configuration.clientSecret,
      'utf8',
    ).toString('base64')
  );
}

function connectionTokenField(connection) {
  return (
    typeof connection?.tokenCiphertext === 'string' && connection.tokenCiphertext
      ? 'tokenCiphertext'
      : 'encryptedTokens'
  );
}

async function revokeEbayAuthorization({
  fetchImpl,
  configuration,
  tokenBundle,
}) {
  const form = new URLSearchParams();
  form.set('token', tokenBundle.refreshToken);
  form.set('token_type_hint', 'refresh_token');

  let response;
  try {
    response = await fetchImpl(ebayRevokeEndpoint(configuration.environment), {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        Authorization: ebayClientAuthorization(configuration),
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: form.toString(),
    });
  } catch {
    error(502, 'KeepFlip could not revoke eBay access.');
  }

  const payload = await parseResponseBody(response);
  if (
    response.ok ||
    (response.status === 400 && payload?.error === 'invalid_token')
  ) {
    return;
  }

  error(502, 'KeepFlip could not revoke eBay access.');
}

async function markConnectionRevoked({
  fetchImpl,
  req,
  runtime,
  configuration,
  connection,
  now,
}) {
  const revokedAt = currentDate(now).toISOString();
  const data = {
    [connectionTokenField(connection)]: '',
    ebayUsername: '',
    revokedAt,
    updatedAt: revokedAt,
  };

  try {
    await appwriteJson({
      fetchImpl,
      runtime,
      apiKey: functionDynamicKey(req),
      method: 'PATCH',
      path: rowPath(
        configuration,
        configuration.connectionsTableId,
        connectionRowId(connection.ownerId, configuration.environment),
      ),
      body: { data },
      failureMessage: 'KeepFlip could not remove the eBay connection.',
    });
  } catch {
    error(500, 'KeepFlip could not remove the eBay connection.');
  }
}


const EBAY_INVENTORY_CONDITIONS = new Set([
  'NEW',
  'NEW_OTHER',
  'NEW_WITH_DEFECTS',
  'LIKE_NEW',
  'CERTIFIED_REFURBISHED',
  'EXCELLENT_REFURBISHED',
  'VERY_GOOD_REFURBISHED',
  'GOOD_REFURBISHED',
  'SELLER_REFURBISHED',
  'USED_EXCELLENT',
  'USED_VERY_GOOD',
  'USED_GOOD',
  'USED_ACCEPTABLE',
  'FOR_PARTS_OR_NOT_WORKING',
]);

function normalizeInventoryCondition(value) {
  const raw = cleanText(value, 128)
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
  const aliases = {
    PREOWNED: 'USED_GOOD',
    PRE_OWNED: 'USED_GOOD',
    USED: 'USED_GOOD',
    GOOD: 'USED_GOOD',
    VERY_GOOD: 'USED_VERY_GOOD',
    EXCELLENT: 'USED_EXCELLENT',
    ACCEPTABLE: 'USED_ACCEPTABLE',
    FOR_PARTS: 'FOR_PARTS_OR_NOT_WORKING',
    PARTS_OR_REPAIR: 'FOR_PARTS_OR_NOT_WORKING',
    REFURBISHED: 'SELLER_REFURBISHED',
  };
  const condition = aliases[raw] || raw;

  if (!EBAY_INVENTORY_CONDITIONS.has(condition)) {
    error(
      400,
      'Choose a supported item condition before publishing on eBay.',
    );
  }

  return condition;
}
function bodyObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
}

function requiredListingValue(body, name, maxLength = 255) {
  const value = cleanText(body?.[name], maxLength);
  if (!value) {
    error(400, 'eBay listing field "' + name + '" is required.');
  }
  return value;
}

function listingString(value, maxLength = 255) {
  return cleanText(value, maxLength);
}

function listingNumber(value, name, { integer = false, minimum = 0 } = {}) {
  const number = Number(value);
  if (
    !Number.isFinite(number) ||
    number < minimum ||
    (integer && !Number.isInteger(number))
  ) {
    error(400, 'eBay listing field "' + name + '" is invalid.');
  }
  return number;
}

function stringArray(value) {
  if (Array.isArray(value)) {
    return value
      .filter((entry) => typeof entry === 'string')
      .map((entry) => entry.trim())
      .filter(Boolean);
  }

  if (typeof value !== 'string' || !value.trim()) return [];
  const cleaned = value.trim();
  try {
    const parsed = JSON.parse(cleaned);
    if (Array.isArray(parsed)) return stringArray(parsed);
  } catch {
    // Appwrite string columns can contain one cover photo ID directly.
  }
  return [cleaned];
}

function equalTableQuery(attribute, value) {
  return 'equal(' + JSON.stringify(attribute) + ',' + JSON.stringify([value]) + ')';
}

async function getOwnedInventoryItem({
  fetchImpl,
  req,
  runtime,
  configuration,
  userId,
  itemId,
}) {
  let item;
  try {
    item = await appwriteJson({
      fetchImpl,
      req,
      runtime,
      apiKey: functionDynamicKey(req),
      path: rowPath(configuration, configuration.itemsTableId, itemId),
      failureMessage: 'KeepFlip could not read that inventory item.',
    });
  } catch (caught) {
    if (caught instanceof UpstreamError && caught.status === 404) {
      error(404, 'That inventory item could not be found.');
    }
    error(500, 'KeepFlip could not read that inventory item.');
  }

  if (item?.ownerId !== userId) {
    error(403, 'You do not have access to this inventory item.');
  }
  return item;
}

async function listInventoryPhotoRows({
  fetchImpl,
  req,
  runtime,
  configuration,
  item,
}) {
  const itemId = cleanText(item?.$id || item?.id, 64);
  const ownerId = cleanText(item?.ownerId, 64);
  if (!itemId || !ownerId) return [];

  const queries = new URLSearchParams();
  queries.append('queries[]', equalTableQuery('ownerId', ownerId));
  queries.append('queries[]', equalTableQuery('itemId', itemId));
  queries.append('queries[]', 'limit(100)');

  try {
    const response = await appwriteJson({
      fetchImpl,
      req,
      runtime,
      apiKey: functionDynamicKey(req),
      path:
        tableRowsPath(configuration, configuration.itemPhotosTableId) +
        '?' +
        queries.toString(),
      failureMessage: 'KeepFlip could not read the saved item photos.',
    });
    return Array.isArray(response?.rows) ? response.rows : [];
  } catch {
    // The item-level photo array remains the source of truth when an older
    // table does not support one of the optional photo queries.
    return [];
  }
}

async function getInventoryPhotoFileIds({
  fetchImpl,
  req,
  runtime,
  configuration,
  item,
}) {
  const ids = [
    ...stringArray(item?.coverPhotoId),
    ...stringArray(item?.itemPhotos),
  ];
  const photoRows = await listInventoryPhotoRows({
    fetchImpl,
    req,
    runtime,
    configuration,
    item,
  });

  for (const row of photoRows) {
    ids.push(...stringArray(row?.fileId));
  }

  const uniqueIds = [...new Set(ids)].slice(0, 12);
  if (!uniqueIds.length) {
    error(400, 'Add at least one item photo before publishing on eBay.');
  }
  return uniqueIds;
}

function appwriteFileViewUrl(runtime, configuration, fileId) {
  return (
    runtime.endpoint +
    '/storage/buckets/' +
    encodeURIComponent(configuration.itemImagesBucketId) +
    '/files/' +
    encodeURIComponent(fileId) +
    '/view?project=' +
    encodeURIComponent(runtime.projectId)
  );
}

function ebayApiBase(configuration) {
  return configuration.environment === 'production'
    ? 'https://api.ebay.com'
    : 'https://api.sandbox.ebay.com';
}

function ebayIdentityApiBase(configuration) {
  return configuration.environment === 'production'
    ? 'https://apiz.ebay.com'
    : 'https://apiz.sandbox.ebay.com';
}

function eBayApiErrorDetail(payload, rawBody) {
  const details = [];
  if (Array.isArray(payload?.errors)) {
    for (const entry of payload.errors) {
      const detail = entry?.longMessage || entry?.message || entry?.errorDescription;
      if (detail) details.push(cleanText(detail, 300));
    }
  }
  if (payload?.message) details.push(cleanText(payload.message, 300));
  if (!details.length && rawBody) {
    details.push(cleanText(rawBody.replace(/\s+/g, ' '), 300));
  }
  return [...new Set(details)].join(' ');
}

async function ebayApiRequest({
  fetchImpl,
  configuration,
  accessToken,
  method,
  path,
  body,
}) {
  let response;
  log(ebayApiBase(configuration) + path);
  try {
    response = await fetchImpl(ebayApiBase(configuration) + path, {
      method,
      headers: {
        Accept: 'application/json',
        'Accept-Language': 'en-US',
        'Content-Language': 'en-US',
        Authorization: 'Bearer ' + accessToken,
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  } catch {
    error(502, 'KeepFlip could not reach eBay to publish this listing.');
  }

  const rawBody = await response.text();
  let payload = {};
  if (rawBody.trim()) {
    try {
      payload = JSON.parse(rawBody);
    } catch {
      payload = {};
    }
  }

  if (!response.ok) {
    const detail = eBayApiErrorDetail(payload, rawBody);
    const failure = new HttpError(
      502,
      'eBay rejected the listing request (HTTP ' +
        response.status +
        ')' +
        (detail ? ': ' + detail : '.'),
    );
    failure.ebayStatus = response.status;
    throw failure;
  }

  return { payload, status: response.status };
}

async function ensureEbayAccessToken({
  fetchImpl,
  req,
  runtime,
  configuration,
  connection,
  now,
  randomBytesImpl,
}) {
  const storedTokens = readTokenBundle(connection, configuration);
  const accessExpiry = Date.parse(storedTokens.accessTokenExpiresAt || '');
  if (Number.isFinite(accessExpiry) && accessExpiry > currentDate(now).getTime() + 60_000) {
    return storedTokens.accessToken;
  }

  const refreshedTokens = await refreshToken({
    fetchImpl,
    configuration,
    tokenBundle: storedTokens,
    now,
  });
  await saveRefreshedConnection({
    fetchImpl,
    req,
    runtime,
    configuration,
    connection,
    tokenBundle: refreshedTokens,
    randomBytesImpl,
  });
  return refreshedTokens.accessToken;
}

async function findExistingEbayOffer({
  fetchImpl,
  configuration,
  accessToken,
  sku,
  marketplaceId,
}) {
  const query = new URLSearchParams({
    sku,
    marketplace_id: marketplaceId,
  });
  try {
    const result = await ebayApiRequest({
      fetchImpl,
      configuration,
      accessToken,
      method: 'GET',
      path: '/sell/inventory/v1/offer?' + query.toString(),
    });
    const offers = Array.isArray(result.payload?.offers)
      ? result.payload.offers
      : [];
    return (
      offers.find(
        (offer) =>
          String(offer?.marketplaceId || offer?.marketplace_id || '') ===
          marketplaceId,
      ) || null
    );
  } catch (caught) {
    if (caught?.ebayStatus === 404) return null;
    throw caught;
  }
}

function listingUrl(configuration, listingId) {
  const host =
    configuration.environment === 'production'
      ? 'https://www.ebay.com/itm/'
      : 'https://www.sandbox.ebay.com/itm/';
  return host + encodeURIComponent(listingId);
}

function nullableText(value, maxLength = 255) {
  return cleanText(value, maxLength) || null;
}

function safeDateTime(value) {
  const text = cleanText(value, 64);
  const timestamp = Date.parse(text);
  return text && Number.isFinite(timestamp)
    ? new Date(timestamp).toISOString()
    : null;
}

function safeInteger(value, minimum = 0) {
  const number = Number(value);
  return Number.isInteger(number) && number >= minimum ? number : null;
}

function safeExternalUrl(value) {
  const text = cleanText(value, 2_048);
  if (!text) return null;

  try {
    const parsed = new URL(text);
    return parsed.protocol === 'https:' || parsed.protocol === 'http:'
      ? parsed.toString()
      : null;
  } catch {
    return null;
  }
}

function allowedValue(value, allowed, fallback) {
  const normalized = cleanText(value, 64);
  return allowed.includes(normalized) ? normalized : fallback;
}

function sellerProfileRowData({
  userId,
  configuration,
  ebayUser,
  now,
  existingProfile,
}) {
  const syncedAt = currentDate(now).toISOString();
  const businessAccount = bodyObject(ebayUser?.businessAccount);
  const safeProfile = {
    username: nullableText(ebayUser?.username, 160),
    accountType: nullableText(ebayUser?.accountType, 32),
    accountStatus: nullableText(
      ebayUser?.accountStatus || ebayUser?.status,
      32,
    ),
    registrationMarketplaceId: nullableText(
      ebayUser?.registrationMarketplaceId,
      64,
    ),
    businessName: nullableText(
      businessAccount?.name || businessAccount?.legalName,
      160,
    ),
    doingBusinessAs: nullableText(businessAccount?.doingBusinessAs, 160),
    businessWebsiteUrl: safeExternalUrl(
      businessAccount?.websiteUrl || businessAccount?.website,
    ),
  };

  return {
    ownerId: userId,
    environment: configuration.environment,
    ebayUsername: safeProfile.username,
    ebayAccountType: safeProfile.accountType,
    ebayAccountStatus: safeProfile.accountStatus,
    ebayRegistrationMarketplaceId: safeProfile.registrationMarketplaceId,
    ebayBusinessName: safeProfile.businessName,
    ebayDoingBusinessAs: safeProfile.doingBusinessAs,
    ebayBusinessWebsiteUrl: safeProfile.businessWebsiteUrl,
    profileSyncState: 'current',
    profileLastAttemptAt: syncedAt,
    profileLastSyncedAt: syncedAt,
    profileSyncErrorCode: null,
    listingSetupState: allowedValue(
      existingProfile?.listingSetupState,
      ['not_checked', 'ready', 'needs_setup', 'failed'],
      'not_checked',
    ),
    listingsSyncState: allowedValue(
      existingProfile?.listingsSyncState,
      ['not_synced', 'current', 'stale', 'failed'],
      'not_synced',
    ),
    schemaVersion:
      safeInteger(existingProfile?.schemaVersion, 1) || 1,
    ebayProfileSnapshotJson: JSON.stringify(safeProfile),
  };
}

function sellerProfileForApp(profile) {
  if (!profile || typeof profile !== 'object') return null;

  const response = {
    username: nullableText(profile.ebayUsername, 160),
    accountType: nullableText(profile.ebayAccountType, 32),
    accountStatus: nullableText(profile.ebayAccountStatus, 32),
    registrationMarketplaceId: nullableText(
      profile.ebayRegistrationMarketplaceId,
      64,
    ),
    businessName: nullableText(profile.ebayBusinessName, 160),
    doingBusinessAs: nullableText(profile.ebayDoingBusinessAs, 160),
    businessWebsiteUrl: safeExternalUrl(profile.ebayBusinessWebsiteUrl),
    lastSyncedAt: safeDateTime(profile.profileLastSyncedAt),
  };

  return Object.values(response).some((value) => value !== null)
    ? response
    : null;
}

function sellerListingForApp(listing) {
  if (!listing || typeof listing !== 'object') return null;

  const response = {
    listingId: nullableText(listing.ebayListingId, 180),
    offerId: nullableText(listing.ebayOfferId, 180),
    sku: nullableText(listing.ebaySku, 180),
    title: nullableText(listing.listingTitle, 512),
    status: nullableText(listing.listingStatus, 64),
    listingUrl: safeExternalUrl(listing.listingUrl),
    currentPriceCents: safeInteger(listing.currentPriceCents),
    currency: nullableText(listing.currency, 3),
    quantityAvailable: safeInteger(listing.quantityAvailable),
    lastSyncedAt: safeDateTime(listing.lastSyncedAt),
  };

  return Object.values(response).some((value) => value !== null)
    ? response
    : null;
}

async function ebayIdentityUser({
  fetchImpl,
  configuration,
  accessToken,
}) {
  const url =
    ebayIdentityApiBase(configuration) +
    '/commerce/identity/v1/user/';

  let response;

  try {
    response = await fetchImpl(url, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        Authorization: 'Bearer ' + accessToken,
      },
    });
  } catch {
    error(
      502,
      'KeepFlip could not reach eBay to read seller details.',
      'EBAY_IDENTITY_NETWORK',
    );
  }

  const rawBody = await response.text();

  let payload = {};

  if (rawBody.trim()) {
    try {
      payload = JSON.parse(rawBody);
    } catch {
      payload = {};
    }
  }

  if (!response.ok) {
    if (response.status === 401) {
      error(
        401,
        'Your eBay authorization needs to be reconnected.',
        'EBAY_IDENTITY_UNAUTHORIZED',
      );
    }

    if (response.status === 403) {
      error(
        401,
        'Your eBay authorization does not have permission to read seller information. Reconnect your eBay account.',
        'EBAY_IDENTITY_FORBIDDEN',
      );
    }

    error(
      502,
      'KeepFlip could not read your eBay seller information.',
      'EBAY_IDENTITY_HTTP_' + String(response.status || 'UNKNOWN'),
    );
  }

  return payload;
}

async function ebaySellerSetupRequest({
  fetchImpl,
  configuration,
  accessToken,
  path,
}) {
  let response;
  try {
    response = await fetchImpl(ebayApiBase(configuration) + path, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        'Accept-Language': 'en-US',
        Authorization: 'Bearer ' + accessToken,
      },
    });
  } catch {
    error(
      502,
      'KeepFlip could not reach eBay to read listing setup.',
      'SELLER_SETUP_NETWORK',
    );
  }

  const payload = await parseResponseBody(response);
  if (!response.ok) {
    if (response.status === 401 || response.status === 403) {
      error(
        401,
        'Your eBay authorization needs to be reconnected to read listing setup.',
        'SELLER_SETUP_RECONNECT_REQUIRED',
      );
    }
    error(
      502,
      'KeepFlip could not read eBay listing setup.',
      'SELLER_SETUP_HTTP_' + response.status,
    );
  }

  return payload;
}

function safeBoolean(value) {
  return typeof value === 'boolean' ? value : null;
}

function periodDays(value) {
  const period = bodyObject(value);
  const direct = safeInteger(value, 1);
  if (direct !== null) return direct;

  const unit = cleanText(period.unit, 32).toUpperCase();
  return /DAY/.test(unit) ? safeInteger(period.value, 1) : null;
}

function policyCategoryType(policy) {
  const categoryTypes = Array.isArray(policy?.categoryTypes)
    ? policy.categoryTypes
    : [];
  const primary = categoryTypes[0];
  return nullableText(
    typeof primary === 'string'
      ? primary
      : primary?.name || primary?.categoryType,
    96,
  );
}

function policySummary(policyType, policyName, handlingTimeDays) {
  if (policyType === 'fulfillment') {
    if (handlingTimeDays !== null) {
      return (
        'Handling: ' +
        handlingTimeDays +
        ' business day' +
        (handlingTimeDays === 1 ? '' : 's')
      );
    }
    return policyName ? 'Shipping policy: ' + policyName : 'eBay shipping policy';
  }

  if (policyType === 'payment') {
    return policyName ? 'Payment policy: ' + policyName : 'eBay payment policy';
  }

  return null;
}

function sellerBusinessPolicyRowData({
  policy,
  policyType,
  userId,
  configuration,
  marketplaceId,
  syncedAt,
}) {
  const idField =
    policyType === 'payment'
      ? 'paymentPolicyId'
      : policyType === 'fulfillment'
        ? 'fulfillmentPolicyId'
        : 'returnPolicyId';
  const policyId = nullableText(policy?.[idField], 100);
  if (!policyId) return null;

  const policyName = nullableText(policy?.name, 128);
  const returnsAccepted =
    policyType === 'return' ? safeBoolean(policy?.returnsAccepted) : null;
  const returnPeriodDays =
    policyType === 'return' ? periodDays(policy?.returnPeriod) : null;
  const returnShippingCostPayer =
    policyType === 'return'
      ? nullableText(policy?.returnShippingCostPayer, 32)
      : null;
  const refundMethod =
    policyType === 'return' ? nullableText(policy?.refundMethod, 32) : null;
  const handlingTimeDays =
    policyType === 'fulfillment' ? periodDays(policy?.handlingTime) : null;
  const safeMarketplaceId =
    nullableText(policy?.marketplaceId, 64) || marketplaceId;
  const categoryType = policyCategoryType(policy);
  const shippingOptionCount = Array.isArray(policy?.shippingOptions)
    ? policy.shippingOptions.length
    : 0;
  const safeDetails = {
    policyType,
    policyId,
    marketplaceId: safeMarketplaceId,
    policyName,
    categoryType,
    returnsAccepted,
    returnPeriodDays,
    returnShippingCostPayer,
    refundMethod,
    handlingTimeDays,
    shippingOptionCount:
      policyType === 'fulfillment' ? shippingOptionCount : undefined,
  };

  return {
    ownerId: userId,
    environment: configuration.environment,
    sourceRecordKey: policyType + ':' + policyId,
    policyType,
    policyId,
    marketplaceId: safeMarketplaceId,
    policyName,
    categoryType,
    returnsAccepted,
    returnPeriodDays,
    returnShippingCostPayer,
    refundMethod,
    handlingTimeDays,
    shippingSummary:
      policyType === 'fulfillment'
        ? policySummary(policyType, policyName, handlingTimeDays)
        : null,
    paymentSummary:
      policyType === 'payment'
        ? policySummary(policyType, policyName, handlingTimeDays)
        : null,
    policyDetailsJson: JSON.stringify(safeDetails),
    lastSyncedAt: syncedAt,
    isArchived: false,
  };
}

function sellerInventoryLocationRowData({
  location,
  userId,
  configuration,
  syncedAt,
}) {
  const merchantLocationKey = nullableText(location?.merchantLocationKey, 100);
  if (!merchantLocationKey) return null;

  const locationBody = bodyObject(location?.location);
  const address = bodyObject(location?.address || locationBody.address);
  const locationTypes = Array.isArray(location?.locationTypes)
    ? location.locationTypes
    : [];
  const locationType = nullableText(
    location?.locationType ||
      locationBody.locationType ||
      locationTypes[0],
    64,
  );
  const countryCode = nullableText(
    address.country || address.countryCode,
    3,
  );

  return {
    ownerId: userId,
    environment: configuration.environment,
    merchantLocationKey,
    locationName: nullableText(location?.name || locationBody.name, 160),
    locationType,
    countryCode: countryCode ? countryCode.toUpperCase() : null,
    locationStatus: nullableText(
      location?.merchantLocationStatus || location?.status,
      64,
    ),
    lastSyncedAt: syncedAt,
    isArchived: false,
  };
}

function policyRowsFromEbayPayload({
  payload,
  policyType,
  userId,
  configuration,
  marketplaceId,
  syncedAt,
}) {
  const listKey =
    policyType === 'payment'
      ? 'paymentPolicies'
      : policyType === 'fulfillment'
        ? 'fulfillmentPolicies'
        : 'returnPolicies';
  const policies = Array.isArray(payload?.[listKey]) ? payload[listKey] : [];
  const seen = new Set();
  const rows = [];

  for (const policy of policies) {
    const row = sellerBusinessPolicyRowData({
      policy,
      policyType,
      userId,
      configuration,
      marketplaceId,
      syncedAt,
    });
    if (!row || seen.has(row.sourceRecordKey)) continue;
    seen.add(row.sourceRecordKey);
    rows.push(row);
  }

  return rows;
}

function locationRowsFromEbayPayload({
  payload,
  userId,
  configuration,
  syncedAt,
}) {
  const locations = Array.isArray(payload?.locations) ? payload.locations : [];
  const seen = new Set();
  const rows = [];

  for (const location of locations) {
    const row = sellerInventoryLocationRowData({
      location,
      userId,
      configuration,
      syncedAt,
    });
    if (!row || seen.has(row.merchantLocationKey)) continue;
    seen.add(row.merchantLocationKey);
    rows.push(row);
  }

  return rows;
}

async function listEbayInventoryLocations({
  fetchImpl,
  configuration,
  accessToken,
}) {
  const limit = 100;
  const maximumPages = 5;
  const locations = [];

  for (let page = 0; page < maximumPages; page += 1) {
    const query = new URLSearchParams({
      limit: String(limit),
      offset: String(page * limit),
    });
    const payload = await ebaySellerSetupRequest({
      fetchImpl,
      configuration,
      accessToken,
      path: '/sell/inventory/v1/location?' + query.toString(),
    });
    const batch = Array.isArray(payload?.locations) ? payload.locations : [];
    locations.push(...batch);

    const total = safeInteger(payload?.total, 0);
    if (
      batch.length === 0 ||
      batch.length < limit ||
      (total !== null && locations.length >= total)
    ) {
      break;
    }
  }

  return { locations };
}

function policyRowsForType(rows, policyType) {
  return rows.filter((row) => row.policyType === policyType);
}

function onlyPolicyId(rows, policyType) {
  const ids = [
    ...new Set(
      policyRowsForType(rows, policyType)
        .map((row) => nullableText(row.policyId, 100))
        .filter(Boolean),
    ),
  ];
  return ids.length === 1 ? ids[0] : null;
}

function onlyMerchantLocationKey(rows) {
  const keys = [
    ...new Set(
      rows
        .map((row) => nullableText(row.merchantLocationKey, 100))
        .filter(Boolean),
    ),
  ];
  return keys.length === 1 ? keys[0] : null;
}

function marketplaceCurrency(marketplaceId) {
  const currencies = {
    EBAY_US: 'USD',
    EBAY_CA: 'CAD',
    EBAY_GB: 'GBP',
    EBAY_AU: 'AUD',
    EBAY_DE: 'EUR',
    EBAY_ES: 'EUR',
    EBAY_FR: 'EUR',
    EBAY_IE: 'EUR',
    EBAY_IT: 'EUR',
    EBAY_NL: 'EUR',
  };
  return currencies[marketplaceId] || null;
}

function sellerListingDefaultsData({
  userId,
  configuration,
  marketplaceId,
  policyRows,
  locationRows,
  syncedAt,
}) {
  const currency = marketplaceCurrency(marketplaceId);
  if (!currency) return null;

  return {
    ownerId: userId,
    environment: configuration.environment,
    marketplaceId,
    defaultMerchantLocationKey: onlyMerchantLocationKey(locationRows),
    defaultPaymentPolicyId: onlyPolicyId(policyRows, 'payment'),
    defaultFulfillmentPolicyId: onlyPolicyId(policyRows, 'fulfillment'),
    defaultReturnPolicyId: onlyPolicyId(policyRows, 'return'),
    defaultListingDuration: 'GTC',
    defaultFormat: 'FIXED_PRICE',
    defaultCurrency: currency,
    defaultQuantity: 1,
    defaultCategoryId: null,
    defaultCondition: null,
    defaultStoreCategoryId: null,
    selectionSource: 'ebay_import',
    updatedAt: syncedAt,
  };
}

function selectedPolicyExists(defaults, field, rows, policyType) {
  const selected = nullableText(defaults?.[field], 100);
  return Boolean(
    selected &&
      policyRowsForType(rows, policyType).some(
        (row) => nullableText(row.policyId, 100) === selected,
      ),
  );
}

function selectedLocationExists(defaults, locationRows) {
  const selected = nullableText(defaults?.defaultMerchantLocationKey, 100);
  return Boolean(
    selected &&
      locationRows.some(
        (row) => nullableText(row.merchantLocationKey, 100) === selected,
      ),
  );
}

function listingSetupMessage(issueCode) {
  const messages = {
    MISSING_PAYMENT_POLICY:
      'Add a payment policy in eBay, then refresh KeepFlip.',
    MISSING_FULFILLMENT_POLICY:
      'Add a shipping policy in eBay, then refresh KeepFlip.',
    MISSING_RETURN_POLICY:
      'Add a return policy in eBay, then refresh KeepFlip.',
    MISSING_INVENTORY_LOCATION:
      'Add an inventory location in eBay, then refresh KeepFlip.',
    CHOOSE_LISTING_DEFAULTS:
      'Choose which saved eBay policies and location KeepFlip should use by default.',
    UNSUPPORTED_MARKETPLACE:
      'Choose a supported marketplace before saving listing defaults.',
    RECONNECT_REQUIRED:
      'Reconnect eBay to let KeepFlip read your listing setup.',
    SETUP_SYNC_FAILED:
      'KeepFlip could not refresh listing setup right now. Try again shortly.',
  };
  return messages[issueCode] || null;
}

function sellerListingSetupForApp({
  marketplaceId,
  policyRows,
  locationRows,
  defaults,
  checkedAt,
  overrideIssueCode = null,
}) {
  const policyCounts = {
    payment: policyRowsForType(policyRows, 'payment').length,
    fulfillment: policyRowsForType(policyRows, 'fulfillment').length,
    return: policyRowsForType(policyRows, 'return').length,
  };
  const defaultSelection = {
    hasMerchantLocation: selectedLocationExists(defaults, locationRows),
    hasPaymentPolicy: selectedPolicyExists(
      defaults,
      'defaultPaymentPolicyId',
      policyRows,
      'payment',
    ),
    hasFulfillmentPolicy: selectedPolicyExists(
      defaults,
      'defaultFulfillmentPolicyId',
      policyRows,
      'fulfillment',
    ),
    hasReturnPolicy: selectedPolicyExists(
      defaults,
      'defaultReturnPolicyId',
      policyRows,
      'return',
    ),
  };
  let issueCode = overrideIssueCode;
  if (!issueCode && policyCounts.payment === 0) {
    issueCode = 'MISSING_PAYMENT_POLICY';
  } else if (!issueCode && policyCounts.fulfillment === 0) {
    issueCode = 'MISSING_FULFILLMENT_POLICY';
  } else if (!issueCode && policyCounts.return === 0) {
    issueCode = 'MISSING_RETURN_POLICY';
  } else if (!issueCode && locationRows.length === 0) {
    issueCode = 'MISSING_INVENTORY_LOCATION';
  } else if (!issueCode && !marketplaceCurrency(marketplaceId)) {
    issueCode = 'UNSUPPORTED_MARKETPLACE';
  } else if (
    !issueCode &&
    Object.values(defaultSelection).some((selected) => !selected)
  ) {
    issueCode = 'CHOOSE_LISTING_DEFAULTS';
  }

  const state =
    issueCode === 'SETUP_SYNC_FAILED'
      ? 'failed'
      : issueCode
        ? 'needs_setup'
        : 'ready';

  return {
    state,
    marketplaceId,
    policyCounts,
    locationCount: locationRows.length,
    defaultSelection,
    lastCheckedAt: checkedAt,
    ...(issueCode ? { issueCode, message: listingSetupMessage(issueCode) } : {}),
  };
}

function sellerListingSetupFailureForApp({ marketplaceId, now, caught }) {
  const issueCode =
    caught instanceof HttpError && caught.status === 401
      ? 'RECONNECT_REQUIRED'
      : 'SETUP_SYNC_FAILED';
  return sellerListingSetupForApp({
    marketplaceId,
    policyRows: [],
    locationRows: [],
    defaults: null,
    checkedAt: currentDate(now).toISOString(),
    overrideIssueCode: issueCode,
  });
}

async function readSellerListingDefaults({
  fetchImpl,
  req,
  runtime,
  configuration,
  userId,
  marketplaceId,
}) {
  const defaults = await getServerRowOrNull({
    fetchImpl,
    req,
    runtime,
    configuration,
    tableId: configuration.sellerListingDefaultsTableId,
    rowId: sellerListingDefaultsRowId(
      userId,
      configuration.environment,
      marketplaceId,
    ),
    failureMessage: 'KeepFlip could not read saved listing defaults.',
  });

  if (
    !defaults ||
    defaults.ownerId !== userId ||
    (defaults.environment &&
      defaults.environment !== configuration.environment) ||
    (defaults.marketplaceId && defaults.marketplaceId !== marketplaceId)
  ) {
    return null;
  }

  return defaults;
}

async function syncSellerListingSetup({
  fetchImpl,
  req,
  runtime,
  configuration,
  userId,
  accessToken,
  marketplaceId,
  now,
}) {
  const query = new URLSearchParams({ marketplace_id: marketplaceId });
  const [paymentPayload, fulfillmentPayload, returnPayload, locationsPayload] =
    await Promise.all([
      ebaySellerSetupRequest({
        fetchImpl,
        configuration,
        accessToken,
        path: '/sell/account/v1/payment_policy?' + query.toString(),
      }),
      ebaySellerSetupRequest({
        fetchImpl,
        configuration,
        accessToken,
        path: '/sell/account/v1/fulfillment_policy?' + query.toString(),
      }),
      ebaySellerSetupRequest({
        fetchImpl,
        configuration,
        accessToken,
        path: '/sell/account/v1/return_policy?' + query.toString(),
      }),
      listEbayInventoryLocations({
        fetchImpl,
        configuration,
        accessToken,
      }),
    ]);
  const syncedAt = currentDate(now).toISOString();
  const policyRows = [
    ...policyRowsFromEbayPayload({
      payload: paymentPayload,
      policyType: 'payment',
      userId,
      configuration,
      marketplaceId,
      syncedAt,
    }),
    ...policyRowsFromEbayPayload({
      payload: fulfillmentPayload,
      policyType: 'fulfillment',
      userId,
      configuration,
      marketplaceId,
      syncedAt,
    }),
    ...policyRowsFromEbayPayload({
      payload: returnPayload,
      policyType: 'return',
      userId,
      configuration,
      marketplaceId,
      syncedAt,
    }),
  ];
  const locationRows = locationRowsFromEbayPayload({
    payload: locationsPayload,
    userId,
    configuration,
    syncedAt,
  });

  for (const row of policyRows) {
    await upsertServerRow({
      fetchImpl,
      req,
      runtime,
      configuration,
      tableId: configuration.sellerBusinessPoliciesTableId,
      rowId: sellerBusinessPolicyRowId(
        userId,
        configuration.environment,
        row.sourceRecordKey,
      ),
      data: row,
      failureMessage: 'KeepFlip could not save an eBay business policy.',
    });
  }

  for (const row of locationRows) {
    await upsertServerRow({
      fetchImpl,
      req,
      runtime,
      configuration,
      tableId: configuration.sellerInventoryLocationsTableId,
      rowId: sellerInventoryLocationRowId(
        userId,
        configuration.environment,
        row.merchantLocationKey,
      ),
      data: row,
      failureMessage: 'KeepFlip could not save an eBay inventory location.',
    });
  }

  let defaults = await readSellerListingDefaults({
    fetchImpl,
    req,
    runtime,
    configuration,
    userId,
    marketplaceId,
  });
  if (!defaults) {
    const data = sellerListingDefaultsData({
      userId,
      configuration,
      marketplaceId,
      policyRows,
      locationRows,
      syncedAt,
    });
    if (data) {
      await upsertServerRow({
        fetchImpl,
        req,
        runtime,
        configuration,
        tableId: configuration.sellerListingDefaultsTableId,
        rowId: sellerListingDefaultsRowId(
          userId,
          configuration.environment,
          marketplaceId,
        ),
        data,
        failureMessage: 'KeepFlip could not save listing defaults.',
      });
      defaults = data;
    }
  }

  return sellerListingSetupForApp({
    marketplaceId,
    policyRows,
    locationRows,
    defaults,
    checkedAt: syncedAt,
  });
}
async function readCachedSellerProfile({
  fetchImpl,
  req,
  runtime,
  configuration,
  userId,
}) {
  return getServerRowOrNull({
    fetchImpl,
    req,
    runtime,
    configuration,
    tableId: configuration.sellerProfilesTableId,
    rowId: sellerProfileRowId(userId, configuration.environment),
    failureMessage: 'KeepFlip could not read the seller profile.',
  });
}

async function listCachedSellerListings({
  fetchImpl,
  req,
  runtime,
  configuration,
  userId,
}) {
  const query = new URLSearchParams();
  query.append('queries[]', equalTableQuery('ownerId', userId));
  query.append('queries[]', equalTableQuery('environment', configuration.environment));
  query.append('queries[]', 'orderDesc("lastSyncedAt")');
  query.append('queries[]', 'limit(6)');

  try {
    const result = await appwriteJson({
      fetchImpl,
      runtime,
      apiKey: functionDynamicKey(req),
      path:
        tableRowsPath(configuration, configuration.sellerListingsTableId) +
        '?' +
        query.toString(),
      failureMessage: 'KeepFlip could not read cached eBay listings.',
    });
    const rows = Array.isArray(result?.rows) ? result.rows : [];
    const listings = rows
      .map(sellerListingForApp)
      .filter(Boolean)
      .slice(0, 6);
    const total = safeInteger(result?.total) || rows.length;

    return { listingCount: Math.max(total, listings.length), listings };
  } catch {
    // A profile remains useful even when a listing cache is temporarily
    // unavailable. A later seller-account refresh retries this read.
    return { listingCount: 0, listings: [] };
  }
}

async function cacheKeepFlipListing({
  fetchImpl,
  req,
  runtime,
  configuration,
  userId,
  itemId,
  listingId,
  offerId,
  sku,
  title,
  marketplaceId,
  categoryId,
  condition,
  price,
  currency,
  quantity,
  now,
  publishedAt,
}) {
  const safeListingId = nullableText(listingId, 180);
  const safeOfferId = nullableText(offerId, 180);
  const safeSku = nullableText(sku, 180);
  const sourceRecordKey = safeListingId
    ? 'listing:' + safeListingId
    : safeOfferId
      ? 'offer:' + safeOfferId
      : safeSku
        ? 'sku:' + safeSku
        : null;
  if (!sourceRecordKey) return false;

  const syncedAt = currentDate(now).toISOString();
  const safeListingUrl = safeListingId
    ? listingUrl(configuration, safeListingId)
    : null;
  const data = {
    ownerId: userId,
    environment: configuration.environment,
    sourceRecordKey,
    ebayListingId: safeListingId,
    ebayOfferId: safeOfferId,
    ebaySku: safeSku,
    keepFlipItemId: nullableText(itemId, 64),
    listingTitle: nullableText(title, 512),
    listingStatus: 'PUBLISHED',
    listingFormat: 'FIXED_PRICE',
    marketplaceId: nullableText(marketplaceId, 64),
    categoryId: nullableText(categoryId, 128),
    condition: nullableText(condition, 128),
    listingUrl: safeListingUrl,
    currentPriceCents: Math.round(Number(price) * 100),
    currency: nullableText(currency, 3),
    quantityAvailable: safeInteger(quantity, 1),
    listingPublishedAt: safeDateTime(publishedAt),
    lastSyncedAt: syncedAt,
    source: 'keepflip_publish',
    isKeepFlipManaged: true,
    isArchived: false,
    listingSnapshotJson: JSON.stringify({
      listingId: safeListingId,
      offerId: safeOfferId,
      sku: safeSku,
      title: nullableText(title, 512),
      status: 'PUBLISHED',
      format: 'FIXED_PRICE',
      marketplaceId: nullableText(marketplaceId, 64),
      categoryId: nullableText(categoryId, 128),
      condition: nullableText(condition, 128),
      priceCents: Math.round(Number(price) * 100),
      currency: nullableText(currency, 3),
      quantityAvailable: safeInteger(quantity, 1),
    }),
  };

  await upsertServerRow({
    fetchImpl,
    req,
    runtime,
    configuration,
    tableId: configuration.sellerListingsTableId,
    rowId: sellerListingRowId(
      userId,
      configuration.environment,
      sourceRecordKey,
    ),
    data,
    failureMessage: 'KeepFlip could not save the published eBay listing.',
  });

  return true;
}

async function handleSellerAccount({
  req,
  res,
  fetchImpl,
  runtime,
  now,
  randomBytesImpl,
}) {
  const body = requestBody(req);
  const environment = normalizeEnvironment(body.environment);
  const marketplaceId =
    listingString(body.marketplaceId, 64).toUpperCase() || 'EBAY_US';
  const configuration = configurationFor(environment);
  const userId = await authenticatedUserId({ req, fetchImpl, runtime });
  const connection = await getConnection({
    fetchImpl,
    req,
    runtime,
    configuration,
    userId,
  });

  if (
    !connection ||
    connection.ownerId !== userId ||
    connection.revokedAt ||
    connection.status === 'revoked'
  ) {
    return res.json({
      ok: true,
      connected: false,
      environment,
      listingCount: 0,
      listings: [],
    });
  }

  const cachedProfile = await readCachedSellerProfile({
    fetchImpl,
    req,
    runtime,
    configuration,
    userId,
  });
  let sellerProfile = cachedProfile;
  let profileFreshness = cachedProfile ? 'stale' : undefined;
  let listingSetup;

  try {
    const accessToken = await ensureEbayAccessToken({
      fetchImpl,
      req,
      runtime,
      configuration,
      connection,
      now,
      randomBytesImpl,
    });
    const ebayUser = await ebayIdentityUser({
      fetchImpl,
      configuration,
      accessToken,
    });
    const data = sellerProfileRowData({
      userId,
      configuration,
      ebayUser,
      now,
      existingProfile: cachedProfile,
    });

    await upsertServerRow({
      fetchImpl,
      req,
      runtime,
      configuration,
      tableId: configuration.sellerProfilesTableId,
      rowId: sellerProfileRowId(userId, environment),
      data,
      failureMessage: 'KeepFlip could not save the seller profile.',
    });
    sellerProfile = { ...cachedProfile, ...data };
    profileFreshness = 'current';

    try {
      listingSetup = await syncSellerListingSetup({
        fetchImpl,
        req,
        runtime,
        configuration,
        userId,
        accessToken,
        marketplaceId,
        now,
      });
    } catch (caught) {
      // The profile is still useful if eBay policy reads are temporarily
      // unavailable or the seller has not granted the new Account-read scope.
      listingSetup = sellerListingSetupFailureForApp({
        marketplaceId,
        now,
        caught,
      });
    }

    const profileWithListingSetup = {
      ...data,
      listingSetupState: listingSetup.state,
      listingSetupLastCheckedAt: listingSetup.lastCheckedAt,
      listingSetupIssueCode: listingSetup.issueCode || null,
    };
    try {
      await upsertServerRow({
        fetchImpl,
        req,
        runtime,
        configuration,
        tableId: configuration.sellerProfilesTableId,
        rowId: sellerProfileRowId(userId, environment),
        data: profileWithListingSetup,
        failureMessage: 'KeepFlip could not save seller listing setup status.',
      });
      sellerProfile = { ...cachedProfile, ...profileWithListingSetup };
    } catch {
      // The identity profile was already saved above. Do not replace it with a
      // generic screen error solely because its optional setup status failed.
    }
  } catch (caught) {
    if (caught instanceof HttpError && caught.status === 401) {
      throw caught;
    }
    if (!(cachedProfile && caught instanceof HttpError && caught.status === 502)) {
      if (caught instanceof HttpError) throw caught;
      error(500, 'KeepFlip could not prepare the seller account.');
    }
  }

  const cachedListings = await listCachedSellerListings({
    fetchImpl,
    req,
    runtime,
    configuration,
    userId,
  });
  const profile = sellerProfileForApp(sellerProfile);

  return res.json({
    ok: true,
    connected: true,
    environment,
    ...(profile ? { profile } : {}),
    ...(profileFreshness ? { profileFreshness } : {}),
    ...(listingSetup ? { listingSetup } : {}),
    ...cachedListings,
  });
}
async function handleEbayListing({
  req,
  res,
  fetchImpl,
  runtime,
  now,
  randomBytesImpl,
}) {
  const body = requestBody(req);
  const environment = normalizeEnvironment(body.environment, 'Listing environment');
  const configuration = configurationFor(environment);
  const userId = await authenticatedUserId({ req, fetchImpl, runtime });
  const itemId = requiredListingValue(body, 'itemId', 64);
  const item = await getOwnedInventoryItem({
    fetchImpl,
    req,
    runtime,
    configuration,
    userId,
    itemId,
  });
  const connection = await getConnection({
    fetchImpl,
    req,
    runtime,
    configuration,
    userId,
  });
  if (!connection || connection.revokedAt) {
    error(404, 'Connect an eBay account before publishing a listing.');
  }

  const accessToken = await ensureEbayAccessToken({
    fetchImpl,
    req,
    runtime,
    configuration,
    connection,
    now,
    randomBytesImpl,
  });

  const listingPolicies = bodyObject(body.listingPolicies);
  const marketplaceId =
    listingString(body.marketplaceId, 40).toUpperCase() || 'EBAY_US';
  let savedListingDefaults = null;
  try {
    savedListingDefaults = await readSellerListingDefaults({
      fetchImpl,
      req,
      runtime,
      configuration,
      userId,
      marketplaceId,
    });
  } catch {
    // A saved preset is optional. Explicit listing-policy values still work
    // when its cache is temporarily unavailable.
  }
  const title =
    listingString(body.title, 80) ||
    listingString(item.title, 80) ||
    [item.brand, item.model, item.category]
      .map((value) => listingString(value, 80))
      .filter(Boolean)
      .join(' ')
      .slice(0, 80);
  const description =
    listingString(body.description, 500_000) ||
    listingString(item.description, 500_000);
  if (!title) error(400, 'eBay listings need a title.');
  if (!description) error(400, 'eBay listings need a description.');

  const price = listingNumber(
    body.price ??
      (body.priceCents === undefined ? undefined : Number(body.priceCents) / 100),
    'price',
    { minimum: 0.01 },
  );
  const quantity = listingNumber(
    body.quantity ?? savedListingDefaults?.defaultQuantity ?? 1,
    'quantity',
    {
      integer: true,
      minimum: 1,
    },
  );
  const categoryId =
    listingString(body.categoryId, 20) ||
    listingString(savedListingDefaults?.defaultCategoryId, 20);
  if (!categoryId) {
    error(400, 'eBay listing field "categoryId" is required.');
  }
  if (!/^\d+$/.test(categoryId)) {
    error(400, 'eBay categoryId must be a numeric category ID.');
  }

  const merchantLocationKey =
    listingString(body.merchantLocationKey, 100) ||
    listingString(listingPolicies.merchantLocationKey, 100) ||
    listingString(savedListingDefaults?.defaultMerchantLocationKey, 100);
  if (!merchantLocationKey) {
    error(
      400,
      'Finish your saved eBay listing setup in Seller Account, then try again.',
    );
  }
  const paymentPolicyId =
    listingString(body.paymentPolicyId, 100) ||
    listingString(listingPolicies.paymentPolicyId, 100) ||
    listingString(savedListingDefaults?.defaultPaymentPolicyId, 100);
  if (!paymentPolicyId) {
    error(
      400,
      'Finish your saved eBay listing setup in Seller Account, then try again.',
    );
  }
  const fulfillmentPolicyId =
    listingString(body.fulfillmentPolicyId, 100) ||
    listingString(listingPolicies.fulfillmentPolicyId, 100) ||
    listingString(savedListingDefaults?.defaultFulfillmentPolicyId, 100);
  if (!fulfillmentPolicyId) {
    error(
      400,
      'Finish your saved eBay listing setup in Seller Account, then try again.',
    );
  }
  const returnPolicyId =
    listingString(body.returnPolicyId, 100) ||
    listingString(listingPolicies.returnPolicyId, 100) ||
    listingString(savedListingDefaults?.defaultReturnPolicyId, 100);
  if (!returnPolicyId) {
    error(
      400,
      'Finish your saved eBay listing setup in Seller Account, then try again.',
    );
  }
  const currency =
    listingString(body.currency, 3).toUpperCase() ||
    listingString(savedListingDefaults?.defaultCurrency, 3).toUpperCase() ||
    'USD';
  const condition = normalizeInventoryCondition(body.condition || item.condition);
  const conditionDescription = ['NEW', 'LIKE_NEW', 'NEW_OTHER', 'NEW_WITH_DEFECTS'].includes(condition)
    ? ''
    : listingString(body.conditionDescription || item.conditionNotes || item.description, 1_000);
  const sku = listingString(body.sku, 50) || ('KF-' + itemId).slice(0, 50);
  if (!/^[A-Za-z0-9._-]+$/.test(sku)) {
    error(
      400,
      'eBay SKU may contain only letters, numbers, periods, underscores, and hyphens.',
    );
  }

  const photoFileIds = await getInventoryPhotoFileIds({
    fetchImpl,
    req,
    runtime,
    configuration,
    item,
  });
  const imageUrls = photoFileIds.map((fileId) =>
    appwriteFileViewUrl(runtime, configuration, fileId),
  );

  await ebayApiRequest({
    fetchImpl,
    configuration,
    accessToken,
    method: 'PUT',
    path: '/sell/inventory/v1/inventory_item/' + encodeURIComponent(sku),
    body: {
      availability: { shipToLocationAvailability: { quantity } },
      condition,
      ...(conditionDescription ? { conditionDescription } : {}),
      product: { title, description, imageUrls },
    },
  });

  const offerPayload = {
    sku,
    marketplaceId,
    format: 'FIXED_PRICE',
    availableQuantity: quantity,
    categoryId,
    listingDescription: description,
    listingDuration:
      listingString(body.listingDuration, 30) ||
      listingString(savedListingDefaults?.defaultListingDuration, 30) ||
      'GTC',
    merchantLocationKey,
    pricingSummary: { price: { value: price.toFixed(2), currency } },
    listingPolicies: { paymentPolicyId, fulfillmentPolicyId, returnPolicyId },
  };
  const existingOffer = await findExistingEbayOffer({
    fetchImpl,
    configuration,
    accessToken,
    sku,
    marketplaceId,
  });
  let offerId = listingString(existingOffer?.offerId, 100);
  const existingListingId = listingString(existingOffer?.listingId, 100);
  if (String(existingOffer?.status || '').toUpperCase() === 'PUBLISHED' && existingListingId) {
    let listingRecordSaved = false;
    try {
      listingRecordSaved = await cacheKeepFlipListing({
        fetchImpl,
        req,
        runtime,
        configuration,
        userId,
        itemId,
        listingId: existingListingId,
        offerId,
        sku,
        title,
        marketplaceId,
        categoryId,
        condition,
        price,
        currency,
        quantity,
        now,
        publishedAt: existingOffer?.listingStartDate,
      });
    } catch {
      // Publishing already succeeded at eBay. The Seller Account cache can
      // safely retry on the next publish or seller-account refresh.
    }

    return res.json({
      ok: true,
      status: 'already_published',
      environment,
      itemId,
      sku,
      offerId: offerId || null,
      listingId: existingListingId,
      listingUrl: listingUrl(configuration, existingListingId),
      listingRecordSaved,
    });
  }

  if (offerId) {
    await ebayApiRequest({
      fetchImpl,
      configuration,
      accessToken,
      method: 'PUT',
      path: '/sell/inventory/v1/offer/' + encodeURIComponent(offerId),
      body: offerPayload,
    });
  } else {
    const createdOffer = await ebayApiRequest({
      fetchImpl,
      configuration,
      accessToken,
      method: 'POST',
      path: '/sell/inventory/v1/offer',
      body: offerPayload,
    });
    offerId = listingString(createdOffer.payload?.offerId, 100);
    if (!offerId) {
      error(502, 'eBay created the offer but did not return an offer ID.');
    }
  }

  const published = await ebayApiRequest({
    fetchImpl,
    configuration,
    accessToken,
    method: 'POST',
    path: '/sell/inventory/v1/offer/' + encodeURIComponent(offerId) + '/publish',
  });
  const listingId = listingString(
    published.payload?.listingId || published.payload?.listing?.listingId,
    100,
  );

  let listingRecordSaved = false;
  try {
    listingRecordSaved = await cacheKeepFlipListing({
      fetchImpl,
      req,
      runtime,
      configuration,
      userId,
      itemId,
      listingId,
      offerId,
      sku,
      title,
      marketplaceId,
      categoryId,
      condition,
      price,
      currency,
      quantity,
      now,
      publishedAt: currentDate(now).toISOString(),
    });
  } catch {
    // Publishing already succeeded at eBay. The Seller Account cache can
    // safely retry on the next publish or seller-account refresh.
  }

  return res.json({
    ok: true,
    status: 'published',
    environment,
    itemId,
    sku,
    offerId,
    listingId: listingId || null,
    listingUrl: listingId ? listingUrl(configuration, listingId) : null,
    listingRecordSaved,
  });
}

async function handleConnect({
  req,
  res,
  fetchImpl,
  runtime,
  now,
  randomBytesImpl,
}) {
  const environment = normalizeEnvironment(requestBody(req).environment);
  const configuration = configurationFor(environment);
  const userId = await authenticatedUserId({ req, fetchImpl, runtime });
  const state = createOpaqueState(randomBytesImpl);

  const stateRecord = await createStateRecord({
    fetchImpl,
    req,
    runtime,
    configuration,
    userId,
    state,
    now,
  });

  // The app owns the browser URL. This endpoint only issues and records the
  // one-time state that the callback will claim and verify.
  return res.json({
    ok: true,
    environment,
    state,
    expiresAt: stateRecord.expiresAt,
  });
}

async function handleStatus({ req, res, fetchImpl, runtime, now, error: reportError }) {
  const environment = normalizeEnvironment(requestBody(req).environment);
  const configuration = configurationFor(environment);
  const userId = await authenticatedUserId({ req, fetchImpl, runtime });
  const connection = await getConnection({
    fetchImpl,
    req,
    runtime,
    configuration,
    userId,
  });

  if (!connection || connection.ownerId !== userId) {
    return res.json({ connected: false, environment });
  }

  try {
    return res.json(
      connectionStatus(
        connection,
        readTokenBundle(connection, configuration),
        configuration,
        now,
      ),
    );
  } catch (caught) {
    if (
      caught instanceof HttpError &&
      (caught.diagnosticCode === 'STORED_CONNECTION_UNREADABLE' ||
        caught.diagnosticCode === 'STORED_CONNECTION_INVALID')
    ) {
      safeError(reportError, caught, '/status');
      return res.json({
        connected: false,
        environment,
        needsReconnect: true,
      });
    }
    throw caught;
  }
}

async function handleRefresh({
  req,
  res,
  fetchImpl,
  runtime,
  now,
  randomBytesImpl,
}) {
  const environment = normalizeEnvironment(requestBody(req).environment);
  const configuration = configurationFor(environment);
  const userId = await authenticatedUserId({ req, fetchImpl, runtime });
  const connection = await getConnection({
    fetchImpl,
    req,
    runtime,
    configuration,
    userId,
  });

  if (!connection || connection.ownerId !== userId || connection.revokedAt) {
    error(404, 'No connected eBay account was found.');
  }

  const tokenBundle = await refreshToken({
    fetchImpl,
    configuration,
    tokenBundle: readTokenBundle(connection, configuration),
    now,
  });

  await saveRefreshedConnection({
    fetchImpl,
    req,
    runtime,
    configuration,
    connection,
    tokenBundle,
    randomBytesImpl,
  });

  return res.json({
    refreshed: true,
    connected: true,
    environment,
    accessTokenExpiresAt: tokenBundle.accessTokenExpiresAt,
    needsReconnect: false,
  });
}

async function handleRevoke({ req, res, fetchImpl, runtime, now }) {
  const environment = normalizeEnvironment(requestBody(req).environment);
  const configuration = configurationFor(environment);
  const userId = await authenticatedUserId({ req, fetchImpl, runtime });
  const connection = await getConnection({
    fetchImpl,
    req,
    runtime,
    configuration,
    userId,
  });

  if (
    !connection ||
    connection.ownerId !== userId ||
    connection.revokedAt ||
    connection.status === 'revoked'
  ) {
    return res.json({ revoked: true, connected: false, environment });
  }

  const tokenBundle = readTokenBundle(connection, configuration);
  await revokeEbayAuthorization({
    fetchImpl,
    configuration,
    tokenBundle,
  });
  await markConnectionRevoked({
    fetchImpl,
    req,
    runtime,
    configuration,
    connection,
    now,
  });

  return res.json({
    revoked: true,
    connected: false,
    environment,
  });
}

function safeError(error, caught, path = '') {
  if (typeof error === 'function') {
    const route = cleanText(path, 80) || 'unknown';
    const code =
      caught instanceof HttpError
        ? cleanText(caught.diagnosticCode, 80) || 'HTTP_' + caught.status
        : caught instanceof UpstreamError
          ? 'UPSTREAM_' + (caught.status || 'NETWORK')
          : ['TypeError', 'ReferenceError', 'SyntaxError', 'RangeError'].includes(
                cleanText(caught?.name, 32),
              )
            ? 'UNEXPECTED_' + cleanText(caught?.name, 32).toUpperCase()
            : 'UNEXPECTED';
    const status =
      caught instanceof HttpError || caught instanceof UpstreamError
        ? String(caught.status || 500)
        : '500';
    error(
      'KeepFlip eBay OAuth backend request failed. route=' +
        route +
        ' status=' +
        status +
        ' reason=' +
        code,
    );
  }
}

export function createHandler({
  fetchImpl = globalThis.fetch,
  now = () => new Date(),
  randomBytesImpl = randomBytes,
} = {}) {
  if (typeof fetchImpl !== 'function') {
    error('A fetch implementation is required.');
  }

  return async function main({ req, res, error } = {}) {
    let path = 'unknown';
    try {
      path = requestPath(req);
      const runtime = functionRuntime();

      if (req?.method === 'GET' && path === '/') {
        return res.json({
          ok: true,
          service: 'KeepFlip eBay OAuth backend',
          routes: [
            '/connect',
            '/status',
            '/refresh',
            '/revoke',
            '/listing',
            '/seller-account',
          ],
        });
      }

      if (req?.method === 'POST' && path === '/connect') {
        return await handleConnect({
          req,
          res,
          fetchImpl,
          runtime,
          now,
          randomBytesImpl,
        });
      }

      if (req?.method === 'POST' && path === '/listing') {
        return await handleEbayListing({
          req,
          res,
          fetchImpl,
          runtime,
          now,
          randomBytesImpl,
        });
      }

      if (req?.method === 'POST' && path === '/seller-account') {
        return await handleSellerAccount({
          req,
          res,
          fetchImpl,
          runtime,
          now,
          randomBytesImpl,
        });
      }

      if (req?.method === 'POST' && path === '/status') {
        return await handleStatus({
          req,
          res,
          fetchImpl,
          runtime,
          now,
          error,
        });
      }

      if (req?.method === 'POST' && path === '/revoke') {
        return await handleRevoke({ req, res, fetchImpl, runtime, now });
      }

      if (req?.method === 'POST' && path === '/refresh') {
        return await handleRefresh({
          req,
          res,
          fetchImpl,
          runtime,
          now,
          randomBytesImpl,
        });
      }

      return res.json({ error: 'Endpoint not found.' }, 404);
    } catch (caught) {
      const status = caught instanceof HttpError ? caught.status : 500;
      if (status >= 500) safeError(error, caught, path);

      return res.json(
        {
          error:
            status >= 500
              ? 'KeepFlip could not complete the eBay OAuth request.'
              : caught.message,
        },
        status,
      );
    }
  };
}

export const __testables = {
  decryptSecret,
  encryptSecret,
};

export default createHandler();


