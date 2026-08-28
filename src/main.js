import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from 'node:crypto';

export const KEEPFLIP_EBAY_USER_SCOPES = Object.freeze([
  'https://api.ebay.com/oauth/api_scope',
  'https://api.ebay.com/oauth/api_scope/commerce.identity.readonly',
]);

const STATE_TTL_MS = 10 * 60 * 1000;

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.name = 'HttpError';
    this.status = status;
  }
}

class UpstreamError extends Error {
  constructor(status, message) {
    super(message);
    this.name = 'UpstreamError';
    this.status = status;
  }
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
    throw new Error('Missing required eBay OAuth Function configuration.');
  }

  return value;
}

function normalizeEnvironment(value, label = 'OAuth environment') {
  const environment = cleanText(String(value ?? '')).toLowerCase();
  if (environment === 'sandbox' || environment === 'production') {
    return environment;
  }

  throw new HttpError(400, label + ' must be "sandbox" or "production".');
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
    throw new Error('Appwrite did not provide this Function a dynamic API key.');
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
  };
}

function decodeEncryptionKey() {
  const text = requiredEnvironmentValue(['EBAY_TOKEN_ENCRYPTION_KEY']);
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(text)) {
    throw new Error('EBAY_TOKEN_ENCRYPTION_KEY must be a Base64 32-byte key.');
  }

  const key = Buffer.from(text, 'base64');
  if (key.length !== 32) {
    throw new Error('EBAY_TOKEN_ENCRYPTION_KEY must decode to exactly 32 bytes.');
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
    throw new HttpError(
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
    throw new HttpError(
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
    throw new HttpError(
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
    throw new Error('The OAuth Function clock is invalid.');
  }

  return date;
}

function addSeconds(date, seconds) {
  const numeric = Number(seconds);
  if (!Number.isFinite(numeric) || numeric <= 0) {
    throw new Error('eBay did not return a valid token expiration.');
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
    throw new HttpError(
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
    throw new HttpError(
      500,
      'KeepFlip could not read the eBay connection.',
    );
  }
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
    throw new Error('Stored eBay token data is invalid.');
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
    throw new HttpError(
      500,
      'KeepFlip could not read the stored eBay connection.',
    );
  }

  if (
    !tokenBundle ||
    typeof tokenBundle.accessToken !== 'string' ||
    typeof tokenBundle.refreshToken !== 'string' ||
    typeof tokenBundle.accessTokenExpiresAt !== 'string' ||
    typeof tokenBundle.refreshTokenExpiresAt !== 'string'
  ) {
    throw new HttpError(
      500,
      'KeepFlip could not read the stored eBay connection.',
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
  if (!Number.isFinite(refreshExpiry) || refreshExpiry <= clock.getTime()) {
    throw new HttpError(
      401,
      'Your eBay authorization has expired. Reconnect your eBay account.',
    );
  }

  const form = new URLSearchParams();
  form.set('grant_type', 'refresh_token');
  form.set('refresh_token', tokenBundle.refreshToken);
  form.set('scope', configuration.scopeText);

  let response;
  try {
    response = await fetchImpl(ebayTokenEndpoint(configuration.environment), {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        Authorization:
          'Basic ' +
          Buffer.from(
            configuration.clientId + ':' + configuration.clientSecret,
            'utf8',
          ).toString('base64'),
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: form.toString(),
    });
  } catch {
    throw new HttpError(502, 'KeepFlip could not refresh the eBay authorization.');
  }

  const payload = await parseResponseBody(response);
  if (
    !response.ok ||
    typeof payload?.access_token !== 'string' ||
    !payload.access_token
  ) {
    throw new HttpError(502, 'KeepFlip could not refresh the eBay authorization.');
  }

  const nextRefreshToken =
    typeof payload.refresh_token === 'string' && payload.refresh_token
      ? payload.refresh_token
      : tokenBundle.refreshToken;
  const nextRefreshExpiresAt =
    payload.refresh_token_expires_in
      ? addSeconds(clock, payload.refresh_token_expires_in)
      : tokenBundle.refreshTokenExpiresAt;

  return {
    ...tokenBundle,
    accessToken: payload.access_token,
    accessTokenExpiresAt: addSeconds(clock, payload.expires_in),
    refreshToken: nextRefreshToken,
    refreshTokenExpiresAt: nextRefreshExpiresAt,
    scopeText: configuration.scopeText,
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
    throw new HttpError(
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
    throw new HttpError(502, 'KeepFlip could not revoke eBay access.');
  }

  const payload = await parseResponseBody(response);
  if (
    response.ok ||
    (response.status === 400 && payload?.error === 'invalid_token')
  ) {
    return;
  }

  throw new HttpError(502, 'KeepFlip could not revoke eBay access.');
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
    throw new HttpError(500, 'KeepFlip could not remove the eBay connection.');
  }
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

async function handleStatus({ req, res, fetchImpl, runtime, now }) {
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

  return res.json(
    connectionStatus(
      connection,
      readTokenBundle(connection, configuration),
      configuration,
      now,
    ),
  );
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
    throw new HttpError(404, 'No connected eBay account was found.');
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

function safeError(error) {
  if (typeof error === 'function') {
    error('KeepFlip eBay OAuth backend request failed.');
  }
}

export function createHandler({
  fetchImpl = globalThis.fetch,
  now = () => new Date(),
  randomBytesImpl = randomBytes,
} = {}) {
  if (typeof fetchImpl !== 'function') {
    throw new Error('A fetch implementation is required.');
  }

  return async function main({ req, res, error } = {}) {
    try {
      const path = requestPath(req);
      const runtime = functionRuntime();

      if (req?.method === 'GET' && path === '/') {
        return res.json({
          ok: true,
          service: 'KeepFlip eBay OAuth backend',
          routes: ['/connect', '/status', '/refresh', '/revoke'],
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

      if (req?.method === 'POST' && path === '/status') {
        return await handleStatus({ req, res, fetchImpl, runtime, now });
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
      if (status >= 500) safeError(error);

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


