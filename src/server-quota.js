import { createHash } from 'node:crypto';

// Deployment-local HTTP bridge to the authoritative quota function. No sibling
// source import: Appwrite deploys this function folder as an isolated package.
export async function reserveListingQuota({ req, runtime, fetchImpl, userId, environment, marketplaceId, sku, fail }) {
  const functionId = process.env.APPWRITE_SUBSCRIPTION_POLICE_FUNCTION_ID?.trim();
  const secret = process.env.SELLER_QUOTA_INTERNAL_SECRET?.trim();
  const headers = req?.headers || {};
  const jwt = Object.entries(headers).find(([key]) => key.toLowerCase() === 'x-appwrite-user-jwt')?.[1];
  if (!functionId || !secret || typeof jwt !== 'string' || !jwt) fail(503, 'Server listing quotas must be configured before publishing.', 'LISTING_QUOTA_UNAVAILABLE');
  const key = 'ebay:' + createHash('sha256').update(JSON.stringify([userId, environment, marketplaceId, sku])).digest('hex');
  let execution;
  try {
    const response = await fetchImpl(runtime.endpoint + '/functions/' + encodeURIComponent(functionId) + '/executions', {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Appwrite-Project': runtime.projectId, 'X-Appwrite-JWT': jwt },
      body: JSON.stringify({ async: false, path: '/internal/quotas', method: 'POST', headers: { 'content-type': 'application/json', 'x-keepflip-quota-secret': secret }, body: JSON.stringify({ action: 'listing.reserve', operationId: key, resourceId: key }) }),
    });
    if (!response.ok) fail(503, 'The listing reservation could not be verified.', 'LISTING_QUOTA_UNAVAILABLE');
    execution = JSON.parse(await response.text());
  } catch { fail(503, 'The listing reservation could not be verified. Retry the same item.', 'LISTING_QUOTA_UNAVAILABLE'); }
  let result;
  try { result = JSON.parse(execution.responseBody); } catch { fail(503, 'The listing reservation could not be verified.', 'LISTING_QUOTA_UNAVAILABLE'); }
  if (execution.status !== 'completed' || execution.responseStatusCode !== 200 || result?.ok !== true || result.allowed !== true) {
    const status = [403, 409].includes(execution.responseStatusCode) ? execution.responseStatusCode : 503;
    fail(status, 'Publishing is blocked by the server subscription or listing quota.', 'LISTING_QUOTA_DENIED');
  }
  if (result.dispatch !== true) fail(409, 'This listing has a previous reservation. Reconcile its eBay result before retrying.', 'LISTING_RECONCILIATION_REQUIRED');
  return { operationId: key, resourceId: key };
}
