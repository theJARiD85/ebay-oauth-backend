import { createHash } from 'node:crypto';
const text = (v, max = 180) => typeof v === 'string' && v.trim().length <= max ? v.trim() || null : null;
const date = v => typeof v === 'string' && Number.isFinite(Date.parse(v)) ? new Date(v).toISOString() : null;
const integer = v => Number.isSafeInteger(v) && v >= 0 ? v : null;
const hash = v => createHash('sha256').update(v).digest('hex');
const money = v => {
  if (!v || !/^\d+(?:\.\d{1,2})?$/.test(String(v.value)) || !/^[A-Z]{3}$/.test(v.currency)) return null;
  const amountCents = Math.round(Number(v.value) * 100);
  return Number.isSafeInteger(amountCents) ? { amountCents, currency: v.currency } : null;
};

// Construct every field; never expose provider payloads containing buyer PII.
export function normalizeSellerOrder(order, { userId, environment, connectionId }) {
  const orderId = text(order.orderId);
  if (!orderId) return null;
  const externalOrderKey = 'ebay:' + hash(JSON.stringify([userId, environment, connectionId, orderId]));
  const lineItems = (Array.isArray(order.lineItems) ? order.lineItems : []).map(line => ({
    externalLineKey: externalOrderKey + ':' + hash(String(line.lineItemId)),
    lineItemId: text(line.lineItemId), listingId: text(line.legacyItemId), sku: text(line.sku),
    itemId: null, matchStatus: 'unmatched', title: text(line.title, 512), quantity: integer(line.quantity),
    fulfillmentStatus: text(line.lineItemFulfillmentStatus, 64), sale: money(line.lineItemCost), total: money(line.total),
    shipBy: date(line.lineItemFulfillmentInstructions?.shipByDate),
  })).filter(line => line.lineItemId);
  const shipDates = lineItems.map(line => line.shipBy).filter(Boolean).sort();
  return {
    channel: 'ebay', environment, externalOrderKey, externalRevision: date(order.lastModifiedDate), orderId,
    soldAt: date(order.creationDate), shipBy: shipDates[0] || null,
    paymentStatus: text(order.orderPaymentStatus, 64), fulfillmentStatus: text(order.orderFulfillmentStatus, 64),
    cancelStatus: text(order.cancelStatus?.cancelState, 64), currency: money(order.pricingSummary?.total)?.currency || null,
    sale: money(order.pricingSummary?.priceSubtotal), shippingCharged: money(order.pricingSummary?.deliveryCost),
    total: money(order.pricingSummary?.total), feesCents: null, refundsCents: null, payoutCents: null,
    reconciliationStatus: 'unreconciled', lineItems,
  };
}

export function seriousSubscriptionAllows(row, userId, now) {
  if (row?.ownerId !== userId || !['serious', 'power'].includes(row.plan)) return false;
  if (!['active', 'trialing', 'cancelled', 'billing_issue', 'grace_period'].includes(row.status)) return false;
  const end = Date.parse(row.currentPeriodEndsAt || '');
  if (!Number.isFinite(end) || end <= now.getTime()) return false;
  if (row.status === 'trialing' && row.trialEndsAt && !(Date.parse(row.trialEndsAt) > now.getTime())) return false;
  return true;
}

export async function fulfillmentRequest({ fetchImpl, configuration, accessToken, path, method = 'GET', body, fail }) {
  const base = configuration.environment === 'production' ? 'https://api.ebay.com' : 'https://api.sandbox.ebay.com';
  let response;
  try {
    response = await fetchImpl(base + '/sell/fulfillment/v1' + path, { method,
      headers: { Authorization: 'Bearer ' + accessToken, Accept: 'application/json', ...(body ? { 'Content-Type': 'application/json' } : {}) },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
  } catch { fail(502, 'eBay fulfillment response is unknown. Refresh before retrying.', 'FULFILLMENT_OUTCOME_UNKNOWN'); }
  if ([401, 403].includes(response.status)) fail(403, 'Reconnect eBay to grant sell.fulfillment permission.', 'EBAY_FULFILLMENT_RECONNECT_REQUIRED');
  if (!response.ok) fail(502, 'eBay could not complete fulfillment. Refresh before retrying.', 'EBAY_FULFILLMENT_FAILED');
  let payload;
  try { const raw = await response.text(); payload = raw ? JSON.parse(raw) : {}; }
  catch { fail(502, 'eBay returned an unreadable fulfillment response.', 'FULFILLMENT_OUTCOME_UNKNOWN'); }
  return { payload, location: response.headers?.get?.('location') || null };
}

export async function fetchSellerOrders({ body, request, userId, environment, connectionId, fail }) {
  const limit = body.limit === undefined ? 50 : body.limit;
  const offset = body.offset === undefined ? 0 : body.offset;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100 || !Number.isSafeInteger(offset) || offset < 0 || offset > 10000) fail(400, 'Use limit 1–100 and offset 0–10000.', 'INVALID_ORDER_PAGE');
  const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  if (body.modifiedSince || body.modifiedUntil) {
    const from = date(body.modifiedSince), until = date(body.modifiedUntil);
    if (!from || !until || from > until) fail(400, 'Provide a valid modifiedSince and modifiedUntil window.', 'INVALID_ORDER_WINDOW');
    params.set('filter', 'lastmodifieddate:[' + from + '..' + until + ']');
  }
  const { payload } = await request('/order?' + params.toString());
  if (!Array.isArray(payload.orders)) fail(502, 'eBay order response could not be verified.', 'INVALID_ORDER_RESPONSE');
  const orders = payload.orders.map(order => normalizeSellerOrder(order, { userId, environment, connectionId })).filter(Boolean);
  const nextCursor = payload.next && payload.orders.length ? { offset: offset + limit, limit, ...(body.modifiedSince ? { modifiedSince: body.modifiedSince, modifiedUntil: body.modifiedUntil } : {}) } : null;
  return { ok: true, schemaVersion: 1, environment, orders, page: { limit, offset, total: integer(payload.total), nextOffset: nextCursor?.offset ?? null }, nextCursor };
}

export async function shipSellerOrder({ body, request, claim, fail, now, userId, environment, connectionId }) {
  const orderId = text(body.orderId), trackingNumber = text(body.trackingNumber, 100), shippingCarrierCode = text(body.shippingCarrierCode, 100);
  if (!orderId || !trackingNumber || !/^[A-Za-z0-9]+$/.test(trackingNumber) || !shippingCarrierCode || !/^[A-Za-z0-9_ -]+$/.test(shippingCarrierCode)) fail(400, 'Provide orderId, shippingCarrierCode and an alphanumeric trackingNumber.', 'INVALID_SHIPMENT');
  const shippedDate = body.shippedDate === undefined ? now().toISOString() : date(body.shippedDate);
  if (!shippedDate || Date.parse(shippedDate) > now().getTime()) fail(400, 'shippedDate must be valid and at or before now.', 'INVALID_SHIPPED_DATE');
  const lines = body.lineItems;
  if (!Array.isArray(lines) || !lines.length || lines.length > 100 || lines.some(line => !text(line?.lineItemId) || !Number.isSafeInteger(line.quantity) || line.quantity < 1) || new Set(lines.map(line => line.lineItemId.trim())).size !== lines.length) fail(400, 'Provide unique lineItems with positive whole quantities.', 'INVALID_SHIPMENT_LINES');
  const lineItems = lines.map(line => ({ lineItemId: line.lineItemId.trim(), quantity: line.quantity })).sort((a, b) => a.lineItemId.localeCompare(b.lineItemId));
  const path = '/order/' + encodeURIComponent(orderId);
  // Serialize all packages for the order before reading remaining quantities.
  const operationId = 's' + hash(JSON.stringify([userId, environment, connectionId, orderId])).slice(0, 35);
  const requestHash = hash(JSON.stringify({ trackingNumber, shippingCarrierCode, lineItems }));
  const reservation = await claim(operationId, { requestHash });
  const { payload: order } = await request(path);
  if (order.orderId !== orderId || !Array.isArray(order.lineItems)) { await reservation.complete(); fail(404, 'This order could not be verified for the connected seller.', 'ORDER_NOT_FOUND'); }
  const { payload: shipments } = await request(path + '/shipping_fulfillment');
  if (!Array.isArray(shipments.fulfillments)) fail(502, 'Existing shipments could not be verified.', 'SHIPMENT_RECONCILIATION_REQUIRED');
  const matched = shipments.fulfillments.find(entry => entry.trackingNumber === trackingNumber && entry.shippingCarrierCode === shippingCarrierCode && JSON.stringify((entry.lineItems || []).map(line => ({ lineItemId: line.lineItemId, quantity: line.quantity })).sort((a, b) => a.lineItemId.localeCompare(b.lineItemId))) === JSON.stringify(lineItems));
  if (matched) { await reservation.complete(); return { ok: true, status: 'already_shipped', orderId, fulfillmentId: text(matched.fulfillmentId), trackingNumber, shippingCarrierCode }; }
  if (reservation.reconcileOnly) fail(409, 'A shipment is pending or its result is unknown. Reconcile before retrying.', 'SHIPMENT_RECONCILIATION_REQUIRED');
  if (order.orderPaymentStatus !== 'PAID' || !['NONE_REQUESTED', 'CANCEL_REJECTED', ''].includes(order.cancelStatus?.cancelState || '')) { await reservation.complete(); fail(409, 'Only paid orders without an active cancellation can be shipped.', 'ORDER_NOT_SHIPPABLE'); }
  for (const line of lineItems) {
    const source = order.lineItems.find(entry => entry.lineItemId === line.lineItemId);
    const shipped = shipments.fulfillments.reduce((sum, entry) => sum + (entry.lineItems || []).filter(entry => entry.lineItemId === line.lineItemId).reduce((n, entry) => n + (integer(entry.quantity) ?? Infinity), 0), 0);
    if (!source || integer(source.quantity) === null || source.lineItemFulfillmentStatus === 'FULFILLED' || line.quantity > source.quantity - shipped) { await reservation.complete(); fail(409, 'Shipment exceeds unfulfilled quantity for ' + line.lineItemId + '.', 'SHIPMENT_QUANTITY_CONFLICT'); }
  }
  const result = await request(path + '/shipping_fulfillment', 'POST', { lineItems, shippedDate, shippingCarrierCode, trackingNumber });
  let fulfillmentId = null;
  if (result.location) { try { fulfillmentId = text(decodeURIComponent(new URL(result.location).pathname.split('/').pop())); } catch { /* never expose raw URL */ } }
  await reservation.complete();
  return { ok: true, status: 'shipped', orderId, fulfillmentId, trackingNumber, shippingCarrierCode, shippedDate };
}
