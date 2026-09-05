const object = value => value && typeof value === 'object' && !Array.isArray(value) ? value : {};
const text = value => typeof value === 'string' ? value.trim() : '';
const parsed = value => { try { return object(typeof value === 'string' ? JSON.parse(value) : value); } catch { return {}; } };

export function normalizeAspects(value) {
  return Object.fromEntries(Object.entries(parsed(value)).filter(([name]) => name.trim() && !['__proto__', 'constructor', 'prototype'].includes(name)).map(([name, values]) => [name.trim(), [...new Set((Array.isArray(values) ? values : [values]).map(v => typeof v === 'number' ? String(v) : text(v)).filter(Boolean))]]));
}

export function resolveListingDraft({ body, item, defaults, normalizeCondition }) {
  const policies = object(body.listingPolicies);
  const resolved = {
    title: text(body.title) || text(item.title) || [item.brand, item.model, item.category].map(text).filter(Boolean).join(' '),
    description: text(body.description) || text(item.description),
    marketplaceId: (text(body.marketplaceId) || 'EBAY_US').toUpperCase(),
    categoryId: text(body.categoryId) || text(defaults?.defaultCategoryId),
    price: Number(body.price ?? (body.priceCents === undefined ? undefined : Number(body.priceCents) / 100)),
    quantity: Number(body.quantity ?? defaults?.defaultQuantity ?? 1),
    currency: (text(body.currency) || text(defaults?.defaultCurrency) || 'USD').toUpperCase(),
    sku: text(body.sku) || text(item.ebaySku) || text(item.sku) || ('KF-' + (item.$id || item.id)).slice(0, 50),
    condition: '',
    conditionDescription: text(body.conditionDescription) || text(item.conditionNotes) || text(item.description),
    aspects: { ...normalizeAspects(item.itemSpecificsJson), ...normalizeAspects(body.aspects), ...normalizeAspects(body.itemSpecifics) },
    measurements: normalizeAspects(body.measurements),
    listingDuration: text(body.listingDuration) || text(defaults?.defaultListingDuration) || 'GTC',
  };
  for (const field of ['merchantLocationKey', 'paymentPolicyId', 'fulfillmentPolicyId', 'returnPolicyId']) {
    resolved[field] = text(body[field]) || text(policies[field]) || text(defaults?.['default' + field[0].toUpperCase() + field.slice(1)]);
  }
  try { resolved.condition = normalizeCondition(body.condition || item.condition); } catch { /* checklist reports it */ }
  return resolved;
}

// A fresh application token keeps readiness read-only, including the connection row.
export async function readCategoryAspects({ fetchImpl, configuration, marketplaceId, categoryId }) {
  const base = configuration.environment === 'production' ? 'https://api.ebay.com' : 'https://api.sandbox.ebay.com';
  const tokenResponse = await fetchImpl(base + '/identity/v1/oauth2/token', {
    method: 'POST', headers: { Authorization: 'Basic ' + Buffer.from(configuration.clientId + ':' + configuration.clientSecret).toString('base64'), 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'client_credentials', scope: 'https://api.ebay.com/oauth/api_scope' }).toString(),
  });
  const token = JSON.parse(await tokenResponse.text());
  if (!tokenResponse.ok || !text(token.access_token)) throw new Error('Category authentication unavailable');
  const get = async path => {
    const response = await fetchImpl(base + '/commerce/taxonomy/v1' + path, { method: 'GET', headers: { Authorization: 'Bearer ' + token.access_token, Accept: 'application/json', 'Accept-Language': 'en-US' } });
    const payload = JSON.parse(await response.text());
    if (!response.ok) throw new Error('Category requirements unavailable');
    return payload;
  };
  const tree = await get('/get_default_category_tree_id?marketplace_id=' + encodeURIComponent(marketplaceId));
  if (!text(tree.categoryTreeId)) throw new Error('Missing category tree');
  const result = await get('/category_tree/' + encodeURIComponent(tree.categoryTreeId) + '/get_item_aspects_for_category?category_id=' + encodeURIComponent(categoryId));
  if (!Array.isArray(result.aspects)) throw new Error('Invalid category requirements');
  return result.aspects;
}

export async function evaluateListingReadiness({ body, item, resolved, connected, defaultsUnavailable = false, readPhotos, verifyPhoto, readAspects, now }) {
  const checklist = [];
  const check = (field, valid, message, unknown = false) => checklist.push({ field, status: valid ? 'complete' : unknown ? 'unavailable' : 'missing', message: valid ? 'Complete.' : message });
  check('connection', connected, 'Connect an eBay account.');
  check('sellerSetup', !defaultsUnavailable, 'Saved seller defaults could not be read. Retry before publishing.', defaultsUnavailable);
  check('title', resolved.title.length > 0 && resolved.title.length <= 80, 'Provide a title of 1–80 characters.');
  check('description', resolved.description.length > 0 && resolved.description.length <= 500000, 'Provide a listing description.');
  check('price', Number.isFinite(resolved.price) && resolved.price >= 0.01, 'Provide a positive listing price.');
  check('quantity', Number.isSafeInteger(resolved.quantity) && resolved.quantity > 0 && Number.isSafeInteger(item.quantityOnHand) && item.quantityOnHand > 0 && resolved.quantity <= item.quantityOnHand, 'Provide a whole quantity within saved stock.');
  check('categoryId', /^\d{1,20}$/.test(resolved.categoryId), 'Choose an eBay leaf category.');
  check('currency', /^[A-Z]{3}$/.test(resolved.currency), 'Provide a three-letter currency.');
  check('sku', /^[A-Za-z0-9._-]{1,50}$/.test(resolved.sku), 'Use a SKU of 1–50 letters, numbers, periods, underscores or hyphens.');
  for (const field of ['merchantLocationKey', 'paymentPolicyId', 'fulfillmentPolicyId', 'returnPolicyId']) check(field, resolved[field].length > 0 && resolved[field].length <= 100, 'Complete saved seller setup or provide ' + field + '.');
  check('condition', !!resolved.condition, 'Choose a supported condition.');
  for (const field of ['identityConfirmed', 'photosReviewed', 'conditionConfirmed', 'measurementsConfirmed', 'shippingConfirmed', 'returnsConfirmed']) {
    check('review.' + field, body.review?.[field] === true, 'Confirm ' + field.replace(/Confirmed|Reviewed/g, '') + ' review.');
  }
  const used = resolved.condition && !['NEW', 'LIKE_NEW', 'NEW_OTHER', 'NEW_WITH_DEFECTS'].includes(resolved.condition);
  if (used) check('conditionDescription', resolved.conditionDescription.length > 0 && resolved.conditionDescription.length <= 1000, 'Describe the item condition and defects.');
  check('review.measurements', ['provided', 'not_applicable'].includes(body.review?.measurements), 'Review measurements or explicitly mark them not applicable.');
  if (body.review?.measurements === 'provided') check('measurements', Object.values(resolved.measurements).some(values => values.length), 'Provide the reviewed measurements.');
  let photoFileIds = [];
  let photosValid = false;
  try {
    photoFileIds = await readPhotos();
    for (const fileId of photoFileIds) await verifyPhoto(fileId);
    photosValid = photoFileIds.length > 0;
  } catch { /* One hard photo gate avoids diluting the score with photo count. */ }
  check('photos', photosValid, 'Save at least one inventory photo and reattach any inaccessible or invalid images.');
  let metadata = [];
  if (/^\d{1,20}$/.test(resolved.categoryId)) {
    try { metadata = await readAspects(); check('categoryRequirements', true); }
    catch { check('categoryRequirements', false, 'eBay category requirements could not be verified. Retry before publishing.', true); }
  } else check('categoryRequirements', false, 'Select a category to check required specifics.');
  const requiredAspects = [];
  for (const aspect of metadata) {
    const name = text(aspect.localizedAspectName);
    if (!name) continue;
    const constraint = object(aspect.aspectConstraint);
    const suppliedName = Object.keys(resolved.aspects).find(key => key.toLowerCase() === name.toLowerCase());
    const values = suppliedName ? resolved.aspects[suppliedName] : [];
    if (suppliedName && suppliedName !== name) { delete resolved.aspects[suppliedName]; resolved.aspects[name] = values; }
    const choices = Array.isArray(aspect.aspectValues) ? aspect.aspectValues : [];
    const allowedValues = choices.map(v => text(v.localizedValue)).filter(Boolean);
    if (constraint.aspectRequired === true) requiredAspects.push({ name, field: 'itemSpecifics.' + name, values, allowedValues, mode: constraint.aspectMode || 'FREE_TEXT', cardinality: constraint.itemToAspectCardinality || 'SINGLE' });
    if (constraint.aspectRequired !== true && !values.length) continue;
    const valid = values.length > 0 && values.length <= (constraint.itemToAspectCardinality === 'MULTI' ? 30 : 1) && values.every(value => {
      if (value.length > (constraint.aspectMaxLength || 50)) return false;
      if (constraint.aspectMode === 'SELECTION_ONLY' && !allowedValues.includes(value)) return false;
      const choice = choices.find(candidate => candidate.localizedValue === value);
      return !choice?.valueConstraints?.length || choice.valueConstraints.every(dependency => (resolved.aspects[dependency.applicableForLocalizedAspectName] || []).some(v => dependency.applicableForLocalizedAspectValues?.includes(v)));
    });
    check('itemSpecifics.' + name, valid, 'Provide valid ' + name + ' values for this category.');
  }
  for (const [name, values] of Object.entries(resolved.aspects)) {
    if (!metadata.some(a => a.localizedAspectName === name)) check('itemSpecifics.' + name, name.length <= 40 && values.length > 0 && values.length <= 30 && values.every(v => v.length <= 50), 'Provide bounded non-empty item specifics.');
  }
  const missingFields = checklist.filter(entry => entry.status !== 'complete').map(entry => entry.field);
  return { photoFileIds, response: { ok: true, schemaVersion: 1, environment: body.environment, itemId: item.$id || item.id, ready: missingFields.length === 0, score: Math.round(100 * (checklist.length - missingFields.length) / checklist.length), missing: missingFields, checks: checklist.map(entry => ({ id: entry.field, label: ({ sellerSetup: 'Saved seller setup', photos: 'Inventory photos', categoryRequirements: 'Category requirements', merchantLocationKey: 'Inventory location', paymentPolicyId: 'Payment policy', fulfillmentPolicyId: 'Shipping policy', returnPolicyId: 'Return policy' })[entry.field] || entry.field.replace(/^review\./, '').replace(/^itemSpecifics\./, '').replace(/([A-Z])/g, ' $1').replace(/^./, c => c.toUpperCase()), complete: entry.status === 'complete', detail: entry.message })), missingFields, checklist, requiredAspects, resolved: { ...resolved, price: Number.isFinite(resolved.price) ? resolved.price : null, quantity: Number.isFinite(resolved.quantity) ? resolved.quantity : null, photoCount: photoFileIds.length }, checkedAt: now().toISOString() } };
}
