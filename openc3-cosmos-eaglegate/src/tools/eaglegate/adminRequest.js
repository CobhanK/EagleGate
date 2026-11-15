// The admin request file the page uploads before an admin-only protocol command
// (RESTORE_TRUST, or an extension's command such as RESET_REPLAY). The firewall
// checks it in targets/EAGLEGATE/lib/eaglegate_admin_requests.py; the shared
// example in tests/fixtures/admin_request_example.json keeps the two in step.

export const REASON_CHARS = 256
// Same characters the firewall refuses: control, format and invisible ones
const UNPRINTABLE = new RegExp(
  '[\\u0000-\\u001f\\u007f-\\u009f\\u2028\\u2029\\u200b-\\u200f\\u202a-\\u202e\\u2066-\\u2069]',
)

// 32 hex characters; crypto.getRandomValues also works outside secure contexts
export function randomNonce(cryptoObj = globalThis.crypto) {
  const bytes = new Uint8Array(16)
  cryptoObj.getRandomValues(bytes)
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

// Why the firewall would refuse this reason, or null
export function reasonProblem(reason) {
  if (typeof reason !== 'string' || !reason.trim())
    return 'A reason is required'
  if (reason.length > REASON_CHARS) return `At most ${REASON_CHARS} characters`
  if (UNPRINTABLE.test(reason))
    return 'Use plain text: no line breaks or invisible characters'
  return null
}

// The request file text
export function buildAdminRequest({
  kind,
  reason,
  params = {},
  requestedBy = '',
  now = new Date(),
  nonce = randomNonce(),
}) {
  const doc = {
    kind,
    reason: reason.trim(),
    nonce,
    requested_at: now.toISOString(),
    requested_by: String(requestedBy || '').slice(0, 64),
    params,
  }
  return JSON.stringify(doc, null, 2) + '\n'
}
