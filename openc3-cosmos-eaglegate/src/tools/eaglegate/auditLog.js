// The Audit tab's data handling (decision C15). The review microservice sends
// cleaned text; it is treated as untrusted anyway and shown only with {{ }}.

import { clampLimit, safeText } from './quarantine.js'

const ACTION = /^[A-Z_]{1,32}$/

// Query parameters for GET /audit; empty filters are left out
export function auditParams(iface, filters, before = '') {
  const params = { interface: iface, limit: String(clampLimit(filters.limit)) }
  const action = String(filters.action || '')
    .trim()
    .toUpperCase()
  if (ACTION.test(action)) params.action = action
  if (filters.ok === 'true' || filters.ok === 'false') params.ok = filters.ok
  const search = String(filters.search || '').trim()
  if (search) params.search = search
  if (before) params.before = before
  return params
}

// Chip colours: what kind of change it was
export function actionColor(action) {
  if (/RULES$/.test(action)) return 'primary'
  if (action === 'RELEASE' || action === 'RESTORE_TRUST') return 'warning'
  if (action === 'SPIKE') return 'error'
  if (action === 'EXPORT') return 'purple'
  if (/KEYS$|REPLAY$/.test(action)) return 'teal'
  return undefined
}

// Who asked: the user COSMOS authenticated, else the name the page reported
export function whoText(entry) {
  if (entry.user) return safeText(entry.user, 64)
  if (entry.requested_by)
    return `${safeText(entry.requested_by, 64)} (as reported)`
  return '-'
}

// Every string inside a parsed JSON value, cleaned (depth-limited)
function cleanDeep(value, depth = 0) {
  if (depth > 5) return '…'
  if (Array.isArray(value))
    return value.slice(0, 50).map((v) => cleanDeep(v, depth + 1))
  if (value !== null && typeof value === 'object') {
    const out = {}
    for (const key of Object.keys(value).slice(0, 50))
      out[safeText(key, 64)] = cleanDeep(value[key], depth + 1)
    return out
  }
  return typeof value === 'string' ? safeText(value, 500) : value
}

// The action-specific fields as name/value rows. Objects become indented JSON
// built from cleaned strings, so its line breaks are only our own layout
// (shown in a <pre>, as text)
export function fieldRows(fields) {
  if (!fields || typeof fields !== 'object') return []
  return Object.keys(fields)
    .sort()
    .map((name) => {
      const value = fields[name]
      const structured = value !== null && typeof value === 'object'
      return {
        name: safeText(name, 64),
        value: structured
          ? JSON.stringify(cleanDeep(value), null, 1)
          : safeText(String(value ?? ''), 4000),
        structured,
      }
    })
}
