// Talks to the quarantine review microservice (microservices/EAGLEGATE_QUARANTINE)
// for the Quarantine tab, and releases entries through the firewall.
//
// Who may see the quarantine is decided by the COSMOS server, not here: the
// microservice forwards the user's token (Api adds it) to an admin-only COSMOS
// endpoint and answers 403 to anyone else. Releasing is an admin request
// (rulesStore.js adminAction): only admins can upload it.

import { Api } from '@openc3/js-common/services'
import { adminAction } from './rulesStore.js'

const PREFIX = '/eaglegate-quarantine'
// Answers the tab explains itself; 401 is left to COSMOS (log in again)
const HANDLED = '400, 403, 404, 405, 413, 415, 500, 502, 503, 504'

function headers(json = false) {
  return {
    Accept: 'application/json',
    ...(json ? { 'Content-Type': 'application/json' } : {}),
    'Ignore-Errors': HANDLED,
  }
}

// The microservice's own message, or a readable one when it is not running
function failure(error) {
  const status = error?.response?.status
  const message = error?.response?.data?.error
  if (message) return new Error(String(message))
  if (status === 404 || status === 502 || status === 503 || status === 504) {
    return new Error(
      'The quarantine review service is not reachable. Is the EAGLEGATE_QUARANTINE microservice running? (Admin > Microservices)',
    )
  }
  return new Error(error?.message || 'request failed')
}

// { interface, stream, entries: [...], scanned, stream_length, next_before }
export async function listEntries(params) {
  try {
    const { data } = await Api.get(`${PREFIX}/entries`, {
      params,
      headers: headers(),
    })
    return data
  } catch (error) {
    throw failure(error)
  }
}

// One entry with bytes_hex
export async function getEntry(iface, stream, id) {
  try {
    const { data } = await Api.get(`${PREFIX}/entry`, {
      params: { interface: iface, stream, id },
      headers: headers(),
    })
    return data.entry
  } catch (error) {
    throw failure(error)
  }
}

// { updated: [...], missing: [...], audit_id }
export async function setReview(iface, stream, ids, state, note, requestedBy) {
  try {
    const { data } = await Api.post(`${PREFIX}/review`, {
      data: {
        interface: iface,
        stream,
        ids,
        state,
        note,
        requested_by: requestedBy || '',
      },
      headers: headers(true),
    })
    return data
  } catch (error) {
    throw failure(error)
  }
}

// RELEASE through the firewall: resolves with its answer { ok, detail, ... }
export function releaseEntry(iface, entry, reason) {
  return adminAction(iface, 'release', 'RELEASE', reason, {
    entry_id: entry.id,
    sha256: entry.sha256,
  })
}
