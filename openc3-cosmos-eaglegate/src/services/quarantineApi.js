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

// The file name COSMOS's answer names (Content-Disposition), or a default
function fileName(headers, fallback) {
  const found = /filename="([A-Za-z0-9_.-]+)"/.exec(
    headers?.['content-disposition'] || '',
  )
  return found ? found[1] : fallback
}

// An export (JSON or pcap) as a browser download; resolves with the file name.
// The review service records every export in the audit log (decision C14).
export function exportEntries(params) {
  return download(
    `${PREFIX}/export`,
    params,
    `eaglegate-export.${params.format === 'pcap' ? 'pcap' : 'json'}`,
  )
}

// The audit log, newest first: { entries, actions, scanned, stream_length,
// next_before } (decision C15)
export async function listAudit(params) {
  try {
    const { data } = await Api.get(`${PREFIX}/audit`, {
      params,
      headers: headers(),
    })
    return data
  } catch (error) {
    throw failure(error)
  }
}

// The matching audit entries as a JSON download (itself audited)
export function exportAudit(params) {
  return download(`${PREFIX}/audit/export`, params, 'eaglegate-audit.json')
}

async function download(path, params, fallbackName) {
  let response
  try {
    response = await Api.get(path, {
      params,
      headers: headers(),
      responseType: 'blob',
    })
  } catch (error) {
    // Error answers arrive as a Blob too: read the JSON message out of it
    const data = error?.response?.data
    if (data instanceof Blob) {
      try {
        error.response.data = JSON.parse(await data.text())
      } catch {
        // not JSON; failure() gives a generic message
      }
    }
    throw failure(error)
  }
  const name = fileName(response.headers, fallbackName)
  const url = URL.createObjectURL(response.data)
  try {
    const link = document.createElement('a')
    link.href = url
    link.download = name
    document.body.appendChild(link)
    link.click()
    link.remove()
  } finally {
    setTimeout(() => URL.revokeObjectURL(url), 10000)
  }
  return name
}

// RELEASE through the firewall: resolves with its answer { ok, detail, ... }
export function releaseEntry(iface, entry, reason) {
  return adminAction(iface, 'release', 'RELEASE', reason, {
    entry_id: entry.id,
    sha256: entry.sha256,
  })
}
