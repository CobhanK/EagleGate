// Talks to COSMOS for the rules editor: the firewall's interface details, the
// config bucket keys holding the rules, and the RELOAD_RULES protocol command.
//
// Who may change the rules is enforced by the COSMOS server, not here: the
// pending key lives outside targets_modified, so the storage API only hands
// out an upload URL to admins (Enterprise) or logged in users (Core). See
// targets/EAGLEGATE/lib/eaglegate_rules_store.py.

import axios from 'axios'
import { Api, OpenC3Api } from '@openc3/js-common/services'

export const TARGET = 'EAGLEGATE' // change if the target was renamed at install time
export const INTERFACE = `${TARGET}_INT`
const PROTOCOL_CLASS = 'EaglegateFirewallProtocol'
const CONFIG_BUCKET = 'OPENC3_CONFIG_BUCKET'
const APPLY_TIMEOUT_MS = 10000
const POLL_MS = 500

const api = new OpenC3Api()

// Status codes we handle ourselves, so COSMOS does not show its error banner
function expecting(codes) {
  return { headers: { Accept: 'application/json', 'Ignore-Errors': codes } }
}

export function scope() {
  return window.openc3Scope
}

// { enterprise: bool, ... }
export async function cosmosInfo() {
  const { data } = await Api.get('/openc3-api/info')
  return data
}

// True when the page should allow editing. Only a convenience: the server
// refuses the upload anyway. Core reports every user as 'admin'.
export function userIsAdmin() {
  try {
    return (OpenC3Auth.userroles() || []).includes('admin')
  } catch {
    return false
  }
}

// The "firewall" section the protocol adds to interface_details()
export async function firewallState() {
  const details = await api.interface_details(INTERFACE)
  const protocol = (details.read_protocols || []).find(
    (p) => p.name === PROTOCOL_CLASS,
  )
  if (!protocol) {
    throw new Error(`${INTERFACE} has no ${PROTOCOL_CLASS} read protocol`)
  }
  return protocol.firewall
}

export async function sha256(text) {
  const bytes = new TextEncoder().encode(text)
  const digest = await crypto.subtle.digest('SHA-256', bytes)
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

// Text of a config bucket key, or null when it does not exist
export async function downloadKey(key) {
  try {
    const { data } = await Api.get(
      `/openc3-api/storage/download_file/${encodeURIComponent(key)}?bucket=${CONFIG_BUCKET}`,
      expecting('404'),
    )
    const binary = window.atob(data.contents)
    const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0))
    return new TextDecoder().decode(bytes)
  } catch (error) {
    if (error?.response?.status === 404) return null
    throw error
  }
}

// Write a config bucket key. Rejects with a readable message when COSMOS
// refuses (not an admin in Enterprise).
export async function uploadKey(key, text) {
  let presigned
  try {
    ;({ data: presigned } = await Api.get(
      `/openc3-api/storage/upload/${encodeURIComponent(key)}?bucket=${CONFIG_BUCKET}`,
      expecting('403'),
    ))
  } catch (error) {
    const status = error?.response?.status
    if (status === 403) {
      throw new Error(
        'COSMOS refused the upload: changing the firewall rules needs the admin role',
      )
    }
    throw error
  }
  await axios({ ...presigned, data: text })
}

// Names of the saved versions, newest first ("000003-abcdef123456.json")
export async function listHistory(prefix) {
  try {
    const { data } = await Api.get(
      `/openc3-api/storage/files/${CONFIG_BUCKET}/${prefix}`,
      expecting('404'),
    )
    return (data[1] || [])
      .map((file) => ({ name: file.name, modified: file.modified }))
      .sort((a, b) => b.name.localeCompare(a.name))
  } catch (error) {
    if (error?.response?.status === 404) return []
    throw error
  }
}

// Upload text as the pending rules, ask the firewall to apply them, and wait
// for the result. Resolves with the new firewall state; rejects with the
// firewall's reason when it refused (nothing changed then).
export async function applyRules(text, baseSha256) {
  const before = await firewallState()
  const pendingSha256 = await sha256(text)
  await uploadKey(before.rules_keys.pending, text)
  await api.exec(
    'interface_protocol_cmd',
    [INTERFACE, 'RELOAD_RULES', baseSha256, pendingSha256],
    { read_write: 'READ' },
  )
  // interface_protocol_cmd is fire-and-forget, so poll for the result
  const deadline = Date.now() + APPLY_TIMEOUT_MS
  while (Date.now() < deadline) {
    const state = await firewallState()
    if (state.rules.sha256 === pendingSha256) return state
    if (
      state.rules_error_at &&
      state.rules_error_at !== before.rules_error_at
    ) {
      throw new Error(
        `The firewall refused the rules, nothing was changed: ${state.rules_error}`,
      )
    }
    await new Promise((resolve) => setTimeout(resolve, POLL_MS))
  }
  throw new Error(
    `No answer from ${INTERFACE} after ${APPLY_TIMEOUT_MS / 1000}s; is the interface running? Check its log in Admin`,
  )
}

// Where the running rule set's text can be read from
export function runningKey(state) {
  if (state.rules_source === 'original' || !state.rules_source) {
    return `${scope()}/targets/${state.rules_file}`
  }
  return state.rules_keys.active
}

// The operator-writable draft of the old workflow (procedure), if any
export function draftKey(state) {
  return `${scope()}/targets_modified/${state.rules_file}`
}
