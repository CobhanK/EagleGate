// Talks to COSMOS for the rules editor: the firewall's interface details, the
// config bucket keys holding the rules, the RELOAD_RULES protocol command, and
// admin requests (RESTORE_TRUST and extension commands).
//
// Every interface whose config has the firewall protocol can be edited: the
// core plugin's EAGLEGATE_INT, and interfaces of extension plugins such as
// eaglegate-sdls. Each keeps its own rules, under its own target.
//
// Who may change the rules is enforced by the COSMOS server, not here: the
// pending key lives outside targets_modified, so the storage API only hands
// out an upload URL to admins (Enterprise) or logged in users (Core). See
// targets/EAGLEGATE/lib/eaglegate_rules_store.py.

import { Api, OpenC3Api } from '@openc3/js-common/services'
import { buildAdminRequest } from '../tools/eaglegate/adminRequest.js'

export const DEFAULT_INTERFACE = 'EAGLEGATE_INT'
const PROTOCOL_CLASS = 'EaglegateFirewallProtocol'
const PROTOCOL_FILE = 'eaglegate_firewall_protocol.py'
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

// Interfaces that run the firewall, from their saved COSMOS config (works while
// they are stopped): [{ name, target, protocols: [file names, in order] }]
export async function firewallInterfaces() {
  const names = await api.get_interface_names()
  const configs = await Promise.all(
    names.map((name) => api.exec('get_interface', [name]).catch(() => null)),
  )
  const result = []
  for (const config of configs) {
    const protocols = (config?.protocols || []).filter(
      (p) => String(p[0]).toUpperCase() !== 'WRITE',
    )
    const firewall = protocols.find((p) => String(p[1]).endsWith(PROTOCOL_FILE))
    if (!firewall) continue
    const rulesFile = firewall[3] || 'EAGLEGATE/rules/firewall_rules.json'
    result.push({
      name: config.name,
      target: rulesFile.split('/')[0],
      protocols: protocols.map((p) => String(p[1]).split('/').pop()),
    })
  }
  return result.sort((a, b) => a.name.localeCompare(b.name))
}

// The "firewall" section the protocol adds to interface_details()
export async function firewallState(iface) {
  const details = await api.interface_details(iface)
  const protocol = (details.read_protocols || []).find(
    (p) => p.name === PROTOCOL_CLASS,
  )
  if (!protocol) {
    throw new Error(`${iface} has no ${PROTOCOL_CLASS} read protocol`)
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
  // The presigned request (storage_controller.rb get_upload_presigned_request):
  // { url, headers, method }. Plain fetch: no HTTP client package needed
  const response = await fetch(presigned.url, {
    method: String(presigned.method || 'put').toUpperCase(),
    headers: presigned.headers || {},
    body: text,
  })
  if (!response.ok) {
    throw new Error(
      `Upload of ${key} failed: HTTP ${response.status} ${response.statusText}`,
    )
  }
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
export async function applyRules(iface, text, baseSha256) {
  const before = await firewallState(iface)
  const pendingSha256 = await sha256(text)
  await uploadKey(before.rules_keys.pending, text)
  await api.exec(
    'interface_protocol_cmd',
    [iface, 'RELOAD_RULES', baseSha256, pendingSha256],
    { read_write: 'READ' },
  )
  // interface_protocol_cmd is fire-and-forget, so poll for the result
  const deadline = Date.now() + APPLY_TIMEOUT_MS
  while (Date.now() < deadline) {
    const state = await firewallState(iface)
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
    `No answer from ${iface} after ${APPLY_TIMEOUT_MS / 1000}s; is the interface running? Check its log in Admin`,
  )
}

function userName() {
  try {
    const user = OpenC3Auth.user?.()
    return user?.preferred_username || user?.name || ''
  } catch {
    return ''
  }
}

// An admin-only action: upload requests/{kind}.json (only admins may), send
// the command with its sha256, and wait for the firewall's answer in
// interface_details. Resolves with { ok, detail, ... }; the firewall writes
// the same entry to its audit stream.
export async function adminAction(iface, kind, command, reason, params = {}) {
  const before = await firewallState(iface)
  const text = buildAdminRequest({
    kind,
    reason,
    params,
    requestedBy: userName(),
  })
  const requestSha256 = await sha256(text)
  await uploadKey(`${before.rules_keys.requests}${kind}.json`, text)
  await api.exec('interface_protocol_cmd', [iface, command, requestSha256], {
    read_write: 'READ',
  })
  const deadline = Date.now() + APPLY_TIMEOUT_MS
  while (Date.now() < deadline) {
    const state = await firewallState(iface)
    const answer = (state.admin_actions || []).find(
      (a) => a.request_sha256 === requestSha256,
    )
    if (answer) return { ...answer, state }
    await new Promise((resolve) => setTimeout(resolve, POLL_MS))
  }
  throw new Error(
    `No answer from ${iface} after ${APPLY_TIMEOUT_MS / 1000}s; is the interface running?`,
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
