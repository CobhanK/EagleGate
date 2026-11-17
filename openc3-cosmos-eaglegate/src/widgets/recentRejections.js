// Data handling for the FIREWALLREJECTIONS Telemetry Viewer widget.
//
// The firewall publishes the last 10 rejections as JSON in FIREWALL_RECENT
// RECENT_JSON (decision C9): metadata and cleaned reasons, never bytes. The
// widget still treats it as untrusted: every field is checked and cleaned
// again here, and the widget renders text only with {{ }} (never v-html).

import { safeText } from '../tools/eaglegate/quarantine.js'

export const MAX_ROWS = 10
const FRAMED = new Set(['RULE', 'DEFAULT', 'ERROR'])
const ENTRY_ID = /^[0-9]{1,20}-[0-9]{1,20}$/
const NAME = /^[A-Za-z0-9_]{1,64}$/

export const SPIKE_STATES = {
  NORMAL: { label: 'Normal', color: 'success' },
  ELEVATED: { label: 'Elevated', color: 'warning' },
  SPIKE: { label: 'Spike', color: 'error' },
}

export const STAGE_COLORS = {
  RULE: 'error',
  DEFAULT: 'warning',
  ERROR: 'purple',
  STRUCTURAL: 'deep-orange',
  UNTRUSTED: 'grey',
  LINK: 'blue',
}

function text(value, limit) {
  return typeof value === 'string' || typeof value === 'number'
    ? safeText(value, limit)
    : ''
}

function int(value) {
  return Number.isInteger(value) ? value : null
}

// RECENT_JSON text -> up to MAX_ROWS clean rows; anything malformed gives []
export function parseRecent(json) {
  if (typeof json !== 'string' || !json) return []
  let data
  try {
    data = JSON.parse(json)
  } catch {
    return []
  }
  if (!Array.isArray(data)) return []
  return data
    .filter((r) => r && typeof r === 'object' && !Array.isArray(r))
    .slice(0, MAX_ROWS)
    .map((r) => ({
      time: text(r.time, 32),
      interface: text(r.interface, 64),
      stage: text(r.stage, 12),
      rule_id: text(r.rule_id, 64),
      rule_type: text(r.rule_type, 32),
      monitor: r.monitor === true,
      layer: text(r.layer, 32),
      apid: text(r.apid, 8),
      packet_type: text(r.packet_type, 3),
      packet: text(r.packet, 80),
      seq_count: int(r.seq_count),
      length: int(r.length),
      link: linkText(r.link),
      reason: text(r.reason, 400),
      entry_id: text(r.entry_id, 32),
    }))
}

function linkText(link) {
  if (!link || typeof link !== 'object' || Array.isArray(link)) return ''
  return Object.entries(link)
    .slice(0, 8)
    .map(([k, v]) => `${safeText(k, 32)}=${text(v, 64)}`)
    .join(' ')
}

// What kind of packet it was: the COSMOS packet name when the firewall knew
// it, else TLM/CMD and APID, else the link layer that refused it
export function packetLabel(row) {
  if (row.packet && row.packet !== 'unknown') return row.packet
  const parts = [row.packet_type, row.apid && `APID ${row.apid}`].filter(
    Boolean,
  )
  if (parts.length) return parts.join(' ')
  if (row.layer) return `${row.layer} frame`
  return row.stage === 'STRUCTURAL' ? 'malformed bytes' : '-'
}

export function ruleLabel(row) {
  return row.rule_id || (row.layer && `link:${row.layer}`) || row.stage || '-'
}

// "2026-11-16T12:34:56.123456Z" -> "12:34:56Z"
export function shortTime(time) {
  const found = /T(\d{2}:\d{2}:\d{2})/.exec(time || '')
  return found ? `${found[1]}Z` : time || ''
}

export function spikeInfo(state) {
  return (
    SPIKE_STATES[state] || { label: safeText(state || '-'), color: undefined }
  )
}

// Link to the entry on the EagleGate page's Quarantine tab (admins only; the
// page asks COSMOS), or null when the row has nothing to link to
export function quarantineHref(row, base = '/tools/eaglegate') {
  if (!ENTRY_ID.test(row.entry_id) || !NAME.test(row.interface)) return null
  const params = new URLSearchParams({
    tab: 'quarantine',
    interface: row.interface,
    stream: FRAMED.has(row.stage) ? 'quarantine' : 'raw',
    entry: row.entry_id,
  })
  return `${base}?${params}`
}

// The page side: { tab, interface, stream, entry } from the location's query,
// each checked, or {} when there is nothing usable
export function quarantineFocus(search) {
  const params = new URLSearchParams(search || '')
  if (params.get('tab') !== 'quarantine') return {}
  const focus = { tab: 'quarantine' }
  const iface = params.get('interface')
  if (iface && NAME.test(iface)) focus.interface = iface
  const stream = params.get('stream')
  if (stream === 'quarantine' || stream === 'raw') focus.stream = stream
  const entry = params.get('entry')
  if (entry && ENTRY_ID.test(entry)) focus.entry = entry
  return focus
}
