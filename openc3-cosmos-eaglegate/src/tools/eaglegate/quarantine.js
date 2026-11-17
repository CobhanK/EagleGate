// The Quarantine tab's data handling: filters, the hex dump, the CCSDS header
// and making text safe to show. The review microservice already sends only
// printable text and hex (microservices/EAGLEGATE_QUARANTINE); everything here
// treats its answers as untrusted anyway, and the tab renders text only with
// Vue's {{ }} (escaped), never v-html.

export const DEFAULT_LIMIT = 50
export const MAX_LIMIT = 1000
export const STAGES = [
  'RULE',
  'DEFAULT',
  'ERROR',
  'STRUCTURAL',
  'UNTRUSTED',
  'LINK',
]
// Review states an admin can set; "released" only comes from RELEASE
export const REVIEW_STATES = [
  { value: 'new', title: 'New', color: undefined },
  { value: 'reviewed', title: 'Reviewed', color: 'info' },
  { value: 'false_positive', title: 'False positive', color: 'warning' },
  { value: 'threat', title: 'Threat', color: 'error' },
  { value: 'dismissed', title: 'Dismissed', color: 'grey' },
]
export const RELEASED_STATE = {
  value: 'released',
  title: 'Released',
  color: 'success',
}
export const NOTE_CHARS = 256

// Same characters the microservice escapes (eaglegate_quarantine_review.UNSAFE)
const UNSAFE = new RegExp(
  '[\\u0000-\\u001f\\u007f-\\u009f\\u00ad\\u061c\\u180e\\u2028\\u2029\\u200b-\\u200f' +
    '\\u202a-\\u202e\\u2060-\\u2064\\u2066-\\u2069\\ufeff\\ufff9-\\ufffb]',
  'g',
)
const ENTRY_ID = /^[0-9]{1,20}-[0-9]{1,20}$/

export function reviewState(value) {
  if (value === RELEASED_STATE.value) return RELEASED_STATE
  return (
    REVIEW_STATES.find((s) => s.value === value) || {
      value,
      title: safeText(value),
      color: undefined,
    }
  )
}

// Printable text: invisible and control characters as visible escapes
export function safeText(value, limit = 1024) {
  if (value === null || value === undefined) return ''
  const text = String(value).replace(UNSAFE, (c) => {
    const code = c.charCodeAt(0)
    return code < 0x100
      ? `\\x${code.toString(16).padStart(2, '0')}`
      : `\\u${code.toString(16).padStart(4, '0')}`
  })
  return text.length > limit ? text.slice(0, limit) + '…' : text
}

// "Show the most recent N": a whole number within 1..MAX_LIMIT
export function clampLimit(value) {
  const n = Number.parseInt(String(value), 10)
  if (!Number.isFinite(n)) return DEFAULT_LIMIT
  return Math.min(MAX_LIMIT, Math.max(1, n))
}

// Query parameters for GET /entries; empty filters are left out
export function listParams(iface, filters, before = '') {
  const params = {
    interface: iface,
    stream: filters.stream || 'quarantine',
    limit: String(clampLimit(filters.limit)),
  }
  for (const name of ['stage', 'rule_id', 'apid', 'review', 'search']) {
    const value = String(filters[name] ?? '').trim()
    if (value) params[name] = value
  }
  if (before) params.before = before
  return params
}

// Why the note would be refused, or null
export function noteProblem(note) {
  if (typeof note !== 'string') return 'Use text'
  if (note.length > NOTE_CHARS) return `At most ${NOTE_CHARS} characters`
  UNSAFE.lastIndex = 0
  if (UNSAFE.test(note))
    return 'Use plain text: no line breaks or invisible characters'
  return null
}

export function isEntryId(value) {
  return typeof value === 'string' && ENTRY_ID.test(value)
}

// Hex text -> bytes; anything that is not an even run of hex digits gives []
export function hexBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 || /[^0-9a-f]/i.test(hex))
    return []
  const bytes = new Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i += 1)
    bytes[i] = Number.parseInt(hex.slice(2 * i, 2 * i + 2), 16)
  return bytes
}

// Only printable ASCII is shown as a character; everything else is "."
export function asciiChar(byte) {
  return byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : '.'
}

// Classic hex dump rows: { offset: "0000", hex: "00 03 c0 ...", ascii: "..A." }
export function hexDump(hex, width = 16) {
  const bytes = hexBytes(hex)
  const rows = []
  for (let start = 0; start < bytes.length; start += width) {
    const chunk = bytes.slice(start, start + width)
    rows.push({
      offset: start.toString(16).padStart(4, '0'),
      hex: chunk
        .map((b) => b.toString(16).padStart(2, '0'))
        .join(' ')
        .padEnd(width * 3 - 1, ' '),
      ascii: chunk.map(asciiChar).join(''),
    })
  }
  return rows
}

// The 6-byte CCSDS primary header, or null when there are fewer bytes
// (raw entries of an untrusted connection may not start at a packet)
export function ccsdsHeader(hex) {
  const b = hexBytes(hex)
  if (b.length < 6) return null
  const word1 = (b[0] << 8) | b[1]
  const word2 = (b[2] << 8) | b[3]
  const lengthField = (b[4] << 8) | b[5]
  const flags = word2 >> 14
  return {
    version: word1 >> 13,
    type: (word1 >> 12) & 1 ? 'CMD' : 'TLM',
    secondary_header: (word1 >> 11) & 1 ? 'yes' : 'no',
    apid: `0x${(word1 & 0x7ff).toString(16).toUpperCase().padStart(3, '0')}`,
    sequence_flags: ['continuation', 'first', 'last', 'unsegmented'][flags],
    sequence_count: word2 & 0x3fff,
    length_field: lengthField,
    declared_length: lengthField + 7,
    actual_length: b.length,
  }
}

// Metadata rows for the expanded entry, all as safe text
export function metadataRows(entry) {
  const rows = [
    ['Entry id', entry.id],
    ['Time (UTC)', entry.time],
    ['Interface', entry.interface],
    ['Connection', entry.connection_id],
    ['Stage', entry.stage],
    ['Rule', entry.rule_id && `${entry.rule_id} (${entry.rule_type})`],
    ['Rule description', entry.rule_description],
    ['Layer', entry.layer],
    ['Rules version', entry.rules_version],
    ['Rules sha256', entry.rules_sha256],
    ['Length', entry.length],
    ['Bytes kept', entry.bytes_kept],
    ['Truncated', entry.truncated ? 'yes' : 'no'],
    ['Packet sha256', entry.sha256],
    ['Releasable', entry.releasable ? 'yes' : 'no'],
  ]
  return rows
    .filter(
      ([, value]) => value !== undefined && value !== null && value !== '',
    )
    .map(([name, value]) => ({ name, value: safeText(value) }))
}

// Link values from an extension (e.g. SDLS virtual channel), as safe text
export function linkRows(link) {
  if (!link || typeof link !== 'object') return []
  return Object.entries(link).map(([name, value]) => ({
    name: safeText(name, 64),
    value: safeText(
      typeof value === 'object' ? JSON.stringify(value) : value,
      256,
    ),
  }))
}

// Can this entry be released from the page? (The firewall checks again.)
export function canRelease(entry) {
  return Boolean(
    entry &&
    entry.stream === 'quarantine' &&
    entry.releasable &&
    !entry.truncated &&
    !entry.released &&
    /^[0-9a-f]{64}$/.test(entry.sha256 || ''),
  )
}
