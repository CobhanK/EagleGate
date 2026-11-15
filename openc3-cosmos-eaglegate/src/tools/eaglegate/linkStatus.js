// The Link status tab's data handling, kept out of the component so node --test
// can check it. The firewall reports traffic counts for every packet it judges
// (targets/EAGLEGATE/lib/eaglegate_traffic.py); extensions describe their own
// panels and admin actions (eaglegate_extensions.py, "Panels and actions"), so
// nothing here knows about any particular extension.

import { checkFields } from './rulesModel.js'

export const EMPTY = '–'

// obj.a.b for path "a.b"; undefined when any step is missing
export function getPath(obj, path) {
  let value = obj
  for (const name of String(path).split('.')) {
    if (value === null || typeof value !== 'object') return undefined
    value = value[name]
  }
  return value
}

// One cell's text
export function formatValue(value) {
  if (value === undefined || value === null || value === '') return EMPTY
  if (typeof value === 'boolean') return value ? 'yes' : 'no'
  if (typeof value === 'number') return value.toLocaleString('en-US')
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

// [{ extension, data }] for the extensions on this interface that describe
// panels or actions; data is their interface_details section (null when their
// protocol reported none, e.g. an older version)
export function extensionViews(extensions, protocols) {
  const views = []
  for (const extension of Object.values(extensions || {})) {
    if (!extension.panels?.length && !extension.actions?.length) continue
    const key = extension.details_key
    const owner = key ? (protocols || []).find((p) => p && key in p) : null
    views.push({ extension, data: owner ? owner[key] : null })
  }
  return views
}

// A "values" panel: [{ key, title, value }] in the panel's order (or all keys)
export function panelValues(panel, data) {
  const section = getPath(data, panel.path)
  if (!section || typeof section !== 'object') return []
  const titles =
    panel.items || Object.fromEntries(Object.keys(section).map((k) => [k, k]))
  return Object.entries(titles).map(([key, title]) => ({
    key,
    title,
    value: formatValue(section[key]),
  }))
}

// A "table" panel: [{ key, cells: { column: text } }]. Rows come from an object
// (key -> row) or a list; a row that is a plain value fills the "value" column
export function panelRows(panel, data) {
  const section = getPath(data, panel.path)
  if (!section || typeof section !== 'object') return []
  const entries = Array.isArray(section)
    ? section.map((row, i) => [String(i), row])
    : Object.entries(section)
  return entries.map(([key, row]) => {
    const values =
      row !== null && typeof row === 'object' ? row : { value: row }
    const cells = {}
    for (const column of Object.keys(panel.columns || {}))
      cells[column] = formatValue(values[column])
    return { key, cells }
  })
}

// What the action dialog shows: the params fixed by the button (and row), and
// the fields the admin still fills in
export function actionForm(action, binding = {}, rowKey = undefined) {
  const fixed = { ...(binding.params || {}) }
  if (binding.row_param && rowKey !== undefined)
    fixed[binding.row_param] = rowKey
  const fields = {}
  for (const [name, spec] of Object.entries(action.params || {}))
    if (!(name in fixed)) fields[name] = spec
  return { fixed, fields }
}

// The request's params: fixed values win; empty fields are left out
export function actionParams(fixed, edited) {
  const params = {}
  for (const [name, value] of Object.entries(edited || {}))
    if (value !== undefined && value !== null && value !== '')
      params[name] = value
  return { ...params, ...fixed }
}

// Why the firewall would refuse these params before even sending them, [] if fine
export function actionProblems(action, params) {
  return checkFields(action.params || {}, params, action.title || action.name)
}

// The per-APID table, sorted by APID
export function apidRows(traffic) {
  return Object.entries(traffic?.apids || {})
    .map(([apid, counts]) => ({ apid, ...counts }))
    .sort((a, b) => parseInt(a.apid, 16) - parseInt(b.apid, 16))
}

// Packets per second between two polls: { packets, at } with at in ms
export function rate(previous, current) {
  if (!previous || !current) return null
  const seconds = (current.at - previous.at) / 1000
  const packets = current.packets - previous.packets
  if (seconds <= 0 || packets < 0) return null // counters restart with the interface
  return packets / seconds
}

// "12 s ago" for a UTC time the firewall reported
export function timeAgo(text, now = Date.now()) {
  if (!text) return EMPTY
  const then = Date.parse(text)
  if (Number.isNaN(then)) return String(text)
  const seconds = Math.max(0, Math.round((now - then) / 1000))
  if (seconds < 120) return `${seconds} s ago`
  if (seconds < 7200) return `${Math.round(seconds / 60)} min ago`
  if (seconds < 172800) return `${Math.round(seconds / 3600)} h ago`
  return `${Math.round(seconds / 86400)} days ago`
}
