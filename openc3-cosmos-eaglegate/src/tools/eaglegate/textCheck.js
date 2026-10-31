// The text rule's field check, for the rules editor's preview and "try a
// sample" box. An exact copy of targets/EAGLEGATE/lib/eaglegate_text.py: the
// shared cases in tests/fixtures/text_rule_cases.json run against both, so
// change the two together. The firewall's Python copy is the one that decides.

import { toInt } from './ints.js'

const BYTE_NAMES = {
  0x00: 'NUL',
  0x09: 'TAB',
  0x0a: 'LF',
  0x0d: 'CR',
  0x1b: 'ESC',
  0x20: 'space',
  0x7f: 'DEL',
  0x22: 'double quote',
  0x27: 'quote',
  0x5c: 'backslash',
  0x60: 'backtick',
}
const MAX_CHARSET = 256
const MAX_CHARSET_RANGE = 0x10000
const CONTROL_OR_FORMAT = /\p{C}/u
const SEPARATOR = /[\p{Zl}\p{Zp}]/u

const hex2 = (n) => n.toString(16).toUpperCase().padStart(2, '0')
const hex4 = (n) => n.toString(16).toUpperCase().padStart(4, '0')

export function describeByte(value) {
  if (value in BYTE_NAMES) return `0x${hex2(value)} (${BYTE_NAMES[value]})`
  if (value >= 0x21 && value <= 0x7e)
    return `0x${hex2(value)} '${String.fromCharCode(value)}'`
  return `0x${hex2(value)} (${value < 0x80 ? 'control' : 'non-ASCII'})`
}

export function quote(text) {
  let out = ''
  for (const ch of text) {
    const cp = ch.codePointAt(0)
    if (cp >= 0x20 && cp <= 0x7e && ch !== '"' && ch !== '\\') out += ch
    else if (cp <= 0xffff) out += `\\u${cp.toString(16).padStart(4, '0')}`
    else out += `\\U${cp.toString(16).padStart(8, '0')}`
  }
  return `"${out}"`
}

export function floorProblem(cp) {
  if (cp < 0x80) return cp >= 0x20 && cp <= 0x7e ? null : 'control character'
  const ch = String.fromCodePoint(cp)
  if (CONTROL_OR_FORMAT.test(ch))
    return 'control, format or unassigned character'
  if (SEPARATOR.test(ch)) return 'line or paragraph separator'
  return null
}

// "A-Z" is a range, anything else is itself, "-" is literal at either end
export function parseCharset(spec, where, encoding) {
  if (typeof spec !== 'string') throw new Error(`${where} must be a string`)
  const chars = Array.from(spec)
  if (chars.length > MAX_CHARSET)
    throw new Error(`${where} is longer than ${MAX_CHARSET} characters`)
  const result = new Set()
  let i = 0
  while (i < chars.length) {
    const low = chars[i].codePointAt(0)
    let high = low
    if (i + 2 < chars.length && chars[i + 1] === '-') {
      high = chars[i + 2].codePointAt(0)
      if (low > high)
        throw new Error(
          `${where}: range ${quote(chars.slice(i, i + 3).join(''))} is backwards`,
        )
      i += 3
    } else {
      i += 1
    }
    if (high - low + 1 + result.size > MAX_CHARSET_RANGE)
      throw new Error(
        `${where} expands to more than ${MAX_CHARSET_RANGE} characters`,
      )
    for (let cp = low; cp <= high; cp++) {
      if (encoding === 'ascii' && !(cp >= 0x20 && cp <= 0x7e))
        throw new Error(
          `${where}: U+${hex4(cp)} is not printable ASCII; ascii text can only allow 0x20-0x7E (use encoding utf8 or raw)`,
        )
      const problem = floorProblem(cp)
      if (problem)
        throw new Error(
          `${where}: U+${hex4(cp)} is a ${problem} and can never be allowed`,
        )
      result.add(cp)
    }
  }
  return result
}

// "0x00-0x1F, 0x7F 27" -> Set of byte values
export function parseByteSet(spec, where) {
  if (typeof spec !== 'string') throw new Error(`${where} must be a string`)
  const result = new Set()
  for (const item of spec.trim().split(/[\s,]+/)) {
    if (!item) continue
    const dash = item.indexOf('-')
    const lowText = dash < 0 ? item : item.slice(0, dash)
    const highText = dash < 0 ? '' : item.slice(dash + 1)
    const low = toInt(lowText)
    const high = highText ? toInt(highText) : low
    if (Number.isNaN(low) || Number.isNaN(high))
      throw new Error(
        `${where}: ${quote(item)} is not a byte value or range like 0x00-0x1F`,
      )
    if (!(low >= 0 && low <= high && high <= 0xff))
      throw new Error(
        `${where}: ${quote(item)} must be within 0x00-0xFF, low <= high`,
      )
    for (let b = low; b <= high; b++) result.add(b)
  }
  return result
}

function hexToBytes(text) {
  const clean = text.replace(/\s+/g, '')
  if (!/^([0-9a-f]{2})*$/i.test(clean)) return null
  return Uint8Array.from(clean.match(/../g) || [], (h) => parseInt(h, 16))
}

// The same settings TextCheck() takes; throws on invalid character sets
export function compileText(params, schema) {
  const encoding = params.encoding || 'ascii'
  const where = params.where || 'text'
  const compiled = {
    encoding,
    padding: params.padding || 'nul',
    minLength: params.min_length ?? null,
    maxLength: params.max_length ?? null,
  }
  if (encoding === 'raw') {
    const allowed = params.allow_bytes
      ? parseByteSet(params.allow_bytes, `${where}.allow_bytes`)
      : new Set(Array.from({ length: 256 }, (_, b) => b))
    for (const b of parseByteSet(
      params.deny_bytes || '',
      `${where}.deny_bytes`,
    ))
      allowed.delete(b)
    compiled.allowed = allowed
    compiled.substrings = (params.deny_substrings || []).map(
      (s) => hexToBytes(s) || new Uint8Array(),
    )
    return compiled
  }
  const profile = params.profile || 'safe_text'
  const spec = schema.text.profiles[profile]
  if (!spec)
    throw new Error(`${where}.profile ${quote(profile)} is not a profile`)
  const chars = parseCharset(spec.chars, `profile ${profile}`, 'ascii')
  for (const ch of spec.minus || '') chars.delete(ch.codePointAt(0))
  for (const cp of parseCharset(
    params.also_allow || '',
    `${where}.also_allow`,
    encoding,
  ))
    chars.add(cp)
  const denied = parseCharset(
    params.also_deny || '',
    `${where}.also_deny`,
    encoding,
  )
  for (const cp of denied) chars.delete(cp)
  Object.assign(compiled, {
    profile,
    asciiAllowed: new Set([...chars].filter((cp) => cp < 0x80)),
    extraUnicode: new Set([...chars].filter((cp) => cp >= 0x80)),
    deniedUnicode: new Set([...denied].filter((cp) => cp >= 0x80)),
    anyUnicode: spec.unicode,
    notFirst: new Set(Array.from(spec.not_first, (c) => c.codePointAt(0))),
    formula:
      params.no_formula_start === false
        ? new Set()
        : new Set(
            Array.from(schema.text.formula_start, (c) => c.codePointAt(0)),
          ),
    substrings: (params.deny_substrings || []).map((s) => s.toLowerCase()),
  })
  return compiled
}

// Offset of the first byte that makes this invalid UTF-8 (Python's
// UnicodeDecodeError.start), or -1 when it is valid
function utf8ErrorOffset(bytes) {
  let i = 0
  while (i < bytes.length) {
    const b = bytes[i]
    if (b < 0x80) {
      i++
      continue
    }
    let need
    let low = 0x80
    let high = 0xbf
    if (b >= 0xc2 && b <= 0xdf) need = 1
    else if (b >= 0xe0 && b <= 0xef) {
      need = 2
      if (b === 0xe0) low = 0xa0
      if (b === 0xed) high = 0x9f
    } else if (b >= 0xf0 && b <= 0xf4) {
      need = 3
      if (b === 0xf0) low = 0x90
      if (b === 0xf4) high = 0x8f
    } else return i
    for (let k = 1; k <= need; k++) {
      const c = bytes[i + k]
      if (c === undefined) return i
      if (k === 1 ? c < low || c > high : c < 0x80 || c > 0xbf) return i
    }
    i += need + 1
  }
  return -1
}

function indexOfBytes(haystack, needle) {
  outer: for (let i = 0; i + needle.length <= haystack.length; i++) {
    for (let j = 0; j < needle.length; j++)
      if (haystack[i + j] !== needle[j]) continue outer
    return i
  }
  return -1
}

// null if the field is fine, otherwise why not (never echoing its content)
export function checkField(compiled, input) {
  let data = Uint8Array.from(input)
  if (compiled.padding === 'nul') {
    const end = data.indexOf(0)
    if (end >= 0) {
      let stray = end
      while (stray < data.length && data[stray] === 0) stray++
      if (stray < data.length)
        return `data after the NUL terminator at offset ${stray}`
      data = data.subarray(0, end)
    }
  } else if (compiled.padding === 'space') {
    let end = data.length
    while (end > 0 && data[end - 1] === 0x20) end--
    data = data.subarray(0, end)
  }
  if (compiled.minLength !== null && data.length < compiled.minLength)
    return `text is ${data.length} bytes, shorter than min_length ${compiled.minLength}`
  if (compiled.maxLength !== null && data.length > compiled.maxLength)
    return `text is ${data.length} bytes, longer than max_length ${compiled.maxLength}`

  if (compiled.encoding === 'raw') {
    const bad = data.findIndex((b) => !compiled.allowed.has(b))
    if (bad >= 0)
      return `byte ${describeByte(data[bad])} at offset ${bad} is not allowed`
    for (const [index, sequence] of compiled.substrings.entries()) {
      if (sequence.length && indexOfBytes(data, sequence) >= 0) {
        const shown = Array.from(sequence, (b) =>
          b.toString(16).padStart(2, '0'),
        ).join('')
        return `contains denied byte sequence #${index + 1} (${shown})`
      }
    }
    return null
  }

  if (compiled.encoding === 'utf8' && data.some((b) => b >= 0x80))
    return checkUtf8(compiled, data)
  const bad = data.findIndex((b) => !compiled.asciiAllowed.has(b))
  if (bad >= 0)
    return `byte ${describeByte(data[bad])} at offset ${bad} is not allowed by profile ${compiled.profile}`
  return checkStartAndSubstrings(
    compiled,
    data[0],
    String.fromCharCode(...data).toLowerCase(),
  )
}

function checkUtf8(compiled, data) {
  const bad = utf8ErrorOffset(data)
  if (bad >= 0) return `invalid UTF-8 at offset ${bad}`
  const text = new TextDecoder('utf-8').decode(data)
  let offset = 0
  for (const ch of text) {
    const cp = ch.codePointAt(0)
    if (cp < 0x80) {
      if (!compiled.asciiAllowed.has(cp))
        return `byte ${describeByte(cp)} at offset ${offset} is not allowed by profile ${compiled.profile}`
    } else {
      const problem = unicodeProblem(compiled, cp)
      if (problem)
        return `character U+${hex4(cp)} at offset ${offset} is not allowed: ${problem}`
    }
    offset += cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4
  }
  return checkStartAndSubstrings(compiled, data[0], text.toLowerCase())
}

function unicodeProblem(compiled, cp) {
  const floor = floorProblem(cp)
  if (floor) return floor
  if (compiled.deniedUnicode.has(cp)) return 'listed in also_deny'
  if (!compiled.anyUnicode && !compiled.extraUnicode.has(cp))
    return `profile ${compiled.profile} allows no other characters`
  for (const ch of String.fromCodePoint(cp).normalize('NFKC')) {
    const n = ch.codePointAt(0)
    if (n < 0x80 && !compiled.asciiAllowed.has(n))
      return `it normalizes (NFKC) to ${describeByte(n)}, which profile ${compiled.profile} does not allow`
  }
  return null
}

function checkStartAndSubstrings(compiled, first, lowered) {
  if (first !== undefined) {
    if (compiled.notFirst.has(first))
      return `byte ${describeByte(first)} is not allowed as the first character by profile ${compiled.profile}`
    if (compiled.formula.has(first))
      return `starts with ${describeByte(first)}, which spreadsheets treat as a formula`
  }
  for (const [index, substring] of compiled.substrings.entries()) {
    if (substring && lowered.includes(substring))
      return `contains denied substring #${index + 1} ${quote(substring)}`
  }
  return null
}

// What the settings let through, in words, for the editor's preview
export function describeAllowed(compiled) {
  const ranges = (values, fmt) => {
    const sorted = [...values].sort((a, b) => a - b)
    const parts = []
    for (let i = 0; i < sorted.length; i++) {
      let j = i
      while (j + 1 < sorted.length && sorted[j + 1] === sorted[j] + 1) j++
      parts.push(
        j - i >= 2 ? `${fmt(sorted[i])}-${fmt(sorted[j])}` : fmt(sorted[i]),
      )
      if (j - i === 1) parts.push(fmt(sorted[j]))
      i = j
    }
    return parts.join(' ')
  }
  if (compiled.encoding === 'raw') {
    if (compiled.allowed.size === 256) return 'every byte value'
    if (!compiled.allowed.size) return 'no byte values'
    return `bytes ${ranges(compiled.allowed, (b) => `0x${hex2(b)}`)}`
  }
  const glyph = (cp) => (cp === 0x20 ? '␠' : String.fromCodePoint(cp))
  let text = compiled.asciiAllowed.size
    ? ranges(compiled.asciiAllowed, glyph)
    : '(no ASCII characters)'
  if (compiled.encoding === 'utf8') {
    if (compiled.anyUnicode)
      text += ', plus other printable non-ASCII characters'
    else if (compiled.extraUnicode.size)
      text += `, plus ${ranges(compiled.extraUnicode, glyph)}`
  }
  return text
}

// Bytes for the sample box: the typed text as UTF-8, or hex for raw fields
export function sampleBytes(sample, encoding) {
  if (encoding === 'raw') return hexToBytes(sample)
  return new TextEncoder().encode(sample)
}
