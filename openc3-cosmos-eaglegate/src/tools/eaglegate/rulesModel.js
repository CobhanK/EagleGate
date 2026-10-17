// The rules file as data for the editor: early validation, warnings, diffs.
//
// The firewall's Python parser (eaglegate_rules_parser.py) is the authority;
// everything here only exists to catch mistakes before upload and to explain
// them in the page. The schema comes from public/eaglegate_rules_schema.json,
// which the build generates from that parser, so the two cannot drift.

// Integers in the rules file may be JSON numbers or strings like "0x1FF".
// Mirrors eaglegate_validate.to_int, i.e. Python's int(text, 0): hex, octal
// (0o), binary and plain decimal, but no leading zeros ("010" is refused).
const INT_LITERAL = {
  16: /^([+-]?)0x([0-9a-f](?:_?[0-9a-f])*)$/i,
  8: /^([+-]?)0o([0-7](?:_?[0-7])*)$/i,
  2: /^([+-]?)0b([01](?:_?[01])*)$/i,
  10: /^([+-]?)([1-9](?:_?\d)*|0+)$/,
}

export function toInt(value) {
  if (typeof value === 'number') return Number.isInteger(value) ? value : NaN
  if (typeof value !== 'string') return NaN // booleans are refused too
  const text = value.trim()
  for (const [base, pattern] of Object.entries(INT_LITERAL)) {
    const found = pattern.exec(text)
    if (found) {
      const n = parseInt(found[2].replaceAll('_', ''), Number(base))
      return found[1] === '-' ? -n : n
    }
  }
  return NaN
}

// Mirrors eaglegate_validate.to_number: JSON numbers only, never strings
export function toNumber(value) {
  return typeof value === 'number' ? value : NaN
}

// What a form field's text becomes in the rules file: ints stay as typed when
// they are hex/octal/binary (readable masks), everything else a JSON number
export function fromInput(spec, text) {
  if (text === null || text === undefined) return undefined
  const trimmed = String(text).trim()
  if (trimmed === '') return undefined
  if (spec.type === 'int') {
    const n = toInt(trimmed)
    if (Number.isNaN(n)) return trimmed // keep it so validation can say what is wrong
    return /^[+-]?0[xob]/i.test(trimmed) ? trimmed : n
  }
  if (spec.type === 'number') {
    const n = Number(trimmed)
    return Number.isNaN(n) ? trimmed : n
  }
  return trimmed
}

function checkValue(spec, value, where, errors) {
  switch (spec.type) {
    case 'int': {
      const n = toInt(value)
      if (Number.isNaN(n)) return errors.push(`${where} must be an integer`)
      if (spec.min !== undefined && n < spec.min)
        errors.push(`${where} must be >= ${spec.min}`)
      if (spec.max !== undefined && n > spec.max)
        errors.push(`${where} must be <= ${spec.max}`)
      return
    }
    case 'number': {
      const n = toNumber(value)
      if (Number.isNaN(n)) return errors.push(`${where} must be a number`)
      if (spec.min !== undefined && n < spec.min)
        errors.push(`${where} must be >= ${spec.min}`)
      if (spec.min_exclusive !== undefined && n <= spec.min_exclusive)
        errors.push(`${where} must be > ${spec.min_exclusive}`)
      if (spec.max !== undefined && n > spec.max)
        errors.push(`${where} must be <= ${spec.max}`)
      return
    }
    case 'enum':
      if (!spec.values.includes(value))
        errors.push(`${where} must be one of ${spec.values.join(', ')}`)
      return
    case 'bool':
      if (typeof value !== 'boolean')
        errors.push(`${where} must be true or false`)
      return
    case 'string':
      if (typeof value !== 'string' || value.trim() === '')
        errors.push(`${where} must be a non-empty string`)
      return
    case 'int_list':
      if (!Array.isArray(value) || value.length === 0)
        return errors.push(`${where} must be a non-empty list`)
      value.forEach((v, i) =>
        checkValue({ ...spec, type: 'int' }, v, `${where}[${i}]`, errors),
      )
      return
    case 'int_pair': {
      if (!Array.isArray(value) || value.length !== 2)
        return errors.push(`${where} must be [low, high]`)
      value.forEach((v, i) =>
        checkValue({ ...spec, type: 'int' }, v, `${where}[${i}]`, errors),
      )
      if (toInt(value[0]) > toInt(value[1])) errors.push(`${where} low > high`)
      return
    }
    case 'byte_checks':
      if (!Array.isArray(value) || value.length === 0)
        return errors.push(`${where} must be a non-empty list`)
      value.forEach((check, i) => {
        const at = `${where}[${i}]`
        checkObject(spec.fields, check, at, errors)
        const mask = check.mask === undefined ? 0xff : toInt(check.mask)
        const v = toInt(check.value)
        if (!Number.isNaN(mask) && !Number.isNaN(v) && (v & ~mask) !== 0)
          errors.push(`${at}.value has bits outside mask (can never match)`)
      })
      return
  }
}

function checkObject(specs, obj, where, errors) {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
    errors.push(`${where} must be an object`)
    return
  }
  for (const key of Object.keys(obj)) {
    if (!(key in specs)) errors.push(`${where} has unknown key '${key}'`)
  }
  for (const [key, spec] of Object.entries(specs)) {
    if (obj[key] === undefined || obj[key] === null || obj[key] === '') {
      if (spec.required) errors.push(`${where} needs '${key}'`)
      continue
    }
    checkValue(spec, obj[key], `${where}.${key}`, errors)
  }
}

function ruleType(rule) {
  return rule.type || 'match'
}

function enabled(rule) {
  return rule.enabled !== false
}

// Errors the firewall would reject the file for (a best effort copy of the
// parser's checks). An empty list does not guarantee acceptance.
export function validate(doc, schema) {
  const errors = []
  const allowedTop = new Set(schema.top_level_keys)
  for (const key of Object.keys(doc)) {
    if (!allowedTop.has(key)) errors.push(`top level has unknown key '${key}'`)
  }
  if (!Number.isInteger(doc.version) || doc.version < 0)
    errors.push("'version' must be a non-negative integer")
  if (!schema.actions.includes(doc.default_action))
    errors.push(`'default_action' must be one of ${schema.actions.join(', ')}`)
  if (!Array.isArray(doc.rules)) {
    errors.push("'rules' must be a list")
    return errors
  }
  if (doc.rules.length > schema.max_rules)
    errors.push(`too many rules (${doc.rules.length} > ${schema.max_rules})`)

  const seen = new Set()
  const ruleKeys = new Set(schema.rule_keys)
  doc.rules.forEach((rule, index) => {
    const id = typeof rule.id === 'string' ? rule.id.trim() : ''
    const where = id ? `rule '${id}'` : `rules[${index}]`
    if (!id) errors.push(`${where}.id must be a non-empty string`)
    else if (seen.has(id)) errors.push(`duplicate rule '${id}'`)
    seen.add(id)
    for (const key of Object.keys(rule)) {
      if (!ruleKeys.has(key)) errors.push(`${where} has unknown key '${key}'`)
    }
    const type = schema.rule_types[ruleType(rule)]
    if (!type) {
      errors.push(`${where}.type '${rule.type}' is not a known rule type`)
      return
    }
    if (!type.actions.includes(rule.action))
      errors.push(`${where}.action must be one of ${type.actions.join(', ')}`)
    if (rule.match === undefined)
      errors.push(`${where} is missing 'match' (use {} to match everything)`)
    else checkMatch(rule.match, `${where}.match`, schema, errors)
    // Like the parser: a disabled rule's param VALUES are not checked
    // (a disabled authenticity rule does not need its key), but its keys are
    const params = rule.params || {}
    for (const key of Object.keys(params)) {
      if (!(key in type.params))
        errors.push(`${where}.params has unknown key '${key}'`)
    }
    if (enabled(rule)) {
      checkObject(type.params, params, `${where}.params`, errors)
      checkParamRules(ruleType(rule), params, `${where}.params`, errors)
    }
  })
  return errors
}

function checkMatch(match, where, schema, errors) {
  checkObject(schema.match.keys, match, where, errors)
  if (
    match &&
    match.min_length !== undefined &&
    match.max_length !== undefined &&
    toInt(match.min_length) > toInt(match.max_length)
  )
    errors.push(`${where} min_length > max_length`)
}

function checkParamRules(type, params, where, errors) {
  if (type === 'range') {
    const hasMin = params.min !== undefined && params.min !== ''
    const hasMax = params.max !== undefined && params.max !== ''
    if (!hasMin && !hasMax) errors.push(`${where} needs 'min', 'max' or both`)
    if (hasMin && hasMax && toNumber(params.min) > toNumber(params.max))
      errors.push(`${where} min > max`)
  }
}

// ---- warnings: valid files that probably do not do what was meant ----------

// The APIDs a match selects, as a predicate plus a description, so two rules
// can be checked for overlap. Conditions other than APID and packet type are
// ignored, so "may overlap" is the conservative answer.
function apidSelector(match) {
  if (match.apid) {
    const set = new Set(match.apid.map(toInt))
    return { has: (a) => set.has(a), list: [...set] }
  }
  if (match.apid_range) {
    const [low, high] = match.apid_range.map(toInt)
    return { has: (a) => a >= low && a <= high, low, high }
  }
  return null // every APID
}

export function mayOverlap(a, b) {
  if (a.packet_type && b.packet_type && a.packet_type !== b.packet_type)
    return false
  const sa = apidSelector(a)
  const sb = apidSelector(b)
  if (!sa || !sb) return true
  if (sa.list) return sa.list.some((x) => sb.has(x))
  if (sb.list) return sb.list.some((x) => sa.has(x))
  return sa.low <= sb.high && sb.low <= sa.high
}

export function warnings(doc, schema, running) {
  const result = []
  const rules = Array.isArray(doc.rules) ? doc.rules : []
  const active = rules.filter(enabled)
  if (doc.default_action === 'ALLOW')
    result.push(
      'default_action is ALLOW: packets no rule decides are let through. The firewall is normally default-deny',
    )
  if (active.length === 0 && doc.default_action === 'DENY')
    result.push('No rule is enabled: every packet will be denied')
  else if (
    doc.default_action === 'DENY' &&
    !active.some((r) => r.action === 'ALLOW')
  )
    result.push('No enabled rule allows anything: every packet will be denied')

  // Check rules below an ALLOW for the same packets never run (first rule that fires wins)
  active.forEach((rule, index) => {
    if (!schema.rule_types[ruleType(rule)]?.is_check) return
    const shadow = active
      .slice(0, index)
      .find(
        (above) =>
          ruleType(above) === 'match' &&
          above.action === 'ALLOW' &&
          mayOverlap(above.match || {}, rule.match || {}),
      )
    if (shadow)
      result.push(
        `'${rule.id}' (${ruleType(rule)}) is below '${shadow.id}', which allows the same packets first; ` +
          `move '${rule.id}' above it or its check may never run`,
      )
  })

  active
    .filter((r) => ruleType(r) === 'authenticity')
    .forEach((r) =>
      result.push(
        `'${r.id}' needs the environment variable ${r.params?.key_env || '(key_env)'} on the interface ` +
          '(a COSMOS secret exposed with SECRET ENV in plugin.txt); otherwise the firewall refuses the file',
      ),
    )

  if (
    running &&
    Number.isInteger(doc.version) &&
    doc.version <= running.version
  )
    result.push(
      `version ${doc.version} is not above the running version ${running.version}; it will be raised on apply`,
    )
  return result
}

// ---- editing helpers ---------------------------------------------------------

// Deep copy that also works on Vue's reactive proxies (structuredClone does not)
export function clone(value) {
  return JSON.parse(JSON.stringify(value))
}

export function newRule(type, schema, existingIds) {
  let n = 1
  while (existingIds.includes(`new-${type}-rule-${n}`)) n += 1
  const rule = {
    id: `new-${type}-rule-${n}`,
    description: '',
    action: schema.rule_types[type].actions[0],
    match: {},
  }
  if (type !== 'match') rule.type = type
  const params = {}
  for (const [key, spec] of Object.entries(schema.rule_types[type].params)) {
    if (spec.default !== undefined) params[key] = spec.default
  }
  if (Object.keys(schema.rule_types[type].params).length) rule.params = params
  return rule
}

// The text that gets uploaded. Stable formatting keeps diffs and history readable.
export function toFileText(doc) {
  return JSON.stringify(doc, null, 2) + '\n'
}

// Raise the version when the content changed but the version did not
export function withBumpedVersion(doc, runningVersion) {
  if (Number.isInteger(doc.version) && doc.version > runningVersion) return doc
  return { ...doc, version: Math.max(runningVersion, 0) + 1 }
}

// Line diff (longest common subsequence): [{ op: ' ' | '-' | '+', line }]
export function lineDiff(before, after) {
  const a = before.split('\n')
  const b = after.split('\n')
  const lcs = Array.from({ length: a.length + 1 }, () =>
    new Array(b.length + 1).fill(0),
  )
  for (let i = a.length - 1; i >= 0; i--)
    for (let j = b.length - 1; j >= 0; j--)
      lcs[i][j] =
        a[i] === b[j]
          ? lcs[i + 1][j + 1] + 1
          : Math.max(lcs[i + 1][j], lcs[i][j + 1])
  const out = []
  let i = 0
  let j = 0
  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) {
      out.push({ op: ' ', line: a[i] })
      i++
      j++
    } else if (lcs[i + 1][j] >= lcs[i][j + 1])
      out.push({ op: '-', line: a[i++] })
    else out.push({ op: '+', line: b[j++] })
  }
  while (i < a.length) out.push({ op: '-', line: a[i++] })
  while (j < b.length) out.push({ op: '+', line: b[j++] })
  return out
}
