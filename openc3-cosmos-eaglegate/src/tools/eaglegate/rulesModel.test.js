// Run with: pnpm test (node --test, no extra dependencies)
// Validation here only gives early feedback; the firewall's Python parser is
// the authority. These tests check the page agrees with it on the shipped
// rules file and on the mistakes the parser's own tests cover.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

import {
  clone,
  fromInput,
  lineDiff,
  linkSummary,
  mayOverlap,
  newRule,
  setSetting,
  settingValue,
  toInt,
  toNumber,
  validate,
  warnings,
  withBumpedVersion,
  withExtensions,
} from './rulesModel.js'

const root = new URL('../../../', import.meta.url)
const schema = JSON.parse(
  readFileSync(new URL('public/eaglegate_rules_schema.json', root)),
)
const shipped = JSON.parse(
  readFileSync(new URL('targets/EAGLEGATE/rules/firewall_rules.json', root)),
)

function doc(rules, extra = {}) {
  return { version: 1, default_action: 'DENY', rules, ...extra }
}

test('the shipped rules file is valid', () => {
  assert.deepEqual(validate(shipped, schema), [])
})

test('integers follow Python int(text, 0)', () => {
  assert.equal(toInt('0x1FF'), 511)
  assert.equal(toInt('0o17'), 15)
  assert.equal(toInt('0b101'), 5)
  assert.equal(toInt('-12'), -12)
  assert.equal(toInt('1_000'), 1000)
  assert.ok(Number.isNaN(toInt('010')))
  assert.ok(Number.isNaN(toInt(true)))
  assert.ok(Number.isNaN(toInt(1.5)))
  assert.ok(Number.isNaN(toNumber('1.5'))) // range/rate params must be JSON numbers
})

test('form input keeps hex text but stores decimals as numbers', () => {
  assert.equal(fromInput({ type: 'int' }, '0x80'), '0x80')
  assert.equal(fromInput({ type: 'int' }, '12'), 12)
  assert.equal(fromInput({ type: 'number' }, '0.9'), 0.9)
  assert.equal(fromInput({ type: 'int' }, ''), undefined)
})

test('typos and bad values are errors', () => {
  const errors = validate(
    doc([
      { id: 'a', action: 'ALLOW', match: { apids: [1] } },
      { id: 'a', action: 'ALOW', match: {} },
      {
        id: 'r',
        type: 'range',
        action: 'ALLOW',
        match: {},
        params: { offset: 6, data_type: 'INT16' },
      },
      {
        id: 'b',
        action: 'DENY',
        match: { bytes: [{ offset: 6, mask: '0x0F', value: '0x80' }] },
      },
      { id: 'n', action: 'DENY' },
    ]),
    schema,
  )
  const text = errors.join('\n')
  assert.match(text, /unknown key 'apids'/)
  assert.match(text, /duplicate rule 'a'/)
  assert.match(text, /action must be one of ALLOW, DENY/)
  assert.match(text, /rule 'r'.action must be one of DENY/)
  assert.match(text, /needs 'min', 'max' or both/)
  assert.match(text, /bits outside mask/)
  assert.match(text, /missing 'match'/)
})

test('a disabled rule needs no param values, but unknown keys still fail', () => {
  const rule = {
    id: 'auth',
    type: 'authenticity',
    action: 'DENY',
    enabled: false,
    match: {},
  }
  assert.deepEqual(validate(doc([{ ...rule, params: {} }]), schema), [])
  assert.match(
    validate(doc([{ ...rule, params: { key: 'secret' } }]), schema).join(),
    /unknown key 'key'/,
  )
})

test('a check rule below an overlapping ALLOW is flagged', () => {
  const allow = { id: 'allow-hk', action: 'ALLOW', match: { apid: ['0x002'] } }
  const seq = {
    id: 'seq',
    type: 'sequence',
    action: 'DENY',
    match: { apid: [2, 3] },
    params: {},
  }
  assert.match(
    warnings(doc([allow, seq]), schema).join(),
    /'seq' \(sequence\) is below 'allow-hk'/,
  )
  assert.ok(
    !warnings(doc([seq, allow]), schema).some((w) => w.includes('is below')),
  )
})

test('overlap is decided on APID and packet type', () => {
  assert.ok(mayOverlap({ apid: [2] }, { apid_range: ['0x000', '0x00F'] }))
  assert.ok(!mayOverlap({ apid: [2] }, { apid: [3] }))
  assert.ok(!mayOverlap({ packet_type: 'CMD' }, { packet_type: 'TLM' }))
  assert.ok(mayOverlap({}, { apid: [9] }))
})

test('lockout and default-allow are warned about', () => {
  assert.match(warnings(doc([]), schema).join(), /every packet will be denied/)
  assert.match(
    warnings(doc([], { default_action: 'ALLOW' }), schema).join(),
    /default-deny/,
  )
})

test('new rules start valid enough to edit and get unique ids', () => {
  const rule = newRule('sequence', schema, ['new-sequence-rule-1'])
  assert.equal(rule.id, 'new-sequence-rule-2')
  assert.deepEqual(rule.params, { max_gap: 1 })
  assert.equal(rule.action, 'DENY')
  assert.equal(newRule('match', schema, []).type, undefined)
})

test('version is raised only when needed', () => {
  assert.equal(withBumpedVersion(doc([], { version: 3 }), 3).version, 4)
  assert.equal(withBumpedVersion(doc([], { version: 7 }), 3).version, 7)
})

test('line diff marks removed and added lines', () => {
  assert.deepEqual(lineDiff('a\nb\nc', 'a\nc\nd'), [
    { op: ' ', line: 'a' },
    { op: '-', line: 'b' },
    { op: ' ', line: 'c' },
    { op: '+', line: 'd' },
  ])
})

// ---- extensions (what interface_details reports as firewall.extensions) ----

const EXTENSIONS = {
  link: {
    name: 'sdls',
    section: 'link',
    layers: ['frame', 'sdls'],
    link_keys: {
      vcid: { type: 'int_list', min: 0, max: 63 },
      protection: { type: 'enum_list', values: ['clear', 'auth'] },
    },
    schema: {
      type: 'object',
      fields: {
        scid: { type: 'int', min: 0, max: 1023, required: true },
        idle: { type: 'enum', values: ['drop', 'keep'] },
        virtual_channels: {
          type: 'map',
          key: { type: 'int', min: 0, max: 63 },
          value: {
            type: 'object',
            fields: { spi: { type: 'int_list', min: 1, max: 65535 } },
          },
        },
      },
    },
  },
}
const withLink = withExtensions(schema, EXTENSIONS)

test('withExtensions adds sections and link keys without changing the base', () => {
  assert.ok(withLink.top_level_keys.includes('link'))
  assert.deepEqual(Object.keys(withLink.match.keys.link.keys), [
    'vcid',
    'protection',
  ])
  assert.ok(!schema.top_level_keys.includes('link'))
  assert.equal(schema.match.keys.link.keys, undefined)
})

test('link conditions need an extension', () => {
  const rule = { id: 'r', action: 'ALLOW', match: { link: { vcid: [1] } } }
  assert.match(
    validate(doc([rule]), schema).join(),
    /no extension on this interface provides link information/,
  )
  assert.deepEqual(validate(doc([rule]), withLink), [])
})

test('bad link conditions are reported', () => {
  const bad = (link) =>
    validate(
      doc([{ id: 'r', action: 'ALLOW', match: { link } }]),
      withLink,
    ).join()
  assert.match(bad({ spi: [1] }), /unknown key 'spi'/)
  assert.match(bad({ vcid: [64] }), /<= 63/)
  assert.match(bad({ protection: ['encrypted'] }), /must be one of/)
  assert.match(bad({ vcid: [] }), /non-empty list/)
  assert.match(bad({}), /non-empty object/)
})

test('extension sections are checked against their schema', () => {
  const good = {
    scid: 3,
    idle: 'drop',
    virtual_channels: { 1: { spi: [5] }, 4: { spi: [6] } },
  }
  assert.deepEqual(validate(doc([], { link: good }), withLink), [])
  const errors = validate(
    doc([], {
      link: { idle: 'maybe', virtual_channels: { 99: { spi: [0] } }, x: 1 },
    }),
    withLink,
  ).join('\n')
  assert.match(errors, /link has unknown key 'x'/)
  assert.match(errors, /link needs 'scid'/)
  assert.match(errors, /link.idle must be one of/)
  assert.match(errors, /link.virtual_channels key '99' must be <= 63/)
  assert.match(errors, /link.virtual_channels.99.spi\[0\] must be >= 1/)
  // without the extension the section is an unknown top-level key
  assert.match(
    validate(doc([], { link: good }), schema).join(),
    /unknown key 'link'/,
  )
})

test('settings: defaults stay out of the file', () => {
  const d = doc([])
  assert.equal(settingValue(d, schema, 'untrust_on_first_packet_reject'), true)
  setSetting(d, schema, 'untrust_on_first_packet_reject', false)
  assert.deepEqual(d.settings, { untrust_on_first_packet_reject: false })
  assert.deepEqual(validate(d, schema), [])
  setSetting(d, schema, 'untrust_on_first_packet_reject', true)
  assert.equal(d.settings, undefined)
  assert.match(
    validate(doc([], { settings: { nope: true } }), schema).join(),
    /settings has unknown key 'nope'/,
  )
  assert.match(
    validate(
      doc([], { settings: { untrust_on_first_packet_reject: 'yes' } }),
      schema,
    ).join(),
    /true or false/,
  )
})

test('linkSummary describes link conditions', () => {
  assert.equal(
    linkSummary({ vcid: [4, 5], protection: ['auth'] }),
    'link vcid 4, 5; link protection auth',
  )
  assert.equal(linkSummary(undefined), '')
})

// ---- the SDLS extension plugin, when it is checked out next to this one ----

const sdlsRoot = new URL('../openc3-cosmos-eaglegate-sdls/', root)
const sdlsExtension = (() => {
  try {
    return JSON.parse(
      readFileSync(new URL('tests/fixtures/extension.json', sdlsRoot)),
    )
  } catch {
    return null
  }
})()

test(
  'the page accepts the SDLS plugin shipped rules',
  { skip: !sdlsExtension && 'openc3-cosmos-eaglegate-sdls not found' },
  () => {
    const sdlsRules = JSON.parse(
      readFileSync(
        new URL('targets/EAGLEGATE_SDLS/rules/firewall_rules.json', sdlsRoot),
      ),
    )
    const sdlsSchema = withExtensions(schema, { link: sdlsExtension })
    assert.deepEqual(validate(sdlsRules, sdlsSchema), [])
    // and catches what the Python parser refuses
    const broken = clone(sdlsRules)
    broken.link.scid = 5000
    broken.link.virtual_channels['9'] = { spi: [5] }
    broken.link.security_associations['7'].mode = 'secret'
    const errors = validate(broken, sdlsSchema).join('\n')
    assert.match(errors, /link.scid must be <= 1023/)
    assert.match(errors, /link.virtual_channels key '9' must be <= 7/)
    assert.match(errors, /link.security_associations.7.mode must be one of/)
    // an empty sync marker is a real value
    broken.link = { ...sdlsRules.link, asm: '' }
    assert.deepEqual(validate(broken, sdlsSchema), [])
  },
)
