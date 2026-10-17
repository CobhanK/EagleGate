// Run with: pnpm test (node --test, no extra dependencies)
// Validation here only gives early feedback; the firewall's Python parser is
// the authority. These tests check the page agrees with it on the shipped
// rules file and on the mistakes the parser's own tests cover.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

import {
  fromInput,
  lineDiff,
  mayOverlap,
  newRule,
  toInt,
  toNumber,
  validate,
  warnings,
  withBumpedVersion,
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
