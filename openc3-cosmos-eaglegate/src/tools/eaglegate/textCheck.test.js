// Run with: pnpm test. The same cases run against the firewall's Python copy
// (tests/test_text_rule.py), so both give identical results and reasons.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

import { newRule, validate, warnings } from './rulesModel.js'
import {
  checkField,
  compileText,
  describeAllowed,
  sampleBytes,
} from './textCheck.js'

const root = new URL('../../../', import.meta.url)
const schema = JSON.parse(
  readFileSync(new URL('public/eaglegate_rules_schema.json', root)),
)
const { cases } = JSON.parse(
  readFileSync(new URL('tests/fixtures/text_rule_cases.json', root)),
)

const bytes = (hex) =>
  Uint8Array.from(hex.match(/../g) || [], (h) => parseInt(h, 16))

for (const c of cases) {
  test(`shared case: ${c.name}`, () => {
    assert.equal(
      checkField(compileText(c.params, schema), bytes(c.field_hex)),
      c.expect,
    )
  })
}

function textDoc(params) {
  return {
    version: 1,
    default_action: 'DENY',
    rules: [
      {
        id: 't',
        type: 'text',
        action: 'DENY',
        match: {},
        params: {
          fields: [{ name: 'F', offset: 6, length: 16 }],
          ...params,
        },
      },
    ],
  }
}

test('bad text settings are reported before upload', () => {
  const check = (params, pattern) =>
    assert.match(validate(textDoc(params), schema).join('\n'), pattern)
  check({ encoding: 'raw', profile: 'path' }, /profile does not apply/)
  check({ profile: 'custom' }, /custom needs also_allow/)
  check({ also_allow: '\t' }, /not printable ASCII/)
  check({ encoding: 'utf8', also_allow: '‮' }, /can never be allowed/)
  check({ encoding: 'raw', allow_bytes: '0x00-0x1FF' }, /within 0x00-0xFF/)
  check({ encoding: 'raw', deny_substrings: ['1b5'] }, /must be hex/)
  check({ min_length: 5, max_length: 2 }, /min_length > max_length/)
  check({ fields: [] }, /at least 1/)
  check(
    { fields: [{ name: 'bad;', offset: 6, length: 4 }] },
    /may only use letters/,
  )
  assert.deepEqual(validate(textDoc({ profile: 'path' }), schema), [])
})

test('every preset makes a valid rule', () => {
  for (const preset of schema.rule_types.text.presets) {
    const rule = newRule('text', schema, [], preset)
    assert.equal(rule.id, `${preset.name}-1`)
    const doc = { version: 1, default_action: 'DENY', rules: [rule] }
    assert.deepEqual(validate(doc, schema), [], preset.name)
  }
})

test('a raw rule that allows everything is warned about', () => {
  const doc = textDoc({ encoding: 'raw', padding: 'none' })
  assert.match(warnings(doc, schema).join(), /allows every byte value/)
})

test('the preview names what is allowed', () => {
  assert.equal(
    describeAllowed(compileText({ profile: 'hex' }, schema)),
    '0-9 A-F a-f',
  )
  assert.equal(
    describeAllowed(
      compileText({ encoding: 'raw', allow_bytes: '0x00-0x7F' }, schema),
    ),
    'bytes 0x00-0x7F',
  )
  assert.match(
    describeAllowed(compileText({ encoding: 'utf8' }, schema)),
    /plus other printable non-ASCII/,
  )
})

test('sample box: text as UTF-8, raw as hex', () => {
  assert.deepEqual([...sampleBytes('é', 'utf8')], [0xc3, 0xa9])
  assert.deepEqual([...sampleBytes('1b 5b', 'raw')], [0x1b, 0x5b])
  assert.equal(sampleBytes('xyz', 'raw'), null)
})
