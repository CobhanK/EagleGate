// Run with: pnpm test (node --test, no extra dependencies)
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { actionColor, auditParams, fieldRows, whoText } from './auditLog.js'

const ESC = String.fromCharCode(0x1b)

test('auditParams keeps only checked filters', () => {
  assert.deepEqual(
    auditParams('EAGLEGATE_INT', {
      limit: 20,
      action: ' reload_rules ',
      ok: 'false',
      search: '',
    }),
    {
      interface: 'EAGLEGATE_INT',
      limit: '20',
      action: 'RELOAD_RULES',
      ok: 'false',
    },
  )
  assert.deepEqual(
    auditParams(
      'X',
      { action: 'x; drop', ok: 'maybe', search: 'alice' },
      '5-0',
    ),
    { interface: 'X', limit: '50', search: 'alice', before: '5-0' },
  )
})

test('whoText prefers the authenticated user', () => {
  assert.equal(whoText({ user: 'carol', requested_by: 'x' }), 'carol')
  assert.equal(whoText({ requested_by: 'alice' }), 'alice (as reported)')
  assert.equal(whoText({}), '-')
})

test('fieldRows shows objects as JSON and cleans text', () => {
  assert.deepEqual(
    fieldRows({ version: '2', changes: { added: ['a'] }, note: `x${ESC}y` }),
    [
      {
        name: 'changes',
        value: '{\n "added": [\n  "a"\n ]\n}',
        structured: true,
      },
      { name: 'note', value: 'x\\x1by', structured: false },
      { name: 'version', value: '2', structured: false },
    ],
  )
  // A control character INSIDE a structured value is still escaped
  assert.equal(
    fieldRows({ changes: { added: [`a${ESC}`] } })[0].value,
    '{\n "added": [\n  "a\\\\x1b"\n ]\n}',
  )
  assert.deepEqual(fieldRows(null), [])
})

test('actionColor groups actions', () => {
  assert.equal(actionColor('RELOAD_RULES'), 'primary')
  assert.equal(actionColor('SPIKE'), 'error')
  assert.equal(actionColor('RELOAD_KEYS'), 'teal')
  assert.equal(actionColor('REVIEW'), undefined)
})
