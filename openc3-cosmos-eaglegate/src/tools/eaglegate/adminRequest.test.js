import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import {
  REASON_CHARS,
  buildAdminRequest,
  randomNonce,
  reasonProblem,
} from './adminRequest.js'

const root = new URL('../../../', import.meta.url)
const example = JSON.parse(
  readFileSync(new URL('tests/fixtures/admin_request_example.json', root)),
)

test('builds exactly the request the firewall test accepts', () => {
  const { inputs } = example
  assert.equal(
    buildAdminRequest({ ...inputs, now: new Date(inputs.now) }),
    example.text,
  )
})

test('nonces are 32 hex characters and differ', () => {
  const a = randomNonce()
  assert.match(a, /^[0-9a-f]{32}$/)
  assert.notEqual(a, randomNonce())
})

test('reason checks mirror the firewall', () => {
  assert.equal(reasonProblem('rebooted'), null)
  assert.ok(reasonProblem(''))
  assert.ok(reasonProblem('   '))
  assert.ok(reasonProblem('x'.repeat(REASON_CHARS + 1)))
  assert.ok(reasonProblem('two\nlines'))
  assert.ok(reasonProblem('abc\u202Edef'))
  assert.equal(reasonProblem('café ok'), null)
})

test('the reason is trimmed and requested_by is capped', () => {
  const doc = JSON.parse(
    buildAdminRequest({
      kind: 'restore_trust',
      reason: '  why  ',
      requestedBy: 'x'.repeat(100),
    }),
  )
  assert.equal(doc.reason, 'why')
  assert.equal(doc.requested_by.length, 64)
  assert.deepEqual(Object.keys(doc).sort(), [
    'kind',
    'nonce',
    'params',
    'reason',
    'requested_at',
    'requested_by',
  ])
})
