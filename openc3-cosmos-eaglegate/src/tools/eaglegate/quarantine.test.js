// Run with: pnpm test (node --test, no extra dependencies)
// The Quarantine tab's data handling (the microservice side is checked by
// tests/test_quarantine_review.py).
import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  DEFAULT_LIMIT,
  MAX_LIMIT,
  asciiChar,
  canRelease,
  ccsdsHeader,
  clampLimit,
  hexBytes,
  hexDump,
  isEntryId,
  linkRows,
  listParams,
  metadataRows,
  noteProblem,
  reviewState,
  safeText,
} from './quarantine.js'

test('safeText escapes control and invisible characters', () => {
  assert.equal(safeText('plain'), 'plain')
  assert.equal(safeText('\u001b[31mred'), '\\x1b[31mred')
  assert.equal(safeText('abc\u202edcba'), 'abc\\u202edcba')
  assert.equal(safeText('a\u200bb\nc'), 'a\\u200bb\\x0ac')
  assert.equal(safeText(null), '')
  assert.equal(safeText('x'.repeat(5), 3), 'xxx…')
  // Markup stays text: Vue escapes it when rendering
  assert.equal(
    safeText('<img src=x onerror=alert(1)>'),
    '<img src=x onerror=alert(1)>',
  )
})

test('clampLimit keeps "most recent N" within 1..1000', () => {
  assert.equal(clampLimit('25'), 25)
  assert.equal(clampLimit(0), 1)
  assert.equal(clampLimit(99999), MAX_LIMIT)
  assert.equal(clampLimit('abc'), DEFAULT_LIMIT)
  assert.equal(clampLimit(''), DEFAULT_LIMIT)
})

test('listParams leaves out empty filters', () => {
  assert.deepEqual(
    listParams('EAGLEGATE_INT', {
      limit: 20,
      stage: '',
      apid: ' 0x3 ',
      search: '',
    }),
    {
      interface: 'EAGLEGATE_INT',
      stream: 'quarantine',
      limit: '20',
      apid: '0x3',
    },
  )
  assert.deepEqual(
    listParams('X', { stream: 'raw', review: 'threat', limit: 5000 }, '17-0'),
    {
      interface: 'X',
      stream: 'raw',
      limit: '1000',
      review: 'threat',
      before: '17-0',
    },
  )
})

test('noteProblem matches what the microservice refuses', () => {
  assert.equal(noteProblem(''), null)
  assert.equal(noteProblem('rule too strict'), null)
  assert.match(noteProblem('a\nb'), /plain text/)
  assert.match(noteProblem('x'.repeat(257)), /256/)
  // The global regex must not keep state between calls
  assert.match(noteProblem('a\u202e'), /plain text/)
  assert.match(noteProblem('b\u202e'), /plain text/)
})

test('hexBytes refuses anything but even hex', () => {
  assert.deepEqual(hexBytes('00ff10'), [0, 255, 16])
  assert.deepEqual(hexBytes('0'), [])
  assert.deepEqual(hexBytes('zz'), [])
  assert.deepEqual(hexBytes(undefined), [])
})

test('hexDump shows only printable ASCII as characters', () => {
  const data = '00414243' + '1b' + '3c7363726970743e' + 'ff' + '7e7f'
  const rows = hexDump(data, 8)
  assert.deepEqual(rows[0], {
    offset: '0000',
    hex: '00 41 42 43 1b 3c 73 63',
    ascii: '.ABC.<sc',
  })
  assert.equal(rows[1].offset, '0008')
  assert.equal(rows[1].ascii, 'ript>.~.')
  assert.equal(rows[1].hex.length, 8 * 3 - 1)
  assert.equal(asciiChar(0x20), ' ')
  assert.equal(asciiChar(0x80), '.')
})

test('ccsdsHeader decodes the primary header', () => {
  // APID 3 TLM, unsegmented, count 5, 4 data bytes
  const hex = '0003c0050003' + '00000000'
  assert.deepEqual(ccsdsHeader(hex), {
    version: 0,
    type: 'TLM',
    secondary_header: 'no',
    apid: '0x003',
    sequence_flags: 'unsegmented',
    sequence_count: 5,
    length_field: 3,
    declared_length: 10,
    actual_length: 10,
  })
  assert.equal(ccsdsHeader('1803'), null)
  assert.equal(ccsdsHeader('f8070000ffff').type, 'CMD')
  assert.equal(ccsdsHeader('f8070000ffff').version, 7)
})

test('metadataRows skips empty values and cleans text', () => {
  const rows = metadataRows({
    id: '1-0',
    stage: 'RULE',
    rule_id: 'deny\u202e',
    rule_type: 'match',
    layer: '',
    truncated: false,
    releasable: true,
  })
  assert.deepEqual(
    rows.map((r) => r.name),
    ['Entry id', 'Stage', 'Rule', 'Truncated', 'Releasable'],
  )
  assert.equal(rows[2].value, 'deny\\u202e (match)')
})

test('linkRows shows extension link values as text', () => {
  assert.deepEqual(linkRows({ vcid: 4, spi: { id: 7 } }), [
    { name: 'vcid', value: '4' },
    { name: 'spi', value: '{"id":7}' },
  ])
  assert.deepEqual(linkRows(null), [])
})

test('canRelease only for whole framed entries not yet released', () => {
  const entry = {
    stream: 'quarantine',
    releasable: true,
    truncated: false,
    released: null,
    sha256: 'a'.repeat(64),
  }
  assert.equal(canRelease(entry), true)
  assert.equal(canRelease({ ...entry, stream: 'raw' }), false)
  assert.equal(canRelease({ ...entry, releasable: false }), false)
  assert.equal(canRelease({ ...entry, released: { time: 't' } }), false)
  assert.equal(canRelease({ ...entry, sha256: 'x' }), false)
})

test('reviewState and isEntryId', () => {
  assert.equal(reviewState('threat').color, 'error')
  assert.equal(reviewState('released').title, 'Released')
  assert.equal(reviewState('odd\u202e').title, 'odd\\u202e')
  assert.equal(isEntryId('1731700000000-0'), true)
  assert.equal(isEntryId('1-0\n'), false)
})
