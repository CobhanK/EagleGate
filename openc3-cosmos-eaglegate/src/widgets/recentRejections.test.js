// Run with: pnpm test (node --test, no extra dependencies)
// The FIREWALLREJECTIONS widget's data handling (the firewall side is checked
// by tests/test_recent_rejections.py).
import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  MAX_ROWS,
  packetLabel,
  parseRecent,
  quarantineFocus,
  quarantineHref,
  ruleLabel,
  shortTime,
  spikeInfo,
} from './recentRejections.js'

// Built from code points so no invisible character sits in this source file
const RLO = String.fromCharCode(0x202e)
const ESC = String.fromCharCode(0x1b)

const ROW = {
  time: '2026-11-16T12:34:56.123456Z',
  interface: 'EAGLEGATE_INT',
  stage: 'RULE',
  rule_id: 'auth-hk',
  rule_type: 'authenticity',
  layer: '',
  apid: '0x002',
  packet_type: 'TLM',
  packet: 'EAGLEGATE HK_STATUS',
  seq_count: 7,
  length: 11,
  link: {},
  reason: "DENY by rule 'auth-hk': MAC mismatch",
  entry_id: '1731700000000-0',
}

test('parseRecent keeps clean rows and drops malformed input', () => {
  assert.deepEqual(parseRecent(''), [])
  assert.deepEqual(parseRecent('not json'), [])
  assert.deepEqual(parseRecent('{"a": 1}'), [])
  assert.deepEqual(parseRecent(null), [])
  const rows = parseRecent(JSON.stringify([ROW, 5, null, [1], ROW]))
  assert.equal(rows.length, 2)
  assert.equal(rows[0].packet, 'EAGLEGATE HK_STATUS')
  assert.equal(rows[0].seq_count, 7)
  const many = parseRecent(JSON.stringify(Array(25).fill(ROW)))
  assert.equal(many.length, MAX_ROWS)
})

test('parseRecent cleans text again and ignores wrong types', () => {
  const [row] = parseRecent(
    JSON.stringify([
      {
        ...ROW,
        reason: `evil ${ESC}[2J ${RLO}txt`,
        rule_id: { toString: 1 },
        seq_count: '7',
        length: 1.5,
        link: { vcid: 5, ['spi' + RLO]: 'x' },
      },
    ]),
  )
  assert.equal(row.reason, 'evil \\x1b[2J \\u202etxt')
  assert.equal(row.rule_id, '')
  assert.equal(row.seq_count, null)
  assert.equal(row.length, null)
  assert.equal(row.link, 'vcid=5 spi\\u202e=x')
})

test('packetLabel and ruleLabel describe what was rejected', () => {
  assert.equal(packetLabel(ROW), 'EAGLEGATE HK_STATUS')
  assert.equal(packetLabel({ ...ROW, packet: 'unknown' }), 'TLM APID 0x002')
  assert.equal(
    packetLabel({ stage: 'LINK', layer: 'sdls', packet: '', apid: '' }),
    'sdls frame',
  )
  assert.equal(packetLabel({ stage: 'STRUCTURAL' }), 'malformed bytes')
  assert.equal(ruleLabel(ROW), 'auth-hk')
  assert.equal(ruleLabel({ layer: 'sdls', stage: 'LINK' }), 'link:sdls')
  assert.equal(ruleLabel({ stage: 'DEFAULT' }), 'DEFAULT')
})

test('shortTime and spikeInfo', () => {
  assert.equal(shortTime(ROW.time), '12:34:56Z')
  assert.equal(shortTime('odd'), 'odd')
  assert.equal(spikeInfo('SPIKE').color, 'error')
  assert.equal(spikeInfo('ELEVATED').color, 'warning')
  assert.equal(spikeInfo('NORMAL').label, 'Normal')
  assert.equal(spikeInfo(undefined).label, '-')
})

test('quarantineHref links only well-formed entries', () => {
  const href = quarantineHref(ROW)
  assert.equal(
    href,
    '/tools/eaglegate?tab=quarantine&interface=EAGLEGATE_INT&stream=quarantine&entry=1731700000000-0',
  )
  assert.match(quarantineHref({ ...ROW, stage: 'LINK' }), /stream=raw/)
  assert.equal(quarantineHref({ ...ROW, entry_id: '' }), null)
  assert.equal(quarantineHref({ ...ROW, interface: 'a/../b' }), null)
  assert.equal(quarantineHref({ ...ROW, entry_id: '1-0"><x' }), null)
})

test('quarantineFocus reads back only checked values', () => {
  assert.deepEqual(
    quarantineFocus(new URL(quarantineHref(ROW), 'http://x').search),
    {
      tab: 'quarantine',
      interface: 'EAGLEGATE_INT',
      stream: 'quarantine',
      entry: '1731700000000-0',
    },
  )
  assert.deepEqual(quarantineFocus('?tab=rules&entry=1-0'), {})
  assert.deepEqual(
    quarantineFocus('?tab=quarantine&interface=../x&stream=audit&entry=1-0%0A'),
    { tab: 'quarantine' },
  )
})
