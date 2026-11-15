// Run with: pnpm test (node --test, no extra dependencies)
// The Link status tab's data handling: the firewall's traffic counts and the
// panels/actions extensions declare (checked in Python by
// tests/test_link_status.py and the SDLS plugin's tests).
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

import {
  EMPTY,
  actionForm,
  actionParams,
  actionProblems,
  apidRows,
  extensionViews,
  formatValue,
  getPath,
  panelRows,
  panelValues,
  rate,
  timeAgo,
} from './linkStatus.js'

const ACTION = {
  name: 'reset_thing',
  command: 'RESET_THING',
  title: 'Reset thing',
  params: {
    which: { type: 'string', required: true },
    floor: { type: 'int', min: 0 },
  },
}
const DETAILS = {
  frames: { received: 12, rejected: 0, in_lock: true },
  replay: {
    counters: {
      7: { kind: 'sn', value: '41', floor: null },
      8: { kind: 'iv', value: null, floor: '256' },
    },
  },
  frame_counts: { 1: 200, 5: 7 },
}

test('getPath follows dotted names and stops at missing steps', () => {
  assert.equal(getPath(DETAILS, 'replay.counters.7.value'), '41')
  assert.equal(getPath(DETAILS, 'replay.nope.x'), undefined)
  assert.equal(getPath(null, 'a'), undefined)
  assert.equal(getPath(DETAILS, 'frames.received.deeper'), undefined)
})

test('values are shown as text, with a dash for nothing', () => {
  assert.equal(formatValue(null), EMPTY)
  assert.equal(formatValue(''), EMPTY)
  assert.equal(formatValue(true), 'yes')
  assert.equal(formatValue(1234567), '1,234,567')
  assert.equal(formatValue('18446744073709551615'), '18446744073709551615') // counters stay exact
  assert.equal(formatValue({ a: 1 }), '{"a":1}')
})

test('a values panel keeps its order and titles', () => {
  const panel = {
    kind: 'values',
    path: 'frames',
    items: { rejected: 'Rejected', received: 'Received', missing: 'Missing' },
  }
  assert.deepEqual(panelValues(panel, DETAILS), [
    { key: 'rejected', title: 'Rejected', value: '0' },
    { key: 'received', title: 'Received', value: '12' },
    { key: 'missing', title: 'Missing', value: EMPTY },
  ])
  // Without items: every key
  assert.deepEqual(
    panelValues({ path: 'frames' }, DETAILS).map((v) => v.key),
    ['received', 'rejected', 'in_lock'],
  )
  assert.deepEqual(panelValues({ path: 'nowhere' }, DETAILS), [])
})

test('table rows come from objects, plain values and lists', () => {
  const counters = {
    path: 'replay.counters',
    columns: { value: 'Last', floor: 'Floor' },
  }
  assert.deepEqual(panelRows(counters, DETAILS), [
    { key: '7', cells: { value: '41', floor: EMPTY } },
    { key: '8', cells: { value: EMPTY, floor: '256' } },
  ])
  const channels = { path: 'frame_counts', columns: { value: 'Last count' } }
  assert.deepEqual(panelRows(channels, DETAILS)[0], {
    key: '1',
    cells: { value: '200' },
  })
  const list = { path: 'items', columns: { name: 'Name' } }
  assert.deepEqual(panelRows(list, { items: [{ name: 'a' }] }), [
    { key: '0', cells: { name: 'a' } },
  ])
  assert.deepEqual(panelRows(list, {}), [])
})

test('only extensions with panels or actions get a view, with their details', () => {
  const extensions = {
    link: { name: 'sdls', details_key: 'sdls', panels: [{}], actions: [] },
    other: { name: 'plain', details_key: '', panels: [], actions: [] },
    gone: { name: 'old', details_key: 'old', panels: [{}], actions: [] },
  }
  const protocols = [{ name: 'X', sdls: DETAILS }, { name: 'Y' }]
  const views = extensionViews(extensions, protocols)
  assert.deepEqual(
    views.map((v) => [v.extension.name, v.data === DETAILS]),
    [
      ['sdls', true],
      ['old', false],
    ],
  )
  assert.equal(views[1].data, null)
})

test('a row action fixes the row key; other params stay editable', () => {
  const row = { action: 'reset_thing', title: 'Reset', row_param: 'which' }
  assert.deepEqual(actionForm(ACTION, row, '7'), {
    fixed: { which: '7' },
    fields: { floor: ACTION.params.floor },
  })
  const all = { action: 'reset_thing', title: 'All', params: { which: 'all' } }
  assert.deepEqual(Object.keys(actionForm(ACTION, all).fields), ['floor'])
  assert.deepEqual(Object.keys(actionForm(ACTION).fields), ['which', 'floor'])
})

test('params: fixed values win and empty fields are left out', () => {
  assert.deepEqual(actionParams({ which: '7' }, { which: 'x', floor: '' }), {
    which: '7',
  })
  assert.deepEqual(actionParams({}, { floor: 5, note: null }), { floor: 5 })
})

test('action params are checked like the firewall would', () => {
  assert.deepEqual(actionProblems(ACTION, { which: 'all' }), [])
  assert.match(actionProblems(ACTION, {}).join(), /needs 'which'/)
  assert.match(actionProblems(ACTION, { which: '1', floor: -1 }).join(), />= 0/)
  assert.match(
    actionProblems(ACTION, { which: '1', surprise: 1 }).join(),
    /unknown key/,
  )
})

test('APID rows are sorted numerically', () => {
  const rows = apidRows({
    apids: { '0x100': { packets: 1 }, '0x002': { packets: 5 } },
  })
  assert.deepEqual(
    rows.map((r) => r.apid),
    ['0x002', '0x100'],
  )
  assert.equal(rows[0].packets, 5)
  assert.deepEqual(apidRows(undefined), [])
})

test('rate is packets per second between polls, unknown after a restart', () => {
  assert.equal(rate({ packets: 10, at: 0 }, { packets: 30, at: 4000 }), 5)
  assert.equal(rate({ packets: 30, at: 0 }, { packets: 2, at: 2000 }), null)
  assert.equal(rate(null, { packets: 2, at: 2000 }), null)
  assert.equal(rate({ packets: 1, at: 5 }, { packets: 2, at: 5 }), null)
})

test('timeAgo', () => {
  const now = Date.parse('2026-11-09T12:00:00Z')
  assert.equal(timeAgo('2026-11-09T11:59:48.500000Z', now), '12 s ago')
  assert.equal(timeAgo('2026-11-09T11:30:00Z', now), '30 min ago')
  assert.equal(timeAgo('2026-11-09T06:00:00Z', now), '6 h ago')
  assert.equal(timeAgo('2026-11-01T12:00:00Z', now), '8 days ago')
  assert.equal(timeAgo(null, now), EMPTY)
  assert.equal(timeAgo('garbage', now), 'garbage')
})

// ---- the SDLS extension plugin, when it is checked out next to this one ----

const root = new URL('../../../', import.meta.url)
const sdlsExtension = (() => {
  try {
    return JSON.parse(
      readFileSync(
        new URL(
          '../openc3-cosmos-eaglegate-sdls/tests/fixtures/extension.json',
          root,
        ),
      ),
    )
  } catch {
    return null
  }
})()

test(
  'every SDLS panel button opens a form the page can fill',
  { skip: !sdlsExtension && 'openc3-cosmos-eaglegate-sdls not found' },
  () => {
    const actions = Object.fromEntries(
      sdlsExtension.actions.map((a) => [a.name, a]),
    )
    assert.ok(sdlsExtension.panels.length > 0)
    for (const panel of sdlsExtension.panels) {
      for (const binding of [
        ...(panel.actions || []),
        ...(panel.row_actions || []),
      ]) {
        const action = actions[binding.action]
        assert.ok(action, binding.action)
        const { fixed, fields } = actionForm(action, binding, '7')
        // What the admin would send with the required fields filled in
        const edited = Object.fromEntries(
          Object.entries(fields)
            .filter(([, spec]) => spec.required)
            .map(([name]) => [name, '7']),
        )
        assert.deepEqual(
          actionProblems(action, actionParams(fixed, edited)),
          [],
          binding.title,
        )
      }
    }
  },
)
