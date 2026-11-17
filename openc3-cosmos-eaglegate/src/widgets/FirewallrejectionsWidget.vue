<!--
  FIREWALLREJECTIONS: the 10 most recent firewall rejections in a Telemetry
  Viewer screen, with the spike warning state.

    FIREWALLREJECTIONS <TARGET>     (EAGLEGATE, or EAGLEGATE_SDLS for SDLS interfaces)

  Reads FIREWALL_RECENT RECENT_JSON and FIREWALL_STATUS SPIKE_STATE /
  REJECT_RATE / SPIKE_REASON through the screen's normal item polling. Shows
  metadata and reasons only (the firewall never publishes bytes); everything
  is cleaned again (recentRejections.js) and rendered as text, never v-html.
  A row links to its entry on the EagleGate page's Quarantine tab, which only
  admins can open.

  Light on purpose: no @openc3/vue-common import (the screen passes plain
  props and listens for addItem/deleteItem), no CSS file (inline styles), no
  extra packages.
-->
<template>
  <div :style="boxStyle">
    <div :style="headerStyle">
      <strong>Recent rejections</strong>
      <span style="opacity: 0.7">{{ target }}</span>
      <span style="flex: 1 1 auto"></span>
      <v-chip size="x-small" :color="spike.color" :title="spikeReason">
        {{ spike.label }}
      </v-chip>
      <span :title="spikeReason">{{ rateText }}</span>
    </div>
    <div v-if="!rows.length" style="opacity: 0.7; padding: 4px 0">
      No rejections since the interface started
    </div>
    <div v-else style="overflow-x: auto">
      <table :style="tableStyle">
        <thead>
          <tr>
            <th :style="cellStyle">Time</th>
            <th :style="cellStyle">Stage</th>
            <th :style="cellStyle">Packet</th>
            <th :style="cellStyle">Rule</th>
            <th :style="cellStyle">Seq</th>
            <th :style="cellStyle">Bytes</th>
            <th :style="cellStyle">Reason</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(row, index) in rows" :key="row.entry_id || index">
            <td :style="cellStyle" :title="row.time">
              <a
                v-if="href(row)"
                :href="href(row)"
                target="_blank"
                rel="noopener noreferrer"
                title="Open in the quarantine (admins only)"
                >{{ shortTime(row.time) }}</a
              >
              <span v-else>{{ shortTime(row.time) }}</span>
            </td>
            <td :style="cellStyle">
              <v-chip size="x-small" :color="stageColor(row.stage)">{{
                row.stage || '-'
              }}</v-chip>
            </td>
            <td :style="cellStyle" :title="row.link">
              {{ packetLabel(row) }}
            </td>
            <td :style="cellStyle">
              <code>{{ ruleLabel(row) }}</code>
            </td>
            <td :style="cellStyle">{{ row.seq_count ?? '' }}</td>
            <td :style="cellStyle">{{ row.length ?? '' }}</td>
            <td :style="reasonStyle" :title="row.reason">{{ row.reason }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script>
import {
  STAGE_COLORS,
  packetLabel,
  parseRecent,
  quarantineHref,
  ruleLabel,
  shortTime,
  spikeInfo,
} from './recentRejections.js'

const TYPE = 'CONVERTED'

export default {
  inheritAttrs: false,
  props: {
    parameters: { type: Array, default: () => [] },
    settings: { type: Array, default: () => [] },
    screenValues: { type: Object, default: () => ({}) },
    screenTimeZone: { type: String, default: 'local' },
    target: { type: String, default: null },
    line: { type: String, default: '' },
    lineNumber: { type: Number, default: 0 },
    widgetIndex: { type: Number, default: null },
  },
  emits: ['addItem', 'deleteItem'],
  data() {
    return {
      boxStyle: {
        padding: '6px 8px',
        minWidth: '520px',
        flex: '1 1 auto',
        fontSize: '0.8rem',
      },
      headerStyle: {
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        marginBottom: '4px',
      },
      tableStyle: { borderCollapse: 'collapse', width: '100%' },
      cellStyle: {
        padding: '2px 6px',
        textAlign: 'left',
        whiteSpace: 'nowrap',
        borderBottom: '1px solid rgba(128, 128, 128, 0.25)',
        verticalAlign: 'top',
      },
      reasonStyle: {
        padding: '2px 6px',
        borderBottom: '1px solid rgba(128, 128, 128, 0.25)',
        maxWidth: '36em',
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        whiteSpace: 'nowrap',
      },
    }
  },
  computed: {
    targetName() {
      return String(this.parameters[0] || 'EAGLEGATE').toUpperCase()
    },
    ids() {
      const t = this.targetName
      return {
        recent: `${t}__FIREWALL_RECENT__RECENT_JSON__${TYPE}`,
        state: `${t}__FIREWALL_STATUS__SPIKE_STATE__${TYPE}`,
        rate: `${t}__FIREWALL_STATUS__REJECT_RATE__${TYPE}`,
        reason: `${t}__FIREWALL_STATUS__SPIKE_REASON__${TYPE}`,
      }
    },
    rows() {
      return parseRecent(this.valueOf('recent'))
    },
    spike() {
      return spikeInfo(this.valueOf('state'))
    },
    spikeReason() {
      const reason = this.valueOf('reason')
      return typeof reason === 'string' ? reason : ''
    },
    rateText() {
      const rate = Number(this.valueOf('rate'))
      return Number.isFinite(rate) ? `${rate.toFixed(0)}/min` : ''
    },
  },
  created() {
    Object.values(this.ids).forEach((id) => this.$emit('addItem', id))
  },
  unmounted() {
    Object.values(this.ids).forEach((id) => this.$emit('deleteItem', id))
  },
  methods: {
    packetLabel,
    ruleLabel,
    shortTime,
    valueOf(key) {
      const value = this.screenValues?.[this.ids[key]]
      return Array.isArray(value) ? value[0] : undefined
    },
    stageColor(stage) {
      return STAGE_COLORS[stage]
    },
    href(row) {
      return quarantineHref(row)
    },
  },
}
</script>
