<!--
  Link status: what one interface's firewall is seeing right now, refreshed
  every few seconds while the tab is open.

  The firewall counts every packet it judges (traffic, per APID, sequence
  gaps). Extensions in front of it (e.g. eaglegate-sdls) add panels and admin
  actions that they describe themselves (eaglegate_extensions.py, "Panels and
  actions"), so this component draws them without knowing what they are.

  Admin actions use the same two steps as Restore trust: upload an admin
  request, then send the protocol command with its sha256 (rulesStore.js
  adminAction). The firewall refuses it for anyone who could not upload.
-->
<template>
  <div>
    <v-alert v-if="error" type="error" variant="tonal" class="ma-2">
      {{ error }}
    </v-alert>

    <!-- Traffic: every packet the firewall judged -->
    <v-card v-if="firewall" class="ma-2">
      <v-card-title class="d-flex align-center">
        Traffic
        <v-chip
          size="small"
          class="ml-2"
          :color="firewall.connection_untrusted ? 'error' : 'success'"
        >
          {{ firewall.connection_untrusted ? 'untrusted' : 'trusted' }}
        </v-chip>
        <v-spacer />
        <span class="text-caption mr-2"
          >since {{ traffic.since || '-' }}; refreshed {{ refreshedText }}</span
        >
        <v-btn
          variant="text"
          icon="mdi-refresh"
          aria-label="Refresh now"
          @click="poll"
        />
      </v-card-title>
      <v-card-text>
        <v-row dense>
          <v-col v-for="item in trafficItems" :key="item.title" cols="6" md="2">
            <div class="text-caption">{{ item.title }}</div>
            <div :class="item.warn ? 'text-warning' : ''">{{ item.value }}</div>
          </v-col>
        </v-row>
        <div class="text-caption mt-2">
          Rejected by stage:
          <v-chip
            v-for="(count, stage) in firewall.rejected_by_stage"
            :key="stage"
            size="x-small"
            class="mr-1"
            :color="count ? 'error' : undefined"
            >{{ stage }} {{ formatValue(count) }}</v-chip
          >
        </div>
      </v-card-text>
    </v-card>

    <!-- Per APID -->
    <v-card v-if="firewall" class="ma-2">
      <v-card-title>Packets by APID</v-card-title>
      <v-card-text>
        <div v-if="!apids.length" class="text-caption">
          No packets judged yet on {{ interfaceName }}.
        </div>
        <v-table v-else density="compact">
          <thead>
            <tr>
              <th>APID</th>
              <th class="text-right">Packets</th>
              <th class="text-right">Allowed</th>
              <th class="text-right">Rejected</th>
              <th class="text-right">Bytes</th>
              <th class="text-right">Seq gaps</th>
              <th class="text-right">Missing (est.)</th>
              <th class="text-right">Last seq</th>
              <th>Last seen</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="row in apids" :key="row.apid">
              <td>
                <code>{{ row.apid }}</code>
              </td>
              <td class="text-right">{{ formatValue(row.packets) }}</td>
              <td class="text-right">{{ formatValue(row.allowed) }}</td>
              <td
                class="text-right"
                :class="{ 'text-error': row.rejected > 0 }"
              >
                {{ formatValue(row.rejected) }}
              </td>
              <td class="text-right">{{ formatValue(row.bytes) }}</td>
              <td
                class="text-right"
                :class="{ 'text-warning': row.seq_gaps > 0 }"
              >
                {{ formatValue(row.seq_gaps) }}
              </td>
              <td class="text-right">{{ formatValue(row.seq_missing) }}</td>
              <td class="text-right">{{ formatValue(row.last_seq) }}</td>
              <td :title="row.last_time">{{ timeAgo(row.last_time, now) }}</td>
            </tr>
          </tbody>
        </v-table>
        <div class="text-caption mt-2">
          A sequence gap is a packet whose CCSDS sequence count is not the
          previous one + 1 for its APID: packets lost upstream, a restarted
          sender, or injected packets. Continuity starts over on reconnect.
        </div>
      </v-card-text>
    </v-card>

    <!-- What extensions in front of the firewall describe -->
    <v-card v-for="view in views" :key="view.extension.name" class="ma-2">
      <v-card-title>
        {{ view.extension.name }} {{ view.extension.version }}
      </v-card-title>
      <v-card-text>
        <v-alert
          v-if="!view.data"
          type="warning"
          variant="tonal"
          density="compact"
        >
          The {{ view.extension.name }} protocol reports no details on
          {{ interfaceName }}.
        </v-alert>
        <template v-else>
          <div
            v-for="(panel, index) in view.extension.panels"
            :key="index"
            class="mb-4"
          >
            <div class="d-flex align-center">
              <span class="text-subtitle-2">{{ panel.title }}</span>
              <v-spacer />
              <template v-if="!readonly">
                <v-btn
                  v-for="binding in panel.actions || []"
                  :key="binding.title"
                  size="small"
                  variant="text"
                  @click="openAction(view.extension, binding)"
                  >{{ binding.title }}…</v-btn
                >
              </template>
            </div>
            <div v-if="panel.help" class="text-caption mb-1">
              {{ panel.help }}
            </div>
            <v-row v-if="panel.kind === 'values'" dense>
              <v-col
                v-for="item in panelValues(panel, view.data)"
                :key="item.key"
                cols="6"
                md="2"
              >
                <div class="text-caption">{{ item.title }}</div>
                {{ item.value }}
              </v-col>
            </v-row>
            <v-table v-else density="compact">
              <thead>
                <tr>
                  <th>{{ panel.key_title || 'Key' }}</th>
                  <th v-for="(title, column) in panel.columns" :key="column">
                    {{ title }}
                  </th>
                  <th v-if="!readonly && panel.row_actions?.length"></th>
                </tr>
              </thead>
              <tbody>
                <tr v-if="!panelRows(panel, view.data).length">
                  <td
                    :colspan="Object.keys(panel.columns).length + 2"
                    class="text-caption"
                  >
                    Nothing yet.
                  </td>
                </tr>
                <tr v-for="row in panelRows(panel, view.data)" :key="row.key">
                  <td>{{ row.key }}</td>
                  <td v-for="(_, column) in panel.columns" :key="column">
                    {{ row.cells[column] }}
                  </td>
                  <td
                    v-if="!readonly && panel.row_actions?.length"
                    class="text-right text-no-wrap"
                  >
                    <v-btn
                      v-for="binding in panel.row_actions"
                      :key="binding.title"
                      size="small"
                      variant="text"
                      @click="openAction(view.extension, binding, row.key)"
                      >{{ binding.title }}…</v-btn
                    >
                  </td>
                </tr>
              </tbody>
            </v-table>
          </div>
        </template>
      </v-card-text>
    </v-card>

    <!-- Recent rejections and admin actions -->
    <v-card v-if="firewall" class="ma-2">
      <v-card-title>Recent rejections</v-card-title>
      <v-card-text>
        <div v-if="!recent.length" class="text-caption">None.</div>
        <v-table v-else density="compact">
          <thead>
            <tr>
              <th>Time</th>
              <th>Stage</th>
              <th>APID / layer</th>
              <th>Reason</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(item, i) in recent" :key="i">
              <td class="text-no-wrap" :title="item.time">
                {{ timeAgo(item.time, now) }}
              </td>
              <td>{{ item.stage }}</td>
              <td>{{ item.apid || item.layer || '-' }}</td>
              <td class="text-caption">{{ item.reason }}</td>
            </tr>
          </tbody>
        </v-table>
      </v-card-text>
    </v-card>

    <v-card v-if="firewall" class="ma-2">
      <v-card-title>Admin actions</v-card-title>
      <v-card-text>
        <div v-if="!adminActions.length" class="text-caption">
          None since the interface started (all of them are also in the audit
          stream).
        </div>
        <v-table v-else density="compact">
          <thead>
            <tr>
              <th>Time</th>
              <th>Action</th>
              <th>Result</th>
              <th>By</th>
              <th>Reason / detail</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(item, i) in adminActions" :key="i">
              <td class="text-no-wrap" :title="item.time">
                {{ timeAgo(item.time, now) }}
              </td>
              <td>{{ item.action }}</td>
              <td>
                <v-chip size="x-small" :color="item.ok ? 'success' : 'error'">
                  {{ item.ok ? 'done' : 'refused' }}
                </v-chip>
              </td>
              <td>{{ item.requested_by || '-' }}</td>
              <td class="text-caption">
                <div v-if="item.reason">{{ item.reason }}</div>
                <div>{{ item.detail }}</div>
              </td>
            </tr>
          </tbody>
        </v-table>
      </v-card-text>
    </v-card>

    <!-- An extension's admin action -->
    <v-dialog v-model="dialog.open" max-width="640">
      <v-card v-if="dialog.action">
        <v-card-title
          >{{ dialog.action.title || dialog.action.name }} on
          {{ interfaceName }}?</v-card-title
        >
        <v-card-text>
          <p v-if="dialog.action.help" class="mb-2">{{ dialog.action.help }}</p>
          <div v-if="Object.keys(dialog.fixed).length" class="mb-2">
            <v-chip
              v-for="(value, name) in dialog.fixed"
              :key="name"
              size="small"
              class="mr-1"
              >{{ dialog.action.params?.[name]?.title || name }}:
              {{ value }}</v-chip
            >
          </div>
          <schema-field
            v-if="Object.keys(dialog.fields).length"
            :spec="{ type: 'object', fields: dialog.fields }"
            :model-value="dialog.edited"
            @update:model-value="dialog.edited = $event || {}"
          />
          <v-alert
            v-if="dialog.action.confirm"
            type="warning"
            variant="tonal"
            density="compact"
            class="my-2"
            >{{ dialog.action.confirm }}</v-alert
          >
          <v-textarea
            v-model="dialog.reason"
            label="Reason (kept in the audit log)"
            :error-messages="
              dialog.reason ? reasonProblem(dialog.reason) || [] : []
            "
            counter="256"
            rows="2"
            auto-grow
          />
          <div
            v-for="problem in dialogProblems"
            :key="problem"
            class="text-caption text-error"
          >
            {{ problem }}
          </div>
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn
            variant="text"
            :disabled="dialog.busy"
            @click="dialog.open = false"
            >Cancel</v-btn
          >
          <v-btn
            color="primary"
            variant="flat"
            :loading="dialog.busy"
            :disabled="
              !!reasonProblem(dialog.reason) || dialogProblems.length > 0
            "
            @click="runAction"
            >{{ dialog.action.title || dialog.action.name }}</v-btn
          >
        </v-card-actions>
      </v-card>
    </v-dialog>
  </div>
</template>

<script>
import SchemaField from './SchemaField.vue'
import { reasonProblem } from './adminRequest.js'
import {
  actionForm,
  actionParams,
  actionProblems,
  apidRows,
  extensionViews,
  formatValue,
  panelRows,
  panelValues,
  rate,
  timeAgo,
} from './linkStatus.js'
import { adminAction, linkState } from '../../services/rulesStore.js'

const POLL_MS = 2000

function closedDialog() {
  return {
    open: false,
    busy: false,
    extension: null,
    action: null,
    fixed: {},
    fields: {},
    edited: {},
    reason: '',
  }
}

export default {
  components: { SchemaField },
  props: {
    interfaceName: { type: String, required: true },
    readonly: { type: Boolean, default: false },
  },
  emits: ['state'], // the firewall section, so the page's banners stay current
  data() {
    return {
      firewall: null,
      protocols: [],
      error: null,
      busy: false,
      timer: null,
      now: Date.now(),
      refreshedAt: null,
      previous: null, // { packets, at } of the previous poll, for the rate
      packetRate: null,
      dialog: closedDialog(),
    }
  },
  computed: {
    traffic() {
      return this.firewall?.traffic || {}
    },
    trafficItems() {
      const t = this.traffic
      const fw = this.firewall
      return [
        { title: 'Packets judged', value: formatValue(t.packets) },
        { title: 'Allowed', value: formatValue(t.allowed) },
        {
          title: 'Rejected (all stages)',
          value: formatValue(fw.rejected),
          warn: fw.rejected > 0,
        },
        {
          title: 'Packets / s',
          value: this.packetRate === null ? '-' : this.packetRate.toFixed(1),
        },
        {
          title: 'Last packet',
          value: timeAgo(t.last_packet_time, this.now),
        },
        {
          title: 'Sequence gaps',
          value: formatValue(t.seq_gaps),
          warn: t.seq_gaps > 0,
        },
        { title: 'Bytes allowed', value: formatValue(t.bytes_allowed) },
        {
          title: 'Bytes discarded',
          value: formatValue(fw.discarded_bytes),
          warn: fw.discarded_bytes > 0,
        },
        {
          title: 'Quarantined',
          value: formatValue(fw.quarantine?.written),
        },
        { title: 'Trust restores', value: formatValue(fw.trust_restores) },
        { title: 'Connection', value: `#${fw.connection_id}` },
        { title: 'Rules version', value: formatValue(fw.rules?.version) },
      ]
    },
    apids() {
      return apidRows(this.traffic)
    },
    views() {
      return extensionViews(this.firewall?.extensions, this.protocols)
    },
    recent() {
      return this.firewall?.quarantine?.recent || []
    },
    adminActions() {
      return this.firewall?.admin_actions || []
    },
    refreshedText() {
      return this.refreshedAt ? timeAgo(this.refreshedAt, this.now) : '-'
    },
    dialogParams() {
      return actionParams(this.dialog.fixed, this.dialog.edited)
    },
    dialogProblems() {
      if (!this.dialog.action) return []
      return actionProblems(this.dialog.action, this.dialogParams)
    },
  },
  watch: {
    interfaceName() {
      this.firewall = null
      this.previous = null
      this.packetRate = null
      this.poll()
    },
  },
  mounted() {
    this.poll()
    this.timer = setInterval(() => {
      this.now = Date.now()
      if (!document.hidden) this.poll()
    }, POLL_MS)
  },
  beforeUnmount() {
    clearInterval(this.timer)
  },
  methods: {
    formatValue,
    panelRows,
    panelValues,
    reasonProblem,
    timeAgo,
    async poll() {
      if (this.busy) return // the previous request is still out
      this.busy = true
      const iface = this.interfaceName
      try {
        const state = await linkState(iface)
        if (iface !== this.interfaceName) return // switched meanwhile
        this.firewall = state.firewall
        this.protocols = state.protocols
        this.error = null
        const sample = {
          packets: state.firewall.traffic?.packets ?? 0,
          at: Date.now(),
        }
        this.packetRate = rate(this.previous, sample)
        this.previous = sample
        this.refreshedAt = new Date(sample.at).toISOString()
        this.now = sample.at
        this.$emit('state', state.firewall)
      } catch (error) {
        this.error = `Could not read the link status of ${iface}: ${error.message}`
      } finally {
        this.busy = false
      }
    },
    openAction(extension, binding, rowKey = undefined) {
      const action = (extension.actions || []).find(
        (a) => a.name === binding.action,
      )
      if (!action) return
      const { fixed, fields } = actionForm(action, binding, rowKey)
      this.dialog = {
        ...closedDialog(),
        open: true,
        extension,
        action,
        fixed,
        fields,
      }
    },
    async runAction() {
      const action = this.dialog.action
      this.dialog.busy = true
      try {
        const answer = await adminAction(
          this.interfaceName,
          action.name,
          action.command,
          this.dialog.reason,
          this.dialogParams,
        )
        this.firewall = answer.state
        if (answer.ok) {
          this.$notify.normal({
            title: `${action.title || action.name}: done`,
            body: answer.detail,
          })
          this.dialog.open = false
        } else {
          this.$notify.serious({
            title: 'The firewall refused',
            body: answer.detail,
          })
        }
      } catch (error) {
        this.$notify.serious({
          title: `${action.title || action.name} failed`,
          body: error.message,
        })
      } finally {
        this.dialog.busy = false
        this.poll()
      }
    },
  },
}
</script>
