<!--
  Audit log: everything admins did and every change to the firewall's policy
  on one interface, newest first (decision C15). Rules applied, loaded or
  refused (with what changed and the reason), trust restored, releases,
  reviews, exports, spikes, SDLS replay resets and key reloads.

  Admins only: the review microservice asks COSMOS whether the user is an
  admin (decision C5). Everything is untrusted text, shown with {{ }} only.
-->
<template>
  <div>
    <v-card class="ma-2">
      <v-card-title class="d-flex align-center flex-wrap">
        Audit log
        <v-chip size="small" class="ml-2">{{ interfaceName }}</v-chip>
        <v-spacer />
        <span class="text-caption mr-2">{{ summaryText }}</span>
        <v-btn
          variant="text"
          prepend-icon="mdi-refresh"
          :loading="loading"
          @click="refresh"
          >Refresh</v-btn
        >
        <v-btn
          variant="text"
          prepend-icon="mdi-download"
          :disabled="!loaded"
          :loading="exporting"
          @click="doExport"
          >Export JSON</v-btn
        >
      </v-card-title>
      <v-card-text>
        <v-row dense>
          <v-col cols="12" sm="4" md="3">
            <v-select
              v-model="filters.action"
              :items="actionItems"
              label="Action"
              density="compact"
              hide-details
              @update:model-value="refresh"
            />
          </v-col>
          <v-col cols="6" sm="3" md="2">
            <v-select
              v-model="filters.ok"
              :items="okItems"
              label="Outcome"
              density="compact"
              hide-details
              @update:model-value="refresh"
            />
          </v-col>
          <v-col cols="6" sm="2" md="2">
            <v-text-field
              v-model="filters.limit"
              type="number"
              :min="1"
              :max="1000"
              label="Most recent"
              density="compact"
              hide-details
              @change="refresh"
              @keyup.enter="refresh"
            />
          </v-col>
          <v-col cols="12" md="5">
            <v-text-field
              v-model="filters.search"
              label="Search (who, reason, details)"
              prepend-inner-icon="mdi-magnify"
              density="compact"
              hide-details
              clearable
              @keyup.enter="refresh"
              @click:clear="clearSearch"
            />
          </v-col>
        </v-row>
      </v-card-text>
    </v-card>

    <v-alert
      v-if="error"
      :type="forbidden ? 'info' : 'error'"
      variant="tonal"
      class="ma-2"
    >
      {{ error }}
    </v-alert>

    <v-card v-if="loaded" class="ma-2">
      <v-data-table
        v-model:expanded="expanded"
        :headers="headers"
        :items="entries"
        item-value="id"
        show-expand
        density="compact"
        :items-per-page="25"
        :items-per-page-options="[10, 25, 50, 100, -1]"
        no-data-text="Nothing in the audit log matches"
      >
        <template #item.time="{ item }">
          <span class="text-no-wrap">{{ shortTime(item.time) }}</span>
        </template>
        <template #item.action="{ item }">
          <v-chip size="x-small" :color="actionColor(item.action)">{{
            item.action || '-'
          }}</v-chip>
        </template>
        <template #item.ok="{ item }">
          <v-icon
            :color="item.ok ? 'success' : 'error'"
            :icon="item.ok ? 'mdi-check' : 'mdi-close'"
            size="small"
            :aria-label="item.ok ? 'done' : 'refused'"
          />
        </template>
        <template #item.who="{ item }">{{ whoText(item) }}</template>
        <template #item.detail="{ item }">
          <span class="detail">{{ item.reason || item.detail }}</span>
        </template>
        <template #expanded-row="{ columns, item }">
          <tr>
            <td :colspan="columns.length" class="pa-3 expanded">
              <div class="mb-2">
                <div class="text-caption">Detail</div>
                <div class="wrap">{{ item.detail || '-' }}</div>
              </div>
              <div v-if="item.reason" class="mb-2">
                <div class="text-caption">Reason given</div>
                <div class="wrap">{{ item.reason }}</div>
              </div>
              <v-table density="compact" class="meta">
                <tbody>
                  <tr>
                    <th>Entry id</th>
                    <td>
                      <code>{{ item.id }}</code>
                    </td>
                  </tr>
                  <tr>
                    <th>Time (UTC)</th>
                    <td>{{ item.time }}</td>
                  </tr>
                  <tr v-for="row in fieldRows(item.fields)" :key="row.name">
                    <th>{{ row.name }}</th>
                    <td>
                      <pre v-if="row.structured" class="json">{{
                        row.value
                      }}</pre>
                      <code v-else>{{ row.value }}</code>
                    </td>
                  </tr>
                </tbody>
              </v-table>
            </td>
          </tr>
        </template>
      </v-data-table>
      <div class="d-flex align-center pa-2">
        <span class="text-caption">{{ scanText }}</span>
        <v-spacer />
        <v-btn
          v-if="nextBefore"
          variant="text"
          :loading="loadingMore"
          @click="loadOlder"
          >Load older</v-btn
        >
      </div>
    </v-card>
  </div>
</template>

<script>
import { actionColor, auditParams, fieldRows, whoText } from './auditLog.js'
import { exportAudit, listAudit } from '../../services/quarantineApi.js'

export default {
  props: {
    interfaceName: { type: String, required: true },
  },
  data() {
    return {
      filters: { action: '', ok: '', limit: 100, search: '' },
      entries: [],
      actions: [],
      loaded: false,
      loading: false,
      loadingMore: false,
      exporting: false,
      error: null,
      forbidden: false,
      streamLength: 0,
      scanned: 0,
      nextBefore: null,
      expanded: [],
      okItems: [
        { title: 'Any', value: '' },
        { title: 'Done', value: 'true' },
        { title: 'Refused', value: 'false' },
      ],
      headers: [
        { title: 'Time (UTC)', key: 'time' },
        { title: 'Action', key: 'action' },
        { title: 'OK', key: 'ok' },
        { title: 'Who', key: 'who', sortable: false },
        { title: 'Reason / detail', key: 'detail', sortable: false },
        { title: '', key: 'data-table-expand' },
      ],
    }
  },
  computed: {
    actionItems() {
      return [
        { title: 'Any', value: '' },
        ...this.actions.map((a) => ({ title: a, value: a })),
      ]
    },
    summaryText() {
      return this.loaded
        ? `${this.entries.length} shown of ${this.streamLength} kept`
        : ''
    },
    scanText() {
      if (!this.loaded) return ''
      return this.nextBefore
        ? `Searched the newest ${this.scanned} entries; older ones may match too`
        : `Searched every kept entry (${this.scanned})`
    },
  },
  watch: {
    interfaceName() {
      this.expanded = []
      this.refresh()
    },
  },
  created() {
    this.refresh()
  },
  methods: {
    actionColor,
    fieldRows,
    whoText,
    shortTime(time) {
      return String(time || '')
        .replace('T', ' ')
        .replace(/\.\d+Z$/, 'Z')
    },
    async refresh() {
      if (this.loading) return
      this.loading = true
      this.error = null
      try {
        const result = await listAudit(
          auditParams(this.interfaceName, this.filters),
        )
        this.entries = result.entries
        this.actions = result.actions || []
        this.streamLength = result.stream_length
        this.scanned = result.scanned
        this.nextBefore = result.next_before
        this.loaded = true
        this.forbidden = false
      } catch (error) {
        this.error = error.message
        this.forbidden = /admins only/.test(error.message)
      } finally {
        this.loading = false
      }
    },
    async loadOlder() {
      this.loadingMore = true
      try {
        const result = await listAudit(
          auditParams(this.interfaceName, this.filters, this.nextBefore),
        )
        const known = new Set(this.entries.map((e) => e.id))
        this.entries = this.entries.concat(
          result.entries.filter((e) => !known.has(e.id)),
        )
        this.scanned += result.scanned
        this.nextBefore = result.next_before
      } catch (error) {
        this.error = error.message
      } finally {
        this.loadingMore = false
      }
    },
    clearSearch() {
      this.filters.search = ''
      this.refresh()
    },
    async doExport() {
      this.exporting = true
      try {
        const params = {
          ...auditParams(this.interfaceName, this.filters),
          limit: '10000',
        }
        const name = await exportAudit(params)
        this.$notify.normal({ title: 'Audit log downloaded', body: name })
        await this.refresh() // the export is now in the log too
      } catch (error) {
        this.$notify.serious({ title: 'Export failed', body: error.message })
      } finally {
        this.exporting = false
      }
    },
  },
}
</script>

<style scoped>
.detail {
  display: inline-block;
  max-width: 48em;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  vertical-align: bottom;
}
.wrap {
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
.expanded {
  background-color: rgba(var(--v-theme-on-surface), 0.03);
}
.meta th {
  white-space: nowrap;
  font-weight: normal;
  opacity: 0.7;
  text-align: left;
  padding-right: 1em;
  vertical-align: top;
}
.meta td code {
  overflow-wrap: anywhere;
}
.json {
  margin: 0;
  font-size: 0.85em;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
</style>
