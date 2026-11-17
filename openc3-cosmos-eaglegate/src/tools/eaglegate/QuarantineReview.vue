<!--
  Quarantine review: the packets one interface's firewall rejected, newest
  first, with why. Admins only: the review microservice
  (microservices/EAGLEGATE_QUARANTINE) asks the COSMOS server whether the user
  is an admin and answers 403 to anyone else.

  - list the most recent N entries (N is set here and remembered) and filter
    them by stage, rule, APID, review state or text
  - expand an entry for its metadata, CCSDS header, link values and bytes
    (hex dump; only printable ASCII is shown as characters)
  - set a review state with a note, for one entry or the selected ones
  - release a wrongly rejected packet: an admin request to the firewall
    (RELEASE), which sends it on into COSMOS without checking the rules
    again, at most once per entry

  Everything from the quarantine is untrusted text: it is shown only with
  {{ }} (escaped by Vue), never v-html, after safeText() (quarantine.js).
-->
<template>
  <div>
    <v-card class="ma-2">
      <v-card-title class="d-flex align-center flex-wrap">
        Quarantine
        <v-chip size="small" class="ml-2">{{ interfaceName }}</v-chip>
        <v-spacer />
        <span class="text-caption mr-2">{{ summaryText }}</span>
        <v-switch
          v-model="autoRefresh"
          label="Auto refresh"
          density="compact"
          hide-details
          color="primary"
          class="mr-2 flex-grow-0"
        />
        <v-btn
          variant="text"
          prepend-icon="mdi-refresh"
          :loading="loading"
          @click="refresh"
          >Refresh</v-btn
        >
      </v-card-title>
      <v-card-text>
        <v-row dense>
          <v-col cols="12" sm="6" md="3">
            <v-select
              v-model="filters.stream"
              :items="streamItems"
              label="Stream"
              density="compact"
              hide-details
              @update:model-value="refresh"
            />
          </v-col>
          <v-col cols="6" sm="3" md="2">
            <v-text-field
              v-model="filters.limit"
              type="number"
              :min="1"
              :max="maxLimit"
              label="Most recent"
              hint="Entries to show (1-1000)"
              density="compact"
              @change="setLimit"
              @keyup.enter="setLimit"
            />
          </v-col>
          <v-col cols="6" sm="3" md="2">
            <v-select
              v-model="filters.stage"
              :items="stageItems"
              label="Stage"
              density="compact"
              hide-details
              @update:model-value="refresh"
            />
          </v-col>
          <v-col cols="6" sm="4" md="2">
            <v-select
              v-model="filters.review"
              :items="reviewFilterItems"
              label="Review state"
              density="compact"
              hide-details
              @update:model-value="refresh"
            />
          </v-col>
          <v-col cols="6" sm="4" md="1">
            <v-text-field
              v-model="filters.apid"
              label="APID"
              placeholder="0x003"
              density="compact"
              hide-details
              @keyup.enter="refresh"
            />
          </v-col>
          <v-col cols="6" sm="4" md="2">
            <v-text-field
              v-model="filters.rule_id"
              label="Rule id"
              density="compact"
              hide-details
              @keyup.enter="refresh"
            />
          </v-col>
          <v-col cols="12" md="6">
            <v-text-field
              v-model="filters.search"
              label="Search reasons"
              prepend-inner-icon="mdi-magnify"
              density="compact"
              hide-details
              clearable
              @keyup.enter="refresh"
              @click:clear="clearSearch"
            />
          </v-col>
          <v-col cols="12" md="6" class="d-flex align-center">
            <v-btn variant="tonal" class="mr-2" @click="refresh">Apply</v-btn>
            <v-btn variant="text" @click="resetFilters">Clear filters</v-btn>
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
      <div v-if="selected.length" class="d-flex align-center pa-2 bg-surface">
        <span class="mr-4">{{ selected.length }} selected</span>
        <v-btn
          variant="tonal"
          prepend-icon="mdi-clipboard-check-outline"
          @click="openReview(selected)"
          >Set review state…</v-btn
        >
        <v-btn variant="text" class="ml-2" @click="selected = []"
          >Clear selection</v-btn
        >
      </div>
      <v-data-table
        v-model="selected"
        v-model:expanded="expanded"
        :headers="headers"
        :items="entries"
        item-value="id"
        show-select
        show-expand
        density="compact"
        :items-per-page="25"
        :items-per-page-options="[10, 25, 50, 100, -1]"
        no-data-text="Nothing in the quarantine matches"
        @update:expanded="loadExpanded"
      >
        <template #item.time="{ item }">
          <span class="text-no-wrap">{{ shortTime(item.time) }}</span>
        </template>
        <template #item.stage="{ item }">
          <v-chip size="x-small" :color="stageColor(item.stage)">{{
            safeText(item.stage)
          }}</v-chip>
        </template>
        <template #item.rule_id="{ item }">
          <code>{{ safeText(item.rule_id || item.layer || '-', 64) }}</code>
        </template>
        <template #item.reason="{ item }">
          <span class="reason">{{
            safeText(item.detail || item.reason, 200)
          }}</span>
        </template>
        <template #item.review_state="{ item }">
          <v-chip
            size="x-small"
            :color="reviewState(item.review_state).color"
            :title="reviewTitle(item)"
            >{{ reviewState(item.review_state).title }}</v-chip
          >
        </template>

        <template #expanded-row="{ columns, item }">
          <tr>
            <td :colspan="columns.length" class="pa-3 expanded">
              <div v-if="detailError[item.id]" class="text-error">
                {{ detailError[item.id] }}
              </div>
              <v-progress-linear
                v-else-if="!details[item.id]"
                indeterminate
                color="primary"
              />
              <template v-else>
                <div class="text-subtitle-2 mb-1">Why</div>
                <div class="mb-3 reason-full">
                  {{ safeText(details[item.id].reason, 1024) }}
                </div>
                <v-row dense>
                  <v-col cols="12" md="5">
                    <div class="text-subtitle-2 mb-1">Metadata</div>
                    <v-table density="compact" class="meta">
                      <tbody>
                        <tr
                          v-for="row in metadataRows(details[item.id])"
                          :key="row.name"
                        >
                          <th>{{ row.name }}</th>
                          <td>
                            <code>{{ row.value }}</code>
                          </td>
                        </tr>
                      </tbody>
                    </v-table>
                  </v-col>
                  <v-col cols="12" md="3">
                    <div class="text-subtitle-2 mb-1">CCSDS header</div>
                    <v-table
                      v-if="headerOf(item.id)"
                      density="compact"
                      class="meta"
                    >
                      <tbody>
                        <tr
                          v-for="(value, name) in headerOf(item.id)"
                          :key="name"
                        >
                          <th>{{ name.replaceAll('_', ' ') }}</th>
                          <td>
                            <code>{{ value }}</code>
                          </td>
                        </tr>
                      </tbody>
                    </v-table>
                    <div v-else class="text-caption">
                      Not a packet header (raw bytes)
                    </div>
                    <template v-if="linkRows(details[item.id].link).length">
                      <div class="text-subtitle-2 mt-3 mb-1">Link</div>
                      <v-table density="compact" class="meta">
                        <tbody>
                          <tr
                            v-for="row in linkRows(details[item.id].link)"
                            :key="row.name"
                          >
                            <th>{{ row.name }}</th>
                            <td>
                              <code>{{ row.value }}</code>
                            </td>
                          </tr>
                        </tbody>
                      </v-table>
                    </template>
                  </v-col>
                  <v-col cols="12" md="4">
                    <div class="text-subtitle-2 mb-1">Review</div>
                    <div v-if="details[item.id].released" class="mb-2">
                      <v-chip size="small" color="success" class="mb-1"
                        >Released</v-chip
                      >
                      <div class="text-caption">
                        {{ safeText(details[item.id].released.time) }} by
                        {{
                          safeText(
                            details[item.id].released.requested_by || '?',
                          )
                        }}: {{ safeText(details[item.id].released.reason) }}
                      </div>
                    </div>
                    <div v-if="details[item.id].review" class="mb-2">
                      <v-chip
                        size="small"
                        :color="
                          reviewState(details[item.id].review.state).color
                        "
                        class="mb-1"
                        >{{
                          reviewState(details[item.id].review.state).title
                        }}</v-chip
                      >
                      <div class="text-caption">
                        {{ reviewTitle(details[item.id]) }}
                      </div>
                    </div>
                    <div
                      v-else-if="!details[item.id].released"
                      class="text-caption mb-2"
                    >
                      Not reviewed yet
                    </div>
                    <v-btn
                      variant="tonal"
                      size="small"
                      prepend-icon="mdi-clipboard-check-outline"
                      class="mr-2 mb-2"
                      @click="openReview([item.id])"
                      >Set review state…</v-btn
                    >
                    <v-btn
                      v-if="canRelease(details[item.id])"
                      variant="tonal"
                      size="small"
                      color="warning"
                      prepend-icon="mdi-send-check"
                      class="mb-2"
                      @click="openRelease(details[item.id])"
                      >Release…</v-btn
                    >
                    <div
                      v-else-if="!details[item.id].released"
                      class="text-caption"
                    >
                      {{ releaseNote(details[item.id]) }}
                    </div>
                  </v-col>
                </v-row>
                <div class="text-subtitle-2 mt-3 mb-1">
                  Bytes ({{ details[item.id].bytes_kept }} of
                  {{ details[item.id].length }})
                </div>
                <div class="dump-wrap">
                  <pre class="dump"><template
                      v-for="row in hexDump(details[item.id].bytes_hex)"
                      :key="row.offset"
                    ><span class="off">{{ row.offset }}</span>  {{ row.hex }}  <span class="asc">{{ row.ascii }}</span>
</template></pre>
                </div>
              </template>
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

    <!-- Review state for one or more entries -->
    <v-dialog v-model="review.open" max-width="560">
      <v-card>
        <v-card-title
          >Review {{ review.ids.length }}
          {{ review.ids.length === 1 ? 'entry' : 'entries' }}</v-card-title
        >
        <v-card-text>
          <v-select
            v-model="review.state"
            :items="reviewStateItems"
            label="State"
            density="compact"
          />
          <v-textarea
            v-model="review.note"
            label="Note (kept with the entry and in the audit log)"
            :error-messages="noteProblem(review.note) || []"
            counter="256"
            rows="2"
            auto-grow
          />
          <div class="text-caption">
            "New" clears the review. Releasing a packet is a separate action.
          </div>
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn variant="text" @click="review.open = false">Cancel</v-btn>
          <v-btn
            color="primary"
            :loading="review.busy"
            :disabled="!!noteProblem(review.note)"
            @click="saveReview"
            >Save</v-btn
          >
        </v-card-actions>
      </v-card>
    </v-dialog>

    <!-- Release: an admin request to the firewall -->
    <v-dialog v-model="release.open" max-width="640">
      <v-card v-if="release.entry">
        <v-card-title>Release this packet into COSMOS?</v-card-title>
        <v-card-text>
          <v-table density="compact" class="meta mb-2">
            <tbody>
              <tr>
                <th>Entry</th>
                <td>
                  <code>{{ safeText(release.entry.id) }}</code>
                </td>
              </tr>
              <tr>
                <th>APID</th>
                <td>
                  <code>{{ safeText(release.entry.apid || '-') }}</code>
                </td>
              </tr>
              <tr>
                <th>Rejected by</th>
                <td>{{ safeText(release.entry.reason, 300) }}</td>
              </tr>
              <tr>
                <th>sha256</th>
                <td>
                  <code>{{ safeText(release.entry.sha256) }}</code>
                </td>
              </tr>
            </tbody>
          </v-table>
          <v-alert
            type="warning"
            variant="tonal"
            density="compact"
            class="mb-2"
          >
            The firewall will send exactly these bytes on to COSMOS as if they
            had just arrived on {{ interfaceName }}, without checking the rules
            again. It can be done once per entry and is written to the audit
            log. If the rule was wrong, fix it on the Rules tab too.
          </v-alert>
          <v-textarea
            v-model="release.reason"
            label="Reason (kept in the audit log)"
            :error-messages="
              release.reason ? reasonProblem(release.reason) || [] : []
            "
            counter="256"
            rows="2"
            auto-grow
          />
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn variant="text" @click="release.open = false">Cancel</v-btn>
          <v-btn
            color="warning"
            :loading="release.busy"
            :disabled="!!reasonProblem(release.reason)"
            @click="doRelease"
            >Release</v-btn
          >
        </v-card-actions>
      </v-card>
    </v-dialog>
  </div>
</template>

<script>
import { reasonProblem } from './adminRequest.js'
import {
  DEFAULT_LIMIT,
  MAX_LIMIT,
  REVIEW_STATES,
  RELEASED_STATE,
  STAGES,
  canRelease,
  ccsdsHeader,
  clampLimit,
  hexDump,
  linkRows,
  listParams,
  metadataRows,
  noteProblem,
  reviewState,
  safeText,
} from './quarantine.js'
import {
  getEntry,
  listEntries,
  releaseEntry,
  setReview,
} from '../../services/quarantineApi.js'
import { userName } from '../../services/rulesStore.js'

const LIMIT_KEY = 'eaglegate.quarantine.limit'
const REFRESH_MS = 10000

function emptyFilters(limit) {
  return {
    stream: 'quarantine',
    limit,
    stage: '',
    review: '',
    apid: '',
    rule_id: '',
    search: '',
  }
}

function rememberedLimit() {
  try {
    return clampLimit(localStorage.getItem(LIMIT_KEY) ?? DEFAULT_LIMIT)
  } catch {
    return DEFAULT_LIMIT
  }
}

export default {
  props: {
    interfaceName: { type: String, required: true },
  },
  data() {
    return {
      filters: emptyFilters(rememberedLimit()),
      maxLimit: MAX_LIMIT,
      entries: [],
      loaded: false,
      loading: false,
      loadingMore: false,
      error: null,
      forbidden: false,
      streamLength: 0,
      scanned: 0,
      nextBefore: null,
      selected: [],
      expanded: [],
      details: {}, // id -> entry with bytes_hex
      detailError: {},
      autoRefresh: false,
      timer: null,
      review: {
        open: false,
        ids: [],
        state: 'reviewed',
        note: '',
        busy: false,
      },
      release: { open: false, entry: null, reason: '', busy: false },
      headers: [
        { title: 'Time (UTC)', key: 'time' },
        { title: 'Stage', key: 'stage' },
        { title: 'Rule / layer', key: 'rule_id' },
        { title: 'APID', key: 'apid' },
        { title: 'Type', key: 'packet_type' },
        { title: 'Seq', key: 'seq_count' },
        { title: 'Bytes', key: 'length' },
        { title: 'Reason', key: 'reason', sortable: false },
        { title: 'Review', key: 'review_state' },
        { title: '', key: 'data-table-expand' },
      ],
    }
  },
  computed: {
    streamItems() {
      return [
        { title: 'Rule denials (releasable)', value: 'quarantine' },
        { title: 'Raw and link rejections (forensics)', value: 'raw' },
      ]
    },
    stageItems() {
      return [
        { title: 'Any', value: '' },
        ...STAGES.map((s) => ({ title: s, value: s })),
      ]
    },
    reviewFilterItems() {
      return [
        { title: 'Any', value: '' },
        ...REVIEW_STATES.map((s) => ({ title: s.title, value: s.value })),
        { title: RELEASED_STATE.title, value: RELEASED_STATE.value },
      ]
    },
    reviewStateItems() {
      return REVIEW_STATES.map((s) => ({ title: s.title, value: s.value }))
    },
    summaryText() {
      if (!this.loaded) return ''
      return `${this.entries.length} shown of ${this.streamLength} stored`
    },
    scanText() {
      if (!this.loaded) return ''
      return this.nextBefore
        ? `Searched the newest ${this.scanned} entries; older ones may match too`
        : `Searched every stored entry (${this.scanned})`
    },
  },
  watch: {
    interfaceName() {
      this.details = {}
      this.expanded = []
      this.selected = []
      this.refresh()
    },
    autoRefresh(on) {
      clearInterval(this.timer)
      this.timer = on ? setInterval(() => this.refresh(true), REFRESH_MS) : null
    },
  },
  created() {
    this.refresh()
  },
  unmounted() {
    clearInterval(this.timer)
  },
  methods: {
    safeText,
    reviewState,
    metadataRows,
    linkRows,
    hexDump,
    canRelease,
    noteProblem,
    reasonProblem,
    params(before = '') {
      return listParams(this.interfaceName, this.filters, before)
    },
    async refresh(quiet = false) {
      if (this.loading) return
      this.loading = true
      if (!quiet) this.error = null
      try {
        const result = await listEntries(this.params())
        this.entries = result.entries
        this.streamLength = result.stream_length
        this.scanned = result.scanned
        this.nextBefore = result.next_before
        const ids = new Set(this.entries.map((e) => e.id))
        this.selected = this.selected.filter((id) => ids.has(id))
        this.loaded = true
        this.error = null
        this.forbidden = false
      } catch (error) {
        this.error = error.message
        this.forbidden = /admins only/.test(error.message)
        if (this.forbidden) this.autoRefresh = false
      } finally {
        this.loading = false
      }
    },
    async loadOlder() {
      this.loadingMore = true
      try {
        const result = await listEntries(this.params(this.nextBefore))
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
    setLimit() {
      this.filters.limit = clampLimit(this.filters.limit)
      try {
        localStorage.setItem(LIMIT_KEY, String(this.filters.limit))
      } catch {
        // not remembered; harmless
      }
      this.refresh()
    },
    clearSearch() {
      this.filters.search = ''
      this.refresh()
    },
    resetFilters() {
      this.filters = emptyFilters(this.filters.limit)
      this.refresh()
    },
    async loadExpanded(ids) {
      for (const id of ids) {
        if (this.details[id]) continue
        const entry = this.entries.find((e) => e.id === id)
        if (!entry) continue
        try {
          this.details[id] = await getEntry(
            this.interfaceName,
            entry.stream,
            id,
          )
          delete this.detailError[id]
        } catch (error) {
          this.detailError[id] = error.message
        }
      }
    },
    headerOf(id) {
      const entry = this.details[id]
      if (!entry || entry.stage === 'UNTRUSTED' || entry.stage === 'LINK')
        return null
      return ccsdsHeader(entry.bytes_hex)
    },
    stageColor(stage) {
      return (
        {
          RULE: 'error',
          DEFAULT: 'warning',
          ERROR: 'purple',
          STRUCTURAL: 'deep-orange',
          UNTRUSTED: 'grey',
          LINK: 'blue',
        }[stage] || undefined
      )
    },
    shortTime(time) {
      return safeText(
        String(time || '')
          .replace('T', ' ')
          .replace(/\.\d+Z$/, 'Z'),
      )
    },
    reviewTitle(entry) {
      const r = entry.review
      if (!r) return ''
      const who = r.user || r.requested_by || '?'
      return safeText(
        `${r.at || ''} by ${who}${r.note ? ': ' + r.note : ''}`,
        400,
      )
    },
    releaseNote(entry) {
      if (entry.stream !== 'quarantine')
        return 'Raw and link rejections are kept for forensics only and cannot be released.'
      if (entry.truncated)
        return 'Only part of this packet was kept; it cannot be released.'
      return 'This entry cannot be released.'
    },
    openReview(ids) {
      const first = this.entries.find((e) => e.id === ids[0])
      this.review = {
        open: true,
        ids: [...ids],
        state:
          first &&
          first.review_state !== 'released' &&
          first.review_state !== 'new'
            ? first.review_state
            : 'reviewed',
        note: '',
        busy: false,
      }
    },
    async saveReview() {
      this.review.busy = true
      try {
        const result = await setReview(
          this.interfaceName,
          this.filters.stream,
          this.review.ids,
          this.review.state,
          this.review.note.trim(),
          userName(),
        )
        for (const id of result.updated) delete this.details[id]
        this.review.open = false
        this.$notify.normal({
          title: 'Review saved',
          body:
            `${result.updated.length} updated` +
            (result.missing.length
              ? `; ${result.missing.length} no longer stored`
              : ''),
        })
        this.selected = []
        await this.refresh()
        await this.loadExpanded(this.expanded)
      } catch (error) {
        this.$notify.serious({ title: 'Review not saved', body: error.message })
      } finally {
        this.review.busy = false
      }
    },
    openRelease(entry) {
      this.release = { open: true, entry, reason: '', busy: false }
    },
    async doRelease() {
      this.release.busy = true
      const id = this.release.entry.id
      try {
        const answer = await releaseEntry(
          this.interfaceName,
          this.release.entry,
          this.release.reason,
        )
        if (answer.ok) {
          this.$notify.normal({
            title: 'Packet released',
            body: safeText(answer.detail),
          })
          this.release.open = false
        } else {
          this.$notify.serious({
            title: 'The firewall refused the release',
            body: safeText(answer.detail),
          })
        }
      } catch (error) {
        this.$notify.serious({ title: 'Not released', body: error.message })
      } finally {
        this.release.busy = false
        delete this.details[id]
        await this.refresh()
        await this.loadExpanded(this.expanded)
      }
    },
  },
}
</script>

<style scoped>
.reason {
  display: inline-block;
  max-width: 42em;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  vertical-align: bottom;
}
.reason-full {
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
}
.meta td code {
  overflow-wrap: anywhere;
}
.dump-wrap {
  overflow-x: auto;
  max-height: 24em;
  overflow-y: auto;
}
.dump {
  font-size: 0.85em;
  line-height: 1.4;
  margin: 0;
}
.dump .off {
  opacity: 0.6;
}
.dump .asc {
  opacity: 0.85;
}
</style>
