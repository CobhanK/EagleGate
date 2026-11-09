<!--
  EagleGate firewall rules editor.

  Shows what the firewall is running and lets an admin change it: edit rules
  with forms, review a diff, apply. Applying uploads the rules as pending and
  asks the firewall to validate and activate them (see
  targets/EAGLEGATE/lib/eaglegate_rules_store.py); the firewall keeps the
  running rules whenever it refuses a file.

  The COSMOS server decides who may apply: the admin role in Enterprise, any
  logged in user in Core. The read-only mode here only mirrors that.

  Every interface running the firewall protocol can be edited (the selector at
  the top); each has its own rules. Interfaces with an extension in front of
  the firewall (e.g. the eaglegate-sdls plugin) also show the extension's rules
  section and link conditions, built from what that interface reports.
-->
<template>
  <div>
    <top-bar :menus="menus" :title="title" />

    <v-alert v-if="loadError" type="error" variant="tonal" class="ma-2">
      {{ loadError }}
    </v-alert>
    <div v-if="interfaces.length > 1" class="ma-2" style="max-width: 520px">
      <v-select
        :model-value="interfaceName"
        :items="interfaceItems"
        label="Interface"
        hint="Each interface running the firewall has its own rules"
        persistent-hint
        density="compact"
        @update:model-value="selectInterface"
      />
    </div>
    <v-alert
      v-if="!isEnterprise && loaded"
      type="info"
      variant="tonal"
      density="compact"
      class="ma-2"
    >
      COSMOS Core has no separate admin role: everyone who can log in to COSMOS
      can change these rules. Treat the COSMOS password as an admin credential.
    </v-alert>
    <v-alert
      v-if="readonly"
      type="info"
      variant="tonal"
      density="compact"
      class="ma-2"
    >
      Read only: changing the firewall rules needs the COSMOS admin role.
    </v-alert>

    <!-- What the firewall is running -->
    <v-card v-if="state" class="ma-2">
      <v-card-title class="d-flex align-center">
        Running rules
        <v-spacer />
        <v-btn
          variant="text"
          prepend-icon="mdi-refresh"
          :loading="loading"
          @click="load"
        >
          Refresh
        </v-btn>
      </v-card-title>
      <v-card-text>
        <v-row dense>
          <v-col cols="6" md="2"
            ><div class="text-caption">Version</div>
            {{ versionText }}</v-col
          >
          <v-col cols="6" md="3">
            <div class="text-caption">sha256</div>
            <code>{{ (state.rules.sha256 || '-').slice(0, 12) }}</code>
            <v-chip
              v-if="signing.enabled"
              size="x-small"
              class="ml-2"
              :color="state.rules_signing?.running_signed ? 'success' : 'error'"
            >
              {{
                state.rules_signing?.running_signed ? 'signed' : 'not signed'
              }}
            </v-chip>
          </v-col>
          <v-col cols="6" md="2"
            ><div class="text-caption">Loaded from</div>
            {{ sourceText }}</v-col
          >
          <v-col cols="6" md="3"
            ><div class="text-caption">Loaded at</div>
            {{ state.rules_loaded_at || '-' }}</v-col
          >
          <v-col cols="6" md="2"
            ><div class="text-caption">Rejected</div>
            {{ state.rejected }}</v-col
          >
        </v-row>
        <v-alert
          v-if="state.rules_error"
          type="error"
          variant="tonal"
          density="compact"
          class="mt-2"
        >
          Last load refused ({{ state.rules_error_at }}):
          {{ state.rules_error }}
        </v-alert>
        <v-alert
          v-if="state.interface_warning"
          type="error"
          variant="tonal"
          density="compact"
          class="mt-2"
        >
          {{ interfaceName }} {{ state.interface_warning }}.
        </v-alert>
        <v-alert
          v-if="state.persist_error"
          type="warning"
          variant="tonal"
          density="compact"
          class="mt-2"
        >
          The rules are running but were not saved, so a restart would bring
          back the previous set:
          {{ state.persist_error }}
        </v-alert>
        <v-alert
          v-if="signing.error"
          type="error"
          variant="tonal"
          density="compact"
          class="mt-2"
        >
          Rules signing is misconfigured, so the firewall loads and applies no
          rules: {{ signing.error }}
        </v-alert>
        <v-alert
          v-else-if="!signing.enabled && !readonly"
          type="info"
          variant="tonal"
          density="compact"
          class="mt-2"
        >
          Rules signing is off: anyone with direct access to the COSMOS bucket
          (its credentials, or root on the host) could change the active rules
          without EagleGate noticing. Set up {{ signing.key_env }} as described
          in plugin.txt to turn it on.
        </v-alert>
        <v-alert
          v-if="state.rules.version < 0 && !readonly"
          type="error"
          variant="tonal"
          density="compact"
          class="mt-2"
        >
          The firewall is denying all telemetry because it has no rules it can
          trust. Review the rules below and apply them to restore filtering.
        </v-alert>
        <v-alert
          v-if="state.connection_untrusted"
          type="warning"
          variant="tonal"
          density="compact"
          class="mt-2"
        >
          <div>
            This connection is untrusted, so all telemetry on
            {{ interfaceName }} is being discarded
            <span v-if="state.untrusted_since"
              >(since {{ state.untrusted_since }})</span
            >. New rules do not change that.
          </div>
          <div v-if="state.untrusted_cause" class="text-caption">
            Why: {{ state.untrusted_cause }}
          </div>
          <div class="text-caption">
            Reconnecting the interface also clears it, but some senders (such as
            the NOS3 radio simulator) never reconnect on their own.
          </div>
          <template v-if="!readonly" #append>
            <v-btn variant="text" @click="openTrustDialog"
              >Restore trust…</v-btn
            >
          </template>
        </v-alert>
        <v-alert
          v-if="readMismatch"
          type="warning"
          variant="tonal"
          density="compact"
          class="mt-2"
        >
          The stored rules differ from what the firewall is running (it may have
          refused a newer file). The editor shows the stored file, which may
          have been changed outside EagleGate: check the diff before applying,
          or load a known good version from History.
        </v-alert>
      </v-card-text>
    </v-card>

    <v-alert v-if="draftOffer" type="info" variant="tonal" class="ma-2">
      There is an edited rules file in {{ draftOffer.key }} (the procedure's
      draft) that differs from the running rules.
      <template #append>
        <v-btn variant="text" @click="importDraft">Load into editor</v-btn>
        <v-btn variant="text" @click="draftOffer = null">Ignore</v-btn>
      </template>
    </v-alert>

    <!-- The editor -->
    <v-card v-if="doc" class="ma-2">
      <v-card-title class="d-flex align-center">
        Rules
        <v-chip v-if="dirty" size="small" color="warning" class="ml-2"
          >unsaved changes</v-chip
        >
        <v-spacer />
        <v-menu v-if="!readonly">
          <template #activator="{ props }">
            <v-btn v-bind="props" variant="text" prepend-icon="mdi-plus"
              >Add rule</v-btn
            >
          </template>
          <v-list>
            <v-list-item
              v-for="item in addMenu"
              :key="item.key"
              :title="item.title"
              :subtitle="item.subtitle"
              :class="{ 'ml-4': item.preset }"
              @click="addRule(item.type, item.preset)"
            />
          </v-list>
        </v-menu>
      </v-card-title>
      <v-card-text>
        <div class="text-caption mb-2">
          Checked top to bottom; the first rule that fires decides. Check rules
          (range, sequence, rate, authenticity, text) go above the ALLOW rules
          they protect.
        </div>
        <v-row dense>
          <v-col cols="12" md="3">
            <v-select
              v-model="doc.default_action"
              :items="schema.actions"
              label="When no rule fires"
              :readonly="readonly"
            />
          </v-col>
          <v-col cols="12" md="9">
            <v-text-field
              v-model="doc.description"
              label="Description"
              :readonly="readonly"
            />
          </v-col>
        </v-row>

        <div class="text-subtitle-2">Settings</div>
        <v-row dense>
          <v-col
            v-for="(spec, key) in schema.settings"
            :key="key"
            cols="12"
            md="6"
          >
            <v-switch
              :model-value="settingValue(doc, schema, key)"
              :label="spec.title || key"
              :hint="spec.help"
              persistent-hint
              color="primary"
              :readonly="readonly"
              @update:model-value="setSetting(doc, schema, key, $event)"
            />
          </v-col>
        </v-row>

        <v-expansion-panels
          v-if="Object.keys(schema.extensions || {}).length"
          multiple
          class="my-4"
        >
          <v-expansion-panel
            v-for="(extension, section) in schema.extensions"
            :key="section"
          >
            <v-expansion-panel-title>
              {{ extension.name }} {{ extension.version }}: "{{ section }}"
              section
              <span class="text-caption ml-2"
                >(applied, versioned and signed with these rules)</span
              >
            </v-expansion-panel-title>
            <v-expansion-panel-text>
              <schema-field
                :spec="extension.schema"
                :model-value="doc[section]"
                :readonly="readonly"
                @update:model-value="setSection(section, $event)"
              />
            </v-expansion-panel-text>
          </v-expansion-panel>
        </v-expansion-panels>

        <v-table density="compact">
          <thead>
            <tr>
              <th>#</th>
              <th>On</th>
              <th>ID</th>
              <th>Type</th>
              <th>Action</th>
              <th>Applies to</th>
              <th class="text-right">Hits</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="(rule, index) in doc.rules"
              :key="rule.id + index"
              :class="{ 'text-disabled': rule.enabled === false }"
            >
              <td>{{ index + 1 }}</td>
              <td>
                <v-switch
                  :model-value="rule.enabled !== false"
                  density="compact"
                  hide-details
                  color="primary"
                  :readonly="readonly"
                  :aria-label="`Enable ${rule.id}`"
                  @update:model-value="setEnabled(rule, $event)"
                />
              </td>
              <td>
                <div>{{ rule.id }}</div>
                <div class="text-caption">{{ rule.description }}</div>
              </td>
              <td>
                <v-chip size="small">{{ rule.type || 'match' }}</v-chip>
              </td>
              <td>
                <v-chip
                  size="small"
                  :color="rule.action === 'ALLOW' ? 'success' : 'error'"
                >
                  {{ rule.action }}
                </v-chip>
              </td>
              <td class="text-caption">{{ matchSummary(rule.match) }}</td>
              <td class="text-right">{{ hits(rule.id) }}</td>
              <td class="text-no-wrap">
                <template v-if="!readonly">
                  <v-btn
                    icon="mdi-arrow-up"
                    size="small"
                    variant="text"
                    :disabled="index === 0"
                    aria-label="Move up"
                    @click="move(index, -1)"
                  />
                  <v-btn
                    icon="mdi-arrow-down"
                    size="small"
                    variant="text"
                    :disabled="index === doc.rules.length - 1"
                    aria-label="Move down"
                    @click="move(index, 1)"
                  />
                </template>
                <v-btn
                  :icon="readonly ? 'mdi-eye' : 'mdi-pencil'"
                  size="small"
                  variant="text"
                  aria-label="Edit"
                  @click="editRule(index)"
                />
                <template v-if="!readonly">
                  <v-btn
                    icon="mdi-content-copy"
                    size="small"
                    variant="text"
                    aria-label="Duplicate"
                    @click="duplicate(index)"
                  />
                  <v-btn
                    icon="mdi-delete"
                    size="small"
                    variant="text"
                    aria-label="Delete"
                    @click="remove(index)"
                  />
                </template>
              </td>
            </tr>
            <tr>
              <td></td>
              <td colspan="5" class="text-caption">
                No rule fired: {{ doc.default_action }}
              </td>
              <td class="text-right">
                {{ state ? state.rules.default_hits : '' }}
              </td>
              <td></td>
            </tr>
          </tbody>
        </v-table>

        <v-alert v-if="errors.length" type="error" variant="tonal" class="mt-4">
          <div class="font-weight-bold">
            The firewall would refuse this file:
          </div>
          <div v-for="error in errors" :key="error">{{ error }}</div>
        </v-alert>
        <v-alert
          v-if="warningList.length"
          type="warning"
          variant="tonal"
          class="mt-4"
        >
          <div v-for="warning in warningList" :key="warning">{{ warning }}</div>
        </v-alert>
      </v-card-text>
      <v-card-actions v-if="!readonly">
        <v-btn variant="text" prepend-icon="mdi-history" @click="openHistory"
          >History</v-btn
        >
        <v-spacer />
        <v-btn variant="text" :disabled="!dirty" @click="discard"
          >Discard changes</v-btn
        >
        <v-btn
          color="primary"
          variant="flat"
          :disabled="!canApply || errors.length > 0"
          @click="review"
        >
          Review and apply
        </v-btn>
      </v-card-actions>
    </v-card>

    <rule-editor
      v-if="schema"
      v-model="editor.open"
      :original="editor.rule"
      :is-new="editor.isNew"
      :other-ids="editor.otherIds"
      :schema="schema"
      :readonly="readonly"
      @save="saveRule"
    />

    <!-- Review: what changes, then apply -->
    <v-dialog v-model="reviewing" max-width="1000" scrollable>
      <v-card>
        <v-card-title
          >Apply version {{ toApply && toApply.doc.version }}?</v-card-title
        >
        <v-card-text>
          <v-alert
            v-if="warningList.length"
            type="warning"
            variant="tonal"
            density="compact"
            class="mb-2"
          >
            <div v-for="warning in warningList" :key="warning">
              {{ warning }}
            </div>
          </v-alert>
          <pre class="diff"><span
            v-for="(row, i) in diffRows"
            :key="i"
            :class="{ added: row.op === '+', removed: row.op === '-' }"
          >{{ row.op }} {{ row.line }}
</span></pre>
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn variant="text" :disabled="applying" @click="reviewing = false"
            >Cancel</v-btn
          >
          <v-btn
            color="primary"
            variant="flat"
            :loading="applying"
            @click="apply"
            >Apply</v-btn
          >
        </v-card-actions>
      </v-card>
    </v-dialog>

    <!-- Restore trust: an admin request, then RESTORE_TRUST -->
    <v-dialog v-model="trust.open" max-width="640">
      <v-card>
        <v-card-title>Restore trust in {{ interfaceName }}?</v-card-title>
        <v-card-text>
          <p class="mb-2">
            The firewall stops discarding this connection's telemetry and judges
            each packet again. Do this only once you know why the connection
            became untrusted:
          </p>
          <p class="text-caption mb-4">{{ state?.untrusted_cause }}</p>
          <v-textarea
            v-model="trust.reason"
            label="Reason (kept in the audit log)"
            :error-messages="
              trust.reason ? reasonProblem(trust.reason) || [] : []
            "
            counter="256"
            rows="2"
            auto-grow
          />
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn
            variant="text"
            :disabled="trust.busy"
            @click="trust.open = false"
            >Cancel</v-btn
          >
          <v-btn
            color="primary"
            variant="flat"
            :loading="trust.busy"
            :disabled="!!reasonProblem(trust.reason)"
            @click="restoreTrust"
            >Restore trust</v-btn
          >
        </v-card-actions>
      </v-card>
    </v-dialog>

    <!-- History of applied versions -->
    <v-dialog v-model="history.open" max-width="700" scrollable>
      <v-card>
        <v-card-title>Applied versions</v-card-title>
        <v-card-text>
          <div v-if="!history.items.length" class="text-caption">
            No versions applied from here yet; the firewall is running the
            plugin's original file.
          </div>
          <v-list density="compact">
            <v-list-item
              v-for="item in history.items"
              :key="item.name"
              :title="item.name"
              :subtitle="String(item.modified || '')"
            >
              <template #append>
                <v-btn variant="text" @click="restore(item.name)"
                  >Load into editor</v-btn
                >
              </template>
            </v-list-item>
          </v-list>
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn variant="text" @click="history.open = false">Close</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </div>
</template>

<script>
import { TopBar } from '@openc3/vue-common/components'
import RuleEditor from './RuleEditor.vue'
import SchemaField from './SchemaField.vue'
import { reasonProblem } from './adminRequest.js'
import {
  clone,
  lineDiff,
  linkSummary,
  newRule,
  setSetting,
  settingValue,
  toFileText,
  toInt,
  validate,
  warnings,
  withBumpedVersion,
  withExtensions,
} from './rulesModel.js'
import {
  DEFAULT_INTERFACE,
  adminAction,
  applyRules,
  cosmosInfo,
  downloadKey,
  draftKey,
  firewallInterfaces,
  firewallState,
  listHistory,
  runningKey,
  sha256,
  userIsAdmin,
} from '../../services/rulesStore.js'

const SCHEMA_URL = '/tools/eaglegate/eaglegate_rules_schema.json'
const EMPTY_RULES = { version: 0, default_action: 'DENY', rules: [] }
const INTERFACE_KEY = 'eaglegate.interface' // remembers the last interface edited

export default {
  components: { RuleEditor, SchemaField, TopBar },
  data() {
    return {
      title: 'EagleGate Firewall Rules',
      interfaceName: DEFAULT_INTERFACE,
      interfaces: [], // [{ name, target, protocols }] running the firewall
      baseSchema: null, // public/eaglegate_rules_schema.json: the core rules format
      isEnterprise: false,
      isAdmin: false,
      loaded: false,
      loading: false,
      loadError: null,
      state: null, // the firewall section of interface_details
      runningText: null, // text of the stored running rule set, as stored
      runningNormal: '', // the same rules in the editor's formatting, for dirty checks and diffs
      readMismatch: false,
      baseSha256: null, // the rule set the edits started from
      doc: null, // the rules being edited
      draftOffer: null,
      editor: {
        open: false,
        rule: null,
        index: -1,
        isNew: false,
        otherIds: [],
      },
      reviewing: false,
      applying: false,
      toApply: null,
      history: { open: false, items: [] },
      trust: { open: false, reason: '', busy: false },
    }
  },
  computed: {
    // The core format plus what this interface's extensions add
    schema() {
      if (!this.baseSchema) return null
      return withExtensions(this.baseSchema, this.state?.extensions || {})
    },
    interfaceItems() {
      return this.interfaces.map((i) => ({
        title: `${i.name} (rules of ${i.target})`,
        subtitle: i.protocols.join(' → '),
        value: i.name,
      }))
    },
    readonly() {
      return this.isEnterprise && !this.isAdmin
    },
    // Each rule type, followed by its presets (ready-made starting points)
    addMenu() {
      const items = []
      for (const [type, spec] of Object.entries(this.schema.rule_types)) {
        items.push({ key: type, type, title: type, subtitle: spec.description })
        for (const preset of spec.presets || [])
          items.push({
            key: `${type}/${preset.name}`,
            type,
            preset,
            title: preset.title,
          })
      }
      return items
    },
    menus() {
      return [
        {
          label: 'File',
          items: [
            {
              label: 'Refresh from firewall',
              icon: 'mdi-refresh',
              command: () => this.load(),
            },
            {
              label: 'History',
              icon: 'mdi-history',
              command: () => this.openHistory(),
            },
          ],
        },
      ]
    },
    versionText() {
      const version = this.state.rules.version
      return version < 0 ? 'none (denying everything)' : version
    },
    sourceText() {
      return (
        {
          active: 'applied rules',
          pending: 'applied rules',
          original: 'plugin original',
        }[this.state.rules_source] || '-'
      )
    },
    dirty() {
      return this.doc !== null && toFileText(this.doc) !== this.runningNormal
    },
    // Unchanged rules can still be applied when the firewall runs none: that is
    // how signing is bootstrapped and how a tampered active file is replaced
    canApply() {
      return this.dirty || (this.state !== null && this.state.rules.version < 0)
    },
    signing() {
      return (
        this.state?.rules_signing || {
          enabled: false,
          error: null,
          key_env: 'EAGLEGATE_RULES_KEY',
        }
      )
    },
    errors() {
      return this.doc && this.schema ? validate(this.doc, this.schema) : []
    },
    warningList() {
      if (!this.doc || !this.schema) return []
      return warnings(
        this.doc,
        this.schema,
        this.state && this.dirty ? this.state.rules : null,
      )
    },
    diffRows() {
      return this.toApply ? lineDiff(this.runningNormal, this.toApply.text) : []
    },
  },
  async created() {
    this.isAdmin = userIsAdmin()
    try {
      const [info, schema] = await Promise.all([
        cosmosInfo(),
        fetch(SCHEMA_URL).then((r) => {
          if (!r.ok)
            throw new Error(`could not load ${SCHEMA_URL} (HTTP ${r.status})`)
          return r.json()
        }),
      ])
      this.isEnterprise = info.enterprise === true
      this.baseSchema = schema
    } catch (error) {
      this.loadError = `Could not start the editor: ${error.message}`
      return
    }
    await this.findInterfaces()
    await this.load()
  },
  methods: {
    settingValue,
    setSetting,
    reasonProblem,
    async findInterfaces() {
      try {
        this.interfaces = await firewallInterfaces()
      } catch {
        this.interfaces = [] // keep the default interface
      }
      const names = this.interfaces.map((i) => i.name)
      let remembered = null
      try {
        remembered = localStorage.getItem(INTERFACE_KEY)
      } catch {
        // storage blocked: use the default
      }
      if (remembered && names.includes(remembered))
        this.interfaceName = remembered
      else if (names.length && !names.includes(DEFAULT_INTERFACE))
        this.interfaceName = names[0]
    },
    async selectInterface(name) {
      if (name === this.interfaceName) return
      if (this.dirty) {
        try {
          await this.$dialog.confirm(
            `Discard your unsaved changes to ${this.interfaceName}'s rules?`,
            { okText: 'Discard' },
          )
        } catch {
          return
        }
      }
      this.interfaceName = name
      try {
        localStorage.setItem(INTERFACE_KEY, name)
      } catch {
        // not remembered; harmless
      }
      this.doc = null // so load() does not ask again
      this.state = null
      await this.load()
    },
    setSection(section, value) {
      if (value === undefined) delete this.doc[section]
      else this.doc[section] = value
    },
    openTrustDialog() {
      this.trust = { open: true, reason: '', busy: false }
    },
    async restoreTrust() {
      this.trust.busy = true
      try {
        const answer = await adminAction(
          this.interfaceName,
          'restore_trust',
          'RESTORE_TRUST',
          this.trust.reason,
        )
        this.state = answer.state
        if (answer.ok) {
          this.$notify.normal({ title: 'Trust restored', body: answer.detail })
          this.trust.open = false
        } else {
          this.$notify.serious({
            title: 'The firewall refused',
            body: answer.detail,
          })
        }
      } catch (error) {
        this.$notify.serious({
          title: 'Trust not restored',
          body: error.message,
        })
      } finally {
        this.trust.busy = false
      }
    },
    async load() {
      if (this.dirty) {
        try {
          await this.$dialog.confirm(
            'Discard your unsaved changes and reload the running rules?',
            {
              okText: 'Discard',
            },
          )
        } catch {
          return
        }
      }
      this.loading = true
      this.loadError = null
      try {
        const state = await firewallState(this.interfaceName)
        const text = await downloadKey(runningKey(state))
        this.state = state
        this.baseSha256 = state.rules.sha256
        this.runningText = text
        this.readMismatch =
          text !== null && (await sha256(text)) !== state.rules.sha256
        this.doc = this.parseOrEmpty(text)
        this.runningNormal = toFileText(this.doc)
        await this.checkDraft(state)
        this.loaded = true
      } catch (error) {
        this.loadError = `Could not read the firewall state from ${this.interfaceName}: ${error.message}`
      } finally {
        this.loading = false
      }
    },
    parseOrEmpty(text) {
      if (text === null) return clone(EMPTY_RULES)
      try {
        return JSON.parse(text)
      } catch {
        this.loadError =
          'The stored rules file is not valid JSON; starting from an empty rule set.'
        return clone(EMPTY_RULES)
      }
    },
    async checkDraft(state) {
      this.draftOffer = null
      if (this.readonly) return
      const key = draftKey(state)
      const text = await downloadKey(key)
      if (text !== null && (await sha256(text)) !== state.rules.sha256) {
        this.draftOffer = { key, text }
      }
    },
    importDraft() {
      try {
        this.doc = JSON.parse(this.draftOffer.text)
      } catch (error) {
        this.$notify.serious({
          title: 'Draft is not valid JSON',
          body: error.message,
        })
        return
      }
      this.draftOffer = null
    },
    matchSummary(match) {
      if (!match || !Object.keys(match).length) return 'every packet'
      const parts = []
      const hex = (v) => {
        const n = toInt(v)
        return Number.isNaN(n)
          ? String(v)
          : `0x${n.toString(16).toUpperCase().padStart(3, '0')}`
      }
      if (match.apid) parts.push(`APID ${match.apid.map(hex).join(', ')}`)
      if (match.apid_range)
        parts.push(
          `APID ${hex(match.apid_range[0])}..${hex(match.apid_range[1])}`,
        )
      if (match.packet_type) parts.push(match.packet_type)
      if (match.sec_hdr !== undefined) parts.push(`sec_hdr ${match.sec_hdr}`)
      if (match.min_length !== undefined || match.max_length !== undefined)
        parts.push(
          `length ${match.min_length ?? ''}..${match.max_length ?? ''}`,
        )
      for (const check of match.bytes || [])
        parts.push(
          `byte[${check.offset}] & ${check.mask ?? '0xFF'} == ${check.value}`,
        )
      if (match.link) parts.push(linkSummary(match.link))
      return parts.join('; ')
    },
    hits(id) {
      return this.state?.rules.rule_hits?.[id] ?? ''
    },
    setEnabled(rule, on) {
      if (on) delete rule.enabled
      else rule.enabled = false
    },
    move(index, step) {
      const rules = this.doc.rules
      ;[rules[index], rules[index + step]] = [rules[index + step], rules[index]]
    },
    otherIds(exceptIndex) {
      return this.doc.rules.filter((_, i) => i !== exceptIndex).map((r) => r.id)
    },
    addRule(type, preset = null) {
      const ids = this.doc.rules.map((r) => r.id)
      this.editor = {
        open: true,
        rule: newRule(type, this.schema, ids, preset),
        index: -1,
        isNew: true,
        otherIds: ids,
      }
    },
    editRule(index) {
      this.editor = {
        open: true,
        rule: this.doc.rules[index],
        index,
        isNew: false,
        otherIds: this.otherIds(index),
      }
    },
    saveRule(rule) {
      if (this.editor.isNew) {
        // New check rules go to the top, where they can protect the ALLOW rules
        if (this.schema.rule_types[rule.type || 'match'].is_check)
          this.doc.rules.unshift(rule)
        else this.doc.rules.push(rule)
      } else {
        this.doc.rules.splice(this.editor.index, 1, rule)
      }
    },
    duplicate(index) {
      const copy = clone(this.doc.rules[index])
      let n = 2
      while (this.doc.rules.some((r) => r.id === `${copy.id}-${n}`)) n += 1
      copy.id = `${copy.id}-${n}`
      this.doc.rules.splice(index + 1, 0, copy)
    },
    async remove(index) {
      try {
        await this.$dialog.confirm(
          `Delete rule '${this.doc.rules[index].id}'?`,
          { okText: 'Delete' },
        )
      } catch {
        return
      }
      this.doc.rules.splice(index, 1)
    },
    discard() {
      this.doc = JSON.parse(this.runningNormal)
    },
    review() {
      const doc = withBumpedVersion(this.doc, this.state.rules.version)
      this.toApply = { doc, text: toFileText(doc) }
      this.reviewing = true
    },
    async apply() {
      this.applying = true
      try {
        const state = await applyRules(
          this.interfaceName,
          this.toApply.text,
          this.baseSha256,
        )
        this.state = state
        this.baseSha256 = state.rules.sha256
        this.runningText = this.toApply.text
        this.runningNormal = this.toApply.text
        this.readMismatch = false
        this.doc = JSON.parse(this.toApply.text)
        this.reviewing = false
        this.$notify.normal({
          title: `Rules version ${state.rules.version} active`,
          body: `${this.interfaceName} is now filtering with the new rules`,
        })
      } catch (error) {
        this.reviewing = false
        const conflict = /someone else/.test(error.message)
        this.$notify.serious({
          title: conflict
            ? 'Someone else changed the rules'
            : 'Rules not applied',
          body: error.message,
        })
        // Show the refusal in the status panel
        try {
          this.state = await firewallState(this.interfaceName)
        } catch {
          // keep the previous state
        }
      } finally {
        this.applying = false
      }
    },
    async openHistory() {
      if (!this.state) return
      try {
        this.history.items = await listHistory(this.state.rules_keys.history)
        this.history.open = true
      } catch (error) {
        this.$notify.serious({
          title: 'Could not list history',
          body: error.message,
        })
      }
    },
    async restore(name) {
      let doc
      try {
        const text = await downloadKey(this.state.rules_keys.history + name)
        if (text === null) throw new Error(`${name} no longer exists`)
        doc = JSON.parse(text)
      } catch (error) {
        this.$notify.serious({
          title: 'Could not load that version',
          body: error.message,
        })
        return
      }
      this.doc = doc
      this.history.open = false
      this.$notify.normal({
        title: `Loaded ${name} into the editor`,
        body: 'Review and apply it to restore it',
      })
    },
  },
}
</script>

<style scoped>
.diff {
  font-size: 0.85em;
  white-space: pre-wrap;
}
.diff .added {
  background-color: rgba(76, 175, 80, 0.25);
}
.diff .removed {
  background-color: rgba(244, 67, 54, 0.25);
}
</style>
