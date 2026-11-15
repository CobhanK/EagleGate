<!--
  Edits one rule in a dialog. The form is generated from the schema the
  firewall's parser publishes (public/eaglegate_rules_schema.json), so every
  field here is one the firewall accepts. Emits "save" with the edited rule.
-->
<template>
  <v-dialog :model-value="modelValue" max-width="900" persistent scrollable>
    <v-card v-if="rule">
      <v-card-title>{{
        isNew ? 'Add rule' : `Edit rule '${original.id}'`
      }}</v-card-title>
      <v-card-text>
        <v-row dense>
          <v-col cols="12" md="6">
            <v-text-field
              v-model="rule.id"
              label="ID"
              hint="Unique; shown in quarantine reasons"
              :readonly="readonly"
            />
          </v-col>
          <v-col cols="6" md="3">
            <v-select
              :model-value="type"
              :items="typeItems"
              label="Type"
              :readonly="readonly"
              @update:model-value="changeType"
            />
          </v-col>
          <v-col cols="6" md="3">
            <v-select
              v-model="rule.action"
              :items="typeSpec.actions"
              label="Action"
              :readonly="readonly"
            />
          </v-col>
          <v-col cols="12">
            <v-text-field
              v-model="rule.description"
              label="Description"
              :readonly="readonly"
            />
          </v-col>
          <v-col cols="12">
            <v-switch
              :model-value="rule.enabled !== false"
              label="Enabled"
              color="primary"
              hide-details
              :readonly="readonly"
              @update:model-value="setEnabled"
            />
          </v-col>
        </v-row>
        <div class="text-caption mb-4">{{ typeSpec.description }}</div>

        <div class="text-subtitle-1">
          Applies to packets where all of these hold
        </div>
        <div class="text-caption mb-2">
          Leave a field empty to not check it; all empty matches every packet.
        </div>
        <v-row dense>
          <v-col
            v-for="(spec, key) in simpleMatchKeys"
            :key="key"
            cols="12"
            md="6"
          >
            <v-select
              v-if="spec.type === 'enum' || spec.type === 'bool'"
              :model-value="choiceValue(rule.match, key)"
              :items="choiceItems(spec)"
              :label="key"
              :hint="spec.help"
              persistent-hint
              :readonly="readonly"
              @update:model-value="setChoice(rule.match, key, spec, $event)"
            />
            <div v-else-if="spec.type === 'int_pair'" class="d-flex ga-2">
              <v-text-field
                :model-value="pairText(rule.match[key], 0)"
                :label="`${key} low`"
                :hint="spec.help"
                persistent-hint
                :readonly="readonly"
                @update:model-value="setPair(rule.match, key, 0, $event)"
              />
              <v-text-field
                :model-value="pairText(rule.match[key], 1)"
                :label="`${key} high`"
                :readonly="readonly"
                @update:model-value="setPair(rule.match, key, 1, $event)"
              />
            </div>
            <v-text-field
              v-else
              :model-value="fieldText(rule.match, key, spec)"
              :label="key"
              :hint="hintFor(spec)"
              persistent-hint
              :readonly="readonly"
              @update:model-value="setField(rule.match, key, spec, $event)"
            />
          </v-col>
        </v-row>

        <div class="text-subtitle-2 mt-4">Byte checks</div>
        <div class="text-caption">{{ matchSpec.bytes.help }}</div>
        <div
          v-for="(check, index) in rule.match.bytes || []"
          :key="index"
          class="d-flex ga-2 align-center"
        >
          <v-text-field
            v-for="(spec, field) in matchSpec.bytes.fields"
            :key="field"
            :model-value="fieldText(check, field, spec)"
            :label="field"
            :readonly="readonly"
            density="compact"
            @update:model-value="setField(check, field, spec, $event)"
          />
          <v-btn
            v-if="!readonly"
            icon="mdi-delete"
            variant="text"
            aria-label="Remove byte check"
            @click="removeByteCheck(index)"
          />
        </div>
        <v-btn
          v-if="!readonly"
          variant="text"
          prepend-icon="mdi-plus"
          @click="addByteCheck"
        >
          Add byte check
        </v-btn>

        <!-- Link conditions: keys come from the extension on this interface -->
        <template v-if="hasLinkKeys || rule.match.link">
          <div class="text-subtitle-2 mt-4">Link conditions</div>
          <div class="text-caption">{{ matchSpec.link.help }}</div>
          <div v-if="!hasLinkKeys" class="text-caption text-error">
            No extension on this interface provides link information; remove
            these conditions or edit the rules of an interface that has one.
          </div>
          <v-row dense>
            <v-col v-for="(spec, key) in linkKeys" :key="key" cols="12" md="6">
              <v-select
                v-if="spec.type === 'enum_list'"
                :model-value="rule.match.link?.[key] || []"
                :items="spec.values"
                :label="`link ${key}`"
                :hint="spec.help"
                persistent-hint
                multiple
                chips
                closable-chips
                :readonly="readonly"
                @update:model-value="setLink(key, $event)"
              />
              <v-text-field
                v-else
                :model-value="(rule.match.link?.[key] || []).join(', ')"
                :label="`link ${key}`"
                :hint="hintFor({ ...spec, type: 'int_list' })"
                persistent-hint
                :readonly="readonly"
                @update:model-value="setLinkInts(key, $event)"
              />
            </v-col>
          </v-row>
          <v-btn
            v-if="!readonly && rule.match.link"
            variant="text"
            prepend-icon="mdi-close"
            @click="clearLink"
            >Remove link conditions</v-btn
          >
        </template>

        <template v-if="Object.keys(typeSpec.params).length">
          <div class="text-subtitle-1 mt-4">{{ type }} settings</div>
          <div
            v-for="text in typeSpec.param_rules"
            :key="text"
            class="text-caption"
          >
            Requires: {{ text }}
          </div>
          <v-row dense>
            <v-col
              v-for="(spec, key) in visibleParams"
              :key="key"
              cols="12"
              :md="spec.type === 'object_list' ? 12 : 6"
            >
              <v-select
                v-if="spec.type === 'enum'"
                :model-value="rule.params[key] ?? spec.default"
                :items="enumItems(spec)"
                :label="labelFor(key, spec)"
                :hint="spec.help"
                persistent-hint
                :readonly="readonly"
                @update:model-value="
                  key === 'encoding'
                    ? changeEncoding($event)
                    : setParam(key, $event)
                "
              />
              <v-switch
                v-else-if="spec.type === 'bool'"
                :model-value="rule.params[key] ?? spec.default"
                :label="key"
                :hint="spec.help"
                persistent-hint
                color="primary"
                :readonly="readonly"
                @update:model-value="setParam(key, $event)"
              />
              <v-combobox
                v-else-if="spec.type === 'string_list'"
                :model-value="rule.params[key] || []"
                :label="labelFor(key, spec)"
                :hint="hintFor(spec)"
                persistent-hint
                multiple
                chips
                closable-chips
                :readonly="readonly"
                @update:model-value="setParam(key, $event)"
              />
              <v-text-field
                v-else-if="spec.type === 'charset'"
                :model-value="rule.params[key] ?? ''"
                :label="labelFor(key, spec)"
                :hint="hintFor(spec)"
                persistent-hint
                :readonly="readonly"
                @update:model-value="setParam(key, $event)"
              />
              <div v-else-if="spec.type === 'object_list'">
                <div class="text-subtitle-2">{{ labelFor(key, spec) }}</div>
                <div class="text-caption">{{ spec.help }}</div>
                <div
                  v-for="(item, index) in rule.params[key] || []"
                  :key="index"
                  class="d-flex ga-2 align-center"
                >
                  <v-text-field
                    v-for="(itemSpec, field) in spec.fields"
                    :key="field"
                    :model-value="fieldText(item, field, itemSpec)"
                    :label="labelFor(field, itemSpec)"
                    :hint="itemSpec.help"
                    :readonly="readonly"
                    density="compact"
                    @update:model-value="
                      setField(item, field, itemSpec, $event)
                    "
                  />
                  <v-btn
                    v-if="!readonly"
                    icon="mdi-delete"
                    variant="text"
                    :aria-label="`Remove ${key} entry`"
                    @click="removeListItem(key, index)"
                  />
                </div>
                <v-btn
                  v-if="
                    !readonly &&
                    (rule.params[key] || []).length < (spec.max_items ?? 99)
                  "
                  variant="text"
                  prepend-icon="mdi-plus"
                  @click="addListItem(key)"
                >
                  Add field
                </v-btn>
              </div>
              <v-text-field
                v-else
                :model-value="fieldText(rule.params, key, spec)"
                :label="labelFor(key, spec)"
                :hint="hintFor(spec)"
                persistent-hint
                :readonly="readonly"
                @update:model-value="setField(rule.params, key, spec, $event)"
              />
            </v-col>
          </v-row>
        </template>

        <!-- Text rules: what the settings let through, and a sample to try -->
        <template v-if="type === 'text'">
          <div class="text-subtitle-1 mt-4">What these settings allow</div>
          <div v-if="compiledText.error" class="text-caption text-error">
            {{ compiledText.error }}
          </div>
          <code v-else class="allowed">{{ allowedPreview }}</code>
          <div class="text-caption mt-1">
            Control characters, DEL and (for ascii) bytes above 0x7E are never
            allowed in text; use encoding raw for binary fields.
          </div>
          <v-text-field
            v-model="sample"
            class="mt-2"
            :label="
              encoding === 'raw'
                ? 'Try a sample (hex bytes)'
                : 'Try a sample value'
            "
            :hint="
              encoding === 'raw'
                ? 'e.g. 41 42 1b 5b'
                : 'Checked exactly as the firewall checks one field'
            "
            persistent-hint
            clearable
          />
          <v-alert
            v-if="sampleResult"
            :type="
              sampleResult.allowed
                ? 'success'
                : sampleResult.denied
                  ? 'error'
                  : 'info'
            "
            variant="tonal"
            density="compact"
            class="mt-2"
          >
            {{
              sampleResult.allowed
                ? 'Allowed'
                : sampleResult.denied
                  ? `Denied: ${sampleResult.denied}`
                  : sampleResult.error
            }}
          </v-alert>
        </template>

        <v-alert v-if="errors.length" type="error" variant="tonal" class="mt-4">
          <div v-for="error in errors" :key="error">{{ error }}</div>
        </v-alert>
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn variant="text" @click="$emit('update:modelValue', false)">
          {{ readonly ? 'Close' : 'Cancel' }}
        </v-btn>
        <v-btn
          v-if="!readonly"
          color="primary"
          variant="flat"
          :disabled="errors.length > 0"
          @click="save"
        >
          Done
        </v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<script>
import {
  appliesTo,
  clone,
  dropInapplicable,
  fromInput,
  newRule,
  validate,
} from './rulesModel.js'
import {
  checkField,
  compileText,
  describeAllowed,
  sampleBytes,
} from './textCheck.js'

export default {
  props: {
    modelValue: { type: Boolean, default: false },
    original: { type: Object, default: null }, // the rule being edited
    isNew: { type: Boolean, default: false },
    otherIds: { type: Array, default: () => [] }, // ids of every other rule
    schema: { type: Object, required: true },
    readonly: { type: Boolean, default: false },
  },
  emits: ['update:modelValue', 'save'],
  data() {
    return { rule: null, sample: '' }
  },
  computed: {
    type() {
      return this.rule.type || 'match'
    },
    typeSpec() {
      return this.schema.rule_types[this.type]
    },
    typeItems() {
      return Object.keys(this.schema.rule_types).map((name) => ({
        title: name,
        value: name,
      }))
    },
    matchSpec() {
      return this.schema.match.keys
    },
    encoding() {
      return this.rule.params.encoding || 'ascii'
    },
    // Settings that apply to the chosen encoding (text rules); all for others
    visibleParams() {
      return Object.fromEntries(
        Object.entries(this.typeSpec.params).filter(([, spec]) =>
          appliesTo(spec, this.encoding),
        ),
      )
    },
    compiledText() {
      try {
        return { ok: compileText(this.rule.params, this.schema) }
      } catch (error) {
        return { error: error.message }
      }
    },
    allowedPreview() {
      return this.compiledText.ok ? describeAllowed(this.compiledText.ok) : ''
    },
    sampleResult() {
      if (!this.sample || !this.compiledText.ok) return null
      const bytes = sampleBytes(this.sample, this.encoding)
      if (!bytes)
        return { error: 'Enter the sample as hex bytes, e.g. 1b 5b 32' }
      const reason = checkField(this.compiledText.ok, bytes)
      return reason ? { denied: reason } : { allowed: true }
    },
    simpleMatchKeys() {
      // Every match condition except "bytes" and "link", which have their own editors
      return Object.fromEntries(
        Object.entries(this.matchSpec).filter(
          ([key]) => key !== 'bytes' && key !== 'link',
        ),
      )
    },
    linkKeys() {
      return this.matchSpec.link?.keys || {}
    },
    hasLinkKeys() {
      return Object.keys(this.linkKeys).length > 0
    },
    errors() {
      // Validate the rule on its own, plus the id clash the page knows about
      const errors = validate(
        { version: 0, default_action: 'DENY', rules: [this.clean(this.rule)] },
        this.schema,
      )
      if (this.otherIds.includes(this.rule.id?.trim()))
        errors.push(`rule id '${this.rule.id}' is already used`)
      return errors
    },
  },
  watch: {
    modelValue: {
      immediate: true,
      handler(open) {
        if (open && this.original) {
          const copy = clone(this.original)
          copy.match = copy.match || {}
          copy.params = copy.params || {}
          this.rule = copy
          this.sample = ''
        }
      },
    },
  },
  methods: {
    labelFor(key, spec) {
      return spec.required ? `${key} *` : key
    },
    hintFor(spec) {
      const parts = []
      if (spec.help) parts.push(spec.help)
      if (spec.type === 'int_list') parts.push('comma separated, e.g. 2, 0x003')
      if (spec.type === 'string_list') parts.push('press Enter after each')
      if (spec.min !== undefined && spec.max !== undefined)
        parts.push(`${spec.min}..${spec.max}`)
      if (spec.default !== undefined) parts.push(`default ${spec.default}`)
      return parts.join('; ')
    },
    fieldText(obj, key, spec) {
      const value = obj[key]
      if (value === undefined || value === null) return ''
      if (spec.type === 'int_list') return value.join(', ')
      return String(value)
    },
    setField(obj, key, spec, text) {
      let value
      if (spec.type === 'int_list') {
        const items = String(text)
          .split(',')
          .map((part) => fromInput({ type: 'int' }, part))
          .filter((v) => v !== undefined)
        value = items.length ? items : undefined
      } else {
        value = fromInput(spec, text)
      }
      if (value === undefined) delete obj[key]
      else obj[key] = value
    },
    pairText(pair, index) {
      return pair && pair[index] !== undefined ? String(pair[index]) : ''
    },
    setPair(obj, key, index, text) {
      const pair = [...(obj[key] || ['', ''])]
      pair[index] = fromInput({ type: 'int' }, text) ?? ''
      if (pair.every((v) => v === '')) delete obj[key]
      else obj[key] = pair
    },
    choiceItems(spec) {
      const values = spec.type === 'bool' ? [true, false] : spec.values
      return [{ title: '(not checked)', value: null }].concat(
        values.map((v) => ({ title: String(v), value: v })),
      )
    },
    choiceValue(obj, key) {
      return obj[key] === undefined ? null : obj[key]
    },
    setChoice(obj, key, spec, value) {
      if (value === null) delete obj[key]
      else obj[key] = value
    },
    enumItems(spec) {
      return spec.values.map((value) => ({
        title: spec.value_help?.[value]
          ? `${value}: ${spec.value_help[value]}`
          : String(value),
        value,
      }))
    },
    // Store a setting; empty values are removed rather than written as ""
    setParam(key, value) {
      const empty =
        value === null ||
        value === undefined ||
        value === '' ||
        (Array.isArray(value) && value.length === 0)
      if (empty) delete this.rule.params[key]
      else this.rule.params[key] = value
    },
    changeEncoding(encoding) {
      this.rule.params.encoding = encoding
      dropInapplicable(this.rule.params, this.typeSpec.params, true)
      this.sample = ''
    },
    addListItem(key) {
      const items = this.rule.params[key] || []
      this.rule.params[key] = [
        ...items,
        { name: `FIELD${items.length + 1}`, offset: 12, length: 32 },
      ]
    },
    removeListItem(key, index) {
      this.rule.params[key].splice(index, 1)
    },
    setEnabled(on) {
      if (on) delete this.rule.enabled
      else this.rule.enabled = false
    },
    setLink(key, values) {
      const link = { ...(this.rule.match.link || {}) }
      if (values && values.length) link[key] = values
      else delete link[key]
      if (Object.keys(link).length) this.rule.match.link = link
      else delete this.rule.match.link
    },
    setLinkInts(key, text) {
      const values = String(text)
        .split(',')
        .map((part) => fromInput({ type: 'int' }, part))
        .filter((v) => v !== undefined)
      this.setLink(key, values)
    },
    clearLink() {
      delete this.rule.match.link
    },
    addByteCheck() {
      this.rule.match.bytes = [
        ...(this.rule.match.bytes || []),
        { offset: 6, mask: '0xFF', value: '0x00' },
      ]
    },
    removeByteCheck(index) {
      this.rule.match.bytes.splice(index, 1)
      if (!this.rule.match.bytes.length) delete this.rule.match.bytes
    },
    changeType(type) {
      // Keep what still applies; take the new type's defaults for the rest
      const fresh = newRule(type, this.schema, [])
      this.rule.type = fresh.type
      if (!fresh.type) delete this.rule.type
      if (!this.schema.rule_types[type].actions.includes(this.rule.action))
        this.rule.action = fresh.action
      this.rule.params = fresh.params || {}
    },
    // The rule as it is written to the file: no empty params object
    clean(rule) {
      const copy = clone(rule)
      if (copy.params && !Object.keys(copy.params).length) delete copy.params
      if (!copy.description) delete copy.description
      copy.id = (copy.id || '').trim()
      return copy
    },
    save() {
      this.$emit('save', this.clean(this.rule))
      this.$emit('update:modelValue', false)
    },
  },
}
</script>

<style scoped>
.allowed {
  white-space: pre-wrap;
  word-break: break-all;
}
</style>
