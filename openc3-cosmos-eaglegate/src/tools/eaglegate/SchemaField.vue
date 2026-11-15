<!--
  One value of an extension's rules section, edited with a form generated from
  the schema the extension reports in interface_details (see
  targets/EAGLEGATE/lib/eaglegate_extensions.py for the vocabulary). Objects and
  maps render their children with this same component.

  Emits update:modelValue with the new value, or undefined to leave the key out
  of the file (the firewall then uses the default).
-->
<template>
  <div class="schema-field">
    <!-- object: one field per key -->
    <template v-if="spec.type === 'object'">
      <div v-if="label" class="text-subtitle-2 mt-2">{{ label }}</div>
      <div v-if="spec.help" class="text-caption mb-1">{{ spec.help }}</div>
      <v-row dense>
        <v-col
          v-for="(child, key) in spec.fields"
          :key="key"
          cols="12"
          :md="isContainer(child) ? 12 : 6"
        >
          <schema-field
            :spec="child"
            :label="titleFor(key, child)"
            :model-value="objectValue[key]"
            :readonly="readonly"
            @update:model-value="setChild(key, $event)"
          />
        </v-col>
      </v-row>
    </template>

    <!-- map: entries keyed by e.g. a virtual channel or SPI number -->
    <template v-else-if="spec.type === 'map'">
      <div class="text-subtitle-2 mt-2">{{ label }}</div>
      <div v-if="spec.help" class="text-caption mb-1">{{ spec.help }}</div>
      <v-card
        v-for="key in mapKeys"
        :key="key"
        variant="outlined"
        class="pa-2 mb-2"
      >
        <div class="d-flex align-center">
          <span class="text-subtitle-2"
            >{{ spec.key?.title || 'key' }} {{ key }}</span
          >
          <v-spacer />
          <v-btn
            v-if="!readonly"
            icon="mdi-delete"
            size="small"
            variant="text"
            :aria-label="`Remove ${key}`"
            @click="removeEntry(key)"
          />
        </div>
        <schema-field
          :spec="spec.value"
          :model-value="objectValue[key]"
          :readonly="readonly"
          @update:model-value="setChild(key, $event, true)"
        />
      </v-card>
      <div v-if="!readonly" class="d-flex ga-2 align-center">
        <v-text-field
          v-model="newKey"
          :label="`New ${spec.key?.title || 'key'}`"
          :hint="keyHint"
          persistent-hint
          density="compact"
          style="max-width: 260px"
          @keyup.enter="addEntry"
        />
        <v-btn
          variant="text"
          prepend-icon="mdi-plus"
          :disabled="!!newKeyProblem"
          @click="addEntry"
          >Add</v-btn
        >
        <span v-if="newKey && newKeyProblem" class="text-caption text-error">{{
          newKeyProblem
        }}</span>
      </div>
    </template>

    <v-switch
      v-else-if="spec.type === 'bool'"
      :model-value="modelValue ?? spec.default ?? false"
      :label="label"
      :hint="spec.help"
      persistent-hint
      color="primary"
      :readonly="readonly"
      @update:model-value="emitValue($event)"
    />

    <v-select
      v-else-if="spec.type === 'enum'"
      :model-value="modelValue ?? spec.default ?? null"
      :items="enumItems"
      :label="label"
      :hint="spec.help"
      persistent-hint
      :readonly="readonly"
      @update:model-value="emitValue($event)"
    />

    <v-select
      v-else-if="spec.type === 'enum_list'"
      :model-value="modelValue ?? []"
      :items="enumItems"
      :label="label"
      :hint="spec.help"
      persistent-hint
      multiple
      chips
      closable-chips
      :readonly="readonly"
      @update:model-value="emitValue($event.length ? $event : undefined)"
    />

    <v-text-field
      v-else
      :model-value="text"
      :label="label"
      :hint="hint"
      persistent-hint
      :placeholder="placeholder"
      :readonly="readonly"
      @update:model-value="setText"
    />
  </div>
</template>

<script>
import { fromInput, toInt } from './rulesModel.js'

export default {
  name: 'SchemaField',
  props: {
    spec: { type: Object, required: true },
    modelValue: {
      type: [Object, Array, String, Number, Boolean],
      default: undefined,
    },
    label: { type: String, default: '' },
    readonly: { type: Boolean, default: false },
  },
  emits: ['update:modelValue'],
  data() {
    return { newKey: '' }
  },
  computed: {
    objectValue() {
      const value = this.modelValue
      return value && typeof value === 'object' && !Array.isArray(value)
        ? value
        : {}
    },
    mapKeys() {
      return Object.keys(this.objectValue).sort(
        (a, b) => toInt(a) - toInt(b) || a.localeCompare(b),
      )
    },
    enumItems() {
      return (this.spec.values || []).map((value) => ({
        title: this.spec.value_help?.[value]
          ? `${value}: ${this.spec.value_help[value]}`
          : String(value),
        value,
      }))
    },
    text() {
      const value = this.modelValue
      if (value === undefined || value === null) return ''
      if (Array.isArray(value)) return value.join(', ')
      return String(value)
    },
    placeholder() {
      return this.spec.default !== undefined
        ? `default ${this.spec.default}`
        : ''
    },
    hint() {
      const parts = []
      if (this.spec.help) parts.push(this.spec.help)
      if (this.spec.type === 'int_list') parts.push('comma separated')
      if (this.spec.min !== undefined && this.spec.max !== undefined)
        parts.push(`${this.spec.min}..${this.spec.max}`)
      return parts.join('; ')
    },
    keyHint() {
      const key = this.spec.key || {}
      return key.min !== undefined && key.max !== undefined
        ? `${key.min}..${key.max}`
        : ''
    },
    newKeyProblem() {
      const key = this.spec.key || { type: 'string' }
      const text = this.newKey.trim()
      if (!text) return 'enter a value'
      if (text in this.objectValue) return 'already listed'
      if (key.type === 'int') {
        const n = toInt(text)
        if (Number.isNaN(n)) return 'must be an integer'
        if (key.min !== undefined && n < key.min) return `must be >= ${key.min}`
        if (key.max !== undefined && n > key.max) return `must be <= ${key.max}`
      }
      return null
    },
  },
  methods: {
    isContainer(spec) {
      return spec.type === 'object' || spec.type === 'map'
    },
    titleFor(key, spec) {
      const title = spec.title || key
      return spec.required ? `${title} *` : title
    },
    emitValue(value) {
      this.$emit('update:modelValue', value)
    },
    setText(text) {
      if (this.spec.type === 'int_list') {
        const items = String(text)
          .split(',')
          .map((part) => fromInput({ type: 'int' }, part))
          .filter((v) => v !== undefined)
        this.emitValue(items.length ? items : undefined)
      } else if (this.spec.allow_empty && String(text ?? '').trim() === '') {
        this.emitValue('') // a real value, e.g. "no sync marker"
      } else {
        this.emitValue(fromInput(this.spec, text))
      }
    },
    // Objects drop keys set to undefined; an empty object leaves the file too
    // (map entries are kept even when empty, since the key itself means something)
    setChild(key, value, keepEmpty = false) {
      const copy = { ...this.objectValue }
      if (value === undefined && !keepEmpty) delete copy[key]
      else copy[key] = value === undefined ? this.emptyValue() : value
      this.emitValue(Object.keys(copy).length ? copy : undefined)
    },
    addEntry() {
      if (this.newKeyProblem) return
      const key =
        this.spec.key?.type === 'int'
          ? String(toInt(this.newKey.trim()))
          : this.newKey.trim()
      this.setChild(key, this.emptyValue(), true)
      this.newKey = ''
    },
    // What a new map entry starts as
    emptyValue() {
      const value = this.spec.value || {}
      if (this.isContainer(value)) return {}
      return value.default ?? null
    },
    removeEntry(key) {
      const copy = { ...this.objectValue }
      delete copy[key]
      this.emitValue(Object.keys(copy).length ? copy : undefined)
    },
  },
}
</script>
