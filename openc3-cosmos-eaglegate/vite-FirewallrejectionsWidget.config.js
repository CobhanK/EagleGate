// The FIREWALLREJECTIONS Telemetry Viewer widget (src/widgets/). COSMOS loads
// tools/widgets/FirewallrejectionsWidget/FirewallrejectionsWidget.umd.min.js
// (plugin.txt: WIDGET FIREWALLREJECTIONS). Vue and Vuetify come from the page;
// the widget has no CSS file (inline styles), so no style-inject plugin is needed.
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  publicDir: false, // the rules schema belongs to the tool page, not the widget
  build: {
    outDir: 'tools/widgets/FirewallrejectionsWidget',
    emptyOutDir: true,
    lib: {
      entry: './src/widgets/FirewallrejectionsWidget.vue',
      name: 'FirewallrejectionsWidget',
      fileName: (format, entryName) => `${entryName}.${format}.min.js`,
      formats: ['umd'],
    },
    rollupOptions: {
      external: ['single-spa', 'vue', 'pinia', 'vue-router', 'vuetify'],
    },
  },
  plugins: [vue()],
})
