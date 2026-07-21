import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/hash.ts'],
  format: ['cjs', 'esm'],
  dts: true,
  sourcemap: true,
  clean: true,
  shims: true,
  splitting: false,
});
