#!/bin/bash -eu

# Install dependencies, Jazzer.js core fuzzer engine, and build library
npm ci
npm install --no-save @jazzer.js/core
npm run build

# Copy fuzz target into $SRC and compile with Jazzer.js
cp .clusterfuzzlite/fuzz_hash.cjs $SRC/fuzz_hash.cjs
compile_javascript_fuzzer $SRC/fuzz_hash.cjs





