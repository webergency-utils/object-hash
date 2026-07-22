#!/bin/bash -eu

# Install dependencies and build library
npm ci
npm run build

# Compile Jazzer.js fuzz target into $OUT directory
compile_javascript_fuzzer object-hash .clusterfuzzlite/fuzz_hash.js
