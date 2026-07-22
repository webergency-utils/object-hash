#!/bin/bash -eu

# Install dependencies, Jazzer.js core fuzzer engine, and build library
npm ci
npm install --no-save @jazzer.js/core
npm run build

# Compile Jazzer.js fuzz target into $OUT directory
compile_javascript_fuzzer object-hash .clusterfuzzlite/fuzz_hash.js

