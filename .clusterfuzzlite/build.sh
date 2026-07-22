#!/bin/bash -eu

# Install dependencies
npm install

# Install Jazzer.js inside the container (ensures correct native binaries for container's GLIBC)
npm install --save-dev @jazzer.js/core

# Build the library
npm run build

# Compile fuzz target
compile_javascript_fuzzer object-hash fuzz_hash.cjs
