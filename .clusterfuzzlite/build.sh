#!/bin/bash -eu

npm ci
npm run build

compile_javascript_fuzzer object-hash fuzz_hash.cjs
