#!/bin/bash -eu

# Install dependencies and build library
npm ci
npm run build

# Compile Jazzer.js fuzz target into $OUT directory
# Args: <project_name> <fuzz_target_path_relative_to_project_root>
compile_javascript_fuzzer object-hash .clusterfuzzlite/fuzz_hash.cjs
