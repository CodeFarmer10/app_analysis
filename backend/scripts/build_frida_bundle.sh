#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$ROOT_DIR/tmp/frida_bundle_build"
SRC_FILE="$ROOT_DIR/phone_agent/frida/agent_src/index.js"
OUT_FILE="$ROOT_DIR/phone_agent/frida/agent.bundle.js"

mkdir -p "$BUILD_DIR"

if [ ! -f "$BUILD_DIR/package.json" ]; then
  npm init -y --prefix "$BUILD_DIR" >/dev/null
fi

if [ ! -d "$BUILD_DIR/node_modules/frida-java-bridge" ] || [ ! -d "$BUILD_DIR/node_modules/esbuild" ]; then
  npm install --prefix "$BUILD_DIR" frida-java-bridge esbuild buffer >/dev/null
fi

NODE_PATH="$BUILD_DIR/node_modules" \
  npx --prefix "$BUILD_DIR" esbuild "$SRC_FILE" \
    --bundle \
    --format=iife \
    --platform=browser \
    --target=es2020 \
    --outfile="$OUT_FILE"

echo "Built: $OUT_FILE"
