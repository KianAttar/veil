#!/bin/bash
# Veil — dev mode: builds extension + starts verify server + demo chat server

trap 'kill 0' EXIT

# Build extension with dev URLs
echo "Building extension..."
pnpm run build

# Start verify server (Cloudflare Worker locally)
echo "Starting verify server on :8787..."
cd verify-server && pnpm run dev &
cd ..

# Start demo chat server
echo "Starting demo chat on :3000..."
python3 -m http.server 3000 -d demo &

wait
