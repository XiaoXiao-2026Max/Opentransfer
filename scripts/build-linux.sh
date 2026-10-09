#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
out="${1:-dist/packages/linux-amd64}"
version="${VERSION:-0.1.0}"
revision="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
mkdir -p "$out"
shopt -s dotglob nullglob
entries=("$out"/*)
if (( ${#entries[@]} != 0 )); then
  printf '发布目录必须为空，请指定新的输出目录；已有配置和凭据不会被覆盖。\n' >&2
  exit 1
fi
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.version=$version -X main.revision=$revision" -o "$out/connect" ./cmd/connect
cp server.example.json "$out/server.example.json"
cp README.md LICENSE THIRD_PARTY_NOTICES.md "$out/"
cp -R licenses docs "$out/"
printf 'Linux package: %s\n' "$out"
