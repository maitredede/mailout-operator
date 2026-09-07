#!/usr/bin/env bash
# Generate the throwaway certificates the compose stack serves.
set -euo pipefail
cd "$(dirname "$0")/../.."
go run ./hack/gencerts -dir deploy/compose/certs \
  -names "mailout.test,localhost,127.0.0.1" \
  -alt-names "alt.mailout.test"
