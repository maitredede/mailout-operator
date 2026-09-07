#!/usr/bin/env bash
# Generate the throwaway certificates the compose stack serves.
set -euo pipefail
cd "$(dirname "$0")/../.."
go run ./hack/gencerts -dir deploy/compose/certs \
  -names "mailout.test,localhost,127.0.0.1" \
  -alt-names "alt.mailout.test"

# A DKIM key for the demo sending domain. Its TXT record is printed so it can be
# checked by hand; nothing resolves it in the compose stack.
if [[ ! -f deploy/compose/certs/dkim.key ]]; then
  go run ./cmd/mailout dkim-key --domain example.test --selector mail \
    -o deploy/compose/certs/dkim.key
  chmod 0644 deploy/compose/certs/dkim.key
fi
