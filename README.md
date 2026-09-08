# mailout-operator

A generic SMTP submission relay for Kubernetes. Applications get an SMTP account
from a custom resource, send their mail to the relay, and the relay filters it
(ClamAV over milter, DKIM signing) before handing it to the SMTP server of your
choice.

Written in Go. One binary, two roles: the controller manager and the SMTP
dataplane.

> Status: v1alpha1. The API may still change.

## Why

An application that needs to send mail usually ends up with the provider's SMTP
credentials in its own environment, and no filtering. This puts one relay in the
cluster instead: applications hold a credential that only works there, the
outbound credentials stay in the operator's namespace, and virus scanning and
DKIM signing happen in one place rather than in every application.

## How it works

```
                    ┌──────────────────────────────────────────┐
  MailoutGateway ──▶│ operator                                 │
  MailoutAccount ──▶│  · generates the password, writes the    │
                    │    Secret in the application's namespace │
                    │  · renders gateway.yaml into a Secret    │
                    └──────────────────┬───────────────────────┘
                                       │ mounted
  app ──587 STARTTLS──▶ ┌──────────────▼─────────┐ ──▶ milters (ClamAV…)
       AUTH PLAIN/LOGIN │ gateway (dataplane)    │ ──▶ DKIM signing
                        └────────────┬───────────┘
                                     └──▶ upstream SMTP (synchronous)
```

Two custom resources:

- **`MailoutGateway`**, in the operator's namespace: the listeners, the
  certificates, the filters, and the upstream server with its credentials. The
  operator renders a Deployment and a Service for it.
- **`MailoutAccount`**, in any namespace: one application's account. The operator
  generates the password, writes it to a `kubernetes.io/basic-auth` Secret in
  that namespace, and keeps only the bcrypt hash.

The decisions worth knowing about:

- **Delivery is synchronous.** The gateway answers `250` only once the upstream
  has accepted the message. There is no queue, so the pods are stateless, no
  message is lost to a restart, and a `4xx` from the upstream reaches the client
  as a `4xx` for it to retry.
- **A large message is buffered on disk, not in memory.** Past 1 MiB the body
  moves to a file for the length of its transaction — a buffer, not a queue:
  it is unlinked the moment it is created, so it cannot outlive the transaction
  and the pod stays stateless. Without it, each stage of the pipeline held a
  full copy and a handful of parallel 25 MiB submissions were enough to have the
  pod OOMKilled, which took the relay down for every tenant. The operator mounts
  a disk-backed `emptyDir` for it; the container's root filesystem is read-only,
  so the gateway refuses to start if that volume is missing.
- **Concurrent connections are capped** (64 per listener by default). Nothing in
  go-smtp bounds them, so without a cap the pod's memory and CPU are sized by
  whoever connects rather than by configuration. Connections past the cap wait
  for a slot.
- **AUTH is only offered over TLS.** No credential crosses the wire in clear.
- **SNI works on both ports**, 587 and 465, so one gateway can answer on several
  names with several certificates.
- **Filters can only be switched off by an account, never added.** An
  application must not be able to route its mail through a filter of its own
  choosing.
- **A filter that is down stops the mail** (`451`, retry later) unless you set
  `failOpen`. A virus scanner that is unreachable must not turn the relay into a
  conduit for malware.
- **An account may only send from what it declares.** `allowedSenders` lists its
  addresses or domains, and the policy applies to the envelope *and* to the
  `From` header the recipient sees. Declare nothing and mail still relays from
  anywhere — but is never signed.
- **Where a policy applies, a message needs exactly one well-formed `From`.**
  Anything else is refused with a `550`, rather than relayed with the check
  quietly skipped. Every way found around this check worked by leaving nothing
  to look at: a second `From` after an allowed one, `From :` with a space before
  the colon, a first line with no colon at all, an unparsable header block. RFC
  5322 already requires exactly one, which is what makes the strictness safe —
  and an account that declares no `allowedSenders` is unaffected, since it gets
  no signature to abuse.
- **Declaring a sender is what earns a DKIM signature.** A signature vouches for
  a domain, so a key held by the gateway is not authority to use it: without
  this, any account could have any of the gateway's domains signed simply by
  claiming to send from it — one tenant vouching for another. Mind the limit,
  though: nothing yet checks that the domains an account declares are its own to
  declare. On a gateway holding keys for several tenants with
  `allowedAccounts.namespaces: All`, a tenant can still write another's domain
  into its own `allowedSenders`. Until per-account delegation exists (below),
  give each tenant its own gateway or restrict `allowedAccounts`.
- **DKIM signs after the filters**, so the signature covers the body and headers
  the filters actually left behind. Mail from a domain with no key goes out
  unsigned rather than signed under a domain you do not own.
- **Let a sending service sign for itself.** Set `upstream.handlesDKIM` when
  relaying through Mailgun, SES, SendGrid or the like: they sign with the key of
  the domain delegated to them, and signing on top would produce a second
  signature that breaks as soon as they rewrite the body for link tracking —
  arriving as `dkim=fail` in your DMARC reports for no benefit.
- **A username belongs to its namespace.** `spec.username` defaults to
  `<namespace>.<name>` and, if you set it, must start with `<namespace>.`. On a
  shared gateway that is what stops one tenant naming — and taking — another's
  SMTP identity, along with the `allowedSenders` attached to it.
- **One tenant's mistake stays its own.** An account that cannot be served is
  dropped from the configuration with the reason in its status; the relay keeps
  running for everyone else.
- **A quota that is not being counted stops the mail.** Rate limiting is
  fail-closed: when the shared store is unreachable the gateway answers `451`
  rather than letting mail through uncounted. That makes the store part of the
  critical path, deliberately — a quota that lapses whenever its store hiccups
  is not a quota. Declare none and nothing is counted.
- **Revoking a credential takes effect on the next message.** Deleting the
  account, setting `disabled`, or narrowing `allowedSenders` applies to sessions
  already open, not only to new ones — the account is re-resolved at the start
  of each transaction. Without that a leaked credential kept working for the
  life of its connection, and nothing closes an idle one: a `NOOP` every
  50 seconds stays under the read deadline forever.
- **Adding an account does not restart anything.** The gateway reloads its
  accounts, keys and certificates from disk; only a change of listener or of
  mounted Secret rolls the pods.
- **The operator runs two replicas.** One reconciles, the other stands by. It is
  the webhook that gains most: its `failurePolicy` is `Fail`, so with a single
  replica every write to a CRD is refused for the length of a rollout.

## Install

Needs cert-manager, for the webhook's serving certificate.

```bash
make deploy IMG=ghcr.io/maitredede/mailout-operator:v0.1.0
```

Or CRDs alone, to look around: `make install`.

## Use

```yaml
apiVersion: mailout.daly.nc/v1alpha1
kind: MailoutGateway
metadata:
  name: default
  namespace: mailout-system
spec:
  hostname: mail.example.com
  listeners:
    submission: {}          # 587, STARTTLS
  tls:
    issuerRef:              # or bring your own Secrets with certificateRefs
      name: letsencrypt
      kind: ClusterIssuer
    dnsNames: [mail.example.com]
  upstream:
    host: smtp.provider.example
    tls: StartTLS
    authSecretRef:
      name: upstream-credentials
  dkim:
    - domain: example.com
      selector: mail
      privateKeySecretRef:
        name: dkim-example-com
  milters:
    - name: clamav
      address: tcp://clamav-milter.security.svc:7357
  rateLimit:                # optional; see Quotas below
    store:
      addresses: [valkey.mailout-system.svc:6379]
    messagesPerMinute: 60
    recipientsPerMinute: 300
```

```yaml
apiVersion: mailout.daly.nc/v1alpha1
kind: MailoutAccount
metadata:
  name: invoicing
  namespace: billing
spec:
  gatewayRef:
    name: default
  secretRef:
    name: invoicing-smtp    # the operator creates and owns this Secret
  allowedSenders:           # what this account may send from — and have signed
    - "*@example.com"
```

The application then reads `invoicing-smtp`, which carries `username`,
`password`, `host`, `port` and `tls` — enough to configure any mail library:

```yaml
envFrom:
  - secretRef:
      name: invoicing-smtp
```

To rotate a password, change `spec.rotation` to any new value.

To generate a DKIM key and the TXT record that publishes it:

```bash
mailout dkim-key --domain example.com --selector mail -o dkim.key
```

## Quotas

`spec.rateLimit` caps what each account may send, per minute, counted in a store
shared by every replica of the gateway — an in-process counter would cap each pod
separately, and therefore cap nothing.

The quota is the gateway's, the same for all its accounts. It is deliberately not
overridable per account: a `MailoutAccount` lives in its tenant's own namespace,
so an override there would be the tenant setting its own quota. An account that
needs a different limit belongs on a different gateway.

The store is **referenced, never deployed**: it is infrastructure with its own
lifecycle, backups and upgrades. Point it at a Valkey (or any Redis-compatible
server) you run yourself. For high availability, one primary and two replicas
behind Sentinel:

```yaml
spec:
  rateLimit:
    store:
      addresses:            # the Sentinels, not the data nodes
        - valkey-sentinel-0.valkey.mailout-system.svc:26379
        - valkey-sentinel-1.valkey.mailout-system.svc:26379
        - valkey-sentinel-2.valkey.mailout-system.svc:26379
      masterName: mailout   # what selects Sentinel
      authSecretRef:
        name: valkey-credentials
      sentinelAuthSecretRef:
        name: valkey-sentinel-credentials
    messagesPerMinute: 60
    recipientsPerMinute: 300
```

One address is a standalone server; several addresses **without** `masterName`
are treated as a Redis Cluster. That is the trap worth knowing: a primary and its
replicas listed without a `masterName` would be taken for a cluster. The webhook
warns, and the gateway logs the mode it deduced at startup:

```
level=INFO msg="rate limiting enabled" mode=sentinel addresses=3 messagesPerMinute=60
```

What to expect at the edges:

- **Over quota is `452 4.2.2`** — a temporary refusal, so a well-behaved client
  holds the message and retries.
- **Store unreachable is `451 4.3.2`** — fail-closed, as above.
- **The window is fixed, not sliding.** An account can spend its quota in the
  last second of one minute and again in the first second of the next, so up to
  twice the limit can go out within one window's span. That is the price of one
  key per account and a single-key operation, which is what keeps this working
  unchanged on a cluster.
- **Messages and recipients are counted separately**, because a thousand
  messages to one recipient and one message to a thousand recipients are the same
  amount of mail and only the second is caught by a message count. Omit either to
  leave that dimension uncounted.

## Metrics

The dataplane serves Prometheus metrics on port 9090 (`/metrics`), on a
`<gateway>-metrics` Service of its own — never on the SMTP Service, which can be
a `LoadBalancer`. A `ServiceMonitor` is created too, but only if
prometheus-operator's CRD is served by the cluster.

| Metric | What it tells you |
|---|---|
| `mailout_messages_total{account,result}` | `relayed`, `rejected` (5xx, permanent), `deferred` (4xx, retry expected), `discarded` (swallowed by a filter) |
| `mailout_message_bytes_total{account}` | Volume relayed, after filtering and signing |
| `mailout_messages_spooled_total{account}` | Bodies too large for memory, buffered on disk. Zero everywhere means the spool volume is dormant; a steady rate means losing it would turn large messages into `451`s |
| `mailout_auth_failures_total{account}` | Refused logins; attempts on unknown usernames land under `<unknown>` |
| `mailout_milter_decisions_total{milter,decision}` | `accept`, `reject`, `discard`, `unavailable` — the last one counted whether the message then went through or not |
| `mailout_dkim_signatures_total{domain,result}` | `signed`, `refused` (the account may not send from that domain), `failed` |
| `mailout_ratelimit_decisions_total{account,decision}` | `allowed`, `denied`, `error` |
| `mailout_upstream_delivery_seconds` | What the submitting application waits on, delivery being synchronous |
| `mailout_config_reloads_total{result}` | A failed reload keeps the previous configuration; this is the only sign the relay is running on something stale |
| `mailout_accounts`, `mailout_accounts_rejected` | Accounts served, and accounts dropped because their own settings are unusable |

The three worth alerting on: `result="deferred"` rising (the upstream is in
trouble), `decision="error"` on the rate limiter (the quota store is, and it is
stopping mail), and `mailout_config_reloads_total{result="failure"}` at all.

Every label is bounded by configuration, never by traffic — which is why an
authentication failure on a username no account has is reported as `<unknown>`
rather than under the name that was tried.

A Grafana dashboard covering all of it ships as a ConfigMap for Grafana's
sidecar:

```bash
kubectl apply -k config/grafana
```

It is not part of `config/default`, and deliberately so: unlike the
`ServiceMonitor`, nothing about a Grafana install can be detected. The label the
sidecar selects on and the namespace it searches are both configurable, so
applying this blind would either be ignored or land where nothing reads it.
Check `sidecar.dashboards.label` and `searchNamespace` against your install; the
manifest uses the usual `grafana_dashboard: "1"` in `mailout-system`. Or import
`config/grafana/mailout.json` by hand.

One dashboard covers every gateway — it describes the shape of the metrics, and
the gateway is a variable in it. A unit test asserts that each metric it queries
is one the dataplane exposes, and that none is left off a panel: a renamed
metric would otherwise leave a graph empty, which reads as "nothing is
happening" rather than as a fault.

## Try it without a cluster

The dataplane has no dependency on the Kubernetes API: it reads a YAML file, and
that is the same file the operator renders in-cluster. So the whole SMTP path
runs under docker-compose:

```bash
make compose-up     # gateway + Mailpit + ClamAV, with throwaway certificates
```

See [deploy/compose/README.md](deploy/compose/README.md) for what to send and
what to look at.

## Development

```bash
make test           # unit tests: no docker, no cluster
make test-envtest   # controllers and webhooks against a real API server
make test-e2e       # the real thing: Mailpit and ClamAV in containers
make test-cluster   # the operator against a throwaway k3s: pods that actually run
make lint build
```

`controller-gen`, `kustomize` and `setup-envtest` are declared as Go tool
dependencies, so there is nothing to install: `make generate manifests` works
from a bare checkout.

`make test-cluster` is the one that catches what the others cannot. It starts a
real k3s in a container and runs three scenarios: the operator reconciling
in-process, to check that the pods it deploys actually relay mail and serve
their metrics; the operator deployed from `config/default` with cert-manager, to
check that the manifests in this repository work — the webhook's CA injection,
the gateway's issued listener certificate, and two operator replicas with a
single leader; and an adversarial one, where a tenant tries to have another
tenant's domain signed. A rendered manifest can be perfectly valid and still
produce a container that will not start.

## Not there yet

`ReferenceGrant`-style per-account delegation — an account declares the domains
it sends from, and nothing but the admin's own namespace policy says those
domains are its own. This is the one gap that still matters for a gateway shared
between tenants who do not trust each other.

A spool with bounces, for clients that cannot retry.

## License

Private, all rights reserved. No license granted.
