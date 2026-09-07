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
  has accepted the message. There is no spool, so the pods are stateless, no
  message is lost to a restart, and a `4xx` from the upstream reaches the client
  as a `4xx` for it to retry.
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
- **Declaring a sender is what earns a DKIM signature.** A signature vouches for
  a domain, so a key held by the gateway is not authority to use it: without
  this, any account could have any of the gateway's domains signed simply by
  claiming to send from it — one tenant vouching for another.
- **DKIM signs after the filters**, so the signature covers the body and headers
  the filters actually left behind. Mail from a domain with no key goes out
  unsigned rather than signed under a domain you do not own.
- **Let a sending service sign for itself.** Set `upstream.handlesDKIM` when
  relaying through Mailgun, SES, SendGrid or the like: they sign with the key of
  the domain delegated to them, and signing on top would produce a second
  signature that breaks as soon as they rewrite the body for link tracking —
  arriving as `dkim=fail` in your DMARC reports for no benefit.
- **One tenant's mistake stays its own.** An account that cannot be served is
  dropped from the configuration with the reason in its status; the relay keeps
  running for everyone else.
- **Adding an account does not restart anything.** The gateway reloads its
  accounts, keys and certificates from disk; only a change of listener or of
  mounted Secret rolls the pods.

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
real k3s in a container and runs two scenarios: the operator reconciling
in-process, to check that the pods it deploys actually relay mail; and the
operator deployed from `config/default` with cert-manager, to check that the
manifests in this repository work — the webhook's CA injection and the
gateway's issued listener certificate included. A rendered manifest can be
perfectly valid and still produce a container that will not start.

## Not there yet

Prometheus metrics for the dataplane, per-account rate limiting,
`ReferenceGrant`-style per-account delegation, and a spool with bounces for
clients that cannot retry.

## License

Private, all rights reserved. No license granted.
