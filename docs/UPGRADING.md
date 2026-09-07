# Upgrading

## To the metrics, HA and quotas release

Nothing breaks, but three things change under you.

**The gateway pods open port 9090.** The dataplane now serves Prometheus metrics
there, and the operator creates a `<gateway>-metrics` ClusterIP Service for it.
Nothing to do, unless a NetworkPolicy has to be widened for your Prometheus to
reach it. To turn it off for one gateway, there is no switch: the endpoint is
part of the dataplane. Point nothing at it and it costs a listening socket.

A `ServiceMonitor` is created as well, but only if your cluster serves
prometheus-operator's CRD. If it does and you did **not** want the gateway
scraped, delete the ServiceMonitor and it will come back at the next
reconciliation — the honest fix there is to scope your Prometheus' own
`serviceMonitorSelector`.

**The operator now runs two replicas.** Check that the namespace has room for
it: a tight `ResourceQuota` will leave the second pod Pending. A
PodDisruptionBudget with `minAvailable: 1` comes with it, which will block a
node drain that would take both pods at once — that is the point, but it is the
kind of thing that surprises you mid-upgrade. The anti-affinity is `preferred`,
so a single-node cluster still schedules both.

**Quotas are opt-in and fail-closed.** Declaring `spec.rateLimit` puts the store
on the path of every message: when it cannot be reached the gateway answers
`451` instead of relaying uncounted. Do not point it at a single unreplicated
Valkey and consider the job done.

## To the sender-policy release (breaking)

Two changes to `MailoutAccount`, both about keeping tenants out of each other's
domains.

### `spec.dkim` is gone

An account could declare its own signing key by naming a Secret. That name was
resolved in the **operator's** namespace, not the account's, so a tenant could
mount any Secret of that namespace into the gateway pod — and sign with it for
somebody else's domain.

Keys are now declared only on the `MailoutGateway`, by whoever administers it.
The field is removed from the CRD, so the API server prunes it; nothing to do
beyond moving the declaration:

```yaml
# MailoutGateway, in the operator's namespace
spec:
  dkim:
    - domain: example.com
      selector: mail
      privateKeySecretRef:
        name: dkim-example-com
```

### An account is signed only for what it declares

`spec.allowedSenders` lists the addresses and domains an account may send from.
It gates two things at once: what it may put in `MAIL FROM` and in the `From`
header, and which domains may be DKIM-signed on its behalf.

An account that declares nothing keeps relaying from any address — **but its
mail is no longer signed**. That is the breaking part: if you relied on the
gateway signing everything that matched one of its keys, declare the sender.

```yaml
spec:
  allowedSenders:
    - "*@example.com"        # a whole domain
    - "billing@other.com"    # one address
```

Find the accounts that need it:

```bash
kubectl get mailoutaccounts -A \
  -o custom-columns=NS:.metadata.namespace,NAME:.metadata.name,SENDERS:.spec.allowedSenders
```

Anything showing `<none>` sends unsigned until it declares a sender.

An application that legitimately sends on behalf of arbitrary addresses — a
ticketing system relaying a customer's reply — keeps the envelope policed and
opts out of the header check alone:

```yaml
spec:
  allowedSenders: ["*@example.com"]
  enforceHeaderFrom: false
```

### While you are there

If the gateway relays through a sending service that signs for you (Mailgun,
SES, SendGrid, Postmark), say so:

```yaml
spec:
  upstream:
    handlesDKIM: true
```

The gateway then signs nothing, even with keys declared. Signing on top would
add a second signature that breaks the moment the service rewrites the body for
link tracking, and it would surface as `dkim=fail` in your DMARC reports for no
benefit. The keys stay in the spec, so switching back is one boolean.
