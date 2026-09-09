# Upgrading

## To the hardening release

**Read this first: a gateway that grants nothing now sends nothing.**
`spec.allowedSenders` moves to the `MailoutGateway`, and it is the authority —
an account can only narrow what its namespace was granted. Until you declare
grants, the relay accepts connections and refuses every message with `550`.

Nothing was deployed from this repository before this release, so this is a
migration only if you are running a build of your own. To build the starting
list from what your accounts use today:

```bash
kubectl get mailoutaccounts -A -o json | jq -r '
  .items[] | select(.spec.allowedSenders != null)
  | .spec.allowedSenders[] as $s | "\(.metadata.namespace)\t\($s)"' | sort -u
```

Then, on the gateway, grant each set to the namespace it belongs to:

```yaml
spec:
  allowedSenders:
    - senders: ["*@billing.example.com"]
      namespaceSelector:
        matchLabels: { kubernetes.io/metadata.name: billing }
    - senders: ["*@shared.example.com"]   # no selector: every namespace
```

Why it moved: an account declared its own senders, so on a gateway holding DKIM
keys for several tenants nothing stopped one from writing another's domain into
its own `allowedSenders` and having it signed. The keys belong to the gateway,
so the right to use them has to as well. An account whose declaration is not
covered by its grant is refused at admission; if the grant is narrowed
afterwards, the operator drops the uncovered entries and logs which.

One consequence worth knowing: every account now has a policy, so **every
message needs a `From` header**. There is no longer an "undeclared" account for
which the check was skipped.

Found by an adversarial review of the previous release. Two of these will refuse
things your cluster accepted yesterday, so read the first two.

**`spec.milters.disable` is gone.** A tenant used it to skip the gateway's
filters, and a virus scanner is what it got used to skip: the account relayed
unscanned attachments through the relay's IP and reputation while the admin who
set `failOpen: false` believed the scan mandatory. The field is pruned by the
API server, so an existing account keeps applying, minus the opt-out — every
filter now runs for every account. If one genuinely needs different filters,
give it its own gateway. To find the accounts that relied on it, before
upgrading:

```bash
kubectl get mailoutaccounts -A -o json | jq -r '
  .items[] | select(.spec.milters.disable != null)
  | "\(.metadata.namespace)/\(.metadata.name): \(.spec.milters.disable | join(","))"'
```

**A username conflict no longer says who holds the name.** The message a tenant
gets is `already taken on this gateway`; the pair is in the operator's log. It
used to name the namespace and object holding it, which let a tenant map the
other tenants of a shared gateway by guessing names.

**`spec.username` is now validated, and an account that fails is dropped.** The
name reaches the `Received` header of every message the account sends, so a name
containing a CR or LF let the account write headers — and a body — of its own
choosing. It must now match
`^[a-zA-Z0-9]([a-zA-Z0-9._@+-]{0,126}[a-zA-Z0-9])?$` and be at most 128
characters. The API server refuses a new one that does not; an account created
before this is dropped from the served configuration with the reason in its
status, and the relay keeps running for everyone else. To find them before
upgrading:

```bash
kubectl get mailoutaccounts -A \
  -o custom-columns=NS:.metadata.namespace,NAME:.metadata.name,USER:.spec.username
```

An empty `USER` means the default `<namespace>.<name>`, which is checked too —
a long namespace plus a long object name can exceed 128 characters together.

**`spec.username`, when you set it, must start with `<namespace>.`** The default
already does. Without this, a tenant on a shared gateway could name any
username it liked: claim another tenant's before they exist and their account is
refused at admission, or race them and the winner was settled by list order —
alphabetically, so a namespace called `aaa-` beat one called `zzz-`. The winner
took the SMTP identity along with the `allowedSenders` and `milters.disable`
attached to it. To find the accounts that need changing:

```bash
kubectl get mailoutaccounts -A -o json | jq -r '
  .items[] | select(.spec.username != null)
  | select(.spec.username | startswith(.metadata.namespace + ".") | not)
  | "\(.metadata.namespace)/\(.metadata.name): \(.spec.username)"'
```

Changing a username changes the credential the application authenticates with;
the operator rewrites the Secret, so an application that reads it at startup
needs a restart.

**`allowedSenders` is capped at 32 entries of 256 characters**, and
`milters.disable` likewise. Unbounded, one account with a few hundred kilobytes
of senders made the gateway's configuration Secret exceed the 1 MiB the API
server allows — and since the previous Secret stays in service, the relay kept
running while no change ever applied again, revocation included. Beyond the
budget the operator now drops accounts largest first rather than failing the
whole reconciliation.

**A password hash outside cost 10–14 is regenerated.** The hash reaches the
shared configuration from a Secret in the tenant's own namespace, so its cost
was attacker-chosen: a hand-written `$2a$31$` hash made every authentication
attempt on that username burn hours of CPU on every replica. Anything the
operator itself produced (cost 12) is untouched. A hash edited by hand outside
the band is replaced, and the application must re-read its Secret.

**The gateway pods now need a writable volume.** The operator mounts a
disk-backed `emptyDir` at `/var/spool/mailout` for message bodies too large to
keep in memory. Nothing to do — but if you deploy the dataplane yourself, note
that it refuses to start when that path is not writable, rather than failing on
the first large message. Set `limits.spoolDir` to a writable directory.

**A message needs exactly one `From` header — but only for accounts that
declare `allowedSenders`.** Two `From` headers, `From :` with a space before the
colon, or a header block with no blank line are now `550`s. They used to relay
with the sender policy silently skipped, and the signer covered both `From`
headers, so a message went out with a signature that verifies and a second
`From` an MUA may be the one to display. Accounts with no `allowedSenders` are
untouched: they were never signed, so there was nothing to abuse.

**A revocation now reaches a session already open.** Deleting an account,
disabling it, or narrowing its `allowedSenders` used to change nothing for a
connection already authenticated — and nothing closes an idle one, so a leaked
credential kept working indefinitely. The account is re-resolved at the start of
each transaction and the connection is closed with `421` if it is gone. An
application holding a long-lived connection through a deliberate narrowing of
its own policy will see a `550` where it used to see `250`.

**Authentication is now rate limited per connection**, and concurrent
connections are capped at 64 per listener. A client that retries a wrong
password more than three times on one connection gets `421` and is
disconnected; a client legitimately opening more than 64 connections at once
waits for a slot instead of being refused.


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
