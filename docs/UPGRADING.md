# Upgrading

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
