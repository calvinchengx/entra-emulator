# Differential capture

Tooling for the one thing no emulator in this family has: evidence gathered by
diffing against **real Azure**, rather than by witnessing locally against real
clients. Everything graded 🟢 in `docs/parity.md` today means "an unmodified
client accepted our responses" — never "our responses matched Entra's".

Nothing here captures anything yet. This is the tenant it will capture from,
and the scripts that make that tenant reproducible.

## The capture tenant

A free Microsoft Entra tenant, separate from any production directory:

| | |
|---|---|
| domain | `entraemulatordiff.onmicrosoft.com` |
| region | Singapore (Asia Pacific) |
| type | Workforce **(legacy)**, deliberately not the Governed Workforce preview |

Legacy rather than the recommended preview because fixtures captured against a
preview configuration would record behaviour that is not the stable product and
can shift underneath them. Note that Microsoft restricts creation of additional
legacy workforce tenants after **15 August 2026**, so this exact configuration
may not be reproducible later.

Entra ID **Free** covers the whole diffable surface — discovery, tokens, Graph
v1.0, consent. The P1/P2 features it does not cover (Conditional Access, PIM,
Identity Protection) are this emulator's stated non-goals anyway. Custom
security attributes are the one 🟢 row that likely needs P1/P2.

## Use

```sh
az login --allow-no-subscriptions --tenant entraemulatordiff.onmicrosoft.com
./seed.sh        # create the directory objects
./teardown.sh    # remove them, and purge from the recycle bin
```

`teardown.sh` is safe on an empty tenant and safe to run twice.

## Why the scripts look defensive

**`tenant-guard.sh` is the important file.** Every other script mutates a
directory, and the failure that matters is doing that in the *wrong* one — a
production tenant is indistinguishable from this one once `az` is signed into
it. So nothing runs before the guard passes, and the guard compares a **verified
domain** rather than a tenant GUID, because a wrong GUID looks like any other
GUID while a wrong domain is readable at a glance.

**Teardown only removes objects prefixed `emudiff`.** A teardown that deleted
"all users" would behave perfectly on a fresh tenant and catastrophically
anywhere else. The blast radius is a property of the code, not of who runs it.

**Teardown purges, it does not merely delete.** Entra soft-deletes into a
recycle bin, and leftover soft-deleted applications are a documented blocker on
deleting a tenant. A teardown that only soft-deleted would leave the tenant
quietly undeletable.

**Teardown was written and run before `seed.sh` existed.** An exit path that has
never executed is a belief about reversibility rather than a capability. The
guard's refusal is tested too — pointed at another tenant it must abort, and a
guard only ever observed passing proves nothing.

## `.capture-identity.json`

Written by `seed.sh`, removed by `teardown.sh`, **gitignored**, mode 600. It
holds generated passwords and a client secret, and:

- **the identity map** — emulator seed id ↔ Azure object id.

That map is the point. Azure assigns its own GUIDs, so the emulator's seeded ids
have no counterpart, and a diff that does not normalise through this map is
drowned in GUID mismatch before it can report anything real.

It is also where the first real risk lives. **The normaliser is the instrument,
and instrument bugs surface as passes**: over-normalise and every response
matches, which is a false pass that no green run would reveal. Whatever consumes
this map needs its own mutation check — feed it a deliberately wrong response
and assert the diff fails.

## What differential evidence will and will not mean

For the recorded interactions, at the capture date, against that API version,
the emulator's normalised response matched Azure's. Fixtures need `capturedAt`
and should report **stale** past a max age rather than passing, or an old
recording silently certifies drift.

It will not mean "parity with Azure", and the grade must not be allowed to read
that way — that is the over-claim this whole evidence system exists to prevent.
