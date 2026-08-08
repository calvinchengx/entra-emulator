# Companion: the ARM control-plane emulator

> **Status: the companion exists.** **`arm-emulator`**
> (module `github.com/calvinchengx/arm-emulator`) emulates the Azure Resource
> Manager control plane. entra-emulator itself stays an Entra ID STS; the
> Entra-layer pieces the companion consumes — the ARM audience and the
> delegated Azure-resource carve-out — **have shipped** (v0.2.1 and v0.3.1).

## Why a companion, not a feature

Nothing about ARM belongs inside an STS. The two systems sit in a strict
order, and entra-emulator is upstream of the other one:

1. **Entra ID** — authenticates the caller and issues a token whose `aud` is
   `https://management.azure.com`. *This is what entra-emulator emulates.*
2. **ARM** — validates that token against this emulator's JWKS, then serves
   subscriptions, resource groups, role assignments and resource providers.
   *A different product, a different protocol.*

So there is no "integration" to write here in the usual sense: ARM depends on
entra, not the reverse. What entra owes the companion is correct tokens, and
that is exactly what shipped.

## What entra-emulator provides

**The ARM audience, without a resource-app seed.** `https://management.azure.com`
(and `https://management.core.windows.net`) are
[well-known Azure resources](14-well-known-azure-resources.md): a
client-credentials or managed-identity caller asking for
`https://management.azure.com/.default` gets a token with that audience, no
registration step required.

**Delegated too, since v0.3.1.** A *signed-in user* can request
`https://management.azure.com/.default` or
`https://vault.azure.net/user_impersonation` and get the right audience. That
is the `az login` → `az group create` path, and it is what makes the CLI work
against the family at all — before v0.3.1 a user token for those resources was
refused with `AADSTS70011`.

**Group claims.** ARM role assignments frequently name a *group*, and the data
plane resolves membership from the token. entra-emulator emits the `groups`
claim when an app's `groupMembershipClaims` asks for it, with Entra's overage
behaviour when the list is too long. The seeded *Engineering* group
(`bbbbbbbb-0000-0000-0000-000000000001`) has Alice and Bob in it, which is what
the family's CI uses to prove a member reaches an assignment they are not
named in.

## The family, in dependency order

```
entra-emulator          issues tokens          (this project)
   ↓
arm-emulator            role assignments, resource groups, vault resources
   ↓
azure-keyvault-emulator enforces them on its data plane
fabric-emulator         (capacities are ARM resources — a future consumer)
```

`az cloud register` points the real Azure CLI at the first two, and everything
downstream follows: `az login` here, `az role assignment create` there, and a
Key Vault data-plane call that flips between `403` and authorized as a result.

## Nothing to do here

entra-emulator needs no change to work with arm-emulator, and adding ARM
concepts to it would invert the trust direction the family is built on. If a
future ARM feature needs a new claim or flow, it belongs in
[the roadmap](17-roadmap.md) as an Entra-layer item — the same way the Fabric
pieces did.
