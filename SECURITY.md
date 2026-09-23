# Security Analysis — Bitcoin Address Utility (this fork)

This is a fork of Mike Caldwell's (Casascius) archived [Bitcoin Address Utility](https://github.com/casascius/Bitcoin-Address-Utility), a Windows desktop tool (2012–2013) for generating Bitcoin private keys, addresses, mini private keys, paper wallets, and BIP38-encrypted keys.

This fork is **not affiliated with the original author**. It exists to document a security review of the random number generation used by the original codebase, and to ship a minimal, targeted fix so the tool can keep being used safely by anyone who still relies on it. No responsible-disclosure process was pursued for this specific finding: the upstream project has been publicly unmaintained for over a decade, has no listed maintainer contact or issue tracker activity, and the finding itself (see below) only affects locally-run key generation — it does not create a remote/network-exploitable condition.

## TL;DR

- The original code seeds its randomness (`Org.BouncyCastle.Security.SecureRandom`, parameterless constructor) using **only `DateTime.Ticks` and CPU-scheduling jitter** — it never consults the operating system's CSPRNG (`RNGCryptoServiceProvider`/`BCryptGenRandom`).
- `DateTime.Ticks`, despite its 100ns-resolution name, only actually changes value roughly every ~6ms on Windows (measured). Two key-generation events that happen to occur within that window start from the same primary seed input.
- We demonstrated **deterministically** (not statistically) that identical seed material always produces an identical private key, with no fallback that breaks the tie — and separately measured, across thousands of independent process launches running the real, unmodified code, that this seed material collides **organically** at a low but non-trivial and consistent rate (roughly 2–4% of samples shared a `Ticks` value with another independent sample).
- This fork replaces the weak default seeding with the operating system's CSPRNG (`CryptoApiRandomGenerator`, which wraps `RNGCryptoServiceProvider`) everywhere a key is generated, and fixes a secondary non-atomic counter increment. See "What this fork changes" below.

## Background

This review began from a real-world report: two independently generated addresses (different physical machines, different dates, manual single-click generation via `Address → New address`) turned out to be **the exact same private key**. That specific incident could not be causally explained after an exhaustive code audit (every method in the seeding chain was disassembled and checked; every alternative explanation — UI bugs, thread concurrency, shared VM state, clock desync, cross-window data reuse, hardcoded values — was ruled out with concrete evidence, not assumption). It remains documented as an open, unreproduced observation. What the investigation *did* conclusively establish, independent of that one incident, is the structural weakness described below — which stands on its own regardless of whether that specific case is ever explained.

## The vulnerability

### No OS CSPRNG fallback

`KeyPair.Create()`, `MiniKeyPair.CreateRandom()`, and `Bip38Intermediate`'s random-owner-entropy path all originally called `new SecureRandom()` — BouncyCastle's parameterless constructor. Disassembling the exact `BouncyCastle.Crypto.dll` this project ships (IL-level, not documentation) shows this constructor's entire entropy chain is:

```
SecureRandom()
  → GetSeed(8) → Master (created once per process, lazily)
      → SetSeed(DateTime.Now.Ticks)                              // absolute timestamp
      → SetSeed(new ThreadedSeedGenerator().GenerateSeed(32, true))  // CPU scheduling jitter
```

`Org.BouncyCastle.Crypto.Prng.CryptoApiRandomGenerator` — BouncyCastle's own wrapper around the Windows CSPRNG — exists in the same DLL and is never used by this code path.

### `DateTime.Ticks` resolution is much coarser than it looks

`DateTime.Ticks` is documented in 100ns units, but on Windows its value is only actually updated on the OS timer tick, typically every ~1–15ms. We measured ~6ms on the target test system (91 distinct values observed in a 500ms sampling window). Two independent generations occurring within that window read the identical `Ticks` value.

### `ThreadedSeedGenerator`'s jitter is CPU-timing based, and degrades under load

The secondary seed component spins a producer thread incrementing a counter as fast as possible, and samples its low byte on a consumer thread woken by `Thread.Sleep(1)`. Under CPU contention (a resource-constrained VM, or many concurrent generations), we measured seeding time increase up to **~19x** (from ~9ms/sample idle to ~167ms/sample under 16-thread contention on 4 vCPUs), and individual `new SecureRandom()` construction taking as long as 4.2 seconds. Degraded scheduling jitter is a well-documented class of weakness for exactly this kind of timing-based entropy source.

### Empirical evidence (reproducible)

All of the following used the real, unmodified compiled code (via reflection over the actual DLLs), not a reimplementation:

- **Deterministic proof**: `SecureRandom` seeded with identical `Ticks` + identical jitter, across independent OS processes, produces byte-identical 32-byte keys, always. A different `Ticks` value produces a completely different key (confirmed avalanche behavior — ruling out "the jitter alone matters" as an oversimplification).
- **Organic collision measurement**: 7,000 independent process launches, each calling the real `KeyPair.Create()` exactly once (simulating one fresh app launch → one "New address" click each) — **148 pairs (4.2%) shared an identical `DateTime.Ticks` value**, entirely without being forced. Jitter still differentiated the final key in every one of those pairs in this sample size; no full private-key collision was observed in >11,000 total real generations across this investigation.
- **No single-instance protection**: the app's `Main()` has no mutex/instance guard, so a user can trivially run two copies of the process concurrently — each with its own fresh, from-scratch seeding sequence, which is exactly the condition under which the organic collisions above were measured.

## What this fork changes

| File | Change |
|---|---|
| `Model/KeyPair.cs` | `new SecureRandom()` → `new SecureRandom(new CryptoApiRandomGenerator())` in `Create()`. Also made the `nonce` counter increment atomic (`Interlocked.Increment`) — it was a plain `nonce++` on a shared static field, a secondary (unrelated) thread-safety issue. |
| `Model/MiniKeyPair.cs` | Same `SecureRandom` fix in `CreateRandom()`. |
| `Model/Bip38Intermediate.cs` | Same `SecureRandom` fix for owner-entropy generation. |
| `Model/Bitcoin.cs`, `Model/PublicKey.cs`, `Model/KeyPair.cs`, `Model/Bip38Confirmation.cs`, `Model/Bip38KeyPair.cs`, `Model/EscrowCode.cs`, `Forms/Bip38ConfValidator.cs` | Unrelated build fix: added an explicit `using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;` alias. This codebase predates `System.Security.Cryptography.ECPoint` (added in .NET Framework 4.6.2), and on any modern .NET Framework install the two types collide, making the project fail to compile at all. No behavior change — purely a name-resolution fix. |
| `Forms/KeyCollectionView.Designer.cs` | Removed a dangling event subscription to a `menuStrip1_ItemClicked` handler that doesn't exist anywhere in the codebase (pre-existing designer/code-behind drift, unrelated to the security fix) — this alone prevented the project from building at all. |

`CryptoApiRandomGenerator` wraps `System.Security.Cryptography.RNGCryptoServiceProvider` (the Windows CSPRNG). This removes the dependency on `Ticks`/CPU-jitter timing entirely for the actual random bytes; the deterministic-collision mechanism documented above no longer applies to a build of this fork.

## Is it safe to use now?

**With this fork's fix applied, and built/run yourself from source: yes**, for the specific weakness documented here — key generation now draws from the OS CSPRNG rather than a timing-based seed. This is the same category of source used by essentially every modern cryptographic library on Windows.

A few things worth knowing regardless of which build you use:

- **Prefer building from source yourself** over running a pre-built binary you didn't compile, for any cryptographic tool, on principle — this is generic advice for any private-key-generating software, not specific to a remaining weakness here.
- This review covered the *seeding* of the RNG in depth. It did not re-audit the elliptic-curve math, Base58Check encoding, or BIP38 encryption logic beyond what was needed to trace the RNG's usage — those paths are unchanged from upstream and were not the subject of this analysis.
- The original, unpatched upstream project (and any other unpatched fork/binary of it) still has the weakness described above. If you have private keys that were generated with an unpatched build — especially via automated/batch generation, on a resource-constrained VM, or by running two copies of the app at once — treat that as a real risk and prefer moving funds to a freshly generated key from a properly-seeded source.

## Reproducing this analysis

The full investigation (IL disassembly commands, proof-of-concept source, raw collision data) is available on request / in the fork's history — reach out via GitHub if you want the complete methodology rather than this summary.

---

## Support this fork

If this analysis or the fix was useful to you, tips are welcome (and never expected):

- **BTC**: `bc1qhpppq4xs5lha6x48fc6l0vgyj6us4hqy0j3vhe`
- **LTC**: `ltc1q0x86knfq53kj4ug4ckcm6rdy9qx6w7cu6fy0hl`
- **DOGE**: `DEHxZkbQZ7EV5NfnhyRp4DmZcFjpY7M1DV`
