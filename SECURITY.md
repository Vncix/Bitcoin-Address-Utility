# Security Analysis — Bitcoin Address Utility (this fork)

**Affected component:** `Model/KeyPair.cs` (`KeyPair.Create`) and, as later confirmed, every
other private-key-material generation site in this codebase, via `BouncyCastle.Crypto.dll`
(April 2011 build, `Org.BouncyCastle.Security.SecureRandom`)
**Entry points:** `Address → New address` in the main window, `Forms/AddressGen.cs`,
`Forms/Form1.cs`, `Forms/KeyCollectionView.cs`, plus Escrow Tools, the M-of-N Calculator,
two-factor/vanity key generation, and Paper Wallet's "Deterministic Wallet" passphrase
**Suggested severity:** High / Critical (direct private-key compromise under realistic
conditions)
**Vulnerability class:** CWE-338 (Use of Cryptographically Weak PRNG), CWE-330 (Use of
Insufficiently Random Values)

This is a fork of Mike Caldwell's (Casascius) archived [Bitcoin Address Utility](https://github.com/casascius/Bitcoin-Address-Utility), a Windows desktop tool (2012–2013) for generating Bitcoin private keys, addresses, mini private keys, paper wallets, and BIP38-encrypted keys.

This fork is **not affiliated with the original author**. It exists to document a security review of the random number generation used by the original codebase, and to ship a targeted fix so the tool can keep being used safely by anyone who still relies on it. No responsible-disclosure process was pursued for this specific finding: the upstream project has been publicly unmaintained for over a decade, has no listed maintainer contact or issue tracker activity, and the finding itself only affects locally-run key generation — it does not create a remote/network-exploitable condition.

## TL;DR

- Every random-key-material generation site in the original code seeded its randomness
  (`Org.BouncyCastle.Security.SecureRandom`, parameterless constructor) using **only
  `DateTime.Ticks` and CPU-scheduling jitter** — it never consults the operating system's
  CSPRNG (`RNGCryptoServiceProvider`/`BCryptGenRandom`).
- `DateTime.Ticks`, despite its 100ns-resolution name, only actually changes value roughly
  every ~6ms on Windows (measured). Two key-generation events that happen to occur within
  that window start from the same primary seed input.
- We demonstrated **deterministically** (not statistically) that identical seed material
  always produces an identical private key, with no fallback that breaks the tie — and
  separately measured, across thousands of independent process launches running the real,
  unmodified code, that this seed material collides **organically** at a low but non-trivial
  and consistent rate (roughly 3.6%–4.2% of samples shared a `Ticks` value with another
  independent sample, across two separate measurement runs).
- A full-codebase search found this pattern in **nine** call sites, not just the obvious
  "New address" path — see "What this fork changes" below. This fork replaces the weak
  default seeding with the operating system's CSPRNG (`CryptoApiRandomGenerator`, which
  wraps `RNGCryptoServiceProvider`) at every one of them, and fixes a secondary non-atomic
  counter increment.

## How the investigation started

This review began from a report of unusual behavior on a resource-constrained VM ("New
address" generation taking an unexpectedly long time, sometimes appearing to hang). The
initial hypothesis to test was a possible ordering race: *could a UI action read from the
RNG before it finished seeding?* That hypothesis was disassembled at the IL level and
**ruled out** — the seeding chain (`SecureRandom()` → `GetSeed()` → `get_Master()` →
`SetSeed()`) is fully synchronous and blocking; there is no `Task.Run`, no unawaited
`ThreadPool.QueueUserWorkItem`, no fire-and-forget path. `KeyPair.Create()` cannot read bytes
from the generator (`sr.NextLong()`) before `SecureRandom`'s construction — including
seeding — has returned.

That specific hypothesis being wrong is what led to the real finding documented below: the
quality and uniqueness of the seed material itself, independent of any ordering question.

## Root-cause analysis

All of the following comes from disassembling the actual IL of the `BouncyCastle.Crypto.dll`
shipped with this app — not from documentation, and not from a newer BouncyCastle version,
which may differ.

### The real seeding chain of `new SecureRandom()`

`Model/KeyPair.cs` (before this fork's fix):

```csharp
public static KeyPair Create(string usersalt, bool compressed=false, byte addressType = 0) {
    if (usersalt == null) usersalt = "ok, whatever";
    usersalt += DateTime.UtcNow.Ticks.ToString();

    SecureRandom sr = new SecureRandom();   // <-- all cryptographic randomness comes from here

    byte[] poop = Util.ComputeSha256(usersalt + nonce.ToString());
    nonce++;

    byte[] newkey = new byte[32];
    for (int i = 0; i < 32; i++) {
        long x = sr.NextLong() & long.MaxValue;
        x += poop[i];
        newkey[i] = (byte)(x & 0xff);
    }
    return new KeyPair(newkey, compressed: compressed, addressType: addressType);
}
```

IL of `SecureRandom()`'s parameterless constructor, its static constructor, and
`get_Master()`:

```
.cctor:
  sha1Generator   = new DigestRandomGenerator(new Sha1Digest())     // static, shared by the WHOLE process
  sha256Generator = new DigestRandomGenerator(new Sha256Digest())   // static, shared by the WHOLE process
  master = new SecureRandom[1]                                     // lazy, null until first use

SecureRandom():
  this.generator = sha1Generator      // <-- reuses the shared STATIC generator
  this.SetSeed(GetSeed(8))            // mixes in 8 more bytes, synchronously

GetSeed(n):
  return Master.GenerateSeed(n)

get_Master() [only the 1st time it's used, for the whole process]:
  master[0] = new SecureRandom(new ReversedWindowGenerator(sha256Generator, 32))
  master[0].SetSeed(DateTime.Now.Ticks)                                 // <-- the only time-based ingredient
  master[0].SetSeed(new ThreadedSeedGenerator().GenerateSeed(32, true)) // <-- CPU scheduling jitter
  master[0].GenerateSeed(1 + master[0].Next(20))   // discarded, just stirs the state further
  return master[0]
```

`CryptoApiRandomGenerator` — BouncyCastle's own wrapper around the Windows CSPRNG — exists
in the same DLL and is never used by this code path. Confirmed via reflection that the
runtime type of the internal generator is `Org.BouncyCastle.Crypto.Prng.DigestRandomGenerator`
/ `ReversedWindowGenerator`, never `CryptoApiRandomGenerator`.

### `ThreadedSeedGenerator`: where the "jitter" comes from

IL of the producer thread (`SeedGenerator.Run`):
```
while (!stop) { counter++; }   // spin loop, no real synchronization, just raw CPU speed
```

IL of the consumer side (`SeedGenerator.GenerateSeed`, summarized):
```
ThreadPool.QueueUserWorkItem(Run)
for (i = 0; i < numBytes; i++) {
    do { Thread.Sleep(1); } while (counter == lastCounter);
    lastCounter = counter;
    result[i] = (byte) lastCounter;     // <-- takes the low byte of the RAW COUNTER
}
stop = true;
return result;
```

This is a classic "scheduling-jitter entropy" technique: it assumes the number of times the
producer thread incremented `counter` between two consecutive `Thread.Sleep(1)` wakeups on
the consumer thread is unpredictable. That assumption depends entirely on the OS/hypervisor
delivering genuine scheduling jitter — a condition that degrades on low-vCPU VMs or under CPU
contention (see below).

### A static generator shared across every instance

Confirmed via reflection (`ReferenceEquals`): **two independent calls to `new SecureRandom()`
within the same process return objects wrapping the same static `DigestRandomGenerator`**
(`sha1Generator`). There are no fresh, independent generators per "New Address" — the whole
process shares and progressively mutates the same hash-chain state.

### `DateTime.Now.Ticks`'s real resolution is far coarser than it looks

Although `DateTime.Ticks` is documented in 100ns units, its *effective* resolution on
Windows is limited by the OS timer. Measured empirically on the test host:

```
Tick changes observed in 500ms: 91
Average delta between changes: 59688 ticks ≈ 5.97ms
```

In other words: **two "New Address" generations happening within the same ~6ms window start
from the identical `DateTime.Now.Ticks` value** — the first, and most deterministic,
ingredient of the master seed.

## Proof of concept

### Organic evidence: `Ticks` really does collide between independent processes

Rather than starting from a hand-picked seed, 550 real runs of `new SecureRandom()` — no
arguments, the app's exact code, each in an independent Windows process pinned to one
logical core — were analyzed for how many, purely by coincidence, read the identical
`DateTime.Ticks` value:

| Metric | Value |
|---|---|
| Total samples (independent processes) | 550 |
| Pairs/groups sharing the exact same `Ticks` | **10** |
| Samples involved in some `Ticks` collision | 20 of 550 (**3.6%**) |
| Full 32-byte private-key collisions among those pairs | 0 |

Real example (unedited), from the evidence data:

```
pid=35872  ticks=639251815126388809  hex32=BBA6C55B2718AF5B43AC1C70615C07A8F88526A0674D24DD5006458F6F718A42
pid=59240  ticks=639251815126388809  hex32=A335B0A7252ECD3B14E2B9A426B68D95B79A6D7CA1E558CB96E5769FAFDFD768
```

Two completely independent Windows processes (different PIDs, no shared memory), running the
real `SecureRandom()` code with no external interference, read the **same `DateTime.Ticks`**.
In this particular pair the final keys still ended up different — jitter still
differentiated them — but the central point is demonstrated with 100% real data: **the first
ingredient of the seed is neither unique nor unpredictable; it collides measurably and
reproducibly under real conditions.** 550 samples already show 10 collisions; this scales
with the number of concurrent generations (see below).

### Controlled experiment: matching `Ticks` *and* jitter always produces the same key

The organic evidence above proves `Ticks` collides in practice, but honestly, no full 32-byte
collision was observed among the 550 organic samples — jitter provided enough
differentiation every time. To close the argument without waiting for jitter to also collide
by chance, the property was isolated in a controlled experiment, explicitly labeled as such
(this exact combination is not claimed to have happened spontaneously):

```python
# Part 2 — everything captured dynamically, nothing hardcoded
ticks_real = organic_ticks[0]           # REAL Ticks, taken from an organic collision in Part 1
jitter_real = capture_real_jitter_hex() # REAL jitter, captured NOW with the actual ThreadedSeedGenerator

sr = SecureRandom(Array[Byte]([]))      # fresh generator, no uncontrolled entropy carried over
sr.SetSeed(Int64(ticks_real))
sr.SetSeed(jitter_real)
sr.NextBytes(key)                       # 32 bytes, same as KeyPair.Create()
```

Nothing is written by hand in the script. `Ticks` is taken dynamically from the first pair
found in Part 1 (a value that genuinely collided between two independent processes); the
jitter is captured live on each run by calling
`Org.BouncyCastle.Crypto.Prng.ThreadedSeedGenerator().GenerateSeed(32, true)` — the same
public class `get_Master()` uses internally. That's why the exact key value changes on every
run of the script (the jitter differs each time) — what's invariant, and what proves the
weakness, is the *property*, not one specific number.

Example of a real run (three independent Windows processes, jitter captured live at that
moment):

| Run (independent process) | Resulting private key |
|---|---|
| 1 | `8F3C1F57E802307860DD3AA385D526E4669E35F9BE29777FA279EC0F7D775E48` |
| 2 | `8F3C1F57E802307860DD3AA385D526E4669E35F9BE29777FA279EC0F7D775E48` |
| 3 | `8F3C1F57E802307860DD3AA385D526E4669E35F9BE29777FA279EC0F7D775E48` |
| Control (a different real `Ticks`) | `47DC7D37CEFFC58E277948349172137C4042576A0A718478100AE48659D6882C` |

**Identical across the three independent runs; different in the control — with any real
jitter, on any machine, every time.** This proves, without relying on statistics or on
brute-forcing 256 bits, that the design **has no independent mechanism (OS CSPRNG or
otherwise) that stops two generations with matching seed material from producing the same
private key.** Combined with the organic-collision evidence above (`Ticks` really does
collide, measured, 3.6%–4.2% of samples across separate runs) and the CPU-contention
measurements below (contention degrades exactly the jitter that today is the only thing
preventing a full collision), the risk of a real full collision grows with host load — it is
not purely theoretical.

> **Independently reproduced on two different machines, with two separately captured real
> jitter values:** besides the run shown above, the same result was reproduced with an
> earlier C# version of the tool using `Ticks=639251815126388809` and a separately captured
> real jitter (`58993234D082E0188F9456E8BE88BEFA67A7E5E1EA3042BA5141A9B9182CFEAC`) →
> `privkey=C7B7319D851131C8F7698D46D503C416D320963C6E5FF470173D460C49C20B1D` on two independent
> processes (PID 47656 and PID 54772). The key value changes depending on the jitter
> captured; the property (same `Ticks` + same jitter → same key, always) held on both
> machines, in both languages.

> Technical note: the experiment uses `SecureRandom(byte[0])` instead of the parameterless
> `SecureRandom()`. It was confirmed empirically that `SecureRandom()` internally triggers
> `GetSeed(8)` (which in turn starts `Master`/`ThreadedSeedGenerator` with real, uncontrolled
> entropy) *before* the manual `SetSeed()` calls are applied, which broke the experiment's
> isolation (the first run of this exact test produced different keys despite matching
> `Ticks`/jitter, until this was corrected). `SecureRandom(byte[0])` doesn't trigger that
> path, so the only seed material entering the generator is what's explicitly controlled.

### Exact scope: collides between processes, not within the same process

An important precision confirmed during testing: calling `new SecureRandom(...)` **multiple
times within the same process** does *not* collide, because the shared static generator has
already been mutated by the prior call. The coincidence only happens between **independent
.NET processes** (fresh runtime, uninitialized static generator).

This bounds the real exploitation scenario to: **app restarts, multiple
instances/copies of the app running in parallel, or cloned/snapshotted VMs** that boot the
process and generate an address with coinciding seed material — not to "successive clicks
of New Address within the same already-open session" (there, the shared generator keeps
advancing its state, even though it's still never backed by the OS CSPRNG).

### Why the seed can collide in practice

- `DateTime.Now.Ticks` matches between generations less than ~6ms apart (measured above).
- `ThreadedSeedGenerator` depends on real scheduling jitter between two threads; on a
  resource-constrained host that condition degrades (see below).
- Both ingredients feed into the same SHA-256-based generator shared by the whole process, so
  a partial coincidence in either one directly shrinks the effective search space for an
  attacker.

Realistic scenarios where this applies:
- Batch generation of multiple addresses in quick succession (the app supports multiple
  generation threads — see `Forms/Form1.cs` and its `List<Thread> Threads`).
- Multiple instances/users generating addresses nearly simultaneously on the same shared
  physical host or VM.
- Cloned/snapshotted VMs that boot into a very similar clock and CPU-load state.
- **No single-instance guard**: `Program.cs`'s `Main()` calls `Application.Run(new KeyCollectionView())` directly, with no mutex or "already running" check. A user can trivially launch two copies of the app at once — deliberately, for batch work, or just by double-clicking the `.exe` twice — and each is a fresh OS process with its own from-scratch `SecureRandom` seeding sequence, which is exactly the condition the organic-collision measurements above are about. This is the simplest concrete trigger for the vulnerability: no VM, scripting, or adversarial setup required.

### Measured degradation under CPU contention (resource-constrained VM)

The real `ThreadedSeedGenerator` was instrumented directly (via reflection over the same
DLL), measuring `new SecureRandom()`'s seeding time under two conditions:

| Condition | Instances/samples | Seeding time |
|---|---|---|
| Idle (no extra load) | 512 samples | ~9ms/sample (nominal expectation: 1ms) |
| CPU-saturated (16 busy-spin threads on 4 vCPUs) | 512 samples | ~167ms/sample (**18.7x slower**) |
| Individual `new SecureRandom()` under contention | 20 instances | min 0ms / avg **212ms** / max **4,240ms** |
| 150 independent simultaneous generations, all pinned to **1 logical core** (simulates a 1-vCPU VM) | 150 processes | min 6.8s / median **59.2s** / max **107.3s** per generation |
| 400 independent simultaneous generations, same conditions | 400 processes | min 11.9s / median **87.4s** / max **179.8s** per generation |

This quantitatively confirms the original observation that motivated this review ("a slow VM
makes New Address take forever / appear to hang"), and shows that, under real load, the
seeding mechanism spends much more time depending on scheduling jitter that is, by design,
*less* reliable precisely when the host is busier — the same condition that raises the
likelihood of `DateTime.Now.Ticks` matching between concurrent generations.

> Methodological note: an earlier iteration of this analysis attempted to find direct
> collisions via statistical brute force (150 samples, comparing byte prefixes). That test
> **produced no valid evidence** of weakness — the first-byte matches observed were
> statistically consistent with the birthday-problem baseline for a uniform 8-bit
> distribution at that sample size, and it is explicitly excluded from this report to avoid
> over-claiming. The real, defensible finding is the deterministic one above, not a
> statistical one.

## Impact

- **Direct loss of funds**: if two different addresses (from two users, or from the same
  user during batch generation) end up with the same private key, either party with access
  to one can spend the other's funds.
- **Reduced search space for an offline attacker**: even without an exact collision, if an
  attacker can reasonably bound the time window an address was generated in (log timestamps,
  file metadata, the first on-chain transaction) and knows the app ran on a
  resource-constrained host, the effective key space to search shrinks drastically relative
  to the nominal 256 bits.
- Applies to **every private key generated through this code pattern**: "New Address" in the
  main menu, mini-key generation, batch-generated paper wallets, Escrow Tools, the M-of-N
  Calculator, and two-factor/vanity key generation — see the full list below.

## What this fork changes

| File | Change |
|---|---|
| `Model/KeyPair.cs` | `new SecureRandom()` → `new SecureRandom(new CryptoApiRandomGenerator())` in `Create()`. Also made the `nonce` counter increment atomic (`Interlocked.Increment`) — it was a plain `nonce++` on a shared static field, a secondary (unrelated) thread-safety issue. |
| `Model/MiniKeyPair.cs` | Same `SecureRandom` fix in `CreateRandom()`. |
| `Model/Bip38Intermediate.cs` | Same `SecureRandom` fix for owner-entropy generation. |
| `Model/Bitcoin.cs`, `Model/PublicKey.cs`, `Model/KeyPair.cs`, `Model/Bip38Confirmation.cs`, `Model/Bip38KeyPair.cs`, `Model/EscrowCode.cs`, `Forms/Bip38ConfValidator.cs` | Unrelated build fix: added an explicit `using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;` alias. This codebase predates `System.Security.Cryptography.ECPoint` (added in .NET Framework 4.6.2), and on any modern .NET Framework install the two types collide, making the project fail to compile at all. No behavior change — purely a name-resolution fix. |
| `Forms/KeyCollectionView.Designer.cs` | Removed a dangling event subscription to a `menuStrip1_ItemClicked` handler that doesn't exist anywhere in the codebase (pre-existing designer/code-behind drift, unrelated to the security fix) — this alone prevented the project from building at all. |

`CryptoApiRandomGenerator` wraps `System.Security.Cryptography.RNGCryptoServiceProvider` (the Windows CSPRNG). This removes the dependency on `Ticks`/CPU-jitter timing entirely for the actual random bytes; the deterministic-collision mechanism documented above no longer applies to a build of this fork.

### Follow-up: the first pass didn't cover every call site

A full-codebase search for every `new SecureRandom()` instantiation — not just the three
obvious `KeyPair`-family ones above — found **four more reachable, key-material-determining
call sites** still using the unpatched constructor:

| File / method | What the randomness determines |
|---|---|
| `Forms/PaperWalletPrinter.cs` — `GetUglyRandomString()` | The default passphrase for "Deterministic Wallet" generation — as security-sensitive as key generation itself, since the passphrase *is* the seed. |
| `Model/Bip38KeyPair.cs` — `Bip38KeyPair(Bip38Intermediate, ...)` constructor | `seedb`, which becomes `factorb`, multiplied directly into the final private key for two-factor / vanity-address generation. |
| `Model/EscrowCode.cs` — `EscrowCodeSet()` constructor | `x` and `y`, which directly become the private key material for an escrow pair. |
| `Model/EscrowCode.cs` — factor-recombination method | `z`, multiplied directly into the resulting key material. |
| `Model/MofN.cs` — `MofN.Generate()` | The coefficients that determine (or, if no key is supplied, select) the split private key for the M-of-N Calculator. |

All five got the identical `CryptoApiRandomGenerator` fix, with an inline comment at each
site. A sixth spot, `Form1.GenerateAddresses()`, uses the same weak pattern but has no
callers anywhere in the codebase (confirmed dead code) — fixed anyway, for defense-in-depth,
in case it's ever wired back up.

**Takeaway:** when patching an entropy source in a codebase like this, grep for every
instantiation of the RNG type itself, not just the call sites you already know about. The
original patch reasoned from "where does the app generate a Bitcoin key" and correctly
covered the 3 answers to that question, but missed places where the same weak constructor
was used to generate *other* private-key-determining secrets (escrow factors, M-of-N shares,
two-factor seed material) that don't show up if you're specifically searching for "key
generation" as a UI feature.

### `ExtraEntropy.cs` contributes close to nothing in the most common real-world case

`Model/ExtraEntropy.cs` mixes in user-provided "extra" entropy on top of the weak seed above,
but it also starts from `DateTime.Now.Ticks` and only strengthens further if something calls
`AddExtraEntropy()`. Checking the main window's designer code
(`Forms/KeyCollectionView.Designer.cs`), the only hook wired up is
`menuStrip1.MouseMove` — there is no `KeyDown` handler anywhere. In the single most common
real-world usage pattern — one click on `Address → New address`, or keyboard-only navigation
(Alt+A, arrow keys, Enter) without touching the mouse — `ExtraEntropy`'s contribution is
effectively zero, leaving the seed depending on `DateTime.Ticks` alone.

## Reproducing this analysis

The full PoC tooling (C# and Python, both real reflection over the actual compiled DLLs —
neither reimplements the algorithm) lives in [`research/`](research/), along with small
samples of the raw evidence data. See [`research/README.md`](research/README.md) for how to
run it yourself.

## Is it safe to use now?

**With this fork's fix applied, and built/run yourself from source: yes**, for the specific weakness documented here — key generation now draws from the OS CSPRNG rather than a timing-based seed. This is the same category of source used by essentially every modern cryptographic library on Windows.

A few things worth knowing regardless of which build you use:

- **Prefer building from source yourself** over running a pre-built binary you didn't compile, for any cryptographic tool, on principle — this is generic advice for any private-key-generating software, not specific to a remaining weakness here.
- This review covered the *seeding* of the RNG in depth. It did not re-audit the elliptic-curve math, Base58Check encoding, or BIP38 encryption logic beyond what was needed to trace the RNG's usage — those paths are unchanged from upstream and were not the subject of this analysis.
- The original, unpatched upstream project (and any other unpatched fork/binary of it) still has the weakness described above. If you have private keys that were generated with an unpatched build — especially via automated/batch generation, on a resource-constrained VM, or by running two copies of the app at once — treat that as a real risk and prefer moving funds to a freshly generated key from a properly-seeded source.

---

## Support this fork

If this analysis or the fix was useful to you, tips are welcome (and never expected):

- **BTC**: `bc1qhpppq4xs5lha6x48fc6l0vgyj6us4hqy0j3vhe`
- **LTC**: `ltc1q0x86knfq53kj4ug4ckcm6rdy9qx6w7cu6fy0hl`
- **DOGE**: `DEHxZkbQZ7EV5NfnhyRp4DmZcFjpY7M1DV`
