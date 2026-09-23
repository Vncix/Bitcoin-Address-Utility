# Changes in this fork vs. upstream (casascius/Bitcoin-Address-Utility)

This file documents every change made in this fork, in line with GPLv3 §5(a).

## Security fix: OS CSPRNG everywhere key material is generated

Originally, every random-key-material generation site in this codebase called BouncyCastle's
parameterless `new SecureRandom()`, which never touches the operating system's CSPRNG — see
[`SECURITY.md`](SECURITY.md) for the full technical write-up. All nine call sites were
changed to `new SecureRandom(new CryptoApiRandomGenerator())`:

- `Model/KeyPair.cs` — `KeyPair.Create()` (also made the `nonce` field's increment atomic via
  `Interlocked.Increment`, a separate pre-existing thread-safety issue)
- `Model/MiniKeyPair.cs` — `MiniKeyPair.CreateRandom()`
- `Model/Bip38Intermediate.cs` — owner-entropy generation
- `Model/Bip38KeyPair.cs` — `seedb` generation (two-factor/vanity key generation)
- `Model/EscrowCode.cs` — `EscrowCodeSet()` constructor, and its factor-recombination method
  (two separate call sites)
- `Model/MofN.cs` — `MofN.Generate()`
- `Forms/PaperWalletPrinter.cs` — `GetUglyRandomString()` (default "Deterministic Wallet"
  passphrase)
- `Forms/Form1.cs` — `GenerateAddresses()` (confirmed dead code / no callers anywhere in the
  codebase; fixed anyway for defense-in-depth)

## Build-compatibility fixes (no behavior change)

- `ECPoint` type ambiguity: this codebase predates `System.Security.Cryptography.ECPoint`
  (added in .NET Framework 4.6.2), which collides by name with BouncyCastle's own `ECPoint`.
  Resolved with an explicit `using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;` alias across
  the affected files (`Model/Bitcoin.cs`, `Model/PublicKey.cs`, `Model/KeyPair.cs`,
  `Model/Bip38Confirmation.cs`, `Model/Bip38KeyPair.cs`, `Model/EscrowCode.cs`,
  `Forms/Bip38ConfValidator.cs`).
- `Forms/KeyCollectionView.Designer.cs` — removed a dangling event subscription to a
  `menuStrip1_ItemClicked` handler that doesn't exist anywhere in the codebase (pre-existing
  designer/code-behind drift). This alone prevented the project from compiling at all.

## Feature additions (new behavior, not present upstream)

- **`Forms/KeyCollectionView.Designer.cs` / `.cs`** — two new "Selection" menu items:
  `Export Address,WIF (CSV)` and `Export Address,WIF,Hex (CSV)`. Plain, unquoted CSV rows
  (`address,WIF` or `address,WIF,hex`), one line per checked item, no extra formatting. The
  existing `Save Address List` and `Save Address List with PrivKey` options are unchanged.
- **`Program.cs`** — added `Program.MainWindow`, a static reference to the running
  `KeyCollectionView` instance, set in `Main()`.
- **`Forms/Form1.cs`** — `btnGenerate_Click` and `btnShacode_Click` (Address Utility's
  "Generate" and mini-key/"Shacode" buttons) now also call
  `Program.MainWindow.KeyCollection.AddItem(...)`, so addresses generated from the Address
  Utility window appear in the main window's list too — previously they only lived in Address
  Utility's own fields and were lost when that window was closed.
- **`Forms/Form1.cs`** — removed the hardcoded block-explorer links in `btnBlockExplorer_Click`
  (blockexplorer.com, dot-bit.org, explorer.litecoin.net, blockchain.info/address — all dead
  or pointing to the wrong service today) and hid the now-inert button
  (`btnBlockExplorer.Visible = false` in the constructor).

## Documentation and reproducible evidence

- **`SECURITY.md`** was substantially expanded with the full root-cause analysis (IL-level
  disassembly of `SecureRandom`'s seeding chain, `ThreadedSeedGenerator`'s jitter mechanism,
  the static-shared-generator finding, measured `DateTime.Ticks` resolution, the
  deterministic same-seed-same-key proof of concept, and measured seeding-time degradation
  under CPU contention), and the previously-undocumented finding that
  `Model/ExtraEntropy.cs`'s only entropy hook is a `MouseMove` handler with no `KeyDown`
  equivalent — so keyboard-only navigation to "New address" adds effectively zero
  supplementary entropy.
- **`research/`** — added the proof-of-concept source (C# and Python, both operating on the
  real compiled DLLs via reflection, not a reimplementation) referenced by `SECURITY.md`,
  plus small (10-row) samples of the raw evidence data. The full evidence CSVs (7,000 and 550
  rows) are not committed, since every row is a real, validly-generated private key/WIF —
  the tooling to regenerate fresh ones is included instead. See `research/README.md`.

## Not changed

Everything else — UI layout, encoding/decoding logic, BIP38 encryption math, printing/report
generation — is unchanged from upstream.
