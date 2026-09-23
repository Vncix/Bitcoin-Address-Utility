# Bitcoin Address Utility (security-reviewed fork)

This is a fork of Mike Caldwell's (Casascius) [Bitcoin Address Utility](https://github.com/casascius/Bitcoin-Address-Utility) — a Windows desktop tool for generating Bitcoin private keys, addresses, mini private keys, paper wallets, and BIP38-encrypted keys. The original project has been publicly unmaintained since ~2013.

**This fork exists to document and fix a real weakness in how the original code generates randomness, and to add a couple of small, non-functional-behavior-changing quality-of-life features.** See [SECURITY.md](SECURITY.md) for the full write-up. Short version: the original always seeded its RNG from timing data (`DateTime.Ticks` + CPU-scheduling jitter) and never touched the operating system's CSPRNG, in *every* place the app generates key material — not just the obvious "New address" path. This fork patches all of them — key generation now uses the OS's cryptographic RNG (`RNGCryptoServiceProvider` via BouncyCastle's `CryptoApiRandomGenerator`) — and fixes a couple of unrelated bugs that prevented the project from even compiling on a modern .NET Framework install.

**Not affiliated with the original author.** Use at your own judgment; see [SECURITY.md](SECURITY.md) for what was and wasn't reviewed.

## Building

Dependencies (same as upstream):

1. The BouncyCastle Crypto library — `BouncyCastle.Crypto.dll` from [bouncycastle.org/csharp](http://www.bouncycastle.org/csharp/) (compiled assembly is enough), placed at the project root.
2. `ThoughtWorks.QRCode.dll`, also at the project root.

Then build `BtcAddress.sln` / `BtcAddress.csproj` with MSBuild or Visual Studio (targets .NET Framework 4.0). This fork also fixes an `ECPoint` name collision with a type .NET added in Framework 4.6.2, so — unlike upstream — it builds cleanly on a current .NET Framework SDK without needing an old targeting pack.

## What changed vs. upstream

See [SECURITY.md](SECURITY.md) and [CHANGES.md](CHANGES.md) for the full list and rationale. In short:

**Security fix — every key-material generation site, not just the obvious ones:**
`KeyPair.Create()`, `MiniKeyPair.CreateRandom()`, `Bip38Intermediate`'s owner-entropy generation, `Bip38KeyPair`'s `seedb` generation (two-factor/vanity key generation), both random-factor generations in `EscrowCode.cs` (Escrow Tools), `MofN.Generate()` (M-of-N Calculator), and `PaperWalletPrinter`'s deterministic-wallet passphrase generator all now seed from the OS CSPRNG instead of timing data. A non-atomic counter increment (`nonce++`) was made thread-safe. One dead-code path (`Form1.GenerateAddresses()`, unreachable, no callers) was fixed too, for defense-in-depth.

**Build fixes:** an `ECPoint` type ambiguity and a dangling designer event-handler reference, both of which broke compilation on a modern .NET Framework toolchain.

**Small additions (new, not present upstream):**
- Two new "Selection" menu export options: `Export Address,WIF (CSV)` and `Export Address,WIF,Hex (CSV)` — plain CSV, no extra formatting, for anyone doing bulk analysis. The existing `Save Address List` / `Save Address List with PrivKey` options are unchanged.
- Addresses generated from the **Address Utility** window (`Tools → Address Utility`, both "Generate" and the mini-key/"Shacode" button) are now also added to the main window's list, matching what `Address → New address` already did. Previously they only appeared in Address Utility's own fields and were lost when you closed that window.
- Removed the hardcoded, ~2013-era block-explorer links (blockexplorer.com, dot-bit.org, etc. — all dead or wrong today).

No other functional/UI behavior was changed.

---

## Support this fork

If this was useful to you, tips are welcome (and never expected):

- **BTC**: `bc1qhpppq4xs5lha6x48fc6l0vgyj6us4hqy0j3vhe`
- **LTC**: `ltc1q0x86knfq53kj4ug4ckcm6rdy9qx6w7cu6fy0hl`
- **DOGE**: `DEHxZkbQZ7EV5NfnhyRp4DmZcFjpY7M1DV`
