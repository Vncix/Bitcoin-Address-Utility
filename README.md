# Bitcoin Address Utility (security-reviewed fork)

This is a fork of Mike Caldwell's (Casascius) [Bitcoin Address Utility](https://github.com/casascius/Bitcoin-Address-Utility) — a Windows desktop tool for generating Bitcoin private keys, addresses, mini private keys, paper wallets, and BIP38-encrypted keys. The original project has been publicly unmaintained since ~2013.

**This fork exists to document and fix a real weakness in how the original code generates randomness.** See [SECURITY.md](SECURITY.md) for the full write-up. Short version: the original always seeded its RNG from timing data (`DateTime.Ticks` + CPU-scheduling jitter) and never touched the operating system's CSPRNG. This fork patches that — key generation now uses the OS's cryptographic RNG (`RNGCryptoServiceProvider` via BouncyCastle's `CryptoApiRandomGenerator`) — and fixes a couple of unrelated bugs that prevented the project from even compiling on a modern .NET Framework install.

**Not affiliated with the original author.** Use at your own judgment; see [SECURITY.md](SECURITY.md) for what was and wasn't reviewed.

## Building

Dependencies (same as upstream):

1. The BouncyCastle Crypto library — `BouncyCastle.Crypto.dll` from [bouncycastle.org/csharp](http://www.bouncycastle.org/csharp/) (compiled assembly is enough), placed at the project root.
2. `ThoughtWorks.QRCode.dll`, also at the project root.

Then build `BtcAddress.sln` / `BtcAddress.csproj` with MSBuild or Visual Studio (targets .NET Framework 4.0). This fork also fixes an `ECPoint` name collision with a type .NET added in Framework 4.6.2, so — unlike upstream — it builds cleanly on a current .NET Framework SDK without needing an old targeting pack.

## What changed vs. upstream

See [SECURITY.md](SECURITY.md) for the full list and rationale. In short:

- `KeyPair.Create()`, `MiniKeyPair.CreateRandom()`, and `Bip38Intermediate`'s entropy generation now seed from the OS CSPRNG instead of timing data.
- A non-atomic counter increment (`nonce++`) was made thread-safe.
- Two unrelated pre-existing bugs that broke the build on modern toolchains were fixed (an `ECPoint` type ambiguity, and a dangling designer event-handler reference).

No functional/UI behavior was changed beyond these fixes.

---

## Support this fork

If this was useful to you, tips are welcome (and never expected):

- **BTC**: `bc1qhpppq4xs5lha6x48fc6l0vgyj6us4hqy0j3vhe`
- **LTC**: `ltc1q0x86knfq53kj4ug4ckcm6rdy9qx6w7cu6fy0hl`
- **DOGE**: `DEHxZkbQZ7EV5NfnhyRp4DmZcFjpY7M1DV`
