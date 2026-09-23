# Research: reproducing the SecureRandom seeding weakness

This folder has the source for the proof-of-concept tooling referenced in
[`SECURITY.md`](../SECURITY.md), and small samples of the raw evidence it produced. It exists
so the finding can be verified independently rather than taken on faith.

**Not included here** (all regenerable by running the tools below): the full raw evidence
CSVs used in the write-up (7,000 and 550 rows) are not committed to this public repo, since
every row is a real, validly-generated Bitcoin private key/WIF (never used, generated purely
for this test — but there's no reason to publish thousands of real private keys when the
tooling to regenerate fresh ones takes a few minutes). Two small samples (10 rows each) are
included below so the CSV format and a few real data points are visible without running
anything.

## What's here

| File | What it does |
|---|---|
| `SeedChild.cs` / `SeedOrchestrator.cs` | Launches many independent Windows processes, each calling the app's exact `new SecureRandom()` (no arguments) once, and records the resulting `DateTime.Ticks` + seeded key material. Used to measure organic `Ticks` collisions across independent process launches, and seeding time under CPU contention. |
| `KeyPairChild.cs` / `KeyPairOrchestrator.cs` | Same idea, but calls the real `KeyPair.Create(ExtraEntropy.GetEntropy())` via reflection over the actual compiled `BtcAddress.exe` — the exact code path behind `Address → New address` — instead of reimplementing it. |
| `GenerateAddresses.cs` | Generates many keys sequentially within a single process, to demonstrate why that scenario does *not* reproduce the cross-process collision (the shared static generator never resets within one process). |
| `SeedCollisionDemo.cs` / `seed_collision_test.py` | The core deterministic proof-of-concept: given identical `Ticks` + identical captured jitter, `SecureRandom` produces byte-identical output every time, across independent processes. Two equivalent implementations (C# and Python via `pythonnet`) as independent cross-checks. |
| `PrngEntropyPoC.cs` | Direct instrumentation of `ThreadedSeedGenerator` via reflection, measuring seeding time under idle vs. CPU-contended conditions. Its Shannon/min-entropy measurement was inconclusive and is not used as evidence in `SECURITY.md` — included for methodological transparency. |
| `*_sample.csv` | First 10 rows of the full evidence CSVs, for format reference only — `SeedCollisionDemo.cs`/`seed_collision_test.py` expect the full file named `seed_samples_evidence.csv` (see below), not the `_sample` one. |

## Running it yourself

Requires Windows with .NET Framework 4.x (`csc.exe`, already required to build the app
itself) and, for the Python variant, `pip install pythonnet`.

```powershell
copy ..\BouncyCastle.Crypto.dll .
$csc = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"

# Core deterministic proof (no compilation needed for the Python version):
pip install pythonnet
python seed_collision_test.py

# ...or the C# equivalent:
& $csc /nologo /reference:BouncyCastle.Crypto.dll /out:SeedCollisionDemo.exe SeedCollisionDemo.cs
.\SeedCollisionDemo.exe

# Organic Ticks-collision measurement across independent processes:
& $csc /nologo /reference:BouncyCastle.Crypto.dll /out:SeedChild.exe SeedChild.cs
& $csc /nologo /out:SeedOrchestrator.exe SeedOrchestrator.cs
.\SeedOrchestrator.exe 400   # writes seed_samples.csv
```

`SeedCollisionDemo.exe` / `seed_collision_test.py` (Part 1) read a file named
`seed_samples_evidence.csv` — not generated automatically. The write-up's numbers came from
running `SeedOrchestrator.exe` more than once (150, then 400) and concatenating the
resulting `seed_samples.csv` files together under that name. Run it once and rename the
output, or run it several times and combine them, to reproduce Part 1 with your own data —
Part 2 (the deterministic proof) only needs one real `Ticks` value from that file and works
the same regardless of sample count.

See `SECURITY.md` for what results to expect and how to interpret them.
