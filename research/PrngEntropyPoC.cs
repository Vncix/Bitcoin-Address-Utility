// PoC: mide la calidad de entropia real del ThreadedSeedGenerator de BouncyCastle
// (el que siembra SecureRandom() por defecto, usado por KeyPair.Create en CASA)
// bajo condiciones idle vs. CPU-contention (simulando una VM lenta / con pocos vCPU).
//
// No modifica ni depende del codigo de CASA: instrumenta el BouncyCastle.Crypto.dll
// real que la app usa, via reflection, replicando exactamente el algoritmo de
// muestreo que corre dentro de SecureRandom.GetSeed() / get_Master().

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Threading;

class PrngEntropyPoC {

    static Assembly bcAsm;
    static Type seedGenType;
    static FieldInfo counterField;
    static FieldInfo stopField;
    static MethodInfo runMethod;

    static void Main(string[] args) {
        string dllPath = args.Length > 0 ? args[0] : @"..\BouncyCastle.Crypto.dll";
        bcAsm = Assembly.LoadFrom(dllPath);
        seedGenType = bcAsm.GetType("Org.BouncyCastle.Crypto.Prng.ThreadedSeedGenerator+SeedGenerator");
        var flags = BindingFlags.NonPublic | BindingFlags.Instance;
        counterField = seedGenType.GetField("counter", flags);
        stopField = seedGenType.GetField("stop", flags);
        runMethod = seedGenType.GetMethod("Run", flags);

        int samples = 512;

        Console.WriteLine("=== PoC: entropia del ThreadedSeedGenerator (BouncyCastle) bajo distintas condiciones de CPU ===");
        Console.WriteLine("Assembly: " + bcAsm.Location);
        Console.WriteLine("Entorno: {0} vCPU logicos detectados por el proceso", Environment.ProcessorCount);
        Console.WriteLine();

        // Condicion 1: idle (sin contencion artificial)
        var idle = CaptureSamples(samples, sleepMs: 1);
        Report("IDLE (sin carga extra)", idle);

        // Condicion 2: CPU-contention simulada (satura todos los cores con hilos "spin")
        int busyThreads = Math.Max(2, Environment.ProcessorCount * 4); // oversubscription fuerte
        var stopBusy = false;
        var busyRunners = new List<Thread>();
        for (int i = 0; i < busyThreads; i++) {
            var t = new Thread(() => { long x = 0; while (!Volatile.Read(ref stopBusy)) { x++; } });
            t.IsBackground = true;
            t.Start();
            busyRunners.Add(t);
        }
        Thread.Sleep(200); // dejar que la saturacion se establezca

        var loaded = CaptureSamples(samples, sleepMs: 1);
        stopBusy = true;
        foreach (var t in busyRunners) t.Join(500);

        Report(string.Format("CPU-CONTENTION ({0} hilos busy-spin sobre {1} vCPU, simula VM saturada)", busyThreads, Environment.ProcessorCount), loaded);

        Console.WriteLine();
        Console.WriteLine("=== Comparacion directa ===");
        Compare(idle, loaded);

        // Prueba adicional: llamar a la API publica real (new SecureRandom()) N veces
        // bajo contencion y ver cuanto tarda + si hay bytes de seed repetidos (control de sanity).
        Console.WriteLine();
        Console.WriteLine("=== Prueba de API publica: new SecureRandom() bajo contencion ===");
        PublicApiTiming();
    }

    class SampleResult {
        public List<long> RawCounterValues = new List<long>();
        public List<long> Deltas = new List<long>();
        public double ElapsedMs;
        public int StuckSamples; // muestras donde el contador no cambio respecto a la anterior
    }

    static SampleResult CaptureSamples(int n, int sleepMs) {
        object seedGen = Activator.CreateInstance(seedGenType, nonPublic: true);
        stopField.SetValue(seedGen, false);
        counterField.SetValue(seedGen, 0);

        var thread = new Thread(new ParameterizedThreadStart(o => runMethod.Invoke(seedGen, new object[] { null })));
        thread.IsBackground = true;
        thread.Priority = ThreadPriority.Normal;
        thread.Start();

        var result = new SampleResult();
        var sw = Stopwatch.StartNew();
        long last = (int)counterField.GetValue(seedGen);
        int stuck = 0;

        for (int i = 0; i < n; i++) {
            Thread.Sleep(sleepMs);
            long cur = (int)counterField.GetValue(seedGen);
            result.RawCounterValues.Add(cur);
            long delta = cur - last;
            result.Deltas.Add(delta);
            if (delta == 0) stuck++;
            last = cur;
        }
        sw.Stop();
        result.ElapsedMs = sw.Elapsed.TotalMilliseconds;
        result.StuckSamples = stuck;

        stopField.SetValue(seedGen, true);
        thread.Join(1000);

        return result;
    }

    // NOTA: el algoritmo real de SeedGenerator.GenerateSeed(n, fast:true) hace
    // result[i] = (byte) lastCounter  -->  toma el byte BAJO del VALOR CRUDO
    // del contador en cada muestra (no la diferencia entre muestras).
    // Por eso medimos entropia sobre RawCounterValues, no sobre Deltas.

    static double ShannonEntropyOfLowBits(List<long> raw) {
        int ones = raw.Count(d => (d & 1) != 0);
        int zeros = raw.Count - ones;
        double p1 = (double)ones / raw.Count;
        double p0 = (double)zeros / raw.Count;
        double h = 0;
        if (p0 > 0) h -= p0 * Math.Log(p0, 2);
        if (p1 > 0) h -= p1 * Math.Log(p1, 2);
        return h; // 1.0 = ideal (50/50), 0.0 = totalmente sesgado/predecible
    }

    static double MinEntropyPerByteSample(List<long> raw) {
        // Estima min-entropia (estilo NIST SP 800-90B, "Most Common Value Estimate")
        // sobre el byte bajo del contador crudo: -log2(max_prob).
        var counts = new Dictionary<long, int>();
        foreach (var d in raw) {
            long b = ((d % 256) + 256) % 256;
            if (!counts.ContainsKey(b)) counts[b] = 0;
            counts[b]++;
        }
        int maxCount = counts.Values.Max();
        double pMax = (double)maxCount / raw.Count;
        return -Math.Log(pMax, 2);
    }

    static void Report(string label, SampleResult r) {
        Console.WriteLine("--- " + label + " ---");
        Console.WriteLine("  Muestras: {0}, tiempo total: {1:F0} ms", r.RawCounterValues.Count, r.ElapsedMs);
        Console.WriteLine("  Muestras 'stuck' (delta==0, cero entropia en esa muestra): {0} ({1:F1}%)",
            r.StuckSamples, 100.0 * r.StuckSamples / r.RawCounterValues.Count);
        Console.WriteLine("  Delta min/avg/max: {0} / {1:F1} / {2}",
            r.Deltas.Min(), r.Deltas.Average(), r.Deltas.Max());
        Console.WriteLine("  Desvio estandar del delta: {0:F1}", StdDev(r.Deltas));
        Console.WriteLine("  Entropia de Shannon del bit bajo del contador crudo (bits, ideal=1.0): {0:F4}", ShannonEntropyOfLowBits(r.RawCounterValues));
        Console.WriteLine("  Min-entropia estimada del byte bajo del contador crudo (bits, ideal=8.0): {0:F2}", MinEntropyPerByteSample(r.RawCounterValues));
        Console.WriteLine();
    }

    static double StdDev(List<long> xs) {
        double avg = xs.Average();
        double sumSq = xs.Sum(x => (x - avg) * (x - avg));
        return Math.Sqrt(sumSq / xs.Count);
    }

    static void Compare(SampleResult idle, SampleResult loaded) {
        double hIdle = ShannonEntropyOfLowBits(idle.RawCounterValues);
        double hLoaded = ShannonEntropyOfLowBits(loaded.RawCounterValues);
        double meIdle = MinEntropyPerByteSample(idle.RawCounterValues);
        double meLoaded = MinEntropyPerByteSample(loaded.RawCounterValues);

        Console.WriteLine("  Entropia Shannon (bit bajo):  idle={0:F4}  contencion={1:F4}  caida={2:F1}%",
            hIdle, hLoaded, 100.0 * (hIdle - hLoaded) / Math.Max(hIdle, 0.0001));
        Console.WriteLine("  Min-entropia (byte bajo):     idle={0:F2} bits  contencion={1:F2} bits  caida={2:F1}%",
            meIdle, meLoaded, 100.0 * (meIdle - meLoaded) / Math.Max(meIdle, 0.0001));
        Console.WriteLine("  Muestras 'stuck':             idle={0}  contencion={1}", idle.StuckSamples, loaded.StuckSamples);

        // GenerateSeed(32, true) pide 32 muestras de 1 byte (modo 'fast', el que usa KeyPair.Create
        // indirectamente via SecureRandom() -> GetSeed(8) -> Master.GenerateSeed(8)).
        // Estimamos bits reales de entropia acumulados en una siembra de 8 bytes:
        double estBitsIdle = 8 * meIdle;
        double estBitsLoaded = 8 * meLoaded;
        Console.WriteLine();
        Console.WriteLine("  --> Entropia estimada en una siembra de 8 bytes (la que usa SecureRandom() por defecto):");
        Console.WriteLine("      idle:       ~{0:F1} bits (nominal: 64 bits)", estBitsIdle);
        Console.WriteLine("      contencion: ~{0:F1} bits (nominal: 64 bits)", estBitsLoaded);
    }

    static void PublicApiTiming() {
        var securRandomType = bcAsm.GetType("Org.BouncyCastle.Security.SecureRandom");
        int iterations = 20;
        var times = new List<double>();
        var seeds = new List<string>();

        // saturar CPU mientras medimos
        bool stopBusy = false;
        var runners = new List<Thread>();
        int n = Math.Max(2, Environment.ProcessorCount * 4);
        for (int i = 0; i < n; i++) {
            var t = new Thread(() => { long x = 0; while (!Volatile.Read(ref stopBusy)) { x++; } });
            t.IsBackground = true; t.Start(); runners.Add(t);
        }
        Thread.Sleep(200);

        for (int i = 0; i < iterations; i++) {
            var sw = Stopwatch.StartNew();
            object sr = Activator.CreateInstance(securRandomType);
            sw.Stop();
            times.Add(sw.Elapsed.TotalMilliseconds);

            var nextBytesMethod = securRandomType.GetMethod("NextBytes", new Type[] { typeof(byte[]) });
            byte[] buf = new byte[8];
            nextBytesMethod.Invoke(sr, new object[] { buf });
            seeds.Add(BitConverter.ToString(buf));
        }
        stopBusy = true;
        foreach (var t in runners) t.Join(500);

        Console.WriteLine("  {0} instancias de new SecureRandom() bajo contencion de CPU:", iterations);
        Console.WriteLine("  Tiempo de construccion min/avg/max: {0:F1} / {1:F1} / {2:F1} ms",
            times.Min(), times.Average(), times.Max());
        Console.WriteLine("  Primeros 8 bytes de NextBytes() por instancia (control de sanity, no deberian repetirse):");
        foreach (var s in seeds) Console.WriteLine("    " + s);
        int dupCount = seeds.Count - seeds.Distinct().Count();
        Console.WriteLine("  Duplicados exactos: {0}", dupCount);
    }
}
