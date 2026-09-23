// Orquestador: lanza K instancias INDEPENDIENTES de SeedChild.exe casi
// simultaneamente, todas fijadas a 1 solo nucleo logico (emulando N
// generaciones de "New Address" ocurriendo cerca en el tiempo sobre una
// VM de 1 vCPU con recursos escasos). Junta los 32 bytes que cada proceso
// obtuvo de new SecureRandom() (el mismo mecanismo que usa KeyPair.Create)
// y busca colisiones/duplicidad en prefijos, mas correlacion con el
// timestamp de arranque de cada proceso.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

class Sample {
    public int Pid;
    public long Ticks;
    public double ElapsedMs;
    public string Hex;
}

class SeedOrchestrator {
    static void Main(string[] args) {
        int K = args.Length > 0 ? int.Parse(args[0]) : 150;
        string exeDir = AppDomain.CurrentDomain.BaseDirectory;
        string childExe = Path.Combine(exeDir, "SeedChild.exe");

        Console.WriteLine("Lanzando " + K + " procesos independientes de SeedChild.exe (cada uno = 1 'New Address'), todos fijados a 1 nucleo logico...");
        var sw = Stopwatch.StartNew();

        var tasks = new Task<Sample>[K];
        for (int i = 0; i < K; i++) {
            tasks[i] = Task.Run(() => RunChild(childExe));
            // pequeno escalonado para que el lanzamiento en si no sea el cuello de botella,
            // pero lo suficientemente rapido para que se solapen en el tiempo (igual que
            // varias generaciones "casi simultaneas" en un host debil)
            Thread.Sleep(5);
        }
        Task.WaitAll(tasks);
        sw.Stop();

        var samples = tasks.Select(t => t.Result).Where(s => s != null).ToList();
        Console.WriteLine("Completado: " + samples.Count + "/" + K + " muestras en " + sw.Elapsed.TotalSeconds.ToString("F1") + " s");
        Console.WriteLine();

        // Guardar CSV crudo
        string csvPath = Path.Combine(exeDir, "seed_samples.csv");
        using (var w = new StreamWriter(csvPath, false)) {
            w.WriteLine("pid,ticks,elapsed_ms,hex32");
            foreach (var s in samples) w.WriteLine(s.Pid + "," + s.Ticks + "," + s.ElapsedMs.ToString("F1") + "," + s.Hex);
        }
        Console.WriteLine("CSV crudo: " + csvPath);
        Console.WriteLine();

        // Colision exacta de 32 bytes completos (control de cordura)
        var fullDup = samples.GroupBy(s => s.Hex).Where(g => g.Count() > 1).ToList();
        Console.WriteLine("=== Colisiones EXACTAS de 32 bytes completos ===");
        Console.WriteLine("  " + fullDup.Count + " grupo(s) duplicado(s) (esperado con buena entropia: ~0)");
        foreach (var g in fullDup) {
            Console.WriteLine("  DUPLICADO: " + g.Key + "  (pids: " + string.Join(",", g.Select(x => x.Pid)) + ")");
        }
        Console.WriteLine();

        // Colisiones por prefijo (1..8 bytes) -- esto es lo que demuestra
        // perdida de entropia efectiva de forma concisa y accionable
        Console.WriteLine("=== Cardinalidad y colisiones por longitud de prefijo ===");
        foreach (int nBytes in new[] { 1, 2, 3, 4, 5, 6, 8 }) {
            int nHexChars = nBytes * 2;
            var groups = samples.GroupBy(s => s.Hex.Substring(0, nHexChars)).ToList();
            int distinct = groups.Count;
            var dups = groups.Where(g => g.Count() > 1).OrderByDescending(g => g.Count()).ToList();
            double expectedBitsIfIdeal = nBytes * 8;
            double observedBits = Math.Log(distinct, 2);
            Console.WriteLine(string.Format(
                "  prefijo {0} bytes: {1} valores distintos de {2} muestras (nominal 2^{3}={4:N0}) -> ~{5:F1} bits efectivos observados vs {6} nominales",
                nBytes, distinct, samples.Count, expectedBitsIfIdeal, Math.Pow(2, expectedBitsIfIdeal), observedBits, expectedBitsIfIdeal));
            if (dups.Count > 0) {
                Console.WriteLine("    --> EJEMPLO DE DUPLICIDAD (prefijo de " + nBytes + " bytes compartido por " + dups[0].Count() + " muestras distintas):");
                Console.WriteLine("        prefijo = " + dups[0].Key);
                foreach (var s in dups[0]) {
                    Console.WriteLine("        pid=" + s.Pid + "  ticks=" + s.Ticks + "  hex_completo=" + s.Hex);
                }
            }
        }
        Console.WriteLine();

        // Correlacion simple con ticks: ¿el valor de los primeros 4 bytes se explica
        // en gran parte por el timestamp de arranque del proceso?
        Console.WriteLine("=== Correlacion entre timestamp de arranque (ticks) y los primeros 4 bytes ===");
        var xs = samples.Select(s => (double)s.Ticks).ToArray();
        var ys = samples.Select(s => (double)Convert.ToUInt32(s.Hex.Substring(0, 8), 16)).ToArray();
        double corr = PearsonCorrelation(xs, ys);
        Console.WriteLine("  Pearson r = " + corr.ToString("F4") + " (cerca de 0 = sin correlacion lineal obvia; no descarta correlacion no lineal)");
        Console.WriteLine();

        Console.WriteLine("=== Tiempos de sembrado (ms) bajo 1 vCPU + contencion entre " + K + " procesos simultaneos ===");
        var elapsed = samples.Select(s => s.ElapsedMs).OrderBy(x => x).ToList();
        Console.WriteLine("  min/mediana/prom/max: " + elapsed.First().ToString("F0") + " / " + elapsed[elapsed.Count/2].ToString("F0") + " / " + elapsed.Average().ToString("F0") + " / " + elapsed.Last().ToString("F0") + " ms");
    }

    static Sample RunChild(string exePath) {
        try {
            var psi = new ProcessStartInfo {
                FileName = exePath,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            };
            using (var p = Process.Start(psi)) {
                string line = p.StandardOutput.ReadLine();
                p.WaitForExit(15000);
                if (line == null) return null;
                var parts = line.Split(',');
                return new Sample {
                    Pid = int.Parse(parts[0]),
                    Ticks = long.Parse(parts[1]),
                    ElapsedMs = double.Parse(parts[2]),
                    Hex = parts[3]
                };
            }
        } catch {
            return null;
        }
    }

    static double PearsonCorrelation(double[] xs, double[] ys) {
        double mx = xs.Average(), my = ys.Average();
        double sumXY = 0, sumX2 = 0, sumY2 = 0;
        for (int i = 0; i < xs.Length; i++) {
            double dx = xs[i] - mx, dy = ys[i] - my;
            sumXY += dx * dy;
            sumX2 += dx * dx;
            sumY2 += dy * dy;
        }
        if (sumX2 == 0 || sumY2 == 0) return 0;
        return sumXY / Math.Sqrt(sumX2 * sumY2);
    }
}
