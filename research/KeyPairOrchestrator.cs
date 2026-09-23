// Lanza K instancias independientes de KeyPairChild.exe (cada una = 1 direccion
// generada con el codigo REAL de "Address > New address", KeyPair.Create(ExtraEntropy.GetEntropy())),
// cada una en su propio proceso de Windows. Busca colisiones COMPLETAS de WIF/direccion.

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
    public string Wif;
    public string Address;
}

class KeyPairOrchestrator {
    static void Main(string[] args) {
        int K = args.Length > 0 ? int.Parse(args[0]) : 300;
        string exeDir = AppDomain.CurrentDomain.BaseDirectory;
        string childExe = Path.Combine(exeDir, "KeyPairChild.exe");

        Console.WriteLine("Lanzando " + K + " direcciones independientes (KeyPair.Create real = 'New address', procesos separados)...");
        var sw = Stopwatch.StartNew();

        var tasks = new Task<Sample>[K];
        for (int i = 0; i < K; i++) {
            tasks[i] = Task.Run(() => RunChild(childExe));
            Thread.Sleep(3);
        }
        Task.WaitAll(tasks);
        sw.Stop();

        var samples = tasks.Select(t => t.Result).Where(s => s != null).ToList();
        Console.WriteLine("Completado: " + samples.Count + "/" + K + " muestras en " + sw.Elapsed.TotalSeconds.ToString("F1") + " s\n");

        string csvPath = Path.Combine(exeDir, "keypair_samples.csv");
        using (var w = new StreamWriter(csvPath, false)) {
            w.WriteLine("pid,ticks,elapsed_ms,wif,address");
            foreach (var s in samples) w.WriteLine(s.Pid + "," + s.Ticks + "," + s.ElapsedMs.ToString("F1") + "," + s.Wif + "," + s.Address);
        }
        Console.WriteLine("CSV: " + csvPath + "\n");

        var dupWif = samples.GroupBy(s => s.Wif).Where(g => g.Count() > 1).ToList();
        var dupAddr = samples.GroupBy(s => s.Address).Where(g => g.Count() > 1).ToList();

        Console.WriteLine("=== Colisiones COMPLETAS de clave privada (WIF) ===");
        Console.WriteLine("  " + dupWif.Count + " grupo(s) duplicado(s) de " + samples.Count + " muestras");
        foreach (var g in dupWif) {
            Console.WriteLine("  *** WIF REPETIDO: " + g.Key + " ***");
            foreach (var s in g) Console.WriteLine("      pid=" + s.Pid + "  ticks=" + s.Ticks + "  address=" + s.Address);
        }

        Console.WriteLine("\n=== Colisiones de direccion (deberian coincidir con las de WIF) ===");
        Console.WriteLine("  " + dupAddr.Count + " grupo(s) duplicado(s)");

        var elapsed = samples.Select(s => s.ElapsedMs).OrderBy(x => x).ToList();
        Console.WriteLine("\nTiempos (ms) min/mediana/prom/max: " + elapsed.First().ToString("F0") + " / " + elapsed[elapsed.Count / 2].ToString("F0") + " / " + elapsed.Average().ToString("F0") + " / " + elapsed.Last().ToString("F0"));
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
                p.WaitForExit(20000);
                if (line == null) return null;
                var parts = line.Split(',');
                return new Sample {
                    Pid = int.Parse(parts[0]),
                    Ticks = long.Parse(parts[1]),
                    ElapsedMs = double.Parse(parts[2]),
                    Wif = parts[3],
                    Address = parts[4]
                };
            }
        } catch {
            return null;
        }
    }
}
