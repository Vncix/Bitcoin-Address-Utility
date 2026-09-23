// PoC unico (todo-en-uno) del hallazgo de siembra debil en
// Org.BouncyCastle.Security.SecureRandom (el mismo tipo/DLL real que usa
// KeyPair.Create() en CASA). Equivalente en C# de seed_collision_test.py,
// mismo diseño de dos partes, mismos datos dinamicos -- NADA hardcodeado:
//
//   PARTE 1 (evidencia organica): lee seed_samples_evidence.csv (550
//   corridas reales de `new SecureRandom()` SIN argumentos -- el mismo
//   codigo que usa KeyPair.Create() -- cada una en un proceso independiente
//   fijado a 1 nucleo logico) y busca pares de procesos que organicamente
//   leyeron el mismo DateTime.Ticks.
//
//   PARTE 2 (experimento controlado, etiquetado como tal): toma UNO DE
//   ESOS TICKS REALES de la Parte 1 (no un numero inventado), CAPTURA UN
//   JITTER REAL AHORA MISMO con la misma clase publica que usa get_Master()
//   internamente (ThreadedSeedGenerator.GenerateSeed(32, true)), y corre
//   tres procesos de Windows independientes con ese mismo ticks+jitter
//   para probar que la clave resultante es identica siempre. Un cuarto
//   proceso, con otro Ticks real distinto, sirve de control.
//
// Uso:
//   SeedCollisionDemo.exe                     -> corre Parte 1 + Parte 2 completas
//   SeedCollisionDemo.exe --worker <t> <j>     -> uso interno (1 sola clave)

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Prng;

class SeedCollisionDemo {

    static string HereDir { get { return AppDomain.CurrentDomain.BaseDirectory; } }
    static string EvidenceCsv { get { return Path.Combine(HereDir, "seed_samples_evidence.csv"); } }

    class Row {
        public string Pid, Ticks, Hex32;
    }

    static void Main(string[] args) {
        if (args.Length == 3 && args[0] == "--worker") {
            Worker(args[1], args[2]);
            return;
        }

        var ticksOrganicos = Parte1EvidenciaOrganica();
        Parte2ExperimentoControlado(ticksOrganicos);
    }

    // -----------------------------------------------------------------
    // PARTE 1: evidencia organica (datos reales ya capturados)
    // -----------------------------------------------------------------

    static List<string> Parte1EvidenciaOrganica() {
        Console.WriteLine("=== PARTE 1: colisiones organicas de Ticks en corridas reales (sin seed manual) ===\n");

        if (!File.Exists(EvidenceCsv)) {
            Console.WriteLine("(no se encontro " + EvidenceCsv + " -- saltando parte 1)");
            return new List<string>();
        }

        var lines = File.ReadAllLines(EvidenceCsv);
        var rows = new List<Row>();
        for (int i = 1; i < lines.Length; i++) { // saltar header
            var parts = lines[i].Split(',');
            if (parts.Length < 4) continue;
            rows.Add(new Row { Pid = parts[0], Ticks = parts[1], Hex32 = parts[3] });
        }

        Console.WriteLine("Muestras totales analizadas: " + rows.Count + "  (cada una = 1 proceso .NET independiente,");
        Console.WriteLine("ejecutando el mismo new SecureRandom() sin argumentos que usa KeyPair.Create())\n");

        var byTicks = rows.GroupBy(r => r.Ticks).Where(g => g.Count() > 1).OrderBy(g => g.Key).ToList();
        int totalInvolved = byTicks.Sum(g => g.Count());

        Console.WriteLine("Pares/grupos de procesos independientes con el MISMO DateTime.Ticks: " + byTicks.Count);
        if (rows.Count > 0) {
            Console.WriteLine(string.Format("Muestras involucradas en alguna colision de Ticks: {0} de {1} ({2:F1}%)\n",
                totalInvolved, rows.Count, 100.0 * totalInvolved / rows.Count));
        }

        int fullKeyCollisions = 0;
        foreach (var g in byTicks) {
            var keys = g.Select(r => r.Hex32).Distinct().ToList();
            if (keys.Count == 1) {
                fullKeyCollisions++;
                Console.WriteLine("  *** COLISION TOTAL (Ticks Y clave identicos) en ticks=" + g.Key + " ***");
                foreach (var r in g) Console.WriteLine("      pid=" + r.Pid + "  hex32=" + r.Hex32);
            } else {
                Console.WriteLine("  ticks=" + g.Key + "  coincide entre pids [" + string.Join(",", g.Select(r => r.Pid)) + "]  -> claves distintas (jitter las diferencio)");
            }
        }

        Console.WriteLine();
        if (fullKeyCollisions == 0 && byTicks.Count > 0) {
            Console.WriteLine("Conclusion parte 1: el primer ingrediente de la semilla (Ticks) SI colisiona de forma");
            Console.WriteLine("organica y medible entre procesos independientes bajo carga real (sin ningun dato");
            Console.WriteLine("inventado). El jitter de ThreadedSeedGenerator alcanzo a diferenciar la clave final en");
            Console.WriteLine("todos los casos de esta muestra -- no se observo colision completa de los 32 bytes.");
            Console.WriteLine("Ver PARTE 2 para la prueba de que, si TAMBIEN el jitter coincidiera, la clave coincide tambien.");
        } else if (fullKeyCollisions > 0) {
            Console.WriteLine("Conclusion parte 1: se observaron " + fullKeyCollisions + " colision(es) TOTAL(es) de clave privada");
            Console.WriteLine("entre procesos independientes, sin ningun dato inventado.");
        }
        Console.WriteLine();

        return byTicks.Select(g => g.Key).ToList();
    }

    // -----------------------------------------------------------------
    // PARTE 2: experimento controlado -- ticks de la Parte 1, jitter
    // capturado en vivo, nada escrito a mano.
    // -----------------------------------------------------------------

    static string CaptureRealTicks() {
        return DateTime.UtcNow.Ticks.ToString();
    }

    static string CaptureRealJitterHex() {
        // Misma llamada publica que get_Master() hace internamente.
        var gen = new ThreadedSeedGenerator();
        byte[] jitter = gen.GenerateSeed(32, true);
        return BitConverter.ToString(jitter).Replace("-", "");
    }

    static void Worker(string ticksStr, string jitterHex) {
        long ticks = long.Parse(ticksStr);
        byte[] jitter = HexToBytes(jitterHex);

        // SecureRandom(byte[0]), NO SecureRandom() sin argumentos: el
        // constructor sin argumentos dispara GetSeed(8)/Master con entropia
        // real no controlada ANTES de nuestros SetSeed manuales, lo que
        // arruinaria el aislamiento del experimento (ver reporte, seccion 4.1.1).
        SecureRandom sr = new SecureRandom(new byte[0]);
        sr.SetSeed(ticks);
        sr.SetSeed(jitter);

        byte[] key = new byte[32];
        sr.NextBytes(key);
        Console.WriteLine(BitConverter.ToString(key).Replace("-", ""));
    }

    static string RunWorkerInNewProcess(string ticks, string jitterHex) {
        var psi = new ProcessStartInfo {
            FileName = Process.GetCurrentProcess().MainModule.FileName,
            Arguments = "--worker " + ticks + " " + jitterHex,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            CreateNoWindow = true
        };
        using (var p = Process.Start(psi)) {
            string line = p.StandardOutput.ReadLine();
            p.WaitForExit(15000);
            return line;
        }
    }

    static void Parte2ExperimentoControlado(List<string> ticksOrganicos) {
        Console.WriteLine("=== PARTE 2: experimento controlado (aisla la propiedad de determinismo) ===");
        Console.WriteLine("Etiquetado explicitamente como CONTROLADO: no afirma que esta combinacion exacta haya");
        Console.WriteLine("ocurrido espontaneamente. Ticks: tomado dinamicamente de una colision real de la Parte 1");
        Console.WriteLine("(o capturado en vivo si no hay evidencia CSV). Jitter: CAPTURADO EN VIVO ahora mismo con");
        Console.WriteLine("la clase real ThreadedSeedGenerator de la app -- nada escrito a mano.\n");

        string ticksReal, ticksControl;
        if (ticksOrganicos.Count >= 2) {
            ticksReal = ticksOrganicos[0];
            ticksControl = ticksOrganicos[1];
            Console.WriteLine("Ticks (de una colision organica real, Parte 1): " + ticksReal);
        } else if (ticksOrganicos.Count == 1) {
            ticksReal = ticksOrganicos[0];
            ticksControl = CaptureRealTicks();
            Console.WriteLine("Ticks (de la unica colision organica, Parte 1): " + ticksReal);
        } else {
            ticksReal = CaptureRealTicks();
            ticksControl = CaptureRealTicks();
            Console.WriteLine("(no hubo colisiones organicas en Parte 1 -- se capturan Ticks reales ahora): " + ticksReal);
        }

        string jitterReal = CaptureRealJitterHex();
        Console.WriteLine("Jitter (capturado en vivo, ThreadedSeedGenerator real): " + jitterReal + "\n");

        string key1 = RunWorkerInNewProcess(ticksReal, jitterReal);
        string key2 = RunWorkerInNewProcess(ticksReal, jitterReal);
        string key3 = RunWorkerInNewProcess(ticksReal, jitterReal);
        Console.WriteLine("Corrida 1: " + key1);
        Console.WriteLine("Corrida 2: " + key2);
        Console.WriteLine("Corrida 3: " + key3);
        bool same = key1 == key2 && key2 == key3;
        Console.WriteLine("-> Mismo Ticks + mismo jitter -> misma clave en 3 procesos independientes: " + same + "\n");

        string keyCtrl = RunWorkerInNewProcess(ticksControl, jitterReal);
        Console.WriteLine("Ticks control (otro valor real, distinto): " + ticksControl);
        Console.WriteLine("Clave resultante: " + keyCtrl);
        Console.WriteLine("-> Es distinta a las anteriores: " + (keyCtrl != key1) + "\n");

        if (same && keyCtrl != key1) {
            Console.WriteLine("Conclusion parte 2: confirmado -- el algoritmo no tiene ningun mecanismo independiente");
            Console.WriteLine("(CSPRNG del SO u otro) que rompa una coincidencia de semilla. Si el Ticks Y el jitter");
            Console.WriteLine("coinciden entre dos procesos, la clave privada resultante es identica, siempre.");
        } else {
            Console.WriteLine("Conclusion parte 2: no se pudo reproducir el comportamiento esperado en este entorno.");
        }
    }

    static byte[] HexToBytes(string hex) {
        byte[] b = new byte[hex.Length / 2];
        for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return b;
    }
}
