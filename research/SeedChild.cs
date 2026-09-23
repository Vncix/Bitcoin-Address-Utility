// Proceso "hijo": simula UNA generacion de "New Address" tal como la hace
// KeyPair.Create() en CASA (Model/KeyPair.cs) -- new SecureRandom() + lectura
// de bytes -- pero corriendo como proceso independiente, fijado a UN SOLO
// nucleo logico y con prioridad reducida, para emular una VM con recursos
// escasos (1 vCPU) bajo la cual multiples generaciones ocurren cerca en el tiempo.
//
// Cada corrida es un proceso .NET fresco: replica fielmente el escenario real
// de "boots/clones/varias generaciones sucesivas en un host debil", no solo
// hilos dentro del mismo proceso (que comparten el generador estatico ya
// mezclado -- ver hallazgo previo de sha1Generator compartido).

using System;
using System.Diagnostics;
using Org.BouncyCastle.Security;

class SeedChild {
    static void Main(string[] args) {
        try { Process.GetCurrentProcess().ProcessorAffinity = (IntPtr)1; } catch { }
        try { Process.GetCurrentProcess().PriorityClass = ProcessPriorityClass.BelowNormal; } catch { }

        long startTicks = DateTime.UtcNow.Ticks;
        var sw = Stopwatch.StartNew();

        SecureRandom sr = new SecureRandom();
        byte[] key = new byte[32]; // mismo tamano que un private key de KeyPair
        sr.NextBytes(key);

        sw.Stop();

        Console.WriteLine(
            Process.GetCurrentProcess().Id + "," +
            startTicks + "," +
            sw.Elapsed.TotalMilliseconds.ToString("F1") + "," +
            BitConverter.ToString(key).Replace("-", ""));
    }
}
