// "Child" process: generates ONE address using EXACTLY the real function behind the
// Address > New address menu item in the main window (KeyCollectionView.cs):
//
//     KeyPair.Create(ExtraEntropy.GetEntropy())
//
// via reflection over the compiled BtcAddress.exe -- not a reimplementation. Runs as an
// independent Windows process each time (simulates "another machine" or "another session").
//
// Usage: KeyPairChild.exe [--pin1core] [path_to_BtcAddress.exe]

using System;
using System.Diagnostics;
using System.Reflection;

class KeyPairChild {
    static void Main(string[] args) {
        bool pinToOneCore = false;
        string exePath = @"..\bin\Release\BtcAddress.exe";
        foreach (var a in args) {
            if (a == "--pin1core") pinToOneCore = true;
            else exePath = a;
        }
        if (pinToOneCore) {
            try { Process.GetCurrentProcess().ProcessorAffinity = (IntPtr)1; } catch { }
        }

        var sw = Stopwatch.StartNew();
        var asm = Assembly.LoadFrom(exePath);
        var extraEntropyT = asm.GetType("Casascius.Bitcoin.ExtraEntropy");
        var keyPairT = asm.GetType("Casascius.Bitcoin.KeyPair");

        string entropy = (string)extraEntropyT.GetMethod("GetEntropy").Invoke(null, null);
        object kp = keyPairT.GetMethod("Create", new Type[] { typeof(string), typeof(bool), typeof(byte) })
            .Invoke(null, new object[] { entropy, false, (byte)0 });

        string wif = (string)keyPairT.GetProperty("PrivateKeyBase58").GetValue(kp);
        string address = (string)keyPairT.GetProperty("AddressBase58").GetValue(kp);

        sw.Stop();
        long ticksNow = DateTime.UtcNow.Ticks;

        Console.WriteLine(
            Process.GetCurrentProcess().Id + "," +
            ticksNow + "," +
            sw.Elapsed.TotalMilliseconds.ToString("F1") + "," +
            wif + "," +
            address);
    }
}
