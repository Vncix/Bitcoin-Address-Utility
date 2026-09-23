// Generates N addresses using the REAL BtcAddress.exe code (via reflection, not a
// reimplementation) -- exactly the same call the "Address > New address" menu item makes
// (KeyCollectionView.cs):
//
//     KeyPair.Create(ExtraEntropy.GetEntropy())
//
// Writes each result to a file, one address per line: "wif,address".
//
// Usage:
//   GenerateAddresses.exe <count> <output.csv> [path_to_BtcAddress.exe]
//
// Note: this runs as a SINGLE process (a sequential loop within one process), the same as
// clicking "New address" many times in a row within the same app session -- it does not
// simulate a fresh process per generation (see KeyPairOrchestrator.cs / KeyPairChild.cs for
// that, used for the organic cross-process Ticks-collision search in SECURITY.md).

using System;
using System.IO;
using System.Reflection;

class GenerateAddresses {
    static void Main(string[] args) {
        if (args.Length < 2) {
            Console.WriteLine("Usage: GenerateAddresses.exe <count> <output.csv> [path_to_BtcAddress.exe]");
            return;
        }

        int count = int.Parse(args[0]);
        string outFile = args[1];
        string exePath = args.Length > 2 ? args[2] : @"..\bin\Release\BtcAddress.exe";

        if (!File.Exists(exePath)) {
            Console.WriteLine("BtcAddress.exe not found at: " + exePath);
            return;
        }

        var asm = Assembly.LoadFrom(exePath);
        var extraEntropyT = asm.GetType("Casascius.Bitcoin.ExtraEntropy");
        var keyPairT = asm.GetType("Casascius.Bitcoin.KeyPair");

        var getEntropy = extraEntropyT.GetMethod("GetEntropy");
        var create = keyPairT.GetMethod("Create", new Type[] { typeof(string), typeof(bool), typeof(byte) });
        var wifProp = keyPairT.GetProperty("PrivateKeyBase58");
        var addressProp = keyPairT.GetProperty("AddressBase58");

        Console.WriteLine("Generando " + count + " direcciones (mismo procedimiento real que 'Address > New address')...");

        using (var w = new StreamWriter(outFile, false)) {
            w.WriteLine("wif,address");
            for (int i = 0; i < count; i++) {
                string entropy = (string)getEntropy.Invoke(null, null);
                object kp = create.Invoke(null, new object[] { entropy, false, (byte)0 });
                string wif = (string)wifProp.GetValue(kp);
                string address = (string)addressProp.GetValue(kp);
                w.WriteLine(wif + "," + address);

                if ((i + 1) % 100 == 0 || i == count - 1) {
                    Console.WriteLine("  " + (i + 1) + "/" + count);
                }
            }
        }

        Console.WriteLine("Listo. Guardado en: " + outFile);
        Console.WriteLine("ADVERTENCIA: cada linea de ese archivo es una clave privada real y utilizable.");
        Console.WriteLine("Tratalo con el mismo cuidado que cualquier clave privada -- no lo compartas ni lo dejes en texto plano sin necesidad.");
    }
}
