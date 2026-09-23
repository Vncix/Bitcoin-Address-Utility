"""
Prueba rapida (Python) del hallazgo de siembra debil en Org.BouncyCastle.Security.SecureRandom
(el mismo tipo/DLL real que usa KeyPair.Create() en CASA).

Este script tiene DOS partes, a proposito separadas para no mezclar evidencia
organica con un experimento controlado. NINGUN valor (ticks, jitter) esta
hardcodeado -- todo se lee de datos reales o se captura en vivo en cada corrida:

  PARTE 1 (la evidencia fuerte): analiza datos REALES, ya capturados, de N
  corridas de la app SIN NINGUN seed manual -- exactamente `new SecureRandom()`,
  cada una en un proceso de Windows independiente, fijado a 1 nucleo logico
  (simulando una VM de 1 vCPU bajo carga). Busca casos donde el PRIMER
  ingrediente de la semilla (DateTime.Now.Ticks) coincidio de forma organica
  entre procesos -- nadie lo forzo, surgio solo por la resolucion real del
  reloj de Windows (~6ms, ver reporte principal). Devuelve esos pares para
  que la Parte 2 los reuse.

  PARTE 2 (experimento controlado, etiquetado como tal): aisla la propiedad
  "si el material de siembra coincide, la clave coincide" llamando a la
  MISMA API publica que usa get_Master() internamente (SetSeed(long) +
  SetSeed(byte[])). El valor de Ticks se toma DINAMICAMENTE del primer par
  organico que haya encontrado la Parte 1 (si no hay evidencia CSV, se
  captura un Ticks real ahora mismo via .NET). El jitter se CAPTURA EN VIVO
  en cada corrida del script llamando a la misma clase real que usa la app
  (Org.BouncyCastle.Crypto.Prng.ThreadedSeedGenerator.GenerateSeed(32, true)),
  no un valor de relleno escrito a mano. Esto NO afirma que la colision total
  ya haya ocurrido espontaneamente en la naturaleza -- eso se documenta
  honestamente como pendiente (Parte 1 no encontro colision completa).

Requiere: pip install pythonnet
Uso:
    python seed_collision_test.py
"""

import csv
import os
import sys
import subprocess
from collections import defaultdict

import clr  # pip install pythonnet

HERE = os.path.dirname(os.path.abspath(__file__))
DLL_PATH = os.path.join(HERE, "..", "BouncyCastle.Crypto.dll")
EVIDENCE_CSV = os.path.join(HERE, "seed_samples_evidence.csv")


# ---------------------------------------------------------------------------
# PARTE 1: analisis de evidencia organica (datos reales ya capturados)
# ---------------------------------------------------------------------------

def parte1_evidencia_organica():
    print("=== PARTE 1: colisiones organicas de Ticks en corridas reales (sin seed manual) ===\n")

    if not os.path.exists(EVIDENCE_CSV):
        print(f"(no se encontro {EVIDENCE_CSV} -- saltando parte 1)")
        return []

    rows = []
    with open(EVIDENCE_CSV, newline="") as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append(r)

    print(f"Muestras totales analizadas: {len(rows)}  (cada una = 1 proceso .NET independiente,")
    print("ejecutando el mismo new SecureRandom() sin argumentos que usa KeyPair.Create())\n")

    by_ticks = defaultdict(list)
    for r in rows:
        by_ticks[r["ticks"]].append(r)

    collided_pairs = {t: rs for t, rs in by_ticks.items() if len(rs) > 1}
    total_involved = sum(len(rs) for rs in collided_pairs.values())

    print(f"Pares/grupos de procesos independientes con el MISMO DateTime.Ticks: {len(collided_pairs)}")
    if rows:
        print(f"Muestras involucradas en alguna colision de Ticks: {total_involved} de {len(rows)} "
              f"({100.0*total_involved/len(rows):.1f}%)\n")

    full_key_collisions = 0
    for ticks, rs in collided_pairs.items():
        keys = {r["hex32"] for r in rs}
        if len(keys) == 1:
            full_key_collisions += 1
            print(f"  *** COLISION TOTAL (Ticks Y clave identicos) en ticks={ticks} ***")
            for r in rs:
                print(f"      pid={r['pid']}  hex32={r['hex32']}")
        else:
            pids = ",".join(r["pid"] for r in rs)
            print(f"  ticks={ticks}  coincide entre pids [{pids}]  -> claves distintas (jitter las diferencio)")

    print()
    if full_key_collisions == 0 and collided_pairs:
        print("Conclusion parte 1: el primer ingrediente de la semilla (Ticks) SI colisiona de forma")
        print("organica y medible entre procesos independientes bajo carga real (sin ningun dato")
        print("inventado). El jitter de ThreadedSeedGenerator alcanzo a diferenciar la clave final en")
        print("todos los casos de esta muestra -- no se observo colision completa de los 32 bytes.")
        print("Es una limitacion honesta de la evidencia disponible, no una negacion del hallazgo:")
        print("ver PARTE 2 para la prueba de que, si TAMBIEN el jitter coincidiera (plausible bajo mas")
        print("contencion, ver seccion 4.3 del reporte), la clave resultante coincidiria tambien.")
    elif full_key_collisions > 0:
        print(f"Conclusion parte 1: se observaron {full_key_collisions} colision(es) TOTAL(es) de clave")
        print("privada entre procesos independientes, sin ningun dato inventado.")
    print()

    # Devuelve los pares de ticks colisionados, ordenados, para que la Parte 2
    # pueda tomar un valor real (no inventado) sin tocar nada a mano.
    return sorted(collided_pairs.keys())


# ---------------------------------------------------------------------------
# PARTE 2: experimento controlado (propiedad de determinismo, sin backstop)
# Ticks: tomado dinamicamente de la Parte 1 (o capturado en vivo si no hay CSV).
# Jitter: capturado en vivo en cada corrida, con la clase real de la app.
# ---------------------------------------------------------------------------

def capture_real_ticks() -> str:
    """Ticks real, leido ahora mismo via .NET (mismo tipo que usa la app)."""
    clr.AddReference(DLL_PATH) if os.path.exists(DLL_PATH) else None
    from System import DateTime  # noqa: E402
    return str(DateTime.UtcNow.Ticks)


def capture_real_jitter_hex() -> str:
    """Jitter real, capturado AHORA con la misma clase publica que usa
    get_Master() internamente: ThreadedSeedGenerator.GenerateSeed(32, true).
    No es un valor escrito a mano -- cambia en cada llamada."""
    if not os.path.exists(DLL_PATH):
        raise FileNotFoundError(DLL_PATH)
    clr.AddReference(DLL_PATH)
    from Org.BouncyCastle.Crypto.Prng import ThreadedSeedGenerator  # noqa: E402
    gen = ThreadedSeedGenerator()
    jitter = gen.GenerateSeed(32, True)
    return "".join("%02X" % (b & 0xFF) for b in jitter)


def worker(ticks_str: str, jitter_hex: str) -> None:
    if not os.path.exists(DLL_PATH):
        print("ERROR: no se encontro BouncyCastle.Crypto.dll en: " + DLL_PATH, file=sys.stderr)
        sys.exit(1)

    clr.AddReference(DLL_PATH)
    from Org.BouncyCastle.Security import SecureRandom  # noqa: E402
    from System import Array, Byte, Int64  # noqa: E402

    # IMPORTANTE: se usa SecureRandom(byte[0]) y NO SecureRandom() sin
    # argumentos. El constructor sin argumentos llama internamente a
    # GetSeed(8) -> Master -> Ticks/ThreadedSeedGenerator REALES y NO
    # controlados (ver IL en el reporte, seccion 3.1) ANTES de que nuestros
    # SetSeed() manuales se apliquen, lo que arruinaria el aislamiento del
    # experimento. SecureRandom(byte[0]) NO dispara esa llamada -- solo usa
    # el generador estatico compartido (fresco en cada proceso nuevo) + el
    # seed que le demos, que es exactamente lo que necesitamos para aislar
    # la propiedad.
    sr = SecureRandom(Array[Byte]([]))
    sr.SetSeed(Int64(int(ticks_str)))
    jitter_raw = bytes.fromhex(jitter_hex)
    jitter_net = Array[Byte]([Byte(b) for b in jitter_raw])
    sr.SetSeed(jitter_net)

    key = Array.CreateInstance(Byte, 32)
    sr.NextBytes(key)
    print("".join("%02X" % (b & 0xFF) for b in key))


def run_worker_in_new_process(ticks_str: str, jitter_hex: str) -> str:
    result = subprocess.run(
        [sys.executable, os.path.abspath(__file__), "--worker", ticks_str, jitter_hex],
        capture_output=True, text=True, check=True,
    )
    return result.stdout.strip()


def parte2_experimento_controlado(ticks_organicos):
    print("=== PARTE 2: experimento controlado (aisla la propiedad de determinismo) ===")
    print("Etiquetado explicitamente como CONTROLADO: no afirma que esta combinacion exacta haya\n"
          "ocurrido espontaneamente. Ticks: tomado dinamicamente de una colision real de la Parte 1\n"
          "(o capturado en vivo si no hay evidencia CSV). Jitter: CAPTURADO EN VIVO ahora mismo con\n"
          "la clase real ThreadedSeedGenerator de la app -- nada escrito a mano.\n")

    if len(ticks_organicos) >= 2:
        ticks_real = ticks_organicos[0]
        ticks_control = ticks_organicos[1]
        print(f"Ticks (de una colision organica real, Parte 1): {ticks_real}")
    elif len(ticks_organicos) == 1:
        ticks_real = ticks_organicos[0]
        ticks_control = capture_real_ticks()
        print(f"Ticks (de la unica colision organica, Parte 1): {ticks_real}")
    else:
        ticks_real = capture_real_ticks()
        ticks_control = capture_real_ticks()
        print(f"(no hubo colisiones organicas en Parte 1 -- se capturan Ticks reales ahora): {ticks_real}")

    jitter_real = capture_real_jitter_hex()
    print(f"Jitter (capturado en vivo, ThreadedSeedGenerator real): {jitter_real}\n")

    key1 = run_worker_in_new_process(ticks_real, jitter_real)
    key2 = run_worker_in_new_process(ticks_real, jitter_real)
    key3 = run_worker_in_new_process(ticks_real, jitter_real)
    print(f"Corrida 1: {key1}")
    print(f"Corrida 2: {key2}")
    print(f"Corrida 3: {key3}")
    same = key1 == key2 == key3
    print(f"-> Mismo Ticks + mismo jitter -> misma clave en 3 procesos independientes: {same}\n")

    key_ctrl = run_worker_in_new_process(ticks_control, jitter_real)
    print(f"Ticks control (otro valor real, distinto): {ticks_control}")
    print(f"Clave resultante: {key_ctrl}")
    print(f"-> Es distinta a las anteriores: {key_ctrl != key1}\n")

    if same and key_ctrl != key1:
        print("Conclusion parte 2: confirmado -- el algoritmo no tiene ningun mecanismo independiente")
        print("(CSPRNG del SO u otro) que rompa una coincidencia de semilla. Si el Ticks Y el jitter")
        print("coinciden entre dos procesos, la clave privada resultante es identica, siempre.")
    else:
        print("Conclusion parte 2: no se pudo reproducir el comportamiento esperado en este entorno.")


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--worker":
        worker(sys.argv[2], sys.argv[3])
    else:
        pares = parte1_evidencia_organica()
        parte2_experimento_controlado(pares)
