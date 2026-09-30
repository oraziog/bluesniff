"""Prepara una copia isolata di bluesniff per lo screenshot del README.

Lo screenshot deve mostrare una dashboard *vera* (dispositivi reali, nomi,
RSSI) ma senza MAC che identifichino qualcuno. Il trucco è non usare la
dashboard in chiaro e non offuscare i dati a posteriori: qui si parte da una
directory separata, con un `presenze.csv` dove i MAC hanno gli ultimi tre
byte azzerati. I primi tre byte restano, e quindi il vendor continua a
combaciare (il valore OUI è pubblico e dice solo "Apple", non chi ha l'AirTag).
"""

import hashlib
import os
import re
import shutil
import sys

CARTELLA = "docs_img"
EXE = "target/release/bluesniff.exe"
SORGENTE = "target/release/presenze.csv"


def maschera(mac: str) -> str:
    """`4C:32:75:11:22:33` -> `4C:32:75:XX:XX:XX`.

    Non si usa una mappa casuale perché due MAC diversi non devono diventare
    lo stesso: altrimenti il dispositivo con piu' avvistamenti si mangerebbe
    quello accanto e lo screenshot mostrerebbe un dato falso.
    """
    parti = mac.strip().upper().split(":")
    if len(parti) != 6:
        return mac
    return ":".join(parti[:3] + ["XX", "XX", "XX"])


def main() -> int:
    os.makedirs(CARTELLA, exist_ok=True)
    shutil.copy2(EXE, os.path.join(CARTELLA, "bluesniff.exe"))
    if not os.path.exists(SORGENTE):
        print("manca presenze.csv: niente screenshot", file=sys.stderr)
        return 1
    testo = open(SORGENTE, encoding="utf-8", errors="replace").read()
    righe = testo.split("\n")
    out = [righe[0]] if righe else []
    mac_re = re.compile(r"\b([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")
    n = 0
    for r in righe[1:]:
        if not r.strip():
            continue
        nuovo, k = mac_re.subn(lambda m: maschera(m.group(0)), r)
        n += k
        out.append(nuovo)
    with open(os.path.join(CARTELLA, "presenze.csv"), "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")
    print(f"{len(out)-1} righe, {n} MAC mascherati")
    return 0


if __name__ == "__main__":
    sys.exit(main())