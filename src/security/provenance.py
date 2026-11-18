"""Traçabilité et intégrité des données d'entraînement.

  python src/security/provenance.py generer    enregistre le manifeste
  python src/security/provenance.py verifier   recalcule et compare (code retour 1 si écart)

Le manifeste contient :
  - le commit exact de chaque source publique clonée ;
  - l'empreinte SHA-256 de chaque fichier de data/processed/.
"""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[2]
MANIFESTE = BASE / "src/security/manifest.json"
SOURCES = ["HttpParamsDataset", "PayloadsAllTheThings", "SecLists"]


def sha256(chemin):
    h = hashlib.sha256()
    with open(chemin, "rb") as f:
        for bloc in iter(lambda: f.read(1 << 20), b""):
            h.update(bloc)
    return h.hexdigest()


def commit(source):
    r = subprocess.run(["git", "-C", str(BASE / "data/raw" / source), "rev-parse", "HEAD"],
                       capture_output=True, text=True, check=True)
    return r.stdout.strip()


def etat_actuel():
    fichiers = sorted((BASE / "data/processed").glob("*.csv"))
    return {
        "sources": {s: commit(s) for s in SOURCES},
        "fichiers": {f"data/processed/{f.name}": sha256(f) for f in fichiers},
    }


def comparer(attendu, actuel):
    ecarts = []
    for section in ("sources", "fichiers"):
        for nom in sorted(set(attendu[section]) | set(actuel[section])):
            a, b = attendu[section].get(nom), actuel[section].get(nom)
            if a != b:
                ecarts.append(f"[{section}] {nom} : attendu {a}, obtenu {b}")
    return ecarts


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("generer", "verifier"):
        sys.exit(__doc__)
    actuel = etat_actuel()
    if sys.argv[1] == "generer":
        MANIFESTE.write_text(json.dumps(actuel, indent=2, sort_keys=True) + "\n")
        print(f"Manifeste écrit : {MANIFESTE.relative_to(BASE)}")
        print(f"  {len(actuel['sources'])} sources, {len(actuel['fichiers'])} fichiers")
        return
    ecarts = comparer(json.loads(MANIFESTE.read_text()), actuel)
    if ecarts:
        print("INTÉGRITÉ COMPROMISE :")
        print("\n".join(ecarts))
        sys.exit(1)
    print(f"Intégrité OK : {len(actuel['sources'])} sources et {len(actuel['fichiers'])} fichiers conformes au manifeste.")


if __name__ == "__main__":
    main()
