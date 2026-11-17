"""Ingestion des payloads d'attaque de PayloadsAllTheThings et SecLists.

Schéma de sortie : payload, label (1 = malveillant), family, source
"""
import re
from pathlib import Path

import pandas as pd

BASE = Path(__file__).resolve().parents[2]
RAW = BASE / "data/raw"
OUT = BASE / "data/processed/payloads_publics.csv"

PATT = RAW / "PayloadsAllTheThings"
SL = RAW / "SecLists/Fuzzing"

# Fichiers retenus pour chaque famille : (source, dossier, motif)
SOURCES = {
    "sqli": [
        ("patt", PATT / "SQL Injection/Intruder", "*"),
        ("seclists", SL / "Databases/SQLi", "**/*.txt"),
    ],
    "xss": [
        ("patt", PATT / "XSS Injection/Intruders", "*.txt"),
        ("seclists", SL / "XSS", "**/*.txt"),
    ],
    "lfi_rfi": [
        ("patt", PATT / "File Inclusion/Intruders", "*.txt"),
        ("patt", PATT / "Directory Traversal/Intruder", "*.txt"),
        ("seclists", SL / "LFI", "**/*.txt"),
    ],
    "rce": [
        ("patt", PATT / "Command Injection/Intruder", "*"),
        ("seclists", SL, "command-injection-commix.txt"),
    ],
}

# Fichiers écartés : listes de chemins génériques (non malveillants en soi)
# ou listes massives quasi identiques qui fausseraient l'équilibre
EXCLUS = {
    "README.md", "jsonp_endpoint.txt", "Web-files.txt", "Windows-Paths.txt",
    "LFI-etc-files-of-all-linux-packages.txt", "LFI-LFISuite-pathtotest-huge.txt",
    "dotdotpwn.txt",
}

# Une ligne LFI n'est conservée que si elle contient un indicateur d'inclusion
LFI_INDICATEURS = re.compile(
    r"\.\.|%2e|%252e|php://|file://|expect://|data:|zip://|phar://|"
    r"/etc/|/proc/|c:\\|c:/|win\.ini|boot\.ini|%00|https?://",
    re.IGNORECASE,
)

LONGUEUR_MIN = 3


def lire_lignes(fichier):
    with open(fichier, encoding="utf-8", errors="ignore") as f:
        for ligne in f:
            ligne = ligne.strip()
            if len(ligne) < LONGUEUR_MIN or ligne.startswith("#"):
                continue
            yield ligne


def main():
    lignes = []
    for famille, entrees in SOURCES.items():
        for source, dossier, motif in entrees:
            for fichier in sorted(dossier.glob(motif)):
                if not fichier.is_file() or fichier.name in EXCLUS:
                    continue
                for payload in lire_lignes(fichier):
                    if famille == "lfi_rfi" and not LFI_INDICATEURS.search(payload):
                        continue
                    lignes.append((payload, 1, famille, source))

    df = pd.DataFrame(lignes, columns=["payload", "label", "family", "source"])
    print(f"Payloads lus : {len(df)}")

    # Un même payload présent dans deux familles est ambigu : on l'écarte
    familles_par_payload = df.groupby("payload")["family"].nunique()
    ambigus = familles_par_payload[familles_par_payload > 1].index
    df = df[~df["payload"].isin(ambigus)]
    print(f"Payloads ambigus (plusieurs familles) écartés : {len(ambigus)}")

    avant = len(df)
    df = df.drop_duplicates(subset=["payload"])
    print(f"Doublons supprimés : {avant - len(df)}")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUT, index=False)

    print(f"\nLignes écrites : {len(df)} -> {OUT.relative_to(BASE)}")
    print("\nRépartition par famille et par source :")
    print(df.groupby(["family", "source"]).size().unstack(fill_value=0).to_string())


if __name__ == "__main__":
    main()
