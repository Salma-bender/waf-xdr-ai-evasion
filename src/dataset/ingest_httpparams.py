"""Ingestion de HttpParamsDataset vers le schéma commun du projet.

Schéma de sortie : payload, label (0 = légitime, 1 = malveillant), family, source
"""
from pathlib import Path

import pandas as pd

BASE = Path(__file__).resolve().parents[2]
SRC = BASE / "data/raw/HttpParamsDataset/payload_full.csv"
OUT = BASE / "data/processed/httpparams.csv"

# Correspondance entre les types du dataset et nos familles
FAMILY_MAP = {
    "norm": "benign",
    "sqli": "sqli",
    "xss": "xss",
    "path-traversal": "lfi_rfi",
    "cmdi": "rce",
}


def main():
    df = pd.read_csv(SRC, dtype=str, keep_default_na=False)
    print(f"Lignes lues : {len(df)}")

    df["family"] = df["attack_type"].map(FAMILY_MAP)
    inconnus = df["family"].isna().sum()
    if inconnus:
        print(f"Types non reconnus ignorés : {inconnus}")
    df = df.dropna(subset=["family"])

    df["label"] = (df["family"] != "benign").astype(int)
    df["source"] = "httpparams"

    df["payload"] = df["payload"].str.strip()
    df = df[df["payload"] != ""]
    avant = len(df)
    df = df.drop_duplicates(subset=["payload"])
    print(f"Doublons supprimés : {avant - len(df)}")

    df = df[["payload", "label", "family", "source"]]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUT, index=False)

    print(f"\nLignes écrites : {len(df)} -> {OUT.relative_to(BASE)}")
    print("\nRépartition par famille :")
    print(df["family"].value_counts().to_string())
    print("\nRépartition par label :")
    print(df["label"].value_counts().to_string())


if __name__ == "__main__":
    main()
