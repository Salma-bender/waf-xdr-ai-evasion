"""Assemblage final du dataset : fusion, dédoublonnage, équilibrage et split.

Entrées (data/processed/) :
  - httpparams.csv          (légitime + attaques réelles étiquetées)
  - payloads_publics.csv    (payloads d'attaque PayloadsAllTheThings + SecLists)
  - variantes_evasion.csv   (variantes d'évasion générées)

Sorties (data/processed/) :
  - dataset.csv       (jeu équilibré complet)
  - train.csv, test.csv (split stratifié par famille)
"""
import random
from pathlib import Path

import pandas as pd

BASE = Path(__file__).resolve().parents[2]
PROCESSED = BASE / "data/processed"
ENTREES = ["httpparams.csv", "payloads_publics.csv", "variantes_evasion.csv"]

GRAINE = 42
CAP_FAMILLE = 2200     # plafond par famille d'attaque
CAP_BENIGN = 8800      # légitime = somme des 4 familles (binaire équilibré)
PROP_TEST = 0.20       # part du jeu de test

FAMILLES_ATTAQUE = ["sqli", "xss", "lfi_rfi", "rce"]
rng = random.Random(GRAINE)


def charger():
    frames = []
    for nom in ENTREES:
        df = pd.read_csv(PROCESSED / nom, dtype=str, keep_default_na=False)
        if "technique" not in df.columns:
            df["technique"] = ""
        frames.append(df[["payload", "label", "family", "source", "technique"]])
    df = pd.concat(frames, ignore_index=True)
    df["label"] = df["label"].astype(int)
    return df


def echantillonner_famille(df_fam, cap):
    """Garde toutes les variantes d'évasion en priorité, complète avec le reste."""
    if len(df_fam) <= cap:
        return df_fam
    variantes = df_fam[df_fam["source"] == "variante"]
    reste = df_fam[df_fam["source"] != "variante"]
    if len(variantes) >= cap:
        idx = rng.sample(list(variantes.index), cap)
        return variantes.loc[idx]
    manque = cap - len(variantes)
    idx = rng.sample(list(reste.index), min(manque, len(reste)))
    return pd.concat([variantes, reste.loc[idx]])


def main():
    df = charger()
    print(f"Lignes fusionnées : {len(df)}")

    avant = len(df)
    df = df.drop_duplicates(subset=["payload"])
    print(f"Doublons inter-sources supprimés : {avant - len(df)}")

    morceaux = [echantillonner_famille(df[df["family"] == "benign"], CAP_BENIGN)]
    for fam in FAMILLES_ATTAQUE:
        morceaux.append(echantillonner_famille(df[df["family"] == fam], CAP_FAMILLE))

    data = pd.concat(morceaux).sample(frac=1, random_state=GRAINE).reset_index(drop=True)
    data.to_csv(PROCESSED / "dataset.csv", index=False)

    # Split stratifié par famille
    test_idx = []
    for fam, grp in data.groupby("family"):
        n = int(len(grp) * PROP_TEST)
        test_idx += rng.sample(list(grp.index), n)
    test = data.loc[test_idx]
    train = data.drop(index=test_idx)
    train.to_csv(PROCESSED / "train.csv", index=False)
    test.to_csv(PROCESSED / "test.csv", index=False)

    print(f"\nDataset final : {len(data)}  ->  train {len(train)} / test {len(test)}")
    print("\nPar famille :")
    print(data["family"].value_counts().to_string())
    print("\nPar label (0=légitime, 1=malveillant) :")
    print(data["label"].value_counts().to_string())
    print("\nPart des variantes d'évasion parmi les attaques :")
    att = data[data["label"] == 1]
    print(f"  {(att['source'] == 'variante').sum()} / {len(att)} "
          f"({100 * (att['source'] == 'variante').mean():.1f} %)")


if __name__ == "__main__":
    main()
