"""Évaluation des modèles de référence sur le jeu de validation RÉEL.

  python evaluer_validation.py baseline [fichier.csv]
  python evaluer_validation.py durci    [fichier.csv]
  python evaluer_validation.py final    [fichier.csv]
  (fichier par défaut : validation_reelle.csv, dans data/processed/)

Étapes :
  1. charge data/processed/validation_reelle.csv (requêtes rejouées depuis Kali) ;
  2. retire toute requête déjà présente dans train.csv  -> garantit l'inédit ;
  3. mesure la détection binaire : rappel PAR FAMILLE (insensible au déséquilibre)
     et taux de faux positifs sur les bénins ;
  4. mesure la classification de famille sur les attaques ;
  5. calcule un score binaire global sur un sous-échantillon équilibré (SQLi plafonné) ;
  6. enregistre le tout dans src/security/validation_reelle_<version>.json.

Les modèles sont chargés via chargement_sur.py : empreinte SHA-256 vérifiée
contre le manifeste avant toute désérialisation.
"""
import json
import random
import sys
from collections import Counter
from pathlib import Path

import pandas as pd

from chargement_sur import ModeleCompromis, charger

BASE = Path(__file__).resolve().parents[2]
PROCESSED = BASE / "data/processed"
VERSIONS = {"baseline": "train.csv", "durci": "train_durci.csv", "final": "train_durci.csv"}

GRAINE = 42
CAP_SQLI = 150          # plafond SQLi pour le score global équilibré


def main():
    if len(sys.argv) not in (2, 3) or sys.argv[1] not in VERSIONS:
        sys.exit(__doc__)
    version = sys.argv[1]
    fichier = sys.argv[2] if len(sys.argv) == 3 else "validation_reelle.csv"
    nom = Path(fichier).stem
    manifeste = BASE / f"src/security/models_manifest_{version}.json"
    resultats = BASE / f"src/security/{nom}_{version}.json"
    try:
        binaire = charger("detection_binaire", manifeste)
        famille = charger("classification_famille", manifeste)
    except ModeleCompromis as e:
        sys.exit(f"INTÉGRITÉ DU MODÈLE COMPROMISE : {e}")
    print(f"Version {version} : empreintes des 2 modèles conformes au manifeste.")

    val = pd.read_csv(PROCESSED / fichier, dtype=str, keep_default_na=False)
    val["label"] = val["label"].astype(int)
    n_brut = len(val)

    # 2. retrait des requêtes déjà vues à l'entraînement
    train = pd.read_csv(PROCESSED / VERSIONS[version], dtype=str, keep_default_na=False)
    deja_vus = set(train["payload"])
    val = val[~val["payload"].isin(deja_vus)].reset_index(drop=True)
    n_retires = n_brut - len(val)

    val = val.assign(pred_bin=binaire.predict(val["payload"]))
    attaques = val[val["label"] == 1].copy()
    benins = val[val["label"] == 0]
    if len(attaques) == 0:
        raise SystemExit("Aucune attaque dans ce fichier.")

    # 3a. rappel binaire par famille d'attaque
    rappel_famille = {}
    for fam, g in attaques.groupby("family"):
        rappel_famille[fam] = {"n": int(len(g)), "rappel": float((g["pred_bin"] == 1).mean())}

    # 3b. faux positifs sur les bénins
    fp = int((benins["pred_bin"] == 1).sum())
    taux_fp = fp / len(benins) if len(benins) else 0.0

    # 4. classification de famille sur les attaques détectées comme attaques
    att_ok = attaques[attaques["pred_bin"] == 1].copy()
    classif = {}
    if len(att_ok):
        att_ok = att_ok.assign(pred_fam=famille.predict(att_ok["payload"]))
        for fam, g in att_ok.groupby("family"):
            classif[fam] = {"n": int(len(g)), "exactitude": float((g["pred_fam"] == fam).mean())}

    # 5. score binaire global sur sous-échantillon équilibré (SQLi plafonné)
    rng = random.Random(GRAINE)
    morceaux = [benins]
    for fam, g in attaques.groupby("family"):
        if fam == "sqli" and len(g) > CAP_SQLI:
            g = g.loc[rng.sample(list(g.index), CAP_SQLI)]
        morceaux.append(g)
    equil = pd.concat(morceaux)
    vrais = (equil["pred_bin"] == equil["label"]).mean()
    att_eq = equil[equil["label"] == 1]
    rappel_global = (att_eq["pred_bin"] == 1).mean()

    res = {
        "version": version,
        "requetes_brutes": n_brut,
        "retirees_car_vues_a_entrainement": n_retires,
        "requetes_evaluees": len(val),
        "repartition": dict(Counter(val["family"])),
        "detection_binaire": {
            "rappel_par_famille": rappel_famille,
            "faux_positifs": fp,
            "benins_total": int(len(benins)),
            "taux_faux_positifs": taux_fp,
        },
        "classification_famille": classif,
        "echantillon_equilibre": {
            "cap_sqli": CAP_SQLI,
            "taille": int(len(equil)),
            "exactitude_globale": float(vrais),
            "rappel_attaques": float(rappel_global),
        },
    }
    resultats.parent.mkdir(parents=True, exist_ok=True)
    resultats.write_text(json.dumps(res, indent=2, ensure_ascii=False) + "\n")

    print(f"Fichier : {fichier}")
    print(f"Requêtes réelles : {n_brut}  (retirées car déjà vues : {n_retires})  ->  évaluées : {len(val)}")
    print("\n=== Détection binaire — rappel sur attaques RÉELLES inédites ===")
    for fam in ("sqli", "xss", "lfi_rfi", "rce"):
        if fam in rappel_famille:
            d = rappel_famille[fam]
            print(f"  {fam:10s} {100 * d['rappel']:6.2f} %   ({d['n']} exemples)")
    print(f"\n  Faux positifs : {fp} / {len(benins)} bénins  =  {100 * taux_fp:.2f} %")
    print("\n=== Classification de famille (attaques détectées) ===")
    if not classif:
        print("  (aucune attaque détectée comme attaque)")
    for fam in ("sqli", "xss", "lfi_rfi", "rce"):
        if fam in classif:
            d = classif[fam]
            print(f"  {fam:10s} {100 * d['exactitude']:6.2f} %   ({d['n']} exemples)")
    print(f"\n=== Échantillon équilibré (SQLi plafonné à {CAP_SQLI}) ===")
    print(f"  taille {len(equil)}   exactitude {100 * vrais:.2f} %   rappel attaques {100 * rappel_global:.2f} %")
    print(f"\nRésultats : {resultats.relative_to(BASE)}")


if __name__ == "__main__":
    main()
