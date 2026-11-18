"""Entraînement des modèles FINAUX (itération 3 du durcissement).

Données : train_durci.csv (identiques à l'itération 2).
Modèle  : n-grammes de caractères (TF-IDF, 10 000 attributs)
          + caractéristiques de structure (caracteristiques.py, sur requête normalisée)
          -> Random Forest, 200 arbres, 3 % des attributs examinés à chaque nœud.
Évaluation sur le MÊME test.csv que les versions précédentes.

Sorties : models/final/*.joblib et src/security/models_manifest_final.json
"""
import json
import platform
from datetime import datetime, timezone

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import FeatureUnion, Pipeline

import train_baseline as tb
from caracteristiques import NOMS, StructureRequete

SORTIE = tb.BASE / "models/final"
MANIFESTE = tb.BASE / "src/security/models_manifest_final.json"
N_NGRAMMES = 10000
PART_ATTRIBUTS = 0.03


def nouveau_modele():
    return Pipeline([
        ("attributs", FeatureUnion([
            ("ngrammes", TfidfVectorizer(analyzer="char", ngram_range=(2, 4), max_features=N_NGRAMMES,
                                         lowercase=False, sublinear_tf=True)),
            ("structure", StructureRequete()),
        ])),
        ("rf", RandomForestClassifier(n_estimators=tb.N_ARBRES, max_features=PART_ATTRIBUTS,
                                      n_jobs=-1, random_state=tb.GRAINE)),
    ])


def part_structure(modele):
    imp = modele.named_steps["rf"].feature_importances_
    struct = imp[-len(NOMS):]
    top = sorted(zip(NOMS, struct), key=lambda x: -x[1])[:5]
    return float(struct.sum()), [(n, float(v)) for n, v in top]


def main():
    tb.verifier_integrite()
    train, test = tb.charger("train_durci.csv"), tb.charger("test.csv")
    print(f"\nEntraînement (final) : {len(train)} exemples / test : {len(test)} exemples")

    print("\n[1/2] Détection binaire ...")
    binaire = nouveau_modele().fit(train["payload"], train["label"])
    mb = tb.metriques_binaire(test, binaire.predict(test["payload"]))

    print("[2/2] Classification de famille (attaques seulement) ...")
    train_att, test_att = train[train["label"] == 1], test[test["label"] == 1]
    famille = nouveau_modele().fit(train_att["payload"], train_att["family"])
    mf = tb.metriques_famille(test_att, famille.predict(test_att["payload"]))

    SORTIE.mkdir(parents=True, exist_ok=True)
    fichiers = {}
    for nom, modele in (("detection_binaire", binaire), ("classification_famille", famille)):
        chemin = SORTIE / f"{nom}.joblib"
        joblib.dump(modele, chemin, compress=3)
        fichiers[nom] = {"fichier": str(chemin.relative_to(tb.BASE)), "sha256": tb.sha256(chemin),
                         "octets": chemin.stat().st_size}

    part_b, top_b = part_structure(binaire)
    MANIFESTE.write_text(json.dumps({
        "date_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "python": platform.python_version(), "scikit_learn": sklearn.__version__,
        "graine": tb.GRAINE, "arbres": tb.N_ARBRES, "donnees": "train_durci.csv",
        "ngrammes": N_NGRAMMES, "part_attributs_par_noeud": PART_ATTRIBUTS,
        "caracteristiques_structure": NOMS,
        "manifeste_donnees_sha256": tb.sha256(tb.MANIFESTE_DATA),
        "requirements_sha256": tb.sha256(tb.BASE / "requirements.txt"),
        "modeles": fichiers,
        "importance_structure_binaire": {"part_totale": part_b, "top5": top_b},
        "metriques_jeu_de_test": {"detection_binaire": mb, "classification_famille": mf},
    }, indent=2, sort_keys=True, ensure_ascii=False) + "\n")

    print("\n=== Détection binaire (jeu de test) ===")
    for k in ("accuracy", "precision", "rappel", "f1", "taux_faux_positifs"):
        print(f"  {k:20s} {100 * mb[k]:.2f} %")
    print(f"  faux positifs : {mb['faux_positifs']}   faux négatifs : {mb['faux_negatifs']}")
    print("\n=== Classification de famille (attaques du jeu de test) ===")
    print(f"  accuracy {100 * mf['accuracy']:.2f} %")
    for f, v in mf["rappel_par_famille"].items():
        print(f"    {f:10s} {100 * v:6.2f} %")
    print(f"\nPart des {len(NOMS)} caractéristiques de structure dans les décisions (binaire) : {100 * part_b:.1f} %")
    for n, v in top_b:
        print(f"    {n:20s} {100 * v:5.2f} %")
    print(f"\nModèles : {SORTIE.relative_to(tb.BASE)}/   Manifeste : {MANIFESTE.relative_to(tb.BASE)}")
    for nom, info in fichiers.items():
        print(f"  {nom}  sha256 {info['sha256']}")


if __name__ == "__main__":
    main()
