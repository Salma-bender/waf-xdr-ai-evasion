"""Entraînement des modèles DURCIS (étape 4).

Même méthode que train_baseline.py (même représentation, mêmes hyperparamètres,
même graine), seule la donnée d'entraînement change : train_durci.csv
(train.csv + augmentation « préfixe de valeur légitime »).
Évaluation sur le MÊME test.csv, pour une comparaison honnête.

Sorties : models/durci/*.joblib et src/security/models_manifest_durci.json
"""
import json
import platform
from datetime import datetime, timezone

import joblib
import sklearn

import train_baseline as tb

SORTIE = tb.BASE / "models/durci"
MANIFESTE = tb.BASE / "src/security/models_manifest_durci.json"


def main():
    tb.verifier_integrite()
    train, test = tb.charger("train_durci.csv"), tb.charger("test.csv")
    print(f"\nEntraînement (durci) : {len(train)} exemples / test : {len(test)} exemples")

    print("\n[1/2] Détection binaire ...")
    binaire = tb.nouveau_modele().fit(train["payload"], train["label"])
    mb = tb.metriques_binaire(test, binaire.predict(test["payload"]))

    print("[2/2] Classification de famille (attaques seulement) ...")
    train_att, test_att = train[train["label"] == 1], test[test["label"] == 1]
    famille = tb.nouveau_modele().fit(train_att["payload"], train_att["family"])
    mf = tb.metriques_famille(test_att, famille.predict(test_att["payload"]))

    SORTIE.mkdir(parents=True, exist_ok=True)
    fichiers = {}
    for nom, modele in (("detection_binaire", binaire), ("classification_famille", famille)):
        chemin = SORTIE / f"{nom}.joblib"
        joblib.dump(modele, chemin, compress=3)
        fichiers[nom] = {"fichier": str(chemin.relative_to(tb.BASE)), "sha256": tb.sha256(chemin),
                         "octets": chemin.stat().st_size}

    MANIFESTE.write_text(json.dumps({
        "date_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "python": platform.python_version(), "scikit_learn": sklearn.__version__,
        "graine": tb.GRAINE, "arbres": tb.N_ARBRES, "donnees": "train_durci.csv",
        "manifeste_donnees_sha256": tb.sha256(tb.MANIFESTE_DATA),
        "requirements_sha256": tb.sha256(tb.BASE / "requirements.txt"),
        "modeles": fichiers,
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
    print(f"\nModèles : {SORTIE.relative_to(tb.BASE)}/   Manifeste : {MANIFESTE.relative_to(tb.BASE)}")
    for nom, info in fichiers.items():
        print(f"  {nom}  sha256 {info['sha256']}")


if __name__ == "__main__":
    main()
