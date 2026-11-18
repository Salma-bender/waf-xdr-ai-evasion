"""Entraînement de référence (baseline) des deux modèles Random Forest.

Avant tout apprentissage, l'intégrité des données est vérifiée par rapport
au manifeste (src/security/provenance.py). Si un écart existe, l'entraînement
s'arrête.

Modèles (aucune normalisation des entrées : c'est l'état « avant durcissement ») :
  - détection binaire        : légitime (0) / malveillant (1), sur tous les exemples
  - classification de famille : sqli / xss / lfi_rfi / rce, sur les attaques seulement

Sorties :
  - models/baseline/*.joblib                   (non versionnés)
  - src/security/models_manifest_baseline.json (empreintes SHA-256 + métriques)
"""
import hashlib
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.pipeline import Pipeline

BASE = Path(__file__).resolve().parents[2]
PROCESSED = BASE / "data/processed"
SORTIE = BASE / "models/baseline"
MANIFESTE_DATA = BASE / "src/security/manifest.json"
MANIFESTE_MODELES = BASE / "src/security/models_manifest_baseline.json"

GRAINE = 42
N_ARBRES = 200


def sha256(chemin):
    h = hashlib.sha256()
    with open(chemin, "rb") as f:
        for bloc in iter(lambda: f.read(1 << 20), b""):
            h.update(bloc)
    return h.hexdigest()


def verifier_integrite():
    r = subprocess.run([sys.executable, str(BASE / "src/security/provenance.py"), "verifier"],
                       capture_output=True, text=True)
    print(r.stdout.strip())
    if r.returncode != 0:
        sys.exit("Entraînement annulé : intégrité des données non garantie.")


def charger(nom):
    df = pd.read_csv(PROCESSED / nom, dtype=str, keep_default_na=False)
    df["label"] = df["label"].astype(int)
    return df


def nouveau_modele():
    return Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char", ngram_range=(2, 4), max_features=20000,
                                  lowercase=False, sublinear_tf=True)),
        ("rf", RandomForestClassifier(n_estimators=N_ARBRES, n_jobs=-1, random_state=GRAINE)),
    ])


def metriques_binaire(test, pred):
    tn, fp, fn, tp = confusion_matrix(test["label"], pred).ravel()
    m = {
        "accuracy": accuracy_score(test["label"], pred),
        "precision": precision_score(test["label"], pred),
        "rappel": recall_score(test["label"], pred),
        "f1": f1_score(test["label"], pred),
        "faux_positifs": int(fp), "faux_negatifs": int(fn),
        "taux_faux_positifs": fp / (fp + tn),
    }
    test = test.assign(pred=pred)
    att = test[test["label"] == 1]
    m["rappel_par_source"] = {s: float((g["pred"] == 1).mean()) for s, g in att.groupby("source")}
    var = att[att["source"] == "variante"]
    m["rappel_par_technique"] = {t: float((g["pred"] == 1).mean()) for t, g in var.groupby("technique")}
    return m


def metriques_famille(test_att, pred):
    m = {"accuracy": accuracy_score(test_att["family"], pred)}
    test_att = test_att.assign(pred=pred)
    m["rappel_par_famille"] = {f: float((g["pred"] == f).mean()) for f, g in test_att.groupby("family")}
    return m


def main():
    verifier_integrite()
    train, test = charger("train.csv"), charger("test.csv")
    print(f"\nEntraînement : {len(train)} exemples / test : {len(test)} exemples")

    print("\n[1/2] Détection binaire ...")
    binaire = nouveau_modele().fit(train["payload"], train["label"])
    mb = metriques_binaire(test, binaire.predict(test["payload"]))

    print("[2/2] Classification de famille (attaques seulement) ...")
    train_att, test_att = train[train["label"] == 1], test[test["label"] == 1]
    famille = nouveau_modele().fit(train_att["payload"], train_att["family"])
    mf = metriques_famille(test_att, famille.predict(test_att["payload"]))

    SORTIE.mkdir(parents=True, exist_ok=True)
    fichiers = {}
    for nom, modele in (("detection_binaire", binaire), ("classification_famille", famille)):
        chemin = SORTIE / f"{nom}.joblib"
        joblib.dump(modele, chemin, compress=3)
        fichiers[nom] = {"fichier": str(chemin.relative_to(BASE)), "sha256": sha256(chemin),
                         "octets": chemin.stat().st_size}

    manifeste = {
        "date_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "python": platform.python_version(), "scikit_learn": sklearn.__version__,
        "graine": GRAINE, "arbres": N_ARBRES,
        "manifeste_donnees_sha256": sha256(MANIFESTE_DATA),
        "requirements_sha256": sha256(BASE / "requirements.txt"),
        "modeles": fichiers,
        "metriques_jeu_de_test": {"detection_binaire": mb, "classification_famille": mf},
    }
    MANIFESTE_MODELES.write_text(json.dumps(manifeste, indent=2, sort_keys=True, ensure_ascii=False) + "\n")

    print("\n=== Détection binaire (jeu de test) ===")
    for k in ("accuracy", "precision", "rappel", "f1", "taux_faux_positifs"):
        print(f"  {k:20s} {100 * mb[k]:.2f} %")
    print(f"  faux positifs : {mb['faux_positifs']}   faux négatifs : {mb['faux_negatifs']}")
    print("\n  Rappel par technique d'évasion :")
    for t, v in sorted(mb["rappel_par_technique"].items(), key=lambda x: x[1]):
        print(f"    {t:28s} {100 * v:6.2f} %")
    print("\n=== Classification de famille (attaques du jeu de test) ===")
    print(f"  accuracy {100 * mf['accuracy']:.2f} %")
    for f, v in mf["rappel_par_famille"].items():
        print(f"    {f:10s} {100 * v:6.2f} %")
    print(f"\nModèles : {SORTIE.relative_to(BASE)}/   Manifeste : {MANIFESTE_MODELES.relative_to(BASE)}")
    for nom, info in fichiers.items():
        print(f"  {nom}  sha256 {info['sha256']}")


if __name__ == "__main__":
    main()
