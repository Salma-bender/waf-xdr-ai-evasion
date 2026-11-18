"""Chargement sécurisé d'un modèle (contre ML10 : altération du fichier modèle).

Un fichier joblib est désérialisé avec pickle : un fichier remplacé peut exécuter
du code dès son chargement. On vérifie donc l'empreinte SHA-256 du fichier par
rapport au manifeste AVANT tout appel à joblib.load. En cas d'écart, le
chargement est refusé.
"""
import hashlib
import json
from pathlib import Path

import joblib

BASE = Path(__file__).resolve().parents[2]


class ModeleCompromis(Exception):
    pass


def sha256(chemin):
    h = hashlib.sha256()
    with open(chemin, "rb") as f:
        for bloc in iter(lambda: f.read(1 << 20), b""):
            h.update(bloc)
    return h.hexdigest()


def charger(nom, manifeste):
    """nom : clé du modèle dans le manifeste (ex. 'detection_binaire')."""
    infos = json.loads(Path(manifeste).read_text())["modeles"].get(nom)
    if infos is None:
        raise ModeleCompromis(f"{nom} : absent du manifeste {manifeste}")
    chemin = BASE / infos["fichier"]
    obtenu = sha256(chemin)
    if obtenu != infos["sha256"]:
        raise ModeleCompromis(f"{nom} : empreinte {obtenu} différente de {infos['sha256']} — chargement refusé")
    return joblib.load(chemin)
