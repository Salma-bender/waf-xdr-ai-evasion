"""Service d'analyse continue de la couche IA (Phase 08).

Reçoit du collecteur du WAF chaque paramètre de requête HTTP observé, avec le
verdict du WAF, et rend le verdict des modèles finaux.

Sécurité :
  - authentification par jeton (en-tête Authorization: Bearer), comparaison en temps constant ;
  - limitation du débit par appelant (seau à jetons) ;
  - validation stricte des entrées (types, tailles) ;
  - modèles chargés via chargement_sur.py (empreinte vérifiée avant désérialisation) ;
  - service hors bande : l'attaquant ne voit jamais le verdict de l'IA (contre ML05) ;
  - chaque prédiction est journalisée dans SQLite (suivi de la dérive, ML08) ;
  - chaque détection est écrite en JSON dans un journal lu par l'agent Wazuh.

Configuration (variables d'environnement) :
  IA_API_TOKEN   jeton partagé avec le collecteur (obligatoire, 32 caractères minimum)
  IA_VERSION     version des modèles (défaut : final)
  IA_DB          base SQLite         (défaut : data/service/detections.db)
  IA_ALERT_LOG   journal des alertes (défaut : logs/ia-alertes.json)
  IA_DEBIT       requêtes par seconde autorisées par appelant (défaut : 50)
"""
import hmac
import json
import os
import sqlite3
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, request

BASE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BASE / "src/models"))
from chargement_sur import ModeleCompromis, charger  # noqa: E402

VERSION = os.environ.get("IA_VERSION", "final")
JETON = os.environ.get("IA_API_TOKEN", "")
DB = Path(os.environ.get("IA_DB", BASE / "data/service/detections.db"))
JOURNAL = Path(os.environ.get("IA_ALERT_LOG", BASE / "logs/ia-alertes.json"))
DEBIT = float(os.environ.get("IA_DEBIT", "50"))

TAILLE_MAX_VALEUR = 4096
TAILLE_MAX_CHAMP = 512

if len(JETON) < 32:
    sys.exit("IA_API_TOKEN absent ou trop court (32 caractères minimum).")

MANIFESTE = BASE / f"src/security/models_manifest_{VERSION}.json"
try:
    BINAIRE = charger("detection_binaire", MANIFESTE)
    FAMILLE = charger("classification_famille", MANIFESTE)
except ModeleCompromis as e:
    sys.exit(f"INTÉGRITÉ DU MODÈLE COMPROMISE : {e}")

DB.parent.mkdir(parents=True, exist_ok=True)
JOURNAL.parent.mkdir(parents=True, exist_ok=True)
_verrou_journal = threading.Lock()


def connexion():
    c = sqlite3.connect(DB, timeout=10)
    c.execute("PRAGMA journal_mode=WAL")
    return c


with connexion() as c:
    c.execute("""CREATE TABLE IF NOT EXISTS predictions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        horodatage TEXT NOT NULL,
        client_ip TEXT, methode TEXT, uri TEXT, parametre TEXT, valeur TEXT,
        waf_statut INTEGER,
        ia_label INTEGER NOT NULL, ia_famille TEXT, ia_score REAL NOT NULL,
        categorie TEXT NOT NULL, version_modele TEXT NOT NULL)""")
    c.execute("CREATE INDEX IF NOT EXISTS idx_horodatage ON predictions(horodatage)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_categorie ON predictions(categorie)")

# --- Limitation du débit : un seau à jetons par appelant -----------------------
_seaux, _verrou_seaux = {}, threading.Lock()


def autorise_debit(appelant):
    maintenant = time.monotonic()
    with _verrou_seaux:
        jetons, dernier = _seaux.get(appelant, (DEBIT, maintenant))
        jetons = min(DEBIT, jetons + (maintenant - dernier) * DEBIT)
        if jetons < 1:
            _seaux[appelant] = (jetons, maintenant)
            return False
        _seaux[appelant] = (jetons - 1, maintenant)
        return True


def categoriser(ia_label, waf_statut):
    bloque = waf_statut == 403
    if ia_label == 1 and not bloque:
        return "evasion_rattrapee"      # le WAF a laissé passer, l'IA détecte
    if ia_label == 1:
        return "attaque_bloquee"        # WAF et IA d'accord
    if bloque:
        return "bloquee_waf_seul"       # le WAF bloque, l'IA ne détecte pas
    return "legitime"


def champ(d, nom, taille=TAILLE_MAX_CHAMP, requis=False):
    v = d.get(nom)
    if v is None:
        if requis:
            raise ValueError(f"champ manquant : {nom}")
        return ""
    if not isinstance(v, str) or len(v) > taille:
        raise ValueError(f"champ invalide : {nom}")
    return v


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024


@app.get("/sante")
def sante():
    return jsonify(statut="ok", version_modele=VERSION)


@app.post("/analyser")
def analyser():
    en_tete = request.headers.get("Authorization", "")
    if not hmac.compare_digest(en_tete.encode(), f"Bearer {JETON}".encode()):
        return jsonify(erreur="non autorisé"), 401
    if not autorise_debit(request.remote_addr or "?"):
        return jsonify(erreur="débit dépassé"), 429

    d = request.get_json(silent=True)
    if not isinstance(d, dict):
        return jsonify(erreur="JSON attendu"), 400
    try:
        valeur = champ(d, "valeur", TAILLE_MAX_VALEUR, requis=True)
        client_ip = champ(d, "client_ip", 64)
        methode = champ(d, "methode", 16)
        uri = champ(d, "uri")
        parametre = champ(d, "parametre", 128)
        waf_statut = d.get("waf_statut")
        if waf_statut is not None and not (isinstance(waf_statut, int) and 100 <= waf_statut <= 599):
            raise ValueError("champ invalide : waf_statut")
    except ValueError as e:
        return jsonify(erreur=str(e)), 400

    score = float(BINAIRE.predict_proba([valeur])[0][1])
    ia_label = int(score >= 0.5)
    ia_famille = str(FAMILLE.predict([valeur])[0]) if ia_label else "benign"
    categorie = categoriser(ia_label, waf_statut)
    horodatage = datetime.now(timezone.utc).isoformat(timespec="seconds")

    with connexion() as c:
        c.execute("""INSERT INTO predictions (horodatage, client_ip, methode, uri, parametre, valeur,
                     waf_statut, ia_label, ia_famille, ia_score, categorie, version_modele)
                     VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                  (horodatage, client_ip, methode, uri, parametre, valeur[:1000],
                   waf_statut, ia_label, ia_famille, score, categorie, VERSION))

    if ia_label:
        alerte = {"source": "ia_detecteur", "categorie": categorie, "famille": ia_famille,
                  "score": round(score, 3), "client_ip": client_ip, "methode": methode,
                  "uri": uri, "parametre": parametre, "waf_statut": waf_statut,
                  "version_modele": VERSION, "horodatage": horodatage}
        with _verrou_journal, open(JOURNAL, "a", encoding="utf-8") as f:
            f.write(json.dumps(alerte, ensure_ascii=False) + "\n")

    return jsonify(ia_label=ia_label, ia_famille=ia_famille, ia_score=round(score, 3),
                   categorie=categorie)
