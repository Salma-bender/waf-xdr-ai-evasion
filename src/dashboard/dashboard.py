"""Dashboard SOC de la couche IA (Phases 08 et 09) : Flask + SQLite + AJAX.

Affiche en temps réel les verdicts du service d'analyse, et (Phase 09) les règles
ModSecurity proposées par le LLM à partir des évasions rattrapées, pour validation
humaine (valider / rejeter) avant toute application sur le WAF.

Les données affichées contiennent des charges d'attaque (dont du XSS) : elles sont
toujours insérées comme du texte (textContent) côté navigateur, et une politique
CSP stricte interdit tout script qui ne vient pas du dashboard (contre le XSS stocké).

  - detections.db : ouverte en LECTURE SEULE (mode=ro), aucune écriture ;
  - regles.db     : ouverte en lecture/écriture UNIQUEMENT pour enregistrer la
                    décision humaine (statut, auteur, date) — jamais pour appliquer ;
  - authentification HTTP Basic, mot de passe stocké sous forme d'empreinte ;
  - la décision (POST) est protégée contre le CSRF : en-tête personnalisé obligatoire
    + corps JSON (non posables en cross-site sans CORS, que le serveur n'accorde jamais) ;
  - en-têtes de sécurité sur toutes les réponses.

La validation NE touche PAS le WAF : elle passe le statut à « valide ». L'application
réelle est faite par l'étape 3 (sur waf-dmz), qui ne récupère que les règles validées.

Variables : IA_DB, IA_REGLES_DB, DASH_USER, DASH_PASS_HASH_FILE (fichier contenant
            l'empreinte) ou DASH_PASS_HASH (empreinte directe, pour les tests)
"""
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Flask, Response, jsonify, request, send_from_directory
from werkzeug.security import check_password_hash

ICI = Path(__file__).resolve().parent
DB = os.environ.get("IA_DB", "/var/lib/ia-soc/detections.db")
REGLES_DB = os.environ.get("IA_REGLES_DB", "/var/lib/ia-soc/regles.db")
UTILISATEUR = os.environ.get("DASH_USER", "")
EMPREINTE = os.environ.get("DASH_PASS_HASH", "")
if not EMPREINTE and os.environ.get("DASH_PASS_HASH_FILE"):
    EMPREINTE = Path(os.environ["DASH_PASS_HASH_FILE"]).read_text().strip()
CATEGORIES = ("evasion_rattrapee", "attaque_bloquee", "bloquee_waf_seul", "legitime")
DECISIONS = {"valide", "rejete"}

if not UTILISATEUR or not EMPREINTE:
    raise SystemExit("DASH_USER et une empreinte de mot de passe sont obligatoires.")

app = Flask(__name__, static_folder=None)


def lecture():
    """detections.db — toujours en lecture seule."""
    c = sqlite3.connect(f"file:{DB}?mode=ro", uri=True, timeout=5)
    c.row_factory = sqlite3.Row
    return c


def regles(ecriture=False):
    """regles.db — lecture seule par défaut ; lecture/écriture seulement pour une décision."""
    mode = "rw" if ecriture else "ro"
    c = sqlite3.connect(f"file:{REGLES_DB}?mode={mode}", uri=True, timeout=5)
    c.row_factory = sqlite3.Row
    return c


@app.before_request
def authentifier():
    a = request.authorization
    if not a or a.username != UTILISATEUR or not check_password_hash(EMPREINTE, a.password or ""):
        return Response("Authentification requise", 401,
                        {"WWW-Authenticate": 'Basic realm="SOC IA", charset="UTF-8"'})


@app.after_request
def entetes(r):
    r.headers["Content-Security-Policy"] = ("default-src 'none'; script-src 'self'; style-src 'self'; "
                                            "connect-src 'self'; img-src 'self'; base-uri 'none'; "
                                            "form-action 'none'; frame-ancestors 'none'")
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Referrer-Policy"] = "no-referrer"
    r.headers["Cache-Control"] = "no-store"
    return r


@app.get("/")
def accueil():
    return send_from_directory(ICI / "static", "index.html")


@app.get("/static/<path:nom>")
def statique(nom):
    return send_from_directory(ICI / "static", nom)


def depuis(heures):
    return (datetime.now(timezone.utc) - timedelta(hours=heures)).isoformat(timespec="seconds")


@app.get("/api/resume")
def resume():
    heures = min(max(request.args.get("heures", 24, type=int), 1), 168)
    seuil = depuis(heures)
    with lecture() as c:
        total = c.execute("SELECT COUNT(*) FROM predictions WHERE horodatage >= ?", (seuil,)).fetchone()[0]
        par_cat = dict(c.execute("SELECT categorie, COUNT(*) FROM predictions WHERE horodatage >= ? "
                                 "GROUP BY categorie", (seuil,)).fetchall())
        par_fam = dict(c.execute("SELECT ia_famille, COUNT(*) FROM predictions WHERE horodatage >= ? "
                                 "AND ia_label = 1 GROUP BY ia_famille", (seuil,)).fetchall())
        sources = [dict(r) for r in c.execute(
            "SELECT client_ip, COUNT(*) AS n, SUM(categorie = 'evasion_rattrapee') AS evasions "
            "FROM predictions WHERE horodatage >= ? AND ia_label = 1 GROUP BY client_ip "
            "ORDER BY n DESC LIMIT 5", (seuil,))]
        chrono = [dict(r) for r in c.execute(
            "SELECT substr(horodatage, 1, 13) AS heure, COUNT(*) AS total, SUM(ia_label) AS attaques "
            "FROM predictions WHERE horodatage >= ? GROUP BY heure ORDER BY heure", (seuil,))]
        score_moyen = c.execute("SELECT AVG(ia_score) FROM predictions WHERE horodatage >= ? AND ia_label = 1",
                                (seuil,)).fetchone()[0]
    return jsonify(heures=heures, total=total,
                   categories={k: par_cat.get(k, 0) for k in CATEGORIES},
                   familles=par_fam, sources=sources, chronologie=chrono,
                   score_moyen=round(score_moyen, 3) if score_moyen is not None else None)


@app.get("/api/detections")
def detections():
    categorie = request.args.get("categorie", "")
    limite = min(max(request.args.get("limite", 50, type=int), 1), 200)
    sql = ("SELECT horodatage, client_ip, methode, uri, parametre, valeur, waf_statut, "
           "ia_famille, ia_score, categorie FROM predictions WHERE ia_label = 1")
    args = []
    if categorie in CATEGORIES:
        sql += " AND categorie = ?"
        args.append(categorie)
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(limite)
    with lecture() as c:
        lignes = [dict(r) for r in c.execute(sql, args)]
    return jsonify(lignes)


# --------- Phase 09 : règles proposées + validation humaine -------------------
CHAMPS_REGLE = ("regle_id", "horodatage", "famille", "emplacement", "client_ip",
                "payload", "motif", "regle_xml", "fournisseur", "statut",
                "decide_par", "decide_le", "applique_le")


@app.get("/api/regles")
def liste_regles():
    statut = request.args.get("statut", "")
    limite = min(max(request.args.get("limite", 100, type=int), 1), 300)
    sql = f"SELECT {', '.join(CHAMPS_REGLE)} FROM regles_proposees"
    args = []
    if statut in ("en_attente", "valide", "rejete", "applique"):
        sql += " WHERE statut = ?"
        args.append(statut)
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(limite)
    try:
        with regles() as c:
            lignes = [dict(r) for r in c.execute(sql, args)]
    except sqlite3.OperationalError:
        lignes = []   # base de règles pas encore créée (aucune évasion traitée)
    compte = {"en_attente": 0, "valide": 0, "rejete": 0, "applique": 0}
    for l in lignes:
        compte[l["statut"]] = compte.get(l["statut"], 0) + 1
    return jsonify(regles=lignes, compte=compte)


@app.post("/api/regles/decider")
def decider_regle():
    # Protection CSRF : en-tête personnalisé non posable en cross-site sans CORS
    # (que le serveur n'accorde jamais), en plus du HTTP Basic déjà exigé.
    if request.headers.get("X-SOC-CSRF") != "1" or not request.is_json:
        return jsonify(erreur="requête invalide"), 400
    data = request.get_json(silent=True) or {}
    rid = data.get("regle_id")
    decision = data.get("decision")
    if not isinstance(rid, int) or decision not in DECISIONS:
        return jsonify(erreur="paramètres invalides"), 400
    maintenant = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        with regles(ecriture=True) as c:
            # transition autorisée uniquement depuis « en_attente »
            cur = c.execute(
                "UPDATE regles_proposees SET statut = ?, decide_par = ?, decide_le = ? "
                "WHERE regle_id = ? AND statut = 'en_attente'",
                (decision, UTILISATEUR, maintenant, rid))
            c.commit()
            if cur.rowcount == 0:
                row = c.execute("SELECT statut FROM regles_proposees WHERE regle_id = ?", (rid,)).fetchone()
                if row is None:
                    return jsonify(erreur="règle inconnue"), 404
                return jsonify(erreur=f"règle déjà traitée (statut : {row['statut']})"), 409
    except sqlite3.OperationalError:
        return jsonify(erreur="base de règles indisponible"), 503
    return jsonify(ok=True, regle_id=rid, statut=decision, decide_par=UTILISATEUR, decide_le=maintenant)
