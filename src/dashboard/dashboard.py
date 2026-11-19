"""Dashboard SOC de la couche IA (Phase 08) : Flask + SQLite + AJAX.

Affiche en temps réel les verdicts du service d'analyse. Les données affichées
contiennent des charges d'attaque (dont du XSS) : elles sont toujours insérées
comme du texte (textContent) côté navigateur, et une politique CSP stricte
interdit tout script qui ne vient pas du dashboard (contre le XSS stocké).

  - base ouverte en lecture seule (mode=ro), aucune route d'écriture ;
  - authentification HTTP Basic, mot de passe stocké sous forme d'empreinte ;
  - en-têtes de sécurité sur toutes les réponses.

Variables : IA_DB, DASH_USER, DASH_PASS_HASH_FILE (fichier contenant l'empreinte)
            ou DASH_PASS_HASH (empreinte directe, pour les tests)
"""
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Flask, Response, jsonify, request, send_from_directory
from werkzeug.security import check_password_hash

ICI = Path(__file__).resolve().parent
DB = os.environ.get("IA_DB", "/var/lib/ia-soc/detections.db")
UTILISATEUR = os.environ.get("DASH_USER", "")
EMPREINTE = os.environ.get("DASH_PASS_HASH", "")
if not EMPREINTE and os.environ.get("DASH_PASS_HASH_FILE"):
    EMPREINTE = Path(os.environ["DASH_PASS_HASH_FILE"]).read_text().strip()
CATEGORIES = ("evasion_rattrapee", "attaque_bloquee", "bloquee_waf_seul", "legitime")

if not UTILISATEUR or not EMPREINTE:
    raise SystemExit("DASH_USER et une empreinte de mot de passe sont obligatoires.")

app = Flask(__name__, static_folder=None)


def lecture():
    c = sqlite3.connect(f"file:{DB}?mode=ro", uri=True, timeout=5)
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
