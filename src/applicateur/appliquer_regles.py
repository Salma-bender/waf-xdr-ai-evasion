#!/usr/bin/env python3
"""Applicateur de règles ModSecurity validées (Phase 09) — tourne sur waf-dmz.

Récupère auprès du service d'analyse (ia-soc) les règles APPROUVÉES par un humain
(validées ou déjà appliquées), reconstruit intégralement le fichier de règles IA
du WAF, teste la configuration Apache, et ne recharge QUE si le test passe. Puis
il signale au service les règles qu'il vient d'appliquer (validée -> appliquée).

Garde-fous :
  - ne récupère que des règles déjà validées par un humain (le service ne renvoie
    rien d'autre : la validation depuis le dashboard est la seule porte d'entrée) ;
  - sauvegarde l'ancien fichier, écrit le nouveau, lance « apache2ctl configtest » ;
    en cas d'échec il RESTAURE la sauvegarde et n'effectue AUCUN rechargement ;
  - les identifiants de règles sont cantonnés à la plage IA (9100000+), sans
    collision avec le CRS OWASP ;
  - bibliothèque standard uniquement ; jeton et URL viennent de l'environnement.

Variables :
  IA_API_URL          URL du service (comme le collecteur ; une URL en .../analyser
                      est acceptée, la base est déduite automatiquement)
  IA_API_TOKEN        jeton Bearer partagé avec le service
  WAF_REGLES_FICHIER  fichier .conf des règles IA (inclus par ModSecurity/Apache)
  WAF_TEST_CMD        test de configuration   (défaut : apache2ctl configtest)
  WAF_RELOAD_CMD      commande de rechargement (défaut : systemctl reload apache2)
"""
import json
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

API = os.environ.get("IA_API_URL", "http://192.168.50.10:8000/analyser")
BASE = API[:-len("/analyser")] if API.endswith("/analyser") else API.rstrip("/")
JETON = os.environ.get("IA_API_TOKEN", "")
FICHIER = os.environ.get("WAF_REGLES_FICHIER", "/etc/modsecurity/ia-generees.conf")
TEST_CMD = os.environ.get("WAF_TEST_CMD", "apache2ctl configtest").split()
RELOAD_CMD = os.environ.get("WAF_RELOAD_CMD", "systemctl reload apache2").split()
ENTETE = f"Bearer {JETON}"


def _appel(chemin, donnees=None):
    corps = json.dumps(donnees).encode() if donnees is not None else None
    methode = "POST" if donnees is not None else "GET"
    req = urllib.request.Request(BASE + chemin, data=corps, method=methode,
                                 headers={"Authorization": ENTETE,
                                          "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


def construire_fichier(regles):
    maintenant = datetime.now(timezone.utc).isoformat(timespec="seconds")
    lignes = [
        "# Règles ModSecurity générées par la couche IA (Phase 09) — NE PAS ÉDITER À LA MAIN.",
        "# Reconstruit par appliquer_regles.py à partir des règles validées sur le SOC.",
        f"# Dernière génération : {maintenant}",
        f"# Nombre de règles : {len(regles)}",
        "",
    ]
    for r in regles:
        lignes.append(f"# règle {r['regle_id']} — famille {r['famille']} — statut {r['statut']}")
        lignes.append(r["regle_xml"])
        lignes.append("")
    return "\n".join(lignes) + "\n"


def main():
    if len(JETON) < 32:
        sys.exit("IA_API_TOKEN absent ou trop court.")
    try:
        rep = _appel("/regles/approuvees")
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
        sys.exit(f"service injoignable : {e}")
    regles = rep.get("regles", [])
    if not regles:
        print("Aucune règle approuvée à appliquer.")
        return
    print(f"Règles approuvées récupérées : {len(regles)}")

    secours = FICHIER + ".bak"
    existait = os.path.exists(FICHIER)
    if existait:
        shutil.copy2(FICHIER, secours)

    with open(FICHIER, "w", encoding="utf-8") as f:
        f.write(construire_fichier(regles))
    print(f"Fichier écrit : {FICHIER}")

    test = subprocess.run(TEST_CMD, capture_output=True, text=True)
    if test.returncode != 0:
        if existait:
            shutil.copy2(secours, FICHIER)
        else:
            os.remove(FICHIER)
        sys.exit("ÉCHEC configtest — configuration restaurée, aucun rechargement :\n"
                 + (test.stderr or test.stdout).strip())
    print("configtest : OK")

    rech = subprocess.run(RELOAD_CMD, capture_output=True, text=True)
    if rech.returncode != 0:
        sys.exit("ÉCHEC rechargement :\n" + (rech.stderr or rech.stdout).strip())
    print("Apache rechargé.")
    if existait and os.path.exists(secours):
        os.remove(secours)

    a_marquer = [r["regle_id"] for r in regles if r["statut"] == "valide"]
    if a_marquer:
        try:
            res = _appel("/regles/applique", {"regle_ids": a_marquer})
            print(f"Règles marquées « appliquée » : {res.get('appliquees')}")
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
            print(f"AVERTISSEMENT : règles appliquées sur le WAF mais statut non mis à jour ({e})")
    else:
        print("Aucune nouvelle règle à marquer (toutes déjà appliquées).")


if __name__ == "__main__":
    main()
