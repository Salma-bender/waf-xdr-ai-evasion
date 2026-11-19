"""Collecteur du WAF (Phase 08) : journal d'audit ModSecurity -> service d'analyse IA.

Suit en continu le journal d'audit natif de ModSecurity (SecAuditEngine On), découpe
les transactions (--<id>-<LETTRE>--) et envoie au service chaque valeur analysable
de la requête, avec son emplacement et le verdict du WAF.

Surface d'analyse (élargie, Phase 08 - option 1) :
  - chemin de l'URL (traversée, inclusion) ;
  - paramètres de requête (URL et corps x-www-form-urlencoded) ;
  - corps JSON (valeurs, parcourues récursivement) ;
  - valeurs de cookies ;
  - en-têtes connus comme vecteurs d'attaque (X-Forwarded-*, X-Original-URL…).
Les en-têtes User-Agent et Referer sont volontairement exclus : trop variables,
ils provoqueraient des faux positifs (parenthèses, ';', mots d'un UA normal).

L'emplacement est transmis dans le champ `parametre` (ex. `header:X-Forwarded-For`,
`cookie:panier`, `json:user.role`, `path`), ce qui le rend visible dans le dashboard
et les alertes sans changer le schéma de la base.

  - bibliothèque standard uniquement ;
  - reprise après redémarrage et suivi de la rotation du journal ;
  - anti-doublon à durée de vie : une même valeur au même emplacement n'est pas
    renvoyée plus d'une fois par fenêtre (réduit le bruit des cookies/en-têtes).
  - jeton lu depuis l'environnement, jamais écrit dans les journaux.

Variables : IA_API_URL, IA_API_TOKEN, AUDIT_LOG, ETAT, ANTI_DOUBLON_TTL
Test :      python3 collecteur_waf.py --fichier <journal>
"""
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import parse_qsl, unquote_plus

API = os.environ.get("IA_API_URL", "http://192.168.50.10:8000/analyser")
JETON = os.environ.get("IA_API_TOKEN", "")
AUDIT = os.environ.get("AUDIT_LOG", "/var/log/apache2/modsec_audit.log")
ETAT = os.environ.get("ETAT", "/var/lib/ia-collecteur/position")
TTL = float(os.environ.get("ANTI_DOUBLON_TTL", "120"))

FRONTIERE = re.compile(r"^--([0-9A-Za-z]+)-([A-Z])--\s*$")
IGNORES = {"Submit", "Login", "user_token", "seclev_submit", "Change", "Upload", "send"}
# En-têtes analysés : vecteurs d'attaque connus, peu susceptibles d'être bénins complexes.
ENTETES_SURVEILLES = {"x-forwarded-for", "x-forwarded-host", "x-forwarded", "forwarded",
                      "x-real-ip", "x-original-url", "x-rewrite-url", "x-api-version",
                      "x-http-method-override"}
TAILLE_MAX = 4096
JSON_MAX_VALEURS = 60
stats = {"transactions": 0, "envoyes": 0, "doublons": 0, "erreurs": 0}

# anti-doublon : empreinte (emplacement|valeur) -> dernier envoi (monotone)
_vus = {}


def recent(cle):
    t = time.monotonic()
    if len(_vus) > 8000:
        for k, v in list(_vus.items()):
            if t - v > TTL:
                del _vus[k]
    dernier = _vus.get(cle)
    _vus[cle] = t
    return dernier is not None and (t - dernier) < TTL


def journal(msg):
    print(time.strftime("%Y-%m-%dT%H:%M:%S"), msg, flush=True)


def envoyer(donnees):
    req = urllib.request.Request(API, data=json.dumps(donnees).encode(), method="POST",
                                 headers={"Content-Type": "application/json",
                                          "Authorization": f"Bearer {JETON}"})
    for essai in range(3):
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code == 429:
                time.sleep(0.5 * (essai + 1))
                continue
            journal(f"refus du service : HTTP {e.code}")
            return None
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            journal(f"service injoignable : {e}")
            time.sleep(1 + essai)
    return None


def valeurs_json(obj, prefixe=""):
    """Parcourt un objet JSON et rend (chemin, valeur) pour chaque feuille textuelle."""
    sortie = []
    def marche(o, chemin):
        if len(sortie) >= JSON_MAX_VALEURS:
            return
        if isinstance(o, dict):
            for k, v in o.items():
                marche(v, f"{chemin}.{k}" if chemin else str(k))
        elif isinstance(o, list):
            for i, v in enumerate(o):
                marche(v, f"{chemin}[{i}]")
        elif o is not None and not isinstance(o, bool):
            sortie.append((chemin, str(o)))
    marche(obj, prefixe)
    return sortie


def entetes(partie_b):
    """Rend les en-têtes (nom_minuscule, valeur) de la partie B, hors ligne de requête."""
    for ligne in partie_b.splitlines()[1:]:
        if ":" in ligne:
            nom, _, val = ligne.partition(":")
            yield nom.strip().lower(), val.strip()


def charges(tx):
    """Rend (emplacement, valeur) pour chaque zone analysable, + méthode, chemin, statut WAF."""
    a, b = tx.get("A", ""), tx.get("B", "")
    corps = tx.get("C") or tx.get("I") or ""
    f = tx.get("F", "")
    champs_a = a.split()
    client_ip = champs_a[3] if len(champs_a) > 3 else ""
    m = re.match(r"(\w+)\s+(\S+)\s+HTTP", b.splitlines()[0] if b else "")
    if not m:
        return None
    methode, uri = m.group(1), m.group(2)
    chemin, _, requete = uri.partition("?")
    s = re.match(r"HTTP/\S+\s+(\d{3})", f.strip())
    waf_statut = int(s.group(1)) if s else None

    items = []  # (emplacement, valeur)
    # 1. chemin de l'URL
    items.append(("path", unquote_plus(chemin)))
    # 2. paramètres d'URL
    for nom, val in parse_qsl(requete, keep_blank_values=True):
        if nom not in IGNORES:
            items.append((nom, unquote_plus(val)))
    # 3. corps : JSON ou formulaire
    ct = ""
    for nom, val in entetes(b):
        if nom == "content-type":
            ct = val.lower()
    corps = corps.strip()
    if corps and "application/json" in ct:
        try:
            for chemin_json, val in valeurs_json(json.loads(corps)):
                items.append((f"json:{chemin_json}", val))
        except (ValueError, TypeError):
            items.append(("json:brut", corps))
    elif corps:
        for nom, val in parse_qsl(corps, keep_blank_values=True):
            if nom not in IGNORES:
                items.append((nom, unquote_plus(val)))
    # 4. cookies et en-têtes surveillés
    for nom, val in entetes(b):
        if nom == "cookie":
            for c in val.split(";"):
                cnom, _, cval = c.strip().partition("=")
                if cval:
                    items.append((f"cookie:{cnom}", unquote_plus(cval)))
        elif nom in ENTETES_SURVEILLES:
            items.append((f"header:{nom}", val))

    return {"client_ip": client_ip, "methode": methode, "chemin": chemin,
            "waf_statut": waf_statut, "items": items}


def traiter(tx):
    stats["transactions"] += 1
    r = charges(tx)
    if not r:
        return
    for emplacement, valeur in r["items"]:
        valeur = valeur.strip()[:TAILLE_MAX]
        if not valeur:
            continue
        cle = f"{emplacement}\x00{valeur}\x00{r['waf_statut']}"
        if recent(cle):
            stats["doublons"] += 1
            continue
        rep = envoyer({"valeur": valeur, "client_ip": r["client_ip"][:64],
                       "methode": r["methode"][:16], "uri": r["chemin"][:512],
                       "parametre": emplacement[:128], "waf_statut": r["waf_statut"]})
        if rep is None:
            stats["erreurs"] += 1
            continue
        stats["envoyes"] += 1
        if rep.get("ia_label"):
            journal(f"{rep['categorie']} : {rep['ia_famille']} ({rep['ia_score']}) "
                    f"de {r['client_ip']} sur {r['chemin']} [{emplacement}], WAF {r['waf_statut']}")


class Decoupeur:
    def __init__(self):
        self.tx, self.lettre, self.buf, self.id = {}, None, [], None

    def ligne(self, l):
        m = FRONTIERE.match(l)
        if not m:
            if self.lettre is not None:
                self.buf.append(l)
            return
        if self.lettre is not None:
            self.tx[self.lettre] = "".join(self.buf)
        tid, lettre = m.group(1), m.group(2)
        if self.id is not None and tid != self.id:
            self.tx = {}
        self.id, self.lettre, self.buf = tid, lettre, []
        if lettre == "Z":
            traiter(self.tx)
            self.tx, self.lettre, self.id = {}, None, None


def lire_position():
    try:
        inode, pos = open(ETAT).read().split()
        return int(inode), int(pos)
    except (OSError, ValueError):
        return None, None


def ecrire_position(inode, pos):
    try:
        with open(ETAT + ".tmp", "w") as f:
            f.write(f"{inode} {pos}")
        os.replace(ETAT + ".tmp", ETAT)
    except OSError as e:
        journal(f"position non enregistrée : {e}")


def suivre():
    d = Decoupeur()
    inode_mem, pos_mem = lire_position()
    while True:
        try:
            f = open(AUDIT, encoding="utf-8", errors="replace")
        except OSError:
            time.sleep(2)
            continue
        st = os.fstat(f.fileno())
        if inode_mem == st.st_ino and pos_mem is not None and pos_mem <= st.st_size:
            f.seek(pos_mem)
        elif inode_mem is None:
            f.seek(0, os.SEEK_END)
        journal(f"suivi de {AUDIT} (position {f.tell()})")
        inode_mem, derniere = st.st_ino, time.monotonic()
        while True:
            l = f.readline()
            if l:
                d.ligne(l)
                if l.startswith("--") and l.rstrip().endswith("-Z--"):
                    ecrire_position(inode_mem, f.tell())
                continue
            time.sleep(0.5)
            try:
                st2 = os.stat(AUDIT)
            except OSError:
                continue
            if st2.st_ino != inode_mem or st2.st_size < f.tell():
                journal("rotation du journal détectée")
                f.close()
                d = Decoupeur()
                f = open(AUDIT, encoding="utf-8", errors="replace")
                inode_mem = os.fstat(f.fileno()).st_ino
            if time.monotonic() - derniere > 300:
                journal(f"bilan : {stats}")
                derniere = time.monotonic()


def main():
    if len(JETON) < 32:
        sys.exit("IA_API_TOKEN absent ou trop court.")
    if len(sys.argv) == 3 and sys.argv[1] == "--fichier":
        d = Decoupeur()
        with open(sys.argv[2], encoding="utf-8", errors="replace") as f:
            for l in f:
                d.ligne(l)
        journal(f"bilan : {stats}")
        return
    suivre()


if __name__ == "__main__":
    main()
