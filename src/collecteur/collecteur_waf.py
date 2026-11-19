"""Collecteur du WAF (Phase 08) : journal d'audit ModSecurity -> service d'analyse IA.

Suit en continu le journal d'audit natif de ModSecurity (SecAuditEngine On), découpe
les transactions (--<id>-<LETTRE>--) et, pour chaque paramètre de requête (URL et
corps), envoie au service : valeur, adresse du client, méthode, chemin, nom du
paramètre et verdict du WAF (code de réponse).

  - bibliothèque standard uniquement (rien à installer sur le WAF) ;
  - reprise après redémarrage (position mémorisée) et suivi de la rotation du journal ;
  - jeton lu depuis l'environnement (fichier protégé), jamais écrit dans les journaux.

Variables : IA_API_URL, IA_API_TOKEN, AUDIT_LOG, ETAT
Test :      python3 collecteur_waf.py --fichier <journal>   (traite le fichier puis s'arrête)
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

FRONTIERE = re.compile(r"^--([0-9A-Za-z]+)-([A-Z])--\s*$")
IGNORES = {"Submit", "Login", "user_token", "seclev_submit", "Change", "Upload", "send"}
TAILLE_MAX = 4096
stats = {"transactions": 0, "envoyes": 0, "erreurs": 0}


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


def traiter(tx):
    stats["transactions"] += 1
    a, b, f = tx.get("A", ""), tx.get("B", ""), tx.get("F", "")
    corps = tx.get("C") or tx.get("I") or ""
    champs_a = a.split()
    client_ip = champs_a[3] if len(champs_a) > 3 else ""
    m = re.match(r"(\w+)\s+(\S+)\s+HTTP", b.splitlines()[0] if b else "")
    if not m:
        return
    methode, uri = m.group(1), m.group(2)
    chemin, _, requete = uri.partition("?")
    s = re.match(r"HTTP/\S+\s+(\d{3})", f.strip())
    waf_statut = int(s.group(1)) if s else None

    params = parse_qsl(requete, keep_blank_values=True) + parse_qsl(corps.strip(), keep_blank_values=True)
    for nom, val in params:
        if nom in IGNORES:
            continue
        valeur = unquote_plus(val).strip()[:TAILLE_MAX]
        if not valeur:
            continue
        r = envoyer({"valeur": valeur, "client_ip": client_ip[:64], "methode": methode[:16],
                     "uri": chemin[:512], "parametre": nom[:128], "waf_statut": waf_statut})
        if r is None:
            stats["erreurs"] += 1
            continue
        stats["envoyes"] += 1
        if r.get("ia_label"):
            journal(f"{r['categorie']} : {r['ia_famille']} ({r['ia_score']}) "
                    f"de {client_ip} sur {chemin} [{nom}], WAF {waf_statut}")


class Decoupeur:
    """Reconstitue les transactions ligne par ligne."""

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
            f.seek(pos_mem)                    # reprise après redémarrage
        elif inode_mem is None:
            f.seek(0, os.SEEK_END)             # premier lancement : nouveau trafic seulement
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
                inode_mem, pos_mem = None, None
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
