"""Extrait un jeu de validation réel depuis le journal d'audit ModSecurity.

Le journal natif est découpé en transactions bornées par --<id>-<LETTRE>--.
On lit la partie B (ligne de requête + en-têtes) et la partie C/I (corps POST),
on en tire la valeur du paramètre, et on décide par LISTE BLANCHE :

  - sur un endpoint vulnérable DVWA, la charge est BÉNIGNE seulement si elle
    respecte le format normal du paramètre (id : chiffres ; name : lettres et
    chiffres ; page : nom de fichier simple ; ip : adresse IPv4 ou nom d'hôte).
    Tout le reste est MALVEILLANT, de la famille de l'endpoint.
  - sur les autres pages, la charge est malveillante si elle contient un
    indicateur d'attaque, bénigne sinon (cas de test de faux positif).

  python extraire_validation.py modsec_audit.log sortie.csv

Sortie : payload,label,family,source,methode,endpoint
"""
import csv
import re
import sys
from collections import Counter
from urllib.parse import unquote_plus, parse_qsl

ENDPOINTS = [
    ("/vulnerabilities/sqli_blind", "sqli", "id"),
    ("/vulnerabilities/sqli", "sqli", "id"),
    ("/vulnerabilities/xss_r", "xss", "name"),
    ("/vulnerabilities/xss_s", "xss", "name"),
    ("/vulnerabilities/fi", "lfi_rfi", "page"),
    ("/vulnerabilities/exec", "rce", "ip"),
]
FORMAT_BENIN = {
    "id": re.compile(r"\d{1,6}"),
    "name": re.compile(r"[A-Za-z0-9]{1,30}"),
    "page": re.compile(r"[A-Za-z0-9_-]{1,40}\.(php|txt|html)"),
    "ip": re.compile(r"(\d{1,3}\.){3}\d{1,3}|[A-Za-z][A-Za-z0-9.-]{0,60}"),
}
FRONTIERE = re.compile(r"^--([0-9A-Za-z]+)-([A-Z])--\s*$")

# Indicateurs d'attaque recherchés sur la charge DÉCODÉE
INDICATEURS = re.compile(
    r"""['"<>;|`$\\]            # métacaractères shell / injection / balise
    | \.\./ | \.\.\\           # traversée de répertoire
    | %00 | \x00               # octet nul
    | php://|data://|file://   # wrappers
    | \b(union|select|sleep|benchmark|or\s+1|and\s+1|information_schema)\b
    | \b(cat|whoami|uname|passwd|etc/passwd|proc/self)\b
    | <\s*(script|img|svg|iframe|body|input|marquee|details|a|object)
    | on\w+\s*=                # gestionnaire d'événement
    | javascript:
    | \$\{?IFS                 # séparateur de champ shell
    """,
    re.IGNORECASE | re.VERBOSE,
)


def est_malveillant(payload):
    return bool(INDICATEURS.search(payload))


def transactions(chemin):
    courant, lettre, buf, id_courant = {}, None, [], None
    with open(chemin, encoding="utf-8", errors="replace") as f:
        for ligne in f:
            m = FRONTIERE.match(ligne)
            if m:
                if lettre is not None:
                    courant[lettre] = "".join(buf)
                tid, nouvelle = m.group(1), m.group(2)
                if id_courant is not None and tid != id_courant:
                    yield courant
                    courant = {}
                id_courant = tid
                lettre, buf = nouvelle, []
                if nouvelle == "Z":
                    courant[lettre] = ""
                    yield courant
                    courant, lettre, id_courant = {}, None, None
            elif lettre is not None:
                buf.append(ligne)
    if courant:
        yield courant


def charges(tx):
    partie_b = tx.get("B", "")
    premiere = partie_b.splitlines()[0] if partie_b else ""
    m = re.match(r"(\w+)\s+(\S+)\s+HTTP", premiere)
    if not m:
        return
    methode, uri = m.group(1), m.group(2)
    chemin = uri.split("?", 1)[0]
    requete = uri.split("?", 1)[1] if "?" in uri else ""
    corps = tx.get("C") or tx.get("I") or ""

    fam_endpoint = par_endpoint = None
    for motif, f, p in ENDPOINTS:
        if motif in chemin:
            fam_endpoint, par_endpoint = f, p
            break

    params = parse_qsl(requete, keep_blank_values=True) + parse_qsl(corps.strip(), keep_blank_values=True)
    for cle, val in params:
        if not val or cle in ("Submit", "user_token", "Login", "seclev_submit", "security"):
            continue
        charge = unquote_plus(val).strip()
        if not charge:
            continue
        if fam_endpoint and cle == par_endpoint:
            if FORMAT_BENIN[cle].fullmatch(charge):
                yield charge, 0, "benign", methode, chemin
            else:
                yield charge, 1, fam_endpoint, methode, chemin
        elif fam_endpoint is None:
            if est_malveillant(charge):
                continue  # attaque hors endpoint connu : famille inconnue, ignorée
            yield charge, 0, "benign", methode, chemin


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    vus, lignes = set(), []
    for tx in transactions(sys.argv[1]):
        for payload, label, fam, methode, endpoint in charges(tx):
            if payload in vus:
                continue
            vus.add(payload)
            lignes.append((payload, label, fam, "rejeu_kali", methode, endpoint))
    with open(sys.argv[2], "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["payload", "label", "family", "source", "methode", "endpoint"])
        w.writerows(lignes)
    print(f"Requetes uniques extraites : {len(lignes)}  ->  {sys.argv[2]}")
    print(f"  dont malveillantes : {sum(1 for l in lignes if l[1] == 1)}")
    print(f"  dont benignes      : {sum(1 for l in lignes if l[1] == 0)}")
    print("Par famille :")
    for fam, n in sorted(Counter(l[2] for l in lignes).items()):
        print(f"  {fam:10s} {n}")


if __name__ == "__main__":
    main()
