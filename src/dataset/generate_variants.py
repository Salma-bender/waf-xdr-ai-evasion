"""Génération de variantes d'évasion à partir des payloads d'attaque de base.

Chaque variante conserve la famille de son payload d'origine mais change de forme,
selon les techniques utilisées pour contourner les WAF à signatures.

Schéma de sortie : payload, label, family, source, technique
"""
import random
import re
from pathlib import Path
from urllib.parse import quote

import pandas as pd

BASE = Path(__file__).resolve().parents[2]
PROCESSED = BASE / "data/processed"
ENTREES = [PROCESSED / "httpparams.csv", PROCESSED / "payloads_publics.csv"]
OUT = PROCESSED / "variantes_evasion.csv"

GRAINE = 42
BASES_PAR_FAMILLE = 800      # payloads d'origine tirés par famille
VARIANTES_PAR_BASE = 2       # techniques appliquées à chaque payload d'origine
LONGUEUR_MAX = 300           # on évite de transformer des payloads démesurés

rng = random.Random(GRAINE)

MOTS_SQL = ["select", "union", "from", "where", "and", "or", "order", "by",
            "sleep", "benchmark", "insert", "into", "values", "null", "having",
            "group", "concat", "char", "substring", "information_schema"]
RE_MOTS_SQL = re.compile(r"\b(" + "|".join(MOTS_SQL) + r")\b", re.IGNORECASE)
RE_BALISE = re.compile(r"<\s*/?\s*([a-zA-Z]+)")
COMMANDES = ["cat", "ls", "id", "whoami", "uname", "echo", "ping", "sleep",
             "wget", "curl", "nc", "bash", "sh", "passwd", "type", "dir"]
RE_COMMANDE = re.compile(r"\b(" + "|".join(COMMANDES) + r")\b")


# --- Techniques communes ----------------------------------------------------

def casse_aleatoire(texte):
    return "".join(c.upper() if rng.random() < 0.5 else c.lower() for c in texte)


def encodage_url(p):
    return quote(p, safe="")


def double_encodage_url(p):
    return quote(quote(p, safe=""), safe="")


def encodage_url_partiel(p):
    """N'encode que les caractères spéciaux, une fois sur deux."""
    return "".join(quote(c, safe="") if not c.isalnum() and rng.random() < 0.5 else c for c in p)


# --- SQLi --------------------------------------------------------------------

def sqli_casse_mots_cles(p):
    return RE_MOTS_SQL.sub(lambda m: casse_aleatoire(m.group(0)), p)


def sqli_commentaires_inline(p):
    return p.replace(" ", "/**/")


def sqli_espaces_alternatifs(p):
    return re.sub(" ", lambda _: rng.choice(["%09", "%0a", "%0d", "%0b", "+"]), p)


def sqli_commentaire_version(p):
    """Commentaires exécutables MySQL : /*!SELECT*/"""
    return RE_MOTS_SQL.sub(lambda m: f"/*!{m.group(0)}*/", p)


def sqli_collate(p):
    """Clause COLLATE insérée avant le commentaire final (ou ajoutée en fin)."""
    clause = " COLLATE " + rng.choice(["utf8mb4_general_ci", "utf8_bin", "latin1_swedish_ci"])
    m = re.search(r"(--|#|/\*)[^'\"]*$", p)
    if m:
        return p[:m.start()].rstrip() + clause + " " + p[m.start():]
    return p + clause


def sqli_operateurs(p):
    p2 = re.sub(r"\bOR\b", "||", p, flags=re.IGNORECASE)
    p2 = re.sub(r"\bAND\b", "&&", p2, flags=re.IGNORECASE)
    return p2


# --- XSS ---------------------------------------------------------------------

def xss_casse_balises(p):
    p2 = RE_BALISE.sub(lambda m: m.group(0).replace(m.group(1), casse_aleatoire(m.group(1))), p)
    return re.sub(r"\bon[a-z]+", lambda m: casse_aleatoire(m.group(0)), p2, flags=re.IGNORECASE)


def xss_entites_html(p):
    """Encode le contenu des attributs (alert(1) -> &#97;&#108;...)."""
    def encoder(m):
        return m.group(1) + "".join(f"&#{ord(c)};" for c in m.group(2)) + m.group(3)
    p2 = re.sub(r'(=\s*["\'])([^"\']{1,60})(["\'])', encoder, p)
    return p2 if p2 != p else None


def xss_protocole_fragmente(p):
    if "javascript:" not in p.lower():
        return None
    return re.sub("javascript:", lambda _: rng.choice(["java%09script:", "java&#x09;script:",
                                                         "jav&#x0A;ascript:", "JaVaScRiPt:"]),
                  p, flags=re.IGNORECASE)


def xss_separateur_slash(p):
    """<img src=x onerror=...> -> <img/src=x/onerror=...>"""
    p2 = re.sub(r"(<[a-zA-Z]+)\s+", r"\1/", p)
    return p2 if p2 != p else None


# --- LFI / RFI ---------------------------------------------------------------

def lfi_point_point_encode(p):
    if "../" not in p:
        return None
    return p.replace("../", rng.choice(["..%2f", "%2e%2e/", "%2e%2e%2f", "%252e%252e%252f"]))


def lfi_traversee_doublee(p):
    if "../" not in p:
        return None
    return p.replace("../", "....//")


def lfi_antislash(p):
    if "../" not in p:
        return None
    return p.replace("../", "..\\/")


def lfi_octet_nul(p):
    return p + rng.choice(["%00", "%00.php", "%00.html"])


def lfi_wrapper_php(p):
    m = re.search(r"(/etc/[\w./-]+|/proc/[\w./-]+)", p)
    if not m:
        return None
    return "php://filter/convert.base64-encode/resource=" + m.group(1)


# --- RCE ---------------------------------------------------------------------

def rce_ifs(p):
    if " " not in p:
        return None
    return p.replace(" ", rng.choice(["${IFS}", "$IFS$9", "%09"]))


def rce_guillemets(p):
    """cat -> c''at ou c\"\"at"""
    def couper(m):
        mot = m.group(0)
        if len(mot) < 2:
            return mot
        g = rng.choice(["'", '"'])
        i = rng.randint(1, len(mot) - 1)
        return mot[:i] + g + g + mot[i:]
    p2 = RE_COMMANDE.sub(couper, p)
    return p2 if p2 != p else None


def rce_antislash(p):
    p2 = RE_COMMANDE.sub(lambda m: "\\".join(m.group(0)), p)
    return p2 if p2 != p else None


def rce_separateurs(p):
    """Remplace le séparateur de tête par un autre (; | && || retour ligne)."""
    corps = re.sub(r"^[;|&\s]+", "", p)
    if not corps:
        return None
    return rng.choice([";", "%0a", "|", "&&", "||"]) + corps


TECHNIQUES = {
    "sqli": [sqli_casse_mots_cles, sqli_commentaires_inline, sqli_espaces_alternatifs,
             sqli_commentaire_version, sqli_collate, sqli_operateurs,
             encodage_url, encodage_url_partiel, double_encodage_url],
    "xss": [xss_casse_balises, xss_entites_html, xss_protocole_fragmente,
            xss_separateur_slash, encodage_url, encodage_url_partiel, double_encodage_url],
    "lfi_rfi": [lfi_point_point_encode, lfi_traversee_doublee, lfi_antislash,
                lfi_octet_nul, lfi_wrapper_php, encodage_url, double_encodage_url],
    "rce": [rce_ifs, rce_guillemets, rce_antislash, rce_separateurs,
            encodage_url, encodage_url_partiel],
}


def main():
    df = pd.concat([pd.read_csv(f, dtype={"payload": str}, keep_default_na=False) for f in ENTREES])
    attaques = df[(df["label"] == 1) & (df["payload"].str.len() <= LONGUEUR_MAX)]
    existants = set(df["payload"])

    lignes = []
    for famille, techniques in TECHNIQUES.items():
        pool = attaques[attaques["family"] == famille]["payload"].tolist()
        bases = rng.sample(pool, min(BASES_PAR_FAMILLE, len(pool)))
        for base in bases:
            produites = 0
            for technique in rng.sample(techniques, len(techniques)):
                if produites >= VARIANTES_PAR_BASE:
                    break
                variante = technique(base)
                if not variante or variante == base or variante in existants:
                    continue
                existants.add(variante)
                produites += 1
                lignes.append((variante, 1, famille, "variante", technique.__name__))

    out = pd.DataFrame(lignes, columns=["payload", "label", "family", "source", "technique"])
    out.to_csv(OUT, index=False)

    print(f"Variantes générées : {len(out)} -> {OUT.relative_to(BASE)}")
    print("\nPar famille :")
    print(out["family"].value_counts().to_string())
    print("\nPar technique :")
    print(out.groupby(["family", "technique"]).size().to_string())


if __name__ == "__main__":
    main()
