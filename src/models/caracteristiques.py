"""Caractéristiques de STRUCTURE des requêtes (itération 3 du durcissement).

Les n-grammes de caractères reconnaissent un vocabulaire déjà vu (ex. « whoami »),
mais pas une commande inconnue (ex. « hostname »). On ajoute donc des
caractéristiques définies à partir de la grammaire des attaques, calculées sur la
requête NORMALISÉE (décodage URL répété + entités HTML) :

  - RCE  : séparateur shell suivi d'un mot, valeur suivie d'un séparateur,
           substitution `...` / $(...), ${IFS}, mot coupé par guillemets/antislash ;
  - SQLi : guillemets, commentaires, mots-clés, comparaisons ;
  - XSS  : balise, gestionnaire d'événement, protocole javascript: ;
  - LFI  : traversée, chemin système, wrapper ;
  - génériques : longueur, proportion de caractères spéciaux, encodage.

Aucune valeur issue des jeux de validation n'a servi à définir ces règles.
"""
import html
import re
from urllib.parse import unquote

import numpy as np
from scipy.sparse import csr_matrix
from sklearn.base import BaseEstimator, TransformerMixin


def normaliser(texte, tours=3):
    """Décode l'URL et les entités HTML jusqu'à stabilité (3 tours maximum)."""
    for _ in range(tours):
        decode = html.unescape(unquote(texte))
        if decode == texte:
            break
        texte = decode
    return texte


SEP = r"(?:;|\|\||\||&&|&|\n|\r|`|\$\()"
MOTIFS = {
    "sep_puis_mot": re.compile(SEP + r"\s*[A-Za-z_./\\'\"]"),
    "valeur_puis_sep": re.compile(r"^[\w.:-]{1,64}\s*" + SEP),
    "substitution": re.compile(r"`[^`]+`|\$\([^)]+\)"),
    "ifs": re.compile(r"\$\{?IFS", re.I),
    "mot_coupe": re.compile(r"[A-Za-z](?:''|\"\"|\\)[A-Za-z]"),
    "chemin_systeme": re.compile(r"/(?:etc|bin|usr|proc|var|tmp|dev|windows)/", re.I),
    "traversee": re.compile(r"\.\.[/\\]"),
    "wrapper": re.compile(r"\b[a-z]{2,10}://", re.I),
    "balise": re.compile(r"<\s*/?\s*[A-Za-z]"),
    "evenement": re.compile(r"\bon[a-z]{3,}\s*=", re.I),
    "proto_js": re.compile(r"javascript\s*:", re.I),
    "guillemet": re.compile(r"['\"]"),
    "commentaire_sql": re.compile(r"--|#|/\*"),
    "mot_sql": re.compile(r"\b(select|union|insert|update|delete|drop|from|where|sleep|"
                          r"benchmark|having|and|or|xor|not|null|case|when)\b", re.I),
    "comparaison": re.compile(r"\w\s*(?:=|<|>|\blike\b)\s*\w", re.I),
}
RE_POURCENT = re.compile(r"%[0-9a-fA-F]{2}")
NOMS = list(MOTIFS) + ["longueur", "longueur_normalisee", "part_speciaux",
                       "part_chiffres", "espaces", "encodage_pct", "a_ete_decode"]


def vecteur(brut):
    texte = normaliser(brut)
    n = max(len(texte), 1)
    v = [len(m.findall(texte)) for m in MOTIFS.values()]
    v += [
        len(brut),
        len(texte),
        sum(not c.isalnum() and not c.isspace() for c in texte) / n,
        sum(c.isdigit() for c in texte) / n,
        texte.count(" "),
        len(RE_POURCENT.findall(brut)),
        float(texte != brut),
    ]
    return v


class StructureRequete(BaseEstimator, TransformerMixin):
    """Transformateur scikit-learn : une ligne de caractéristiques par requête."""

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        return csr_matrix(np.array([vecteur(str(x)) for x in X], dtype=np.float32))

    def get_feature_names_out(self, input_features=None):
        return np.array(NOMS)
