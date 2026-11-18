"""Durcissement par augmentation du SEUL jeu d'entraînement.

Constat (étape 3) : en conditions réelles, l'injection arrive après une valeur
légitime (ex. une adresse IP suivie d'un séparateur). Aucun payload RCE
d'entraînement n'avait ce contexte : le modèle en ratait la majorité.

Itération 1 : préfixer des payloads d'entraînement -> sans effet sur le RCE réel
(les payloads préfixés restaient longs, alors que l'attaque réelle est une
commande courte après une valeur légitime).
Itération 2 : ajout de RCE courts, construits à partir de la liste de commandes
figée en Phase 06 (generate_variants.py), avant toute validation.

Ce script produit data/processed/train_durci.csv = train.csv + :
  - variantes « préfixe de valeur légitime » de payloads d'attaque de train.csv
    (RCE en priorité, SQLi et XSS) ;
  - RCE courts : [valeur légitime] + séparateur + commande [+ argument],
    avec parfois une technique d'évasion ;
  - autant de valeurs légitimes seules (IP, noms d'hôte, nombres, noms, fichiers),
    étiquetées légitimes, pour que le modèle n'apprenne pas « IP = attaque ».

Garde-fous anti-fuite :
  - les bases sont tirées de train.csv uniquement ;
  - toute charge générée présente dans test.csv ou validation_reelle.csv est écartée ;
  - l'adresse 127.0.0.1 (utilisée par la cible DVWA) n'est jamais générée.
"""
import random
from pathlib import Path

import pandas as pd

BASE = Path(__file__).resolve().parents[2]
PROCESSED = BASE / "data/processed"
GRAINE = 42
rng = random.Random(GRAINE)

VARIANTES = {"rce": 1500, "sqli": 500, "xss": 500}
N_RCE_COURTS = 1500
N_LEGITIMES = 4000
# Liste figée en Phase 06 (generate_variants.py, COMMANDES)
COMMANDES = ["cat", "ls", "id", "whoami", "uname", "echo", "ping", "sleep",
             "wget", "curl", "nc", "bash", "sh", "passwd", "type", "dir"]
ARGUMENTS = ["", "", "-a", "-la", "/etc/hosts", "/tmp", "/etc/issue", "1", "5",
             "test", "-c 1 10.0.0.1", "http://example.com/x", "/var/www"]
SEPARATEURS = [";", "|", "&&", "||", "&", "%0a", "\n"]
HOTES = ["example.com", "srv01", "intranet.local", "backup-02", "mail.example.org",
         "db.internal", "web01.corp", "fileserver", "api.example.net", "printer3"]
PRENOMS = ["karim", "sara", "youssef", "nadia", "hamza", "lina", "mehdi", "aya",
           "ilyas", "rania", "anas", "imane", "zakaria", "kenza", "adam", "hiba"]
FICHIERS = ["accueil", "contact", "profil", "rapport", "galerie", "aide", "tarifs", "blog"]


def ip_aleatoire():
    while True:
        ip = ".".join(str(rng.randint(1, 254)) for _ in range(4))
        if ip != "127.0.0.1":
            return ip


def valeur_legitime():
    tirage = rng.random()
    if tirage < 0.45:
        return ip_aleatoire()
    if tirage < 0.60:
        return rng.choice(HOTES)
    if tirage < 0.75:
        return str(rng.randint(1, 99999))
    if tirage < 0.90:
        return rng.choice(PRENOMS) + (str(rng.randint(1, 99)) if rng.random() < 0.5 else "")
    return rng.choice(FICHIERS) + rng.choice([".php", ".html", ".txt"])


def prefixer(payload, famille):
    if famille == "rce":
        prefixe = ip_aleatoire() if rng.random() < 0.7 else rng.choice(HOTES)
        corps = payload.lstrip()
        if not corps[:1] in (";", "|", "&", "\n", "`", "$") and not corps.lower().startswith("%0a"):
            corps = rng.choice(SEPARATEURS) + corps
        return prefixe + corps
    if famille == "sqli":
        return str(rng.randint(1, 9999)) + payload if not payload[:1].isdigit() else None
    if famille == "xss":
        return rng.choice(PRENOMS) + payload
    return None


def rce_court():
    cmd = rng.choice(COMMANDES)
    arg = rng.choice(ARGUMENTS)
    corps = cmd + (" " + arg if arg else "")
    evasion = rng.random()
    if evasion < 0.15:
        corps = corps.replace(" ", "${IFS}")
    elif evasion < 0.30 and len(cmd) > 1:
        i = rng.randint(1, len(cmd) - 1)
        corps = cmd[:i] + rng.choice(["''", '""', "\\"]) + cmd[i:] + corps[len(cmd):]
    prefixe = ""
    if rng.random() < 0.8:
        prefixe = ip_aleatoire() if rng.random() < 0.7 else rng.choice(HOTES)
    sep = rng.choice(SEPARATEURS)
    return prefixe + sep + corps if rng.random() < 0.9 else prefixe + sep + "`" + corps + "`"


def main():
    lire = lambda n: pd.read_csv(PROCESSED / n, dtype=str, keep_default_na=False)
    train = lire("train.csv")
    interdits = set(lire("test.csv")["payload"]) | set(lire("validation_reelle.csv")["payload"])
    existants = set(train["payload"]) | interdits

    lignes = []
    for famille, n in VARIANTES.items():
        pool = train[(train["label"] == "1") & (train["family"] == famille)]["payload"].tolist()
        produites, essais = 0, 0
        while produites < n and essais < n * 20:
            essais += 1
            v = prefixer(rng.choice(pool), famille)
            if not v or v in existants:
                continue
            existants.add(v)
            lignes.append((v, "1", famille, "augmentation", "prefixe_valeur_legitime"))
            produites += 1

    produites, essais = 0, 0
    while produites < N_RCE_COURTS and essais < N_RCE_COURTS * 20:
        essais += 1
        v = rce_court()
        if v in existants:
            continue
        existants.add(v)
        lignes.append((v, "1", "rce", "augmentation", "rce_commande_courte"))
        produites += 1

    produites, essais = 0, 0
    while produites < N_LEGITIMES and essais < N_LEGITIMES * 20:
        essais += 1
        v = valeur_legitime()
        if v in existants:
            continue
        existants.add(v)
        lignes.append((v, "0", "benign", "augmentation", "valeur_legitime"))
        produites += 1

    ajout = pd.DataFrame(lignes, columns=["payload", "label", "family", "source", "technique"])
    durci = pd.concat([train, ajout], ignore_index=True).sample(frac=1, random_state=GRAINE)
    durci.to_csv(PROCESSED / "train_durci.csv", index=False)

    print(f"train.csv : {len(train)}   ajouts : {len(ajout)}   train_durci.csv : {len(durci)}")
    print("\nAjouts par famille :")
    print(ajout["family"].value_counts().to_string())
    print("\nAjouts par technique :")
    print(ajout["technique"].value_counts().to_string())
    fuite = ajout["payload"].isin(interdits).sum()
    print(f"\nContrôle anti-fuite : {fuite} charge(s) commune(s) avec test / validation réelle")


if __name__ == "__main__":
    main()
