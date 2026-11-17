# Phase 6 — Constitution du dataset

## Objectif

Construire un jeu de données étiqueté de requêtes HTTP pour entraîner les deux modèles de la couche IA :

- **détection binaire** : légitime ou malveillant ;
- **classification de famille** : SQLi, XSS, LFI/RFI, RCE.

Le dataset doit contenir des **variantes d'évasion**, afin que les modèles apprennent à reconnaître une attaque par sa nature et non par sa forme, ce que la détection par signatures ne sait pas faire.

## 1. Environnement de travail

Tout le travail est réalisé sur la VM `ia-soc` (zone IA, 192.168.50.10), dans un environnement virtuel Python dédié (Python 3.12, pandas, numpy).

```
~/waf-ia/
  src/dataset/      scripts (versionnés dans ce dépôt)
  data/raw/         sources publiques clonées (non versionnées)
  data/processed/   jeux de données produits (non versionnés)
```

## 2. Schéma commun

Toutes les sources sont ramenées au même format :

| Colonne | Description |
|---------|-------------|
| `payload` | Chaîne analysée (paramètre de requête HTTP) |
| `label` | 0 = légitime, 1 = malveillant |
| `family` | `benign`, `sqli`, `xss`, `lfi_rfi`, `rce` |
| `source` | Origine de l'exemple (`httpparams`, `patt`, `seclists`, `variante`) |
| `technique` | Technique d'évasion appliquée (variantes uniquement) |

## 3. Sources publiques

| Source | Apport |
|--------|--------|
| HttpParamsDataset | Paramètres HTTP réels étiquetés : trafic légitime et attaques |
| PayloadsAllTheThings | Payloads d'attaque classés par famille |
| SecLists (dossier `Fuzzing`) | Payloads d'attaque complémentaires |

**Preuve** : `06-sources-publiques-clonees.png`

## 4. Ingestion

### HttpParamsDataset — `ingest_httpparams.py`

Correspondance des types vers le schéma commun (`norm` → `benign`, `path-traversal` → `lfi_rfi`, `cmdi` → `rce`), suppression des lignes vides et des doublons.

| Famille | Exemples |
|---------|----------|
| benign | 19 304 |
| sqli | 10 852 |
| xss | 532 |
| lfi_rfi | 290 |
| rce | 89 |

Cette source fournit l'essentiel du trafic légitime, mais ses familles d'attaque sont très déséquilibrées (10 852 SQLi contre 89 RCE).

**Preuve** : `06-ingestion-httpparams.png`

### PayloadsAllTheThings et SecLists — `ingest_payloads.py`

Lecture des seuls dossiers pertinents pour chaque famille, avec trois filtres :

- exclusion des listes de chemins génériques, qui ne sont pas malveillantes en soi ;
- exclusion des listes massives quasi identiques, qui déséquilibreraient le jeu ;
- pour LFI/RFI, conservation des seules lignes contenant un indicateur d'inclusion.

| Famille | PayloadsAllTheThings | SecLists |
|---------|----------------------|----------|
| sqli | 1 326 | 535 |
| xss | 2 113 | 8 645 |
| lfi_rfi | 5 013 | 842 |
| rce | 478 | 8 262 |

Résultat : 27 214 payloads uniques, qui comblent le manque de XSS, LFI/RFI et RCE.

**Preuve** : `06-ingestion-payloads-publics.png`

## 5. Variantes d'évasion — `generate_variants.py`

800 attaques sont tirées par famille. Deux techniques de contournement, choisies au hasard parmi celles de la famille, sont appliquées à chacune. La variante conserve la famille d'origine et la technique utilisée est enregistrée.

| Famille | Techniques |
|---------|------------|
| SQLi | casse aléatoire des mots-clés, commentaires en ligne, espaces alternatifs, commentaires exécutables MySQL, clause `COLLATE`, opérateurs logiques alternatifs |
| XSS | casse des balises et des gestionnaires d'événements, entités HTML, protocole fragmenté, séparateurs alternatifs |
| LFI/RFI | traversée encodée, traversée doublée, antislash, octet nul, wrapper PHP |
| RCE | séparateur de champs shell, guillemets et antislashs dans les commandes, séparateurs de commandes alternatifs |
| Toutes | encodage URL simple, partiel et double |

La clause `COLLATE` reproduit la technique qui a permis, lors de la démonstration, d'extraire un hash de mot de passe sans déclencher d'alerte.

Résultat : 6 368 variantes (environ 1 600 par famille). La graine aléatoire est fixée : le résultat est reproductible à l'identique.

**Preuve** : `06-variantes-evasion.png`

## 6. Dataset final — `build_dataset.py`

Fusion des trois jeux, suppression des doublons inter-sources (61), puis équilibrage :

- 2 200 exemples par famille d'attaque, les variantes d'évasion étant retenues en priorité ;
- 8 800 exemples légitimes, soit autant que l'ensemble des attaques.

Séparation stratifiée par famille : 80 % entraînement, 20 % test.

| Famille | Exemples |
|---------|----------|
| benign | 8 800 |
| sqli | 2 200 |
| xss | 2 200 |
| lfi_rfi | 2 200 |
| rce | 2 200 |
| **Total** | **17 600** |

| Jeu | Exemples |
|-----|----------|
| Entraînement | 14 080 |
| Test | 3 520 |

Les variantes d'évasion représentent 72,4 % des attaques (6 368 sur 8 800) : c'est volontaire, puisque l'objectif est la détection des attaques reformulées.

**Preuve** : `06-dataset-final.png`

## 7. Reproduire le dataset

Depuis la racine du dossier de travail, avec l'environnement virtuel actif :

```
git clone --depth 1 https://github.com/Morzeux/HttpParamsDataset.git data/raw/HttpParamsDataset
git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git data/raw/PayloadsAllTheThings
git clone --depth 1 --filter=blob:none --sparse https://github.com/danielmiessler/SecLists.git data/raw/SecLists
git -C data/raw/SecLists sparse-checkout set Fuzzing

python src/dataset/ingest_httpparams.py
python src/dataset/ingest_payloads.py
python src/dataset/generate_variants.py
python src/dataset/build_dataset.py
```

Les données produites ne sont pas versionnées dans ce dépôt (volume, et présence de payloads d'attaque).

## Suite

Un jeu de validation distinct, composé de payloads réels rejoués depuis Kali à travers le WAF, sera constitué avant l'entraînement. Il ne sera jamais utilisé pour l'apprentissage et servira à mesurer la capacité des modèles à généraliser sur des attaques inconnues.
