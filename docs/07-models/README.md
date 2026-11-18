# Phase 7 — Modèles de détection : cycle de vie sécurisé

## Objectif

Entraîner les deux modèles de la couche IA (détection binaire, classification de famille) en appliquant au modèle et à son entraînement la même démarche de sécurité que celle appliquée au reste de l'architecture. Un modèle de détection mal protégé peut devenir le maillon faible de la chaîne.

## Cycle de vie appliqué

| Étape | Application au modèle |
|-------|-----------------------|
| 1. Threat Modeling | Actifs IA, frontières de confiance, menaces (OWASP Machine Learning Security Top 10) |
| 2. Secure Development | Intégrité des données et des sources, dépendances figées, entraînement reproductible, intégrité du modèle par empreinte |
| 3. Security Assessment | Évaluation sur le jeu de test et sur des requêtes réelles rejouées depuis Kali à travers le WAF, y compris évasives |
| 4. Hardening | Correction de la faiblesse constatée en 3 itérations (augmentation ciblée, caractéristiques de structure sur requête normalisée), contrôle d'intégrité au chargement |
| 5. Re-testing | Mêmes jeux réels avant / après, puis deux jeux RCE inédits dont un jeu aveugle final |
| 6. Continuous Monitoring | Agent Wazuh sur `ia-soc` : surveillance en temps réel des modèles, manifestes et données, règles d'alerte dédiées ; fermeture d'un contournement réseau |

## 1. Threat Modeling

### Actifs à protéger

| Actif | Emplacement | Pourquoi il est sensible |
|-------|-------------|--------------------------|
| Dataset (brut et traité) | `ia-soc`, `data/` | Sa falsification oriente l'apprentissage |
| Modèles entraînés | `ia-soc`, `models/` | Leur remplacement ou altération change les décisions de détection |
| Code d'entraînement | Dépôt Git | Une modification altère le modèle produit |
| Service d'analyse (phase ultérieure) | `ia-soc` | Exposé aux requêtes issues du trafic analysé |

### Frontières de confiance

1. Sources publiques (Internet) vers `ia-soc` : données non maîtrisées, entrée de l'entraînement.
2. Requêtes analysées (issues de l'attaquant) vers le modèle : entrée hostile par nature, au moment de l'inférence.

### Menaces

| Menace | OWASP ML | Risque pour le projet | Traitée à l'étape |
|--------|----------|-----------------------|-------------------|
| Empoisonnement des données | ML02 | Une source publique modifiée apprend au modèle à laisser passer certaines attaques | 2 |
| Chaîne d'approvisionnement | ML06 | Dépendance Python ou dépôt de données compromis | 2 |
| Contournement du modèle | ML01 | L'attaquant reformule son attaque pour tromper le modèle, comme il le fait avec le WAF | 3, 4, 5 |
| Altération du fichier modèle | ML10 | Un fichier modèle remplacé peut exécuter du code au chargement ou fausser les décisions | 2, 4, 6 |
| Vol / extraction du modèle | ML05 | Interrogation en masse du service pour reconstruire sa logique | 6 (et service d'analyse) |
| Dérive | ML08 | Les attaques évoluent, la performance baisse sans être vue | 6 |

### Constat issu de la Phase 06

Les sources publiques ont été clonées sans noter leur version exacte (empreinte de commit). Sans cette trace, une modification de la source ne pourrait pas être prouvée. Première action de l'étape 2.

## 2. Secure Development

### 2.1 Traçabilité des sources et intégrité des données — `src/security/provenance.py`

Le commit exact de chaque source publique et l'empreinte SHA-256 de chaque fichier de `data/processed/` sont enregistrés dans un manifeste versionné (`src/security/manifest.json`). Les données ne sont pas versionnées, mais toute modification devient détectable.

| Source | Commit |
|--------|--------|
| HttpParamsDataset | `926670a710283f87c05b554680facf3f9530548c` |
| PayloadsAllTheThings | `08ea40e77db3f42ef8f20c65196f3936a19b6c86` |
| SecLists | `6b19c2f5088c45b5dadb4d8918d2ab4f7efb03a9` |

```
python src/security/provenance.py generer    # enregistre le manifeste
python src/security/provenance.py verifier   # code retour 1 en cas d'écart
```

Résultat : 3 sources et 6 fichiers conformes au manifeste.

**Preuves** : `07-provenance-sources-et-hash.png`, `07-manifeste-integrite.png`

### 2.2 Dépendances figées et auditées

Les versions exactes de toutes les bibliothèques sont figées dans `requirements.txt` (notamment scikit-learn 1.9.1, pandas 3.1.1, numpy 2.5.5, joblib 1.6.0). L'outil `pip-audit` compare chaque paquet à la base publique des vulnérabilités connues.

Résultat : aucune vulnérabilité connue.

**Preuve** : `07-dependances-audit.png`

### 2.3 Entraînement reproductible — `src/models/train_baseline.py`

- vérification du manifeste des données avant tout apprentissage : en cas d'écart, l'entraînement est annulé (ML02) ;
- graine fixée (42), versions enregistrées ;
- représentation : n-grammes de caractères (2 à 4) pondérés TF-IDF, 20 000 attributs, sans mise en minuscules ni décodage (état avant durcissement) ;
- modèle : Random Forest, 200 arbres ;
- détection binaire entraînée sur tous les exemples, classification de famille sur les attaques seulement ;
- empreinte SHA-256 de chaque modèle enregistrée dans `src/security/models_manifest_baseline.json`, avec la graine, les versions, l'empreinte du manifeste des données, celle de `requirements.txt` et les métriques (ML10).

**Résultats sur le jeu de test (3 520 exemples)**

| Détection binaire | Valeur |
|-------------------|--------|
| Accuracy | 99,57 % |
| Précision | 100,00 % |
| Rappel | 99,15 % |
| F1 | 99,57 % |
| Taux de faux positifs | 0,00 % (0 faux positif, 15 faux négatifs) |

| Classification de famille | Rappel |
|---------------------------|--------|
| LFI/RFI | 100,00 % |
| RCE | 98,64 % |
| SQLi | 99,77 % |
| XSS | 100,00 % |
| **Accuracy globale** | **99,60 %** |

Techniques d'évasion les moins bien détectées : casse des balises XSS (95,74 %), guillemets dans les commandes RCE (95,83 %), séparateurs de commandes RCE (97,85 %). Toutes les autres techniques sont détectées à 100 %.

**Limite** : le jeu de test contient des variantes issues des mêmes payloads d'origine que certaines variantes d'entraînement. Ces scores sont donc optimistes. La capacité de généralisation est mesurée à l'étape 3, sur des requêtes réelles jamais vues.

| Modèle | SHA-256 |
|--------|---------|
| Détection binaire | `4c5add622b5df08b140f9254b73b7aaad7a6367e8e2e8a7555a2327b17b0e81e` |
| Classification de famille | `c1f05799c9a9bc24102e0d5d11eb1c6085b2a4cfc0318d79efd366fa73b9ea52` |

**Preuve** : `07-entrainement-baseline.png`

## 3. Security Assessment

### 3.1 Constitution du jeu de validation réel

Des requêtes réelles ont été rejouées depuis Kali, à travers le WAF, vers DVWA (session authentifiée, niveau « low ») :

- SQLi : `sqlmap`, en passe classique puis en passe évasive (tampers `space2comment`, `randomcase`, `charencode`) ;
- XSS, LFI/RFI et RCE : requêtes classiques et variantes de forme ;
- trafic légitime : valeurs normales envoyées aux mêmes endpoints (identifiants numériques, noms, noms de fichiers, adresses IP), afin de mesurer les faux positifs.

Le WAF a bloqué toutes les injections sqlmap (403), y compris en passe évasive.

Pendant la collecte, la journalisation ModSecurity a été passée temporairement de `RelevantOnly` à `On`, pour enregistrer aussi les requêtes non bloquées. Le blocage n'a pas été modifié. La configuration d'origine a ensuite été restaurée depuis une sauvegarde.

**Preuves** : `07-waf-audit-complet-collecte.png`, `07-waf-retour-relevantonly.png`

### 3.2 Extraction et étiquetage — `src/models/extraire_validation.py`

Le script lit le journal d'audit natif (partie B : ligne de requête, parties C/I : corps POST) et extrait la valeur de chaque paramètre. L'étiquetage suit une liste blanche : sur un endpoint vulnérable, une charge n'est bénigne que si elle respecte le format normal du paramètre (`id` : chiffres ; `name` : lettres et chiffres ; `page` : nom de fichier simple ; `ip` : adresse IPv4 ou nom d'hôte). Toute autre charge est une attaque de la famille de l'endpoint.

| Famille | Requêtes uniques |
|---------|------------------|
| SQLi | 1 234 |
| XSS | 15 |
| LFI/RFI | 13 |
| RCE | 11 |
| Légitime | 38 |
| **Total** | **1 311** |

Le jeu reste déséquilibré : sqlmap produit un grand nombre de variantes. L'équilibrage est réalisé au moment de la mesure, sans supprimer de données réelles.

**Preuve** : `07-extraction-validation.png`

### 3.3 Mesure — `src/models/evaluer_validation.py`

Les 3 requêtes déjà présentes dans le jeu d'entraînement sont retirées : 1 308 requêtes inédites sont évaluées. Le rappel est mesuré par famille, ce qui le rend insensible au déséquilibre. Un score global est aussi calculé sur un échantillon équilibré (SQLi plafonné à 150).

| Détection binaire | Rappel | Exemples |
|-------------------|--------|----------|
| SQLi | 99,35 % | 1 233 |
| XSS | 100,00 % | 15 |
| LFI/RFI | 100,00 % | 12 |
| RCE | **36,36 %** | 11 |
| Faux positifs | 1 sur 37 légitimes (2,70 %) | |

| Classification de famille (attaques détectées) | Exactitude | Exemples |
|------------------------------------------------|------------|----------|
| SQLi | 100,00 % | 1 225 |
| XSS | 100,00 % | 15 |
| LFI/RFI | 100,00 % | 12 |
| RCE | **0,00 %** | 4 |

Échantillon équilibré (225 requêtes) : exactitude 96,00 %, rappel des attaques 95,74 %.

**Preuve** : `07-evaluation-validation-reelle.png`

### 3.4 Constats

- Le modèle généralise bien sur SQLi, XSS et LFI/RFI, y compris sur les injections évasives produites par sqlmap.
- **Faiblesse confirmée sur le RCE** : 4 injections de commandes détectées sur 11, et aucune bien classée. Le jeu de test annonçait pourtant 98,64 % : l'écart confirme que ce jeu surestimait la généralisation.
- Le taux de faux positifs est faible, mais il repose sur 37 exemples légitimes seulement : il est indicatif.
- Les effectifs XSS, LFI/RFI et RCE sont réduits (11 à 15 exemples) : ces rappels sont des tendances, pas des mesures précises.

Ces constats orientent le durcissement (étape 4).

## 4. Hardening

La correction porte sur la faiblesse RCE constatée à l'étape 3. Règle suivie : seules les données d'entraînement sont enrichies, `test.csv` et les jeux réels ne changent jamais, et toute charge générée présente dans un jeu de test ou de validation est écartée (contrôle anti-fuite).

### 4.1 Diagnostic

| Constat | Valeur |
|---------|--------|
| RCE réels commençant par une adresse IP | 11 sur 11 |
| RCE d'entraînement commençant par une adresse IP | 0 sur 1 760 |

Dans l'application cible, l'injection de commande arrive après une valeur légitime. Ce contexte était absent de l'entraînement.

### 4.2 Itération 1 — préfixe de valeur légitime — `src/dataset/augmenter_train.py`

Ajout à l'entraînement de payloads d'attaque de `train.csv` préfixés par une valeur légitime (IP, nom d'hôte, nombre), et d'autant de valeurs légitimes seules, pour éviter que le modèle n'apprenne « IP = attaque ». L'adresse `127.0.0.1` utilisée par la cible n'est jamais générée.

Résultat : 5 000 ajouts, contrôle anti-fuite à 0. **Sans effet sur le RCE réel** (36,36 % inchangé) : les payloads préfixés restaient longs, alors que l'attaque réelle est une commande courte.

**Preuves** : `07-augmentation-train-durci.png`, `07-manifeste-mise-a-jour.png`, `07-entrainement-durci.png`

### 4.3 Itération 2 — commandes courtes

Ajout de 1 500 RCE courts construits à partir de la liste de commandes figée en Phase 06, avant toute validation (valeur légitime facultative, séparateur, commande, argument, parfois une technique d'évasion), et de 1 500 valeurs légitimes supplémentaires. Jeu d'entraînement : 22 080 exemples.

Résultat sur les RCE réels : 81,82 %. Mais sur un jeu de **commandes jamais vues** (étape 5) : 25 %. Le modèle reconnaissait un vocabulaire, pas une structure.

**Preuves** : `07-augmentation-iteration2.png`, `07-iteration2-entrainement-et-retest.png`

### 4.4 Itération 3 — caractéristiques de structure — `src/models/caracteristiques.py`, `src/models/train_final.py`

Les n-grammes de caractères sont complétés par 22 caractéristiques définies à partir de la grammaire des attaques, et non des exemples. Elles sont calculées sur la requête **normalisée** (décodage URL répété jusqu'à 3 fois, entités HTML) :

| Famille | Caractéristiques |
|---------|------------------|
| RCE | séparateur shell suivi d'un mot, valeur suivie d'un séparateur, substitution `` `…` `` / `$(…)`, `${IFS}`, mot coupé par guillemets ou antislash |
| SQLi | guillemets, commentaires, mots-clés, comparaisons |
| XSS | balise, gestionnaire d'événement, protocole `javascript:` |
| LFI/RFI | traversée, chemin système, wrapper |
| Génériques | longueurs brute et normalisée, proportion de caractères spéciaux et de chiffres, espaces, encodage |

Modèle final : n-grammes TF-IDF (10 000 attributs) + structure, Random Forest de 200 arbres, 3 % des attributs examinés à chaque nœud, graine 42. Mêmes données que l'itération 2.

Les caractéristiques de structure représentent **52,4 %** de l'importance des décisions du modèle binaire. Le séparateur shell suivi d'un mot (`sep_puis_mot`) figure parmi les plus utilisées.

| Jeu de test (3 520) | Baseline | Itération 1 | Itération 2 | **Final** |
|---------------------|----------|-------------|-------------|-----------|
| Accuracy binaire | 99,57 % | 99,63 % | 99,74 % | **99,77 %** |
| Précision | 100,00 % | 100,00 % | 99,94 % | **100,00 %** |
| Rappel | 99,15 % | 99,26 % | 99,55 % | **99,55 %** |
| Faux positifs | 0 | 0 | 1 | **0** |
| Accuracy famille | 99,60 % | 99,55 % | 99,49 % | **99,77 %** |

| Modèle final | SHA-256 |
|--------------|---------|
| Détection binaire | `cc30f6da0440ca6e4985d63562deea3a93847f20ac81930c34f8e3eda77d76d6` |
| Classification de famille | `957af86bb29e7466970ec9e5e8034ef69fafd5c897fbef5d2c3c7f1359e849ca` |

**Preuve** : `07-entrainement-final.png`

### 4.5 Intégrité des données en action

L'ajout d'un nouveau fichier de données non déclaré au manifeste a provoqué l'arrêt de l'entraînement (« Entraînement annulé : intégrité des données non garantie »). L'entraînement n'a repris qu'après validation explicite de l'ajout (`provenance.py generer`).

**Preuve** : `07-blocage-entrainement-integrite.png`

### 4.6 Chargement sécurisé — `src/models/chargement_sur.py`

Un fichier joblib est désérialisé avec pickle : un fichier remplacé peut exécuter du code dès son chargement (ML10). L'empreinte SHA-256 est donc vérifiée par rapport au manifeste **avant** tout chargement. Toutes les évaluations passent par ce contrôle.

Test : le modèle final a été volontairement altéré (ajout d'un octet). Le chargement a été refusé avant désérialisation, avec affichage des empreintes obtenue et attendue. Après restauration, le chargement est de nouveau accepté.

**Preuve** : `07-test-alteration-modele.png`

## 5. Re-testing

### 5.1 Jeu réel de l'étape 3 (1 308 requêtes inédites)

| Détection binaire | Baseline | Itération 1 | Itération 2 | **Final** |
|-------------------|----------|-------------|-------------|-----------|
| SQLi (1 233) | 99,35 % | 99,35 % | 99,35 % | **99,76 %** |
| XSS (15) | 100,00 % | 100,00 % | 100,00 % | **100,00 %** |
| LFI/RFI (12) | 100,00 % | 100,00 % | 100,00 % | **100,00 %** |
| RCE (11) | 36,36 % | 36,36 % | 81,82 % | **100,00 %** |
| Faux positifs (37 légitimes) | 1 | 0 | 1 | **0** |
| Classification RCE | 0,00 % | 0,00 % | 100,00 % | **100,00 %** |
| Échantillon équilibré : exactitude | 96,00 % | 96,44 % | 98,22 % | **99,56 %** |

La version baseline a redonné exactement les chiffres de l'étape 3 : la mesure est reproductible.

**Preuves** : `07-retest-baseline.png`, `07-retest-durci.png`, `07-iteration2-entrainement-et-retest.png`, `07-retest-final-validation.png`

### 5.2 Jeu RCE « commandes inconnues »

Ce jeu a été collecté selon la même méthode, avec des commandes absentes de la liste d'apprentissage. Il contient 8 RCE et 2 requêtes légitimes.

| | Baseline | Itération 2 | **Final** |
|---|----------|-------------|-----------|
| RCE détectés | 0 % | 25 % | **100 %** |
| Faux positifs | 0 / 2 | 0 / 2 | **0 / 2** |

Ce jeu a motivé l'ajout des caractéristiques de structure : il n'est donc plus totalement aveugle pour la version finale.

**Preuves** : `07-extraction-rce-inconnu.png`, `07-verdict-rce.png`, `07-retest-final-rce2.png`

### 5.3 Jeu aveugle final

Collecté après la construction du modèle final, ce jeu n'a influencé aucune décision. Il emploie d'autres commandes et d'autres formes d'évasion (substitution `$(…)`, backticks, mots coupés, nom d'hôte en préfixe, saut de ligne encodé). Il contient 8 RCE et 7 requêtes légitimes.

| | Baseline | **Final** |
|---|----------|-----------|
| RCE détectés | 100 % | **100 %** |
| RCE bien classés | 12,5 % | **100 %** |
| Faux positifs | 0 / 7 | **0 / 7** |

Les chemins système présents dans ces injections les rendaient détectables, même par la baseline. La différence porte sur la classification : la baseline rangeait 7 RCE sur 8 dans une autre famille.

**Preuves** : `07-extraction-aveugle.png`, `07-verdict-aveugle.png`

## 6. Continuous Monitoring

### 6.1 Contournement réseau détecté et corrigé

La carte de gestion de `ia-soc` (192.168.56.70) se trouve sur le même réseau que le manager Wazuh. Le flux passait directement (TTL 64, sans routeur), donc sans contrôle de pfSense : la zone IA disposait d'une porte latérale vers le SOC.

Correction : pare-feu local `ufw` sur `ia-soc`. Sur la carte de gestion, seuls deux flux restent autorisés :

- entrée : SSH depuis le poste d'administration ;
- sortie : agent Wazuh vers 192.168.56.20, ports TCP 1514-1515.

Vérification : ping vers Wazuh bloqué, port 1514 autorisé, port 443 (dashboard) bloqué.

**Preuves** : `07-ufw-carte-gestion.png`, `07-ufw-carte-gestion-status.png`

### 6.2 Agent Wazuh

Agent installé en version identique au manager (4.9.2), version bloquée (`apt-mark hold`), nommé `ia-soc`.

**Preuves** : `07-ia-agent-wazuh-running.png`, `07-wazuh-agent-ia-actif.png`

### 6.3 Surveillance d'intégrité en temps réel (FIM)

Dossiers surveillés en temps réel (taille, droits, propriétaire, dates, MD5, SHA-1, SHA-256) :

- `models/` (modèles) ;
- `src/security/` (manifestes d'empreintes, résultats) ;
- `data/processed/` (données d'entraînement et de validation).

Configuration : `configs/ia-soc/ossec-syscheck.conf`.

**Preuve** : `07-ia-fim-configure.png`

### 6.4 Règles d'alerte dédiées

Les règles sont ajoutées dans `local_rules.xml`, dans un groupe `ia_integrite`. Copie versionnée : `rules/wazuh/local_rules_ia.xml`.

| Règle | Niveau | Événement | MITRE |
|-------|--------|-----------|-------|
| 100300 | 12 | Fichier de modèle modifié | T1565.001 |
| 100301 | 12 | Fichier de modèle supprimé | T1565.001 |
| 100302 | 10 | Nouveau fichier dans le dossier des modèles | T1565.001 |
| 100303 | 10 | Manifeste ou donnée d'entraînement modifié | T1565.001 |

**Preuve** : `07-wazuh-regles-integrite-ia.png`

### 6.5 Test de bout en bout

L'altération volontaire du modèle final a produit deux alertes de niveau 12 (altération puis restauration). Le détail de chaque alerte indique le chemin, les attributs modifiés, les empreintes avant et après, et la technique MITRE. L'écriture des résultats d'évaluation dans `src/security/` a aussi déclenché la règle 100303 (niveau 10), comme prévu.

Deux protections se complètent :

- **détection** : Wazuh alerte le SOC dès l'altération ;
- **prévention** : le chargement sécurisé refuse le fichier altéré.

**Preuves** : `07-wazuh-alerte-modele-altere.png`, `07-wazuh-alerte-modele-detail.png`

## 7. Bilan des menaces

| Menace | OWASP ML | Mesure en place | Vérifiée par |
|--------|----------|-----------------|--------------|
| Empoisonnement des données | ML02 | Manifeste des sources et des données, entraînement refusé en cas d'écart, FIM sur `data/processed/` | Blocage réel de l'entraînement, alerte 100303 |
| Chaîne d'approvisionnement | ML06 | Dépendances figées, `pip-audit`, versions de l'agent bloquées | Aucune vulnérabilité connue |
| Contournement du modèle | ML01 | Requêtes réelles et évasives, augmentation ciblée, caractéristiques de structure sur requête normalisée | Jeu aveugle final : 100 % des RCE détectés et classés |
| Altération du fichier modèle | ML10 | Empreinte vérifiée avant chargement, FIM temps réel, règles de niveau 12 | Chargement refusé, alertes 100300 |
| Vol / extraction du modèle | ML05 | Zone IA isolée, carte de gestion filtrée | Limitation des requêtes à mettre en place avec le service d'analyse |
| Dérive | ML08 | Jeux de validation réels reproductibles | Journalisation des prédictions à mettre en place avec le service d'analyse |

## 8. Limites

- Les effectifs réels XSS, LFI/RFI et RCE restent réduits (8 à 15 exemples par jeu). Les rappels de ces familles sont des tendances fortes, pas des mesures précises.
- Le taux de faux positifs repose sur une quarantaine de requêtes légitimes, envoyées vers une seule application cible.
- Les jeux de l'étape 3 et le jeu des commandes inconnues ont guidé le durcissement. Seul le jeu aveugle final est entièrement indépendant des choix de conception.

## Suite

Le service d'analyse continue (Phase 08) chargera les modèles finaux via `chargement_sur.py`. Il ajoutera la journalisation des prédictions, pour suivre la dérive (ML08), et une limitation du nombre de requêtes, contre l'extraction du modèle (ML05).
