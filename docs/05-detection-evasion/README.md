# Phase 5 — Pont de normalisation et détection par famille

## Objectif

Transformer les alertes ModSecurity brutes en alertes structurées et exploitables : classifier chaque attaque par famille (SQLi, XSS, LFI, RFI, RCE) et par gravité (3 niveaux selon le score d'anomalie du CRS).

## 1. Point de départ (avant normalisation)

L'outil `wazuh-logtest` confirme que le décodage natif n'extrait que l'IP source et l'identifiant ModSecurity. L'id de règle CRS, le score et la famille restent non structurés ; la règle native 30411 est générique.

**Preuve** : `05-logtest-avant-normalisation.png`

## 2. Approche retenue

Deux approches de normalisation existent : extraction au niveau des décodeurs, ou analyse au niveau des règles. L'analyse est réalisée au niveau des règles, en exploitant le contenu du log ModSecurity, qui est déjà structuré.

Les règles personnalisées sont placées dans `/var/ossec/etc/rules/local_rules.xml`, dans un groupe dédié, sans conflit avec les règles existantes.

## 3. Détection par famille

Chaque famille est identifiée par la plage d'identifiants de règles du CRS :

| Famille | Règle | Niveau | Plage CRS | MITRE |
|---------|-------|--------|-----------|-------|
| SQLi | 100110 | 10 | 942xxx | T1190 |
| XSS | 100120 | 10 | 941xxx | T1059.007 |
| LFI | 100130 | 10 | 930xxx | T1083 |
| RFI | 100140 | 10 | 931xxx | T1190 |
| RCE | 100150 | 12 | 932xxx | T1059 |

Chaque règle s'appuie sur les événements ModSecurity (`if_sid` 30401, 30411) et reconnaît sa famille via la plage d'id CRS présente dans le log.

**Preuves** : `05-logtest-sqli.png`, `05-logtest-xss.png`, `05-logtest-lfi.png`, `05-logtest-rfi.png`, `05-logtest-rce.png`

## 4. Gradation par gravité (3 niveaux)

La gravité est déduite du score d'anomalie du CRS (champ « Total Score »), indépendamment de la famille :

| Niveau | Règle | Score CRS | Niveau Wazuh | Signification |
|--------|-------|-----------|--------------|---------------|
| 1 - Suspect | 100200 | 1 à 4 | 7 | Détecté, sous le seuil de blocage |
| 2 - Avéré | 100201 | 5 à 9 | 11 | Attaque confirmée et bloquée |
| 3 - Critique | 100202 | 10 et + | 14 | Attaque sévère ou combinée |

**Preuves** : `05-logtest-niveau1-suspect.png`, `05-logtest-niveau2-avere.png`, `05-logtest-niveau3-critique.png`

## 5. Validation de bout en bout

Les 4 familles ont été lancées depuis Kali vers le WAF : toutes bloquées (403) et remontées dans Wazuh avec leur classification personnalisée.

Pour une injection SQL (score 8), deux alertes complémentaires sont générées simultanément :

- 100110 (famille : SQLi, niveau 10)
- 100201 (gravité : Niveau 2 Avéré, niveau 11)

L'alerte normalisée contient désormais : agent, IP source (attaquant), famille, gravité, URI visée, et le log brut.

**Preuves** : `05-kali-4-familles-403.png`, `05-wazuh-4-familles-normalisees.png`, `05-wazuh-famille-et-gravite.png`, `05-wazuh-alerte-normalisee-detail.png`

## Résultat

Le pont de normalisation ModSecurity vers Wazuh est opérationnel : les alertes sont classifiées par famille et par gravité, avec une classification MITRE correcte. Cette structuration prépare la couche IA (phases suivantes), qui exploitera ces champs pour la détection généralisée.
