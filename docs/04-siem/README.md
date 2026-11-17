# Phase 4 — SIEM (Wazuh) et remontée des alertes

## Objectif

Faire remonter les détections du WAF (ModSecurity) vers le SIEM Wazuh, afin de centraliser et superviser les attaques web depuis une console SOC.

## 1. Maintenance préalable : démarrage de l'indexer

Au démarrage, l'indexer Wazuh (OpenSearch) dépassait le délai d'attente de systemd (recouvrement d'un volume d'index accru), provoquant un échec « timeout exceeded ». L'indexer fonctionne mais démarre lentement.

Correction appliquée : augmentation du délai de démarrage via un override systemd.

```
sudo systemctl edit wazuh-indexer
# [Service]
# TimeoutStartSec=300
sudo systemctl daemon-reload
sudo systemctl restart wazuh-indexer
```

Résultat : les trois services (indexer, manager, dashboard) démarrent et restent actifs.

**Preuves** : `04-wazuh-indexer-running.png`, `04-wazuh-dashboard-acces.png`

## 2. Flux réseau WAF vers Wazuh (Zero Trust)

Le WAF (DMZ) doit joindre le manager Wazuh (zone SOC) sur les ports de l'agent. Une règle pfSense précise a été ajoutée **au-dessus** du blocage Zero Trust :

- `PASS` WAF (192.168.30.10) → Wazuh (192.168.56.20), ports TCP 1514-1515

Les deux ports : 1515 pour l'enregistrement initial de l'agent, 1514 pour l'envoi continu des événements.

Vérification depuis le WAF : `nc -zv 192.168.56.20 1514` et `1515` renvoient « succeeded ».

**Preuves** : `04-pfsense-regle-waf-vers-wazuh.png`, `04-waf-nc-ports-wazuh-ok.png`

## 3. Agent Wazuh sur le WAF

Installation de l'agent en version identique au manager (4.9.2), pointé vers le manager et nommé `waf-dmz`. Version bloquée (`apt-mark hold`) pour garantir la compatibilité.

L'agent lit automatiquement les logs Apache, dont `/var/log/apache2/error.log` où ModSecurity écrit ses détections.

Résultat : l'agent apparaît « active » dans le dashboard (ID 004, IP 192.168.30.10, v4.9.2).

**Preuves** : `04-waf-agent-running.png`, `04-wazuh-agent-waf-actif.png`

## 4. Validation de la chaîne complète

Attaque réelle lancée depuis Kali vers le WAF : injection SQL, bloquée (403), remontée dans Wazuh.

```
Kali (192.168.20.10) -> pfSense -> WAF (ModSecurity, 403) -> agent -> manager Wazuh -> alerte
```

Deux alertes natives observées pour la même attaque :

| Règle | Description | Source |
|-------|-------------|--------|
| 30411 | ModSecurity: Rejected a query | error.log |
| 31164 | SQL injection attempt | access.log |

**Preuves** : `04-kali-sqli-403-via-waf.png`, `04-wazuh-alertes-sqli-waf.png`

## 5. Constat justifiant la normalisation

Le décodage natif n'extrait que l'IP source et l'identifiant « ModSecurity ». L'id de règle CRS, le score d'anomalie, la famille d'attaque et l'URI restent dans le champ `full_log`, non structurés. La classification MITRE native est générique et imprécise.

Ce constat justifie la construction d'un pont de normalisation ([Phase 05](../05-detection-evasion/README.md)).

**Preuve** : `04-wazuh-alerte-detail-modsecurity.png`
