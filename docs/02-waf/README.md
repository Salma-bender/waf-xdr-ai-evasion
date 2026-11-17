# Phase 2 — WAF : reverse proxy Apache et ModSecurity

## Objectif

Placer devant l'application un pare-feu applicatif (WAF) en zone DMZ : un serveur Apache en reverse proxy, équipé de ModSecurity et de l'OWASP Core Rule Set (CRS), par lequel passe obligatoirement tout le trafic vers l'application.

## 1. Serveur WAF

VM Ubuntu Server 24.04 LTS, nom d'hôte `waf-dmz`, zone DMZ, IP fixe 192.168.30.10. Administration en SSH.

Connectivité validée : passerelle pfSense (192.168.30.1) et Internet joignables.

**Preuves** : `02-waf-ssh-acces.png`, `02-waf-connectivite-ok.png`

## 2. Apache

Apache 2.4 installé et actif sur le WAF.

**Preuves** : `02-waf-apache-status.png`, `02-waf-apache-itworks.png`

## 3. Flux DMZ vers APP

Règle pfSense sur l'interface DMZ : `PASS` TCP 192.168.30.10 → 192.168.40.10 port 80 (reverse proxy HTTP, Zero Trust).

Vérification depuis le WAF : `curl -I http://192.168.40.10` renvoie `HTTP/1.1 200 OK` (Apache/2.4.58 du serveur applicatif).

**Preuves** : `02-pfsense-regle-dmz-vers-app.png`, `02-waf-curl-vers-app.png`

## 4. Reverse proxy vers DVWA

Apache est configuré en reverse proxy vers le serveur applicatif. L'application est désormais accessible via l'adresse du WAF, `http://192.168.30.10/dvwa/`, sans exposition directe de la zone APP.

**Preuves** : `02-waf-dvwa-via-proxy.png`, `03-dvwa-dashboard.png`

## 5. ModSecurity + OWASP CRS

### Installation

Module ModSecurity installé et chargé par Apache :

```
sudo apt install libapache2-mod-security2
sudo apachectl -M | grep security
# security2_module (shared)
```

Configuration activée à partir du modèle recommandé, avec deux réglages clés dans `/etc/modsecurity/modsecurity.conf` :

- `SecRuleEngine On` : mode actif, ModSecurity bloque les attaques détectées
- `SecRequestBodyAccess On` : inspection du corps des requêtes, nécessaire pour les attaques POST

### OWASP Core Rule Set (CRS)

Le CRS officiel (version 4.x) a été cloné depuis le dépôt OWASP et connecté à Apache :

```
sudo git clone https://github.com/coreruleset/coreruleset.git /etc/modsecurity/crs
sudo cp /etc/modsecurity/crs/crs-setup.conf.example /etc/modsecurity/crs/crs-setup.conf
```

Chargement dans `/etc/apache2/mods-enabled/security2.conf` :

```
IncludeOptional /etc/modsecurity/crs/crs-setup.conf
IncludeOptional /etc/modsecurity/crs/rules/*.conf
```

### Principe de fonctionnement : score d'anomalie

Le CRS ne bloque pas règle par règle, mais par **score d'anomalie cumulatif**. Chaque règle déclenchée ajoute des points ; lorsque le score dépasse le seuil (5 en entrée), la requête est bloquée (403). Ce mécanisme est robuste pour les attaques connues, mais c'est précisément ce que les techniques d'évasion cherchent à contourner : une attaque reformulée qui n'accumule pas assez de points passe sous le seuil.

## 6. Validation : attaque bloquée

Injection SQL rejouée à travers le WAF (même charge utile que la démonstration sans protection, voir [Phase 03](../03-app/README.md)) :

```
http://192.168.30.10/dvwa/vulnerabilities/sqli/?id=1' OR '1'='1&Submit=Submit
```

Résultat : **403 Forbidden**. La requête est bloquée par le WAF avant d'atteindre l'application.

Journalisation (`error.log`), règles déclenchées :

| Règle | Signification |
|-------|---------------|
| 942100 | SQL Injection détectée via libinjection (sévérité CRITICAL) |
| 949110 | Score d'anomalie dépassé (total 8 ≥ seuil 5) → blocage |
| 980170 | Récapitulatif des scores (SQLI=5) |

**Preuves** : `02-waf-modsecurity-bloque-sqli.png`, `02-waf-modsecurity-log-sqli.png`

## Comparaison avant / après

| Scénario | Résultat |
|----------|----------|
| SQLi sans protection (accès direct APP) | Tous les utilisateurs révélés — attaque réussie |
| SQLi avec WAF (ModSecurity + CRS) | 403 Forbidden — attaque bloquée |

Cette base valide la détection par signatures pour une attaque classique. La suite du projet consiste à montrer qu'une attaque reformulée (évasion) peut contourner ce même WAF, justifiant l'apport d'une couche de détection par IA.
