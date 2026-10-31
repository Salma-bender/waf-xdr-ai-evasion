Phase 2 (suite) — Application vulnérable (DVWA)

Objectif



Déployer l’application volontairement vulnérable (DVWA) sur un serveur back isolé (zone APP), et démontrer son exploitabilité — point de départ de la démonstration : prouver qu’une attaque réussit sans protection.



1\. Serveur applicatif



VM Ubuntu Server 24.04 LTS, zone APP, IP fixe 192.168.40.10.



Pile installée : Apache2, PHP 8.3, MariaDB.



Preuves : 02-app-ip-a.png, 03-app-connectivite-ok.png, 03-app-services-actifs.png



2\. Déploiement de DVWA

Clonage du dépôt officiel dans la racine web (/var/www/html/dvwa).

Fichier de configuration créé à partir du modèle ; base de données dédiée.



Base de données (MariaDB) :



Base : dvwa

Utilisateur dédié : dvwa (droits limités à la base dvwa uniquement)



Options PHP activées pour couvrir toutes les familles d’attaques :



allow\_url\_fopen = On

allow\_url\_include = On (nécessaire pour les tests RFI)



Module Apache activé : mod\_rewrite.



Preuve : 03-dvwa-setup-check-ok.png



3\. Configuration DVWA

Base initialisée via la page de setup.

Niveau de sécurité réglé sur low (aucune protection applicative) pour la phase de démonstration de vulnérabilité.



Preuve : 03-dvwa-dashboard.png, 03-dvwa-security-low.png



4\. Démonstration de vulnérabilité (sans protection)



Injection SQL sur le module SQL Injection, charge utile :



1' OR '1'='1



Résultat : la requête retourne l’intégralité des utilisateurs de la base au lieu d’un seul, confirmant l’exploitabilité. La condition injectée étant toujours vraie, toutes les lignes sont renvoyées.



Preuve : 03-dvwa-sqli-reussie-sans-waf.png



Importance pour la suite



Cette attaque réussie sans protection constitue la référence « avant ». Elle sera comparée au comportement « après » mise en place du WAF/ModSecurity et de la couche IA, pour mesurer l’apport de chaque couche défensive.5. ModSecurity + OWASP CRS

Installation



Module ModSecurity installé et chargé par Apache :



sudo apt install libapache2-mod-security2

sudo apachectl -M | grep security   → security2\_module (shared)



Configuration activée à partir du modèle recommandé, avec deux réglages clés dans /etc/modsecurity/modsecurity.conf :



SecRuleEngine On (mode actif : ModSecurity bloque les attaques détectées)

SecRequestBodyAccess On (inspection du corps des requêtes, nécessaire pour les attaques POST)

OWASP Core Rule Set (CRS)



Le CRS officiel (version 4.x) a été cloné depuis le dépôt OWASP et connecté à Apache :



sudo git clone https://github.com/coreruleset/coreruleset.git /etc/modsecurity/crs

sudo cp /etc/modsecurity/crs/crs-setup.conf.example /etc/modsecurity/crs/crs-setup.conf



Chargement dans /etc/apache2/mods-enabled/security2.conf :



IncludeOptional /etc/modsecurity/crs/crs-setup.conf

IncludeOptional /etc/modsecurity/crs/rules/\*.conf

Principe de fonctionnement : score d’anomalie



Le CRS ne bloque pas règle par règle, mais par score d’anomalie cumulatif. Chaque règle déclenchée ajoute des points ; lorsque le score dépasse le seuil (5 en entrée), la requête est bloquée (403). Ce mécanisme est robuste pour les attaques connues, mais c’est précisément ce que les techniques d’évasion cherchent à contourner : une attaque reformulée qui n’accumule pas assez de points passe sous le seuil.



Validation : attaque bloquée



Injection SQL rejouée à travers le WAF (même charge utile que la démonstration sans protection) :



http://192.168.30.10/dvwa/vulnerabilities/sqli/?id=1' OR '1'='1\&Submit=Submit



Résultat : 403 Forbidden. La requête est bloquée par le WAF avant d’atteindre l’application.



Journalisation (error.log) — règles déclenchées :



942100 : SQL Injection détectée via libinjection (sévérité CRITICAL)

949110 : score d’anomalie dépassé (total 8 ≥ seuil 5) → blocage

980170 : récapitulatif des scores (SQLI=5)



Preuves : 02-waf-modsecurity-bloque-sqli.png, 02-waf-modsecurity-log-sqli.png



Comparaison avant / après (cœur de la démonstration)

Scénario	Résultat

SQLi sans protection (accès direct APP)	Tous les utilisateurs révélés — attaque réussie

SQLi avec WAF (ModSecurity + CRS)	403 Forbidden — attaque bloquée



Cette base valide la détection par signatures pour une attaque classique. La suite du projet consistera à montrer qu’une attaque reformulée (évasion) peut contourner ce même WAF, justifiant l’apport d’une couche de détection par IA.

