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



Preuves : 03-dvwa-dashboard.png, 03-dvwa-security-low.png



4\. Démonstration de vulnérabilité (sans protection)



Injection SQL sur le module SQL Injection, charge utile :



1' OR '1'='1



Résultat : la requête retourne l’intégralité des utilisateurs de la base au lieu d’un seul, confirmant l’exploitabilité. La condition injectée étant toujours vraie, toutes les lignes sont renvoyées.



Preuve : 03-dvwa-sqli-reussie-sans-waf.png



Importance pour la suite



Cette attaque réussie sans protection constitue la référence « avant ». Elle sera comparée au comportement « après » mise en place du WAF/ModSecurity et de la couche IA, pour mesurer l’apport de chaque couche défensive.

