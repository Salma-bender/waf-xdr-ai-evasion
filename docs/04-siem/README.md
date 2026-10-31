Phase 3 — SIEM (Wazuh) et remontée des alertes

Objectif



Faire remonter les detections du WAF (ModSecurity) vers le SIEM Wazuh, afin de centraliser et superviser les attaques web depuis une console SOC.



1\. Maintenance prealable : demarrage de l’indexer



Au demarrage, l’indexer Wazuh (OpenSearch) depassait le delai d’attente de systemd (recouvrement d’un volume d’index accru), provoquant un echec « timeout exceeded ». L’indexer fonctionne mais demarre lentement.



Correction appliquee : augmentation du delai de demarrage via un override systemd.



sudo systemctl edit wazuh-indexer

\# \[Service]

\# TimeoutStartSec=300

sudo systemctl daemon-reload

sudo systemctl restart wazuh-indexer



Resultat : les trois services (indexer, manager, dashboard) demarrent et restent actifs.



Preuve : 04-wazuh-indexer-running.png, 04-wazuh-dashboard-acces.png



2\. Flux reseau WAF vers Wazuh (Zero Trust)



Le WAF (DMZ) doit joindre le manager Wazuh (zone SOC) sur les ports de l’agent. Une regle pfSense precise a ete ajoutee AU-DESSUS du blocage Zero Trust :



PASS : WAF (192.168.30.10) vers Wazuh (192.168.56.20), ports TCP 1514-1515



Les deux ports : 1515 pour l’enregistrement initial de l’agent, 1514 pour l’envoi continu des evenements.



Verification : depuis le WAF, nc -zv 192.168.56.20 1514 et 1515 renvoient « succeeded ».



Preuves : 04-pfsense-regle-waf-vers-wazuh.png, 04-waf-nc-ports-wazuh-ok.png



3\. Agent Wazuh sur le WAF



Installation de l’agent en version identique au manager (4.9.2), pointe vers le manager et nomme waf-dmz. Version bloquee (apt-mark hold) pour garantir la compatibilite.



L’agent lit automatiquement les logs Apache, dont /var/log/apache2/error.log ou ModSecurity ecrit ses detections.



Resultat : l’agent apparait « active » dans le dashboard (ID 004, IP 192.168.30.10, v4.9.2).



Preuves : 04-waf-agent-running.png, 04-wazuh-agent-waf-actif.png



4\. Validation de la chaine complete



Attaque reelle lancee depuis Kali vers le WAF : injection SQL, bloquee (403), remontee dans Wazuh.



Chaine : Kali (192.168.20.10) -> pfSense -> WAF (ModSecurity, 403) -> agent -> manager Wazuh -> alerte.



Deux alertes natives observees pour la meme attaque :



30411 (ModSecurity: Rejected a query) depuis error.log

31164 (SQL injection attempt) depuis access.log



Preuves : 04-kali-sqli-403-via-waf.png, 04-wazuh-alertes-sqli-waf.png



5\. Constat justifiant la normalisation



Le decodage natif n’extrait que l’IP source et l’identifiant « ModSecurity ». L’id de regle CRS, le score d’anomalie, la famille d’attaque et l’URI restent dans le champ full\_log, non structures. La classification MITRE native est generique et imprecise.



Ce constat justifie la construction d’un pont de normalisation (Phase 4).



Preuve : 04-wazuh-alerte-detail-modsecurity.png

