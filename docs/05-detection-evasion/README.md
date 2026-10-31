Phase 4 — Pont de normalisation et detection par famille

Objectif



Transformer les alertes ModSecurity brutes en alertes structurees et exploitables : classifier chaque attaque par famille (SQLi, XSS, LFI, RFI, RCE) et par gravite (3 niveaux selon le score d’anomalie du CRS).



1\. Point de depart (avant normalisation)



L’outil wazuh-logtest confirme que le decodage natif n’extrait que l’IP source et l’identifiant ModSecurity. L’id de regle CRS, le score et la famille restent non structures ; la regle native 30411 est generique.



Preuve : 05-logtest-avant-normalisation.png



2\. Approche retenue



Deux approches de normalisation existent : extraction au niveau des decodeurs, ou analyse au niveau des regles. Les decodeurs enfants n’ont pas pu s’enchainer au decodeur natif apache-errorlog. L’analyse a donc ete realisee au niveau des regles, en exploitant le contenu du log ModSecurity (qui est deja structure).



Les regles personnalisees sont placees dans /var/ossec/etc/rules/local\_rules.xml, dans un groupe dedie, sans conflit avec les regles existantes.



3\. Detection par famille



Chaque famille est identifiee par la plage d’identifiants de regles du CRS :



Famille	Regle	Niveau	Plage CRS	MITRE

SQLi	100110	10	942xxx	T1190

XSS	100120	10	941xxx	T1059.007

LFI	100130	10	930xxx	T1083

RFI	100140	10	931xxx	T1190

RCE	100150	12	932xxx	T1059



Chaque regle s’appuie sur les evenements ModSecurity (if\_sid 30401, 30411) et reconnait sa famille via la plage d’id CRS presente dans le log.



Preuves : 05-logtest-sqli-detectee.png, 05-logtest-xss.png, 05-logtest-lfi.png, 05-logtest-rfi.png, 05-logtest-rce.png



4\. Gradation par gravite (3 niveaux)



La gravite est deduite du score d’anomalie du CRS (champ « Total Score »), independamment de la famille :



Niveau	Regle	Score CRS	Niveau Wazuh	Signification

1 - Suspect	100200	1 a 4	7	Detecte, sous le seuil de blocage

2 - Avere	100201	5 a 9	11	Attaque confirmee et bloquee

3 - Critique	100202	10 et +	14	Attaque severe ou combinee



Preuves : 05-logtest-niveau1-suspect.png, 05-logtest-niveau2-avere.png, 05-logtest-niveau3-critique.png



5\. Validation de bout en bout



Les 4 familles ont ete lancees depuis Kali vers le WAF : toutes bloquees (403) et remontees dans Wazuh avec leur classification personnalisee.



Pour une injection SQL (score 8), deux alertes complementaires sont generees simultanement :



100110 (famille : SQLi, niveau 10)

100201 (gravite : Niveau 2 Avere, niveau 11)



L’alerte normalisee contient desormais : agent, IP source (attaquant), famille, gravite, URI visee, et le log brut.



Preuves : 05-kali-4-familles-403.png, 05-wazuh-4-familles-normalisees.png, 05-wazuh-famille-et-gravite.png, 05-wazuh-alerte-normalisee-detail.png



Resultat



Le pont de normalisation ModSecurity vers Wazuh est operationnel : les alertes sont classifiees par famille et par gravite, avec une classification MITRE correcte. Cette structuration prepare la couche IA (Phases suivantes), qui exploitera ces champs pour la detection generalisee.

