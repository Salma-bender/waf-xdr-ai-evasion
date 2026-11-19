# Phase 8 — Service d'analyse continue et dashboard SOC

## Objectif

Transformer les modèles de la Phase 07 en un composant du SOC qui analyse en
continu le trafic vu par le WAF, lève des alertes dans Wazuh et les présente dans
un dashboard. Le cas central est l'**évasion rattrapée** : une attaque que le WAF
laisse passer, détectée par l'IA.

## Architecture

```
Kali ──> WAF (ModSecurity) ──> DVWA
             │  journal d'audit
             ▼
      collecteur (waf-dmz) ──TLS interne──> service d'analyse (ia-soc)
                                                 │         │
                                     journal JSON│         │SQLite
                                                 ▼         ▼
                                       agent Wazuh     dashboard SOC (HTTPS)
                                                 │
                                                 ▼
                                          manager Wazuh (SOC)
```

| Composant | Hôte | Rôle |
|-----------|------|------|
| Service d'analyse | `ia-soc` | Charge les modèles, rend un verdict par requête |
| Collecteur | `waf-dmz` | Lit le journal d'audit et transmet au service |
| Agent Wazuh | `ia-soc` | Lit le journal du service, applique les règles |
| Dashboard SOC | `ia-soc` | Présente les détections (Flask, SQLite, AJAX) |

Les quatre catégories de verdict :

| Catégorie | WAF | IA | Signification |
|-----------|-----|----|--------------| 
| `evasion_rattrapee` | laisse passer (200) | attaque | évasion non bloquée, détectée par l'IA |
| `attaque_bloquee` | bloque (403) | attaque | WAF et IA d'accord |
| `bloquee_waf_seul` | bloque (403) | légitime | bloquée par le WAF seul |
| `legitime` | laisse passer | légitime | trafic normal |

## 1. Service d'analyse — `src/service/analyse_api.py`

Service Flask servi par Gunicorn. Il reçoit du collecteur chaque paramètre de
requête avec le verdict du WAF, et rend le verdict des modèles finaux.

Mesures de sécurité :

- authentification par jeton (comparaison en temps constant) ;
- limitation du débit par appelant (seau à jetons), contre l'extraction du modèle (ML05) ;
- validation stricte des entrées (types, tailles) ;
- modèles chargés via `chargement_sur.py`, empreinte vérifiée avant désérialisation (ML10) ;
- service hors bande : l'attaquant ne voit jamais le verdict de l'IA ;
- chaque prédiction journalisée dans SQLite, pour le suivi de la dérive (ML08) ;
- chaque détection écrite dans un journal JSON lu par l'agent Wazuh.

Dépendances figées et auditées (`pip-audit`) : aucune vulnérabilité connue.

**Preuves** : `08-dependances-audit.png`, `08-service-test-local.png`

### Déploiement durci — `src/service/deployer.sh`, `configs/ia-soc/ia-analyse.service`

- code, modèles et manifeste copiés dans `/opt/ia-soc`, en lecture seule pour le service ;
- utilisateur système dédié `ia-svc`, sans shell ;
- écriture limitée à la base et aux journaux ;
- jeton dans `/etc/ia-soc/service.env` (`root:ia-svc`, 640), jamais versionné ;
- unité systemd durcie : `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, aucune capacité root.

Vérifications : le service tourne sous `ia-svc` ; il ne peut pas modifier les
modèles (`Permission denied`) ; note d'exposition systemd 3,0.

**Preuves** : `08-service-systemd-durci.png`, `08-service-test-production.png`

## 2. Intégration dans Wazuh — `rules/wazuh/local_rules_ia_phase08.xml`

| Règle | Niveau | Événement | MITRE |
|-------|--------|-----------|-------|
| 100400 | 3 | Verdict d'attaque émis par le détecteur IA | — |
| 100401 | 8 | Attaque confirmée, déjà bloquée par le WAF | T1190 |
| 100402 | **13** | **Évasion : attaque non bloquée par le WAF, détectée par l'IA** | T1190 |
| 100304 | 10 | Code ou configuration du service d'analyse modifié | T1565.001 |

Les règles d'intégrité 100300 à 100302 de la Phase 07 ont été étendues aux
modèles de production (`/opt/ia-soc/models/`). L'agent lit le journal du service
et surveille en temps réel le code, les modèles, la configuration et l'unité.

**Preuves** : `08-wazuh-regles-ia.png`, `08-logtest-evasion.png`, `08-agent-ia-journal-fim.png`, `08-wazuh-alertes-ia.png`, `08-wazuh-alerte-evasion-detail.png`

## 3. Flux réseau (Zero Trust)

- **pfSense** : règle précise WAF (192.168.30.10) → ia-soc (192.168.50.10), port 8000, placée au-dessus du blocage des réseaux internes.
- **`ufw` sur ia-soc** : le port 8000 n'accepte que le WAF.

Vérifications : le WAF joint le service (`ok`) ; Kali en est bloqué (code `000`).

**Preuves** : `08-pfsense-regle-waf-vers-ia.png`, `08-flux-waf-ia-zerotrust.png`, `08-flux-waf-vers-ia.png`, `08-flux-kali-bloque.png`

## 4. Collecteur — `src/collecteur/collecteur_waf.py`

Suit le journal d'audit natif de ModSecurity (passé en mode `On`), découpe les
transactions et transmet chaque paramètre au service, avec le code de réponse du
WAF. Bibliothèque standard uniquement, reprise après redémarrage, suivi de la
rotation du journal.

Déploiement durci (`src/collecteur/deployer_collecteur.sh`,
`configs/waf-dmz/ia-collecteur.service`) : utilisateur dédié `ia-collect`
(lecture seule des journaux), jeton protégé, unité systemd dont la sortie réseau
est restreinte au seul service d'analyse (`IPAddressAllow=192.168.50.10`).

Chaîne réelle validée : une injection SQL lancée depuis Kali est bloquée par le
WAF (403), lue par le collecteur, classée `attaque_bloquee` (SQLi, 0,915) et
attribuée à l'attaquant.

**Preuves** : `08-collecteur-deploye.png`, `08-chaine-reelle-kali-waf-ia.png`

### 4.1 Surface d'analyse élargie

Le collecteur n'analyse plus seulement les paramètres de requête, mais toutes
les zones où une attaque peut se cacher :

| Zone | Emplacement transmis |
|------|----------------------|
| Chemin de l'URL | `path` |
| Paramètres d'URL et de formulaire | nom du paramètre |
| Corps JSON (parcouru récursivement) | `json:<chemin>` |
| Valeurs de cookies | `cookie:<nom>` |
| En-têtes vecteurs d'attaque (`X-Forwarded-For`, `X-Original-URL`…) | `header:<nom>` |

L'emplacement est transmis dans le champ `parametre`, donc visible dans le
dashboard et les alertes, sans changer le schéma de la base.

Deux choix de conception :

- les en-têtes `User-Agent` et `Referer` sont volontairement exclus : un
  `User-Agent` normal contient des `;`, des parenthèses et des mots, que les
  caractéristiques de structure du modèle prendraient pour une injection. Les
  analyser provoquerait des faux positifs sur le trafic légitime ;
- un anti-doublon à durée de vie évite de renvoyer sans cesse une même valeur au
  même emplacement (bruit des cookies de session, des en-têtes répétés).

Démonstration : une injection de commande (`10.0.0.9;id`) placée dans l'en-tête
`X-Forwarded-For` n'est pas bloquée par le WAF (code 200). Le collecteur la
soumet au service, qui la détecte (`evasion_rattrapee`, RCE, score 0,95). Le
dashboard affiche l'emplacement `header:x-forwarded-for`. Avant l'élargissement,
cette attaque n'était jamais analysée.

**Preuves** : `08-collecteur-surface-elargie.png`, `08-demo-surface-kali.png`, `08-demo-surface-collecteur.png`, `08-demo-surface-dashboard.png`

## 5. Dashboard SOC — `src/dashboard/`

Flask + SQLite (lecture seule) + AJAX, rafraîchissement automatique toutes les
5 secondes. Compteurs par catégorie, familles d'attaque, sources les plus
actives, activité par heure, et tableau des détections.

Mesures de sécurité :

- les données (dont des charges XSS) sont insérées comme du texte (`textContent`), jamais comme du HTML ;
- politique CSP stricte (`script-src 'self'`), contre le XSS stocké visant l'analyste ;
- base ouverte en lecture seule, aucune route d'écriture ;
- HTTPS, authentification HTTP Basic avec mot de passe stocké en empreinte ;
- accessible uniquement depuis le poste d'administration, par l'interface de gestion.

**Preuves** : `08-dashboard-deploye.png`, `08-dashboard-soc.png`

## 6. Démonstration de bout en bout

Un lot de 14 variantes d'évasion avancées, réparties sur les quatre familles, a
été rejoué depuis Kali à travers le WAF (`demo/rejeu_evasions.sh`). Les
techniques employées reprennent la grammaire des attaques apprise au
chapitre~\ref{chap:modeles} : séparateurs shell, mots coupés par des backticks,
substitution de commande, wrappers, commentaires exécutables.

| Étape | Résultat |
|-------|----------|
| Attaques envoyées | 14 |
| Bloquées par le WAF (403) | 11 |
| Passées au WAF (200) | 3 — toutes des injections de commande (`127.0.0.1\|id`, `127.0.0.1%0aid`, `` 127.0.0.1;w`h`oami ``) |
| Détectées par l'IA | 14 sur 14 |
| Évasions rattrapées | 3 sur 3 |
| Attaques manquées par l'IA | 0 |

Le dashboard a affiché 3 évasions rattrapées, 11 attaques confirmées et 0
« bloquée par le WAF seul » : l'IA n'a manqué aucune attaque, et a rattrapé les
trois que le WAF a laissées passer. Wazuh a levé pour ces trois évasions une
alerte 100402 de niveau 13, et une alerte 100401 de niveau 8 pour chaque attaque
bloquée.

C'est la démonstration de la valeur de la couche IA : les attaques que le WAF
seul laisse passer sont détectées et remontent au SOC comme alertes critiques.

**Preuves** : `08-demo-evasions-kali.png`, `08-demo-evasions-dashboard1.png`, `08-demo-evasions-dashboard2.png`, `08-demo-evasions-wazuh.png`, `08-demo-evasions-wazuh2.png`

## 7. Bilan des menaces (couche IA en service)

| Menace | OWASP ML | Mesure | État |
|--------|----------|--------|------|
| Extraction du modèle | ML05 | Service hors bande, limitation de débit, zone isolée | Traitée |
| Dérive | ML08 | Chaque prédiction journalisée dans SQLite | Journalisation en place ; suivi dans le temps à poursuivre |
| Altération du modèle | ML10 | Chargement vérifié par empreinte, FIM, règles de niveau 12 | Traitée |
| Requêtes forgées au service | — | Jeton, flux pfSense + `ufw` restreints au WAF | Traitée |
| XSS stocké visant l'analyste | — | Rendu en texte, CSP stricte | Traitée |

## Limites

- La surface couvre chemin, paramètres, corps JSON, cookies et en-têtes ciblés ; `User-Agent` et `Referer` sont exclus par choix (faux positifs).
- Le suivi de la dérive repose sur la journalisation ; aucune alerte automatique de dérive n'est encore en place.
- Le jeu de validation réel reste de taille modeste (cf. Phase 07).

## Suite

Phase 09 : génération assistée par un modèle de langage d'une règle ModSecurity à
partir des évasions rattrapées, avec validation humaine depuis le dashboard avant
application sur le WAF.
