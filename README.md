# waf-xdr-ai-evasion

Projet personnel : **conception d'une architecture de cybersécurité basée sur l'IA, le XDR et le WAF pour détecter les techniques d'évasion avancées dans les attaques Web.**

Les défenses classiques (WAF, XDR) reposent sur des signatures : une attaque reformulée pour les contourner passe inaperçue. Ce projet démontre cette limite de manière empirique dans un laboratoire segmenté, puis y répond avec une couche de détection par apprentissage automatique.

## Architecture

Laboratoire VirtualBox piloté par pfSense, en micro-segmentation Zero Trust (default deny) :

| Zone | Réseau | Machine | Rôle |
|------|--------|---------|------|
| SOC / LAN | 192.168.56.0/24 | Wazuh (192.168.56.20) | SIEM / XDR |
| Attaquant | 192.168.20.0/24 | Kali (192.168.20.10) | Génération des attaques |
| DMZ | 192.168.30.0/24 | waf-dmz (192.168.30.10) | Apache reverse proxy + ModSecurity + OWASP CRS |
| APP | 192.168.40.0/24 | DVWA (192.168.40.10) | Application vulnérable |
| IA | 192.168.50.0/24 | ia-soc (192.168.50.10) | Dataset, modèles ML, service d'analyse |

Détails : [docs/00-architecture](docs/00-architecture/README.md)

## Avancement

| Phase | Contenu | État |
|-------|---------|------|
| [01 — Lab et segmentation](docs/01-lab-setup/README.md) | pfSense 6 zones, règles Zero Trust, validation | ✅ |
| [02 — WAF](docs/02-waf/README.md) | Reverse proxy Apache, ModSecurity + OWASP CRS | ✅ |
| [03 — Application](docs/03-app/README.md) | DVWA en zone APP, SQLi réussie sans protection | ✅ |
| [04 — SIEM](docs/04-siem/README.md) | Wazuh, agent sur le WAF, alertes ModSecurity | ✅ |
| [05 — Détection et évasion](docs/05-detection-evasion/README.md) | Pont de normalisation, 4 familles, 3 niveaux de gravité | ✅ |
| [06 — Dataset](docs/06-dataset/README.md) | 17 600 requêtes labellisées, variantes d'évasion, split train/test | ✅ |
| 07 — Modèles | Random Forest binaire + classification de famille | ⏳ |
| 08 — Dashboard | Dashboard SOC (Flask / SQLite / AJAX) | ⏳ |
| 09 — Pipeline LLM | Génération de règles assistée par LLM, validation humaine | ⏳ |

## Stack

pfSense 2.8.1 · VirtualBox · Ubuntu Server 24.04 · Kali Linux · Apache 2.4 · ModSecurity · OWASP CRS 4.x · DVWA · Wazuh 4.9.2 · Python

## Auteur

Salma Bender — Cycle ingénieur, Génie Informatique (Cybersécurité), FST Marrakech, Université Cadi Ayyad.
