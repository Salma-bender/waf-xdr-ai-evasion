# Phase 1 — Montage du laboratoire et segmentation réseau

## Objectif

Construire l'infrastructure réseau segmentée (micro-segmentation Zero Trust) sur VirtualBox, pilotée par pfSense, et durcir les flux inter-zones jusqu'à une politique de moindre privilège vérifiée par tests.

## 1. Création des zones réseau

Trois réseaux internes supplémentaires ont été ajoutés à pfSense (DMZ, APP, IA) via `VBoxManage`, portant le pare-feu à 6 interfaces.

Les interfaces ont ensuite été assignées et adressées dans pfSense :

| Interface | Zone | Adresse |
|-----------|------|---------|
| em0 | WAN | 192.168.9.151 (DHCP) |
| em1 | LAN / SOC | 192.168.56.1/24 |
| em2 | OPT1 (Kali) | 192.168.20.1/24 |
| em3 | DMZ | 192.168.30.1/24 |
| em4 | APP | 192.168.40.1/24 |
| em5 | IA | 192.168.50.1/24 |

**Preuves** : `01-reseau-6-cartes-vboxmanag.png`, `01-pfsense-6-interfaces-assignees.png`, `01-pfsense-dashboard-6-interfaces.png`, `01-pfsense-ia-ip.png`

## 2. Politique de pare-feu Zero Trust

Le principe appliqué est le **default deny** : chaque interface ne laisse passer que les flux explicitement autorisés, l'ordre des règles étant déterminant (lecture de haut en bas, première règle correspondante appliquée).

### Alias utilisé

`Reseaux_Internes` (type Network) : 192.168.30.0/24, 192.168.40.0/24, 192.168.50.0/24, 192.168.56.0/24

### Zone attaquant (Kali / OPT1)

1. `PASS` Kali (192.168.20.10) → WAF (192.168.30.10) :80
2. `BLOCK + log` Kali → alias `Reseaux_Internes` (toutes les zones internes)
3. `PASS` Kali → Internet

Résultat : l'attaquant ne peut atteindre que le WAF ; tout accès direct à l'application ou aux autres zones est impossible.

**Preuve** : `01-pfsense-regles-kali-zerotrust.png`

### Zone DMZ (WAF)

1. `PASS` WAF → APP (192.168.40.10) :80 — reverse proxy
2. `BLOCK + log` WAF → `Reseaux_Internes`
3. `PASS` WAF → Internet (conservé temporairement pour l'installation de ModSecurity / CRS)

**Preuve** : `01-pfsense-regles-dmz-durcies.png`

### Zone APP (back)

1. `BLOCK + log` APP → `Reseaux_Internes`
2. `BLOCK + log` APP → Internet

Résultat : l'application n'initie aucune connexion sortante ; elle ne fait que répondre au WAF et à l'administration (géré par le suivi d'état du pare-feu).

**Preuve** : `01-pfsense-regles-app-durcies.png`

### Zone IA

1. `BLOCK` IA → `Reseaux_Internes`
2. `PASS` IA → Internet

Résultat : la couche IA ne peut joindre aucune autre zone interne, mais dispose d'un accès Internet (installation des paquets Python, récupération des sources de données, appels aux API LLM).

**Preuve** : `01-pfsense-regles-ia-zerotrust.png`

## 3. Machine de la zone IA (ia-soc)

| Paramètre | Valeur |
|-----------|--------|
| Système | Ubuntu Server 24.04 LTS |
| Ressources | 2 vCPU, 4 Go de RAM, disque 30 Go |
| Nom d'hôte | ia-soc |
| Carte 1 (zone IA) | réseau interne `intenet-ia`, IP fixe 192.168.50.10/24, passerelle 192.168.50.1 |
| Carte 2 (administration) | réseau host-only, IP fixe 192.168.56.70/24, sans passerelle (accès SSH depuis le poste d'administration) |
| DNS | 8.8.8.8, 1.1.1.1 |
| Services | OpenSSH |

La passerelle par défaut reste sur la carte de la zone IA : tout le trafic sortant de la machine traverse pfSense et ses règles Zero Trust. La carte d'administration ne sert qu'à l'accès SSH.

**Preuve** : `01-ia-install-network-ip.png`

## 4. Validation empirique de la segmentation

Tests réalisés depuis Kali, l'APP, la DMZ et la zone IA :

| Test | Résultat attendu | Observé |
|------|------------------|---------|
| Kali → WAF :80 | Autorisé (302) | ✅ |
| Kali → APP direct | Bloqué (timeout) | ✅ |
| Kali → SOC (56.x) | Bloqué (100 % de perte) | ✅ |
| Kali → Internet | Autorisé | ✅ |
| APP → Internet | Bloqué | ✅ |
| Admin (SSH) → APP | Autorisé (stateful) | ✅ |
| WAF → APP :80 (proxy) | Autorisé (302) | ✅ |
| IA → WAF (DMZ) | Bloqué (100 % de perte) | ✅ |
| IA → Internet | Autorisé | ✅ |

**Preuves** : `01-kali-bloque-vers-app-direct.png`, `01-kali-isolement-vs-internet.png`, `01-app-durcie-internet-coupe.png`, `01-dmz-durcie-tests-ok.png`, `01-ia-isolement-vs-internet.png`

## Conclusion

La segmentation Zero Trust est fonctionnelle et prouvée : l'attaquant est confiné au seul point d'entrée légitime (le WAF), le back est isolé de tout trafic sortant, la couche IA est isolée des autres zones, et chaque flux autorisé correspond à un besoin réel et justifié.
