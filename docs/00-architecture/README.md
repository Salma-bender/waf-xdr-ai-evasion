\# Architecture du projet



\## Vue d'ensemble



Le laboratoire implémente une architecture de cybersécurité défensive en \*\*micro-segmentation Zero Trust\*\*, dont l'objectif est de détecter les techniques d'évasion dans les attaques web. Le trafic circule depuis un attaquant, traverse un WAF (reverse proxy avec inspection), puis atteint une application vulnérable, le tout supervisé par un SIEM.



\## Plan d'adressage réseau



Le pare-feu pfSense assure le routage et le filtrage entre toutes les zones. Chaque zone est un réseau interne isolé au niveau de l'hyperviseur.



| Zone | Interface pfSense | Réseau | Passerelle | Hôte | IP hôte |

|------|-------------------|--------|------------|------|---------|

| WAN | em0 (WAN) | Bridge Wi-Fi | — | pfSense | 192.168.9.151 |

| LAN / SOC | em1 (LAN) | 192.168.56.0/24 | 192.168.56.1 | Wazuh | 192.168.56.20 |

| Attaquant | em2 (OPT1) | 192.168.20.0/24 | 192.168.20.1 | Kali | 192.168.20.10 |

| DMZ (front) | em3 (DMZ) | 192.168.30.0/24 | 192.168.30.1 | WAF | 192.168.30.10 |

| APP (back) | em4 (APP) | 192.168.40.0/24 | 192.168.40.1 | DVWA | 192.168.40.10 |

| IA | em5 (IA) | 192.168.50.0/24 | 192.168.50.1 | — (à venir) | 192.168.50.10 |



\## Matrice de flux (Zero Trust — default deny)



Le principe directeur : tout flux non explicitement autorisé est bloqué et journalisé.



| Source | Destination | Autorisé | Justification |

|--------|-------------|----------|---------------|

| Kali | WAF (DMZ) :80 | ✅ | Seul chemin d'attaque autorisé |

| Kali | APP, SOC, IA, LAN | ❌ | Isolement de l'attaquant |

| Kali | Internet | ✅ | Téléchargement d'outils |

| WAF | APP :80 | ✅ | Reverse proxy vers l'application |

| WAF | Autres zones internes | ❌ | Confinement du front |

| WAF | Internet | ✅ (temporaire) | Installation ModSecurity/CRS |

| APP | Toute sortie | ❌ | Back isolé, ne répond qu'au WAF et à l'admin |

| LAN (admin) | Toutes zones | ✅ | Zone de confiance (administration) |



\## Chaîne de traitement d'une requête

