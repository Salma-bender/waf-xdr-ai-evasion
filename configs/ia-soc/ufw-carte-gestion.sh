#!/bin/sh
# Phase 07 — Pare-feu local de ia-soc : filtrage de la carte de gestion (enp0s8).
# PC = adresse du poste d'administration (source de la session SSH).
PC=192.168.56.254
ufw default deny incoming
ufw default allow outgoing
ufw allow in on enp0s8 from "$PC" to any port 22 proto tcp
ufw allow out on enp0s8 to 192.168.56.20 port 1514:1515 proto tcp
ufw deny out on enp0s8
ufw enable
