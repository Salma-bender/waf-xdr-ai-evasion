#!/bin/bash
# Déploiement du collecteur sur le WAF (Phase 08).
# À lancer depuis le dossier qui contient collecteur_waf.py :  sudo bash deployer_collecteur.sh
#   - utilisateur dédié ia-collect, membre du groupe adm (lecture seule des journaux Apache) ;
#   - jeton saisi sans écho, stocké dans /etc/ia-collecteur/collecteur.env (root:ia-collect, 640) ;
#   - journal d'audit ModSecurity passé en mode On (toutes les requêtes) ; le blocage ne change pas.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "À lancer avec sudo"; exit 1; }
[ -f collecteur_waf.py ] || { echo "collecteur_waf.py introuvable dans le dossier courant"; exit 1; }
CONF=/etc/modsecurity/modsecurity.conf

echo "[1/5] Utilisateur de service"
id ia-collect >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin ia-collect
usermod -aG adm ia-collect

echo "[2/5] Programme -> /opt/ia-collecteur (lecture seule)"
install -d -o root -g root -m 755 /opt/ia-collecteur
install -o root -g root -m 644 collecteur_waf.py /opt/ia-collecteur/
install -d -o ia-collect -g ia-collect -m 750 /var/lib/ia-collecteur

echo "[3/5] Jeton partagé avec le service d'analyse"
install -d -o root -g ia-collect -m 750 /etc/ia-collecteur
if [ ! -f /etc/ia-collecteur/collecteur.env ]; then
    read -r -s -p "Colle le jeton (64 caractères, rien ne s'affiche) puis Entrée : " JETON; echo
    [[ "$JETON" =~ ^[0-9a-f]{64}$ ]] || { echo "Jeton invalide"; exit 1; }
    ( umask 027; cat > /etc/ia-collecteur/collecteur.env <<ENV
IA_API_URL=http://192.168.50.10:8000/analyser
IA_API_TOKEN=$JETON
AUDIT_LOG=/var/log/apache2/modsec_audit.log
ETAT=/var/lib/ia-collecteur/position
ENV
    )
    chown root:ia-collect /etc/ia-collecteur/collecteur.env
    chmod 640 /etc/ia-collecteur/collecteur.env
    unset JETON
fi

echo "[4/5] Journal d'audit ModSecurity en mode On"
[ -f "$CONF.bak-phase08" ] || cp "$CONF" "$CONF.bak-phase08"
sed -i 's/^\s*SecAuditEngine .*/SecAuditEngine On/' "$CONF"
grep "^SecAuditEngine" "$CONF"
apache2ctl configtest
systemctl reload apache2

echo "[5/5] Unité systemd durcie"
cat > /etc/systemd/system/ia-collecteur.service <<'UNIT'
[Unit]
Description=Collecteur WAF vers service d'analyse IA (Phase 08)
After=network-online.target apache2.service
Wants=network-online.target

[Service]
User=ia-collect
Group=ia-collect
SupplementaryGroups=adm
EnvironmentFile=/etc/ia-collecteur/collecteur.env
ExecStart=/usr/bin/python3 /opt/ia-collecteur/collecteur_waf.py
Restart=always
RestartSec=5

# Durcissement
NoNewPrivileges=yes
CapabilityBoundingSet=
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/ia-collecteur
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_INET AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native
# Sortie réseau limitée au seul service d'analyse
IPAddressDeny=any
IPAddressAllow=192.168.50.10
UMask=0027

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable ia-collecteur >/dev/null 2>&1
systemctl restart ia-collecteur
sleep 3
systemctl is-active ia-collecteur
