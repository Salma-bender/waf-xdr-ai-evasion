#!/bin/bash
# Déploiement du dashboard SOC sur ia-soc (Phase 08).
# À lancer depuis ~/waf-ia :   sudo bash src/dashboard/deployer_dashboard.sh
#   - code en lecture seule dans /opt/ia-soc/src/dashboard ;
#   - HTTPS (certificat auto-signé), compte analyste avec mot de passe stocké en empreinte ;
#   - accessible uniquement depuis le poste d'administration, par l'interface de gestion.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "À lancer avec sudo"; exit 1; }
[ -f src/dashboard/dashboard.py ] || { echo "À lancer depuis ~/waf-ia"; exit 1; }
[ -x /opt/ia-soc/venv/bin/gunicorn ] || { echo "Déployer d'abord le service d'analyse"; exit 1; }
POSTE_ADMIN=192.168.56.254
IP_GESTION=192.168.56.70

echo "[1/5] Code -> /opt/ia-soc/src/dashboard (lecture seule)"
install -d -o root -g root -m 755 /opt/ia-soc/src/dashboard /opt/ia-soc/src/dashboard/static
install -o root -g root -m 644 src/dashboard/dashboard.py /opt/ia-soc/src/dashboard/
install -o root -g root -m 644 src/dashboard/static/* /opt/ia-soc/src/dashboard/static/

echo "[2/5] Certificat TLS auto-signé"
if [ ! -f /etc/ia-soc/dashboard.crt ]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 397 \
        -keyout /etc/ia-soc/dashboard.key -out /etc/ia-soc/dashboard.crt \
        -subj "/CN=ia-soc - SOC IA" -addext "subjectAltName=IP:$IP_GESTION" 2>/dev/null
    chown root:ia-svc /etc/ia-soc/dashboard.key /etc/ia-soc/dashboard.crt
    chmod 640 /etc/ia-soc/dashboard.key
    chmod 644 /etc/ia-soc/dashboard.crt
fi

echo "[3/5] Compte analyste"
if [ ! -f /etc/ia-soc/dashboard.hash ]; then
    read -r -p "Nom de l'analyste [analyste] : " NOM; NOM=${NOM:-analyste}
    read -r -s -p "Mot de passe (12 caractères minimum) : " MDP; echo
    read -r -s -p "Confirmation : " MDP2; echo
    [ "$MDP" = "$MDP2" ] || { echo "Les mots de passe diffèrent"; exit 1; }
    [ ${#MDP} -ge 12 ] || { echo "Mot de passe trop court"; exit 1; }
    ( umask 027
      printf '%s' "$MDP" | /opt/ia-soc/venv/bin/python -c \
        "import sys; from werkzeug.security import generate_password_hash as g; print(g(sys.stdin.read()))" \
        > /etc/ia-soc/dashboard.hash
      printf 'IA_DB=/var/lib/ia-soc/detections.db\nDASH_USER=%s\nDASH_PASS_HASH_FILE=/etc/ia-soc/dashboard.hash\n' "$NOM" \
        > /etc/ia-soc/dashboard.env )
    chown root:ia-svc /etc/ia-soc/dashboard.hash /etc/ia-soc/dashboard.env
    chmod 640 /etc/ia-soc/dashboard.hash /etc/ia-soc/dashboard.env
    unset MDP MDP2
fi

echo "[4/5] Pare-feu : poste d'administration uniquement"
ufw allow in on enp0s8 from "$POSTE_ADMIN" to any port 8443 proto tcp >/dev/null
ufw status | grep 8443

echo "[5/5] Unité systemd durcie"
cat > /etc/systemd/system/ia-dashboard.service <<'UNIT'
[Unit]
Description=Dashboard SOC de la couche IA (Phase 08)
After=network-online.target ia-analyse.service
Wants=network-online.target

[Service]
User=ia-svc
Group=ia-svc
EnvironmentFile=/etc/ia-soc/dashboard.env
WorkingDirectory=/opt/ia-soc/src/dashboard
ExecStart=/opt/ia-soc/venv/bin/gunicorn --bind 192.168.56.70:8443 --certfile /etc/ia-soc/dashboard.crt --keyfile /etc/ia-soc/dashboard.key --workers 1 --threads 4 dashboard:app
Restart=on-failure
RestartSec=5

# Durcissement
NoNewPrivileges=yes
CapabilityBoundingSet=
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/ia-soc
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
UMask=0027

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable ia-dashboard >/dev/null 2>&1
systemctl restart ia-dashboard
sleep 4
systemctl is-active ia-dashboard
