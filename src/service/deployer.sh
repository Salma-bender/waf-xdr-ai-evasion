#!/bin/bash
# Déploiement du service d'analyse en production sur ia-soc (Phase 08).
# À lancer depuis ~/waf-ia :   sudo bash src/service/deployer.sh
#
# Espace de travail (~/waf-ia)  ->  production (/opt/ia-soc, propriété de root)
#   - utilisateur système dédié ia-svc, sans shell ;
#   - code, modèles et manifeste en lecture seule pour le service ;
#   - écriture limitée à /var/lib/ia-soc (base) et /var/log/ia-soc (alertes) ;
#   - jeton dans /etc/ia-soc/service.env (root:ia-svc, 640), jamais versionné.
set -euo pipefail
SRC=$(pwd)
DEST=/opt/ia-soc
[ -f "$SRC/src/security/models_manifest_final.json" ] || { echo "À lancer depuis ~/waf-ia"; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "À lancer avec sudo"; exit 1; }

echo "[1/6] Utilisateur de service"
id ia-svc >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin ia-svc

echo "[2/6] Code, modèles et manifeste -> $DEST (lecture seule)"
install -d -o root -g root -m 755 "$DEST" "$DEST/src" "$DEST/src/models" "$DEST/src/service" \
        "$DEST/src/security" "$DEST/models" "$DEST/models/final"
install -o root -g root -m 644 "$SRC/src/models/chargement_sur.py" "$SRC/src/models/caracteristiques.py" "$DEST/src/models/"
install -o root -g root -m 644 "$SRC/src/service/analyse_api.py" "$DEST/src/service/"
install -o root -g root -m 644 "$SRC/src/security/models_manifest_final.json" "$DEST/src/security/"
install -o root -g root -m 644 "$SRC"/models/final/*.joblib "$DEST/models/final/"
install -o root -g root -m 644 "$SRC/requirements.txt" "$DEST/"

echo "[3/6] Environnement Python dédié (versions figées de requirements.txt)"
if [ ! -x "$DEST/venv/bin/gunicorn" ]; then
    python3 -m venv "$DEST/venv"
    "$DEST/venv/bin/pip" install -q -r "$DEST/requirements.txt"
fi

echo "[4/6] Dossiers d'écriture et secret"
install -d -o ia-svc -g ia-svc -m 750 /var/lib/ia-soc /var/log/ia-soc
install -d -o root -g ia-svc -m 750 /etc/ia-soc
if [ ! -f /etc/ia-soc/service.env ]; then
    JETON=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    ( umask 027; cat > /etc/ia-soc/service.env <<ENV
IA_API_TOKEN=$JETON
IA_VERSION=final
IA_DB=/var/lib/ia-soc/detections.db
IA_ALERT_LOG=/var/log/ia-soc/ia-alertes.json
IA_DEBIT=50
IA_BIND=127.0.0.1:8000
ENV
    )
    chown root:ia-svc /etc/ia-soc/service.env
    chmod 640 /etc/ia-soc/service.env
fi

echo "[5/6] Unité systemd durcie"
cat > /etc/systemd/system/ia-analyse.service <<'UNIT'
[Unit]
Description=Service d'analyse IA - detection d'attaques Web (Phase 08)
After=network-online.target
Wants=network-online.target

[Service]
User=ia-svc
Group=ia-svc
EnvironmentFile=/etc/ia-soc/service.env
WorkingDirectory=/opt/ia-soc/src/service
ExecStart=/opt/ia-soc/venv/bin/gunicorn --bind ${IA_BIND} --workers 1 --threads 4 --access-logfile - analyse_api:app
Restart=on-failure
RestartSec=5

# Durcissement
NoNewPrivileges=yes
CapabilityBoundingSet=
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/ia-soc /var/log/ia-soc
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
systemctl enable ia-analyse >/dev/null 2>&1
systemctl restart ia-analyse

echo "[6/6] Vérification"
sleep 8
systemctl is-active ia-analyse
