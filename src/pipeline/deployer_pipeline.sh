#!/bin/bash
# Déploiement du pipeline de génération de règles sur ia-soc (Phase 09, étape 1).
# À lancer depuis ~/waf-ia :   sudo bash src/pipeline/deployer_pipeline.sh
#   - code en lecture seule dans /opt/ia-soc/src/pipeline ;
#   - clé LLM dans /etc/ia-soc/pipeline.env (root:ia-svc, 640), jamais versionnée ;
#   - base des règles /var/lib/ia-soc/regles.db, propriété de ia-svc.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "À lancer avec sudo"; exit 1; }
[ -f src/pipeline/generer_regle.py ] || { echo "À lancer depuis ~/waf-ia"; exit 1; }

echo "[1/3] Code -> /opt/ia-soc/src/pipeline (lecture seule)"
install -d -o root -g root -m 755 /opt/ia-soc/src/pipeline
install -o root -g root -m 644 src/pipeline/fournisseurs.py src/pipeline/generer_regle.py /opt/ia-soc/src/pipeline/

echo "[2/3] Clé LLM (Gemini)"
if [ ! -f /etc/ia-soc/pipeline.env ]; then
    read -r -s -p "Colle ta clé d'API Gemini (rien ne s'affiche) puis Entrée : " CLE; echo
    [ -n "$CLE" ] || { echo "Clé vide"; exit 1; }
    ( umask 027; cat > /etc/ia-soc/pipeline.env <<ENV
GEMINI_API_KEY=$CLE
GEMINI_MODELE=gemini-3.5-flash-lite
IA_DB=/var/lib/ia-soc/detections.db
IA_REGLES_DB=/var/lib/ia-soc/regles.db
ENV
    )
    chown root:ia-svc /etc/ia-soc/pipeline.env
    chmod 640 /etc/ia-soc/pipeline.env
    unset CLE
    echo "  clé enregistrée dans /etc/ia-soc/pipeline.env"
else
    echo "  /etc/ia-soc/pipeline.env existe déjà (inchangé)"
fi

echo "[3/3] Base des règles"
install -d -o ia-svc -g ia-svc -m 750 /var/lib/ia-soc
echo "Déploiement terminé. Pour générer les règles des évasions :"
echo "  sudo -u ia-svc bash -c 'set -a; . /etc/ia-soc/pipeline.env; set +a; python3 /opt/ia-soc/src/pipeline/generer_regle.py'"
