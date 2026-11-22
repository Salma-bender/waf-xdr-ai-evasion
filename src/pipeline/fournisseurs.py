"""Appel à un LLM avec rotation de fournisseurs (Phase 09).

Le LLM a un rôle étroit et encadré : il ne propose qu'un *motif de détection*
(expression régulière) pour un payload. Il n'écrit jamais la règle ModSecurity ;
c'est le générateur (generer_regle.py) qui la construit à partir d'un gabarit figé.

Rotation : plusieurs fournisseurs sont essayés dans l'ordre jusqu'à ce que l'un
réponde. Cela donne de la résilience sans dépendre d'un seul service.

Fournisseurs reconnus (configurés par variables d'environnement) :
  - Gemini   : GEMINI_API_KEY (et GEMINI_API_KEY_2, _3… pour plusieurs clés)
               GEMINI_MODELE (défaut : gemini-3.5-flash-lite)
  - Ollama   : OLLAMA_URL (ex. http://127.0.0.1:11434), OLLAMA_MODELE (défaut : qwen2.5:3b)

Bibliothèque standard uniquement. Les clés viennent de l'environnement, jamais du code.
"""
import json
import os
import urllib.error
import urllib.request


class ErreurFournisseur(Exception):
    pass


class Fournisseur:
    nom = "abstrait"

    def appeler(self, invite, timeout=30):
        raise NotImplementedError


class FournisseurGemini(Fournisseur):
    def __init__(self, cle, modele="gemini-3.5-flash-lite", etiquette="gemini"):
        self.cle = cle
        self.modele = modele
        self.nom = etiquette

    def appeler(self, invite, timeout=30):
        url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
               f"{self.modele}:generateContent?key={self.cle}")
        corps = {
            "contents": [{"parts": [{"text": invite}]}],
            "generationConfig": {"temperature": 0, "maxOutputTokens": 512,
                                 "responseMimeType": "application/json"},
        }
        req = urllib.request.Request(url, data=json.dumps(corps).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                rep = json.loads(r.read())
        except urllib.error.HTTPError as e:
            raise ErreurFournisseur(f"{self.nom} HTTP {e.code}")
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise ErreurFournisseur(f"{self.nom} injoignable : {e}")
        try:
            parties = rep["candidates"][0]["content"]["parts"]
        except (KeyError, IndexError):
            raison = ""
            try:
                raison = rep["candidates"][0].get("finishReason", "")
            except (KeyError, IndexError):
                pass
            raise ErreurFournisseur(f"{self.nom} : réponse inattendue {raison}".strip())
        texte = "".join(p["text"] for p in parties if isinstance(p, dict) and "text" in p)
        if not texte.strip():
            raison = rep["candidates"][0].get("finishReason", "")
            raise ErreurFournisseur(f"{self.nom} : réponse vide {raison}".strip())
        return texte


class FournisseurOllama(Fournisseur):
    def __init__(self, url, modele="qwen2.5:3b", etiquette="ollama"):
        self.url = url.rstrip("/")
        self.modele = modele
        self.nom = etiquette

    def appeler(self, invite, timeout=60):
        corps = {"model": self.modele, "prompt": invite, "stream": False,
                 "format": "json", "options": {"temperature": 0}}
        req = urllib.request.Request(self.url + "/api/generate",
                                     data=json.dumps(corps).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read()).get("response", "")
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise ErreurFournisseur(f"{self.nom} injoignable : {e}")


def fournisseurs_configures():
    """Construit la liste des fournisseurs à partir de l'environnement, dans l'ordre d'essai."""
    liste = []
    for suffixe in ("", "_2", "_3", "_4", "_5", "_6", "_7"):
        cle = os.environ.get(f"GEMINI_API_KEY{suffixe}")
        if cle:
            modele = os.environ.get("GEMINI_MODELE", "gemini-3.5-flash-lite")
            liste.append(FournisseurGemini(cle, modele, f"gemini{suffixe or '_1'}"))
    if os.environ.get("OLLAMA_URL"):
        liste.append(FournisseurOllama(os.environ["OLLAMA_URL"],
                                       os.environ.get("OLLAMA_MODELE", "qwen2.5:3b")))
    return liste


def interroger(invite, fournisseurs=None):
    """Essaie chaque fournisseur dans l'ordre. Rend (nom_fournisseur, texte_reponse)."""
    fournisseurs = fournisseurs or fournisseurs_configures()
    if not fournisseurs:
        raise ErreurFournisseur("aucun fournisseur configuré (GEMINI_API_KEY absent)")
    erreurs = []
    for f in fournisseurs:
        try:
            return f.nom, f.appeler(invite)
        except ErreurFournisseur as e:
            erreurs.append(str(e))
    raise ErreurFournisseur("tous les fournisseurs ont échoué : " + " ; ".join(erreurs))
