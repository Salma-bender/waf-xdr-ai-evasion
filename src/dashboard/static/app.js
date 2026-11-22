"use strict";
// Toutes les données viennent du trafic analysé : elles sont insérées UNIQUEMENT
// via textContent (jamais innerHTML), pour qu'une charge XSS reste du texte.
const $ = (id) => document.getElementById(id);
const LIBELLES = {
  evasion_rattrapee: "Évasion rattrapée",
  attaque_bloquee: "Attaque confirmée",
  bloquee_waf_seul: "WAF seul",
  legitime: "Légitime",
};
const FAMILLES = { sqli: "SQLi", xss: "XSS", lfi_rfi: "LFI/RFI", rce: "RCE" };
const STATUTS = {
  en_attente: "En attente",
  valide: "Validée",
  rejete: "Rejetée",
  applique: "Appliquée",
};

function el(tag, texte, classe) {
  const e = document.createElement(tag);
  if (texte !== undefined && texte !== null) e.textContent = String(texte);
  if (classe) e.className = classe;
  return e;
}

function vider(n) { while (n.firstChild) n.removeChild(n.firstChild); }

async function lire(url) {
  const r = await fetch(url, { credentials: "same-origin", cache: "no-store" });
  if (!r.ok) throw new Error("HTTP " + r.status);
  return r.json();
}

function afficherResume(d) {
  $("k-evasion").textContent = d.categories.evasion_rattrapee;
  $("k-bloquee").textContent = d.categories.attaque_bloquee;
  $("k-wafseul").textContent = d.categories.bloquee_waf_seul;
  $("k-total").textContent = d.total;
  $("k-score").textContent = d.score_moyen === null ? "aucune attaque" : "score moyen " + d.score_moyen;

  const fam = $("familles"); vider(fam);
  const max = Math.max(1, ...Object.values(d.familles));
  for (const cle of Object.keys(FAMILLES)) {
    const n = d.familles[cle] || 0;
    const ligne = el("div", null, "barre");
    ligne.appendChild(el("span", FAMILLES[cle], "nom"));
    const piste = el("span", null, "piste");
    const plein = el("span", null, "plein f-" + cle);
    plein.style.width = (100 * n / max) + "%";
    piste.appendChild(plein);
    ligne.appendChild(piste);
    ligne.appendChild(el("span", n, "nb"));
    fam.appendChild(ligne);
  }

  const src = $("sources"); vider(src);
  if (!d.sources.length) { const tr = el("tr"); const td = el("td", "aucune attaque", "vide"); td.colSpan = 3; tr.appendChild(td); src.appendChild(tr); }
  for (const s of d.sources) {
    const tr = el("tr");
    tr.appendChild(el("td", s.client_ip || "?", "mono"));
    tr.appendChild(el("td", s.n));
    tr.appendChild(el("td", s.evasions, s.evasions ? "alerte" : ""));
    src.appendChild(tr);
  }

  const ch = $("chrono"); vider(ch);
  const maxT = Math.max(1, ...d.chronologie.map((h) => h.total));
  for (const h of d.chronologie) {
    const col = el("div", null, "col");
    col.title = h.heure.replace("T", " ") + "h — " + h.total + " requêtes, " + h.attaques + " attaques";
    const tot = el("span", null, "tot"); tot.style.height = (100 * h.total / maxT) + "%";
    const att = el("span", null, "att"); att.style.height = (100 * h.attaques / maxT) + "%";
    col.appendChild(tot); col.appendChild(att);
    col.appendChild(el("span", h.heure.slice(11, 13) + "h", "h"));
    ch.appendChild(col);
  }
  if (!d.chronologie.length) ch.appendChild(el("p", "aucune requête sur la période", "vide"));
}

function afficherDetections(lignes) {
  const tb = $("detections"); vider(tb);
  if (!lignes.length) { const tr = el("tr"); const td = el("td", "aucune détection", "vide"); td.colSpan = 9; tr.appendChild(td); tb.appendChild(tr); return; }
  for (const l of lignes) {
    const tr = el("tr", null, l.categorie === "evasion_rattrapee" ? "ligne-evasion" : "");
    tr.appendChild(el("td", (l.horodatage || "").replace("T", " ").slice(0, 19), "mono"));
    tr.appendChild(el("td", LIBELLES[l.categorie] || l.categorie, "pastille c-" + l.categorie));
    tr.appendChild(el("td", FAMILLES[l.ia_famille] || l.ia_famille));
    tr.appendChild(el("td", Number(l.ia_score).toFixed(2), "mono"));
    tr.appendChild(el("td", l.waf_statut ?? "–", "mono"));
    tr.appendChild(el("td", l.client_ip, "mono"));
    tr.appendChild(el("td", l.uri, "mono petit"));
    tr.appendChild(el("td", l.parametre, "mono"));
    tr.appendChild(el("td", l.valeur, "mono charge"));
    tb.appendChild(tr);
  }
}

// ----- Phase 09 : règles proposées + validation humaine ---------------------
async function decider(rid, decision, bouton) {
  if (decision === "rejete" && !confirm("Rejeter la règle " + rid + " ?")) return;
  const parent = bouton.parentNode;
  parent.querySelectorAll("button").forEach((b) => (b.disabled = true));
  try {
    const r = await fetch("/api/regles/decider", {
      method: "POST",
      credentials: "same-origin",
      cache: "no-store",
      headers: { "Content-Type": "application/json", "X-SOC-CSRF": "1" },
      body: JSON.stringify({ regle_id: rid, decision: decision }),
    });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.erreur || "HTTP " + r.status);
    rafraichirRegles();
  } catch (e) {
    alert("Échec : " + e.message);
    parent.querySelectorAll("button").forEach((b) => (b.disabled = false));
  }
}

function afficherRegles(d) {
  const lignes = d.regles || [];
  const tb = $("regles"); vider(tb);
  if (!lignes.length) { const tr = el("tr"); const td = el("td", "aucune règle", "vide"); td.colSpan = 9; tr.appendChild(td); tb.appendChild(tr); return; }
  for (const l of lignes) {
    const tr = el("tr", null, l.statut === "en_attente" ? "ligne-attente" : "");
    tr.appendChild(el("td", l.regle_id, "mono"));
    tr.appendChild(el("td", FAMILLES[l.famille] || l.famille));
    tr.appendChild(el("td", l.emplacement, "mono petit"));
    tr.appendChild(el("td", l.client_ip || "?", "mono"));
    tr.appendChild(el("td", l.payload, "mono charge"));
    tr.appendChild(el("td", l.motif, "mono charge"));
    const tdx = el("td", l.regle_xml, "mono regle");
    tdx.title = l.regle_xml;
    tr.appendChild(tdx);
    tr.appendChild(el("td", STATUTS[l.statut] || l.statut, "pastille s-" + l.statut));

    const act = el("td");
    if (l.statut === "en_attente") {
      const ok = el("button", "Valider", "btn btn-ok");
      ok.addEventListener("click", () => decider(l.regle_id, "valide", ok));
      const no = el("button", "Rejeter", "btn btn-no");
      no.addEventListener("click", () => decider(l.regle_id, "rejete", no));
      act.appendChild(ok); act.appendChild(no);
    } else {
      const quand = (l.applique_le || l.decide_le || "").replace("T", " ").slice(0, 19);
      act.appendChild(el("span", (l.decide_par ? l.decide_par + " · " : "") + quand, "petit"));
    }
    tr.appendChild(act);
    tb.appendChild(tr);
  }
}

async function rafraichirRegles() {
  try {
    const d = await lire("/api/regles?statut=" + encodeURIComponent($("filtre-regles").value));
    afficherRegles(d);
  } catch (e) {
    const tb = $("regles"); vider(tb);
    const tr = el("tr"); const td = el("td", "règles indisponibles (" + e.message + ")", "vide");
    td.colSpan = 9; tr.appendChild(td); tb.appendChild(tr);
  }
}

async function rafraichir() {
  try {
    const h = $("periode").value;
    const [res, det] = await Promise.all([
      lire("/api/resume?heures=" + encodeURIComponent(h)),
      lire("/api/detections?limite=100&categorie=" + encodeURIComponent($("filtre").value)),
    ]);
    afficherResume(res);
    afficherDetections(det);
    $("maj").textContent = "mis à jour " + new Date().toLocaleTimeString("fr-FR");
    $("maj").className = "";
  } catch (e) {
    $("maj").textContent = "connexion perdue (" + e.message + ")";
    $("maj").className = "erreur";
  }
  rafraichirRegles();
}

document.addEventListener("DOMContentLoaded", () => {
  $("periode").addEventListener("change", rafraichir);
  $("filtre").addEventListener("change", rafraichir);
  $("filtre-regles").addEventListener("change", rafraichirRegles);
  rafraichir();
  setInterval(rafraichir, 5000);
});
