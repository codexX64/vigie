// Le moteur de la Sentinelle : pré-décodage, décodage, puis l'arbre des règles
// — chaque ligne de journal d'hôte reçoit un niveau de 0 à 15. Les règles
// composées (« n fois en t secondes », « après telle autre alerte », « première
// fois vue ») tiennent leur mémoire ici, en fenêtres glissantes bornées.
//
// Une ligne → traiter() → { evenement, alerte }. L'événement existe dès qu'une
// règle a correspondu (niveau ≥ 1, pas silencieuse) ; l'alerte quand le niveau
// atteint le seuil. Tout est dérivé des règles : rien n'est codé en dur ici.
import { predecoder } from './predecodeur.js';
import { decoder } from './decodeurs.js';
import { REGLES, RACINES, ENFANTS, gravite } from './regles.js';

const MAX_FENETRES = 20000;      // clés de comptage vivantes (par règle composée)
const MAX_HISTORIQUE = 4000;     // entrées par clé d'« après »
const MAX_HOTES = 2000;
const MAX_RECENTS = 300;

// Les règles et groupes qu'une règle « après » consulte : seuls ceux-là sont historisés.
const SUIVIS = new Set();
for (const r of REGLES) if (r.apres) SUIVIS.add(r.apres.regle ? `regle:${r.apres.regle}` : `groupe:${r.apres.groupe}`);

const valeur = (ev, champ) => champ === 'hote' ? ev.hote : champ === 'decodeur' ? ev.decodeur : champ === 'programme' ? ev.programme : ev.champs[champ];
const cleDe = (ev, champs) => champs.map(c => valeur(ev, c) ?? '').join('\u0001');
const estComposee = r => r.frequence || r.apres || r.fts;

export class Sentinelle {
  /**
   * @param {object} o
   * @param {() => number} [o.maintenant]
   * @param {{ vu(cle): boolean, noter(cle): void }} [o.vus]  mémoire « première fois » (persistée par l'appelant)
   * @param {(ev) => void} [o.surEvenement]  toute ligne qui a un niveau ≥ 1 et n'est pas silencieuse
   * @param {(alerte) => void} [o.surAlerte]  niveau ≥ seuil()
   * @param {() => number} [o.seuil]  niveau à partir duquel on alerte (défaut 7)
   */
  constructor({ maintenant = () => Date.now(), vus, surEvenement = () => {}, surAlerte = () => {}, seuil = () => 7, log = console } = {}) {
    Object.assign(this, { maintenant, surEvenement, surAlerte, seuil, log });
    const memo = new Set();
    this.vus = vus || { vu: c => memo.has(c), noter: c => memo.add(c) };
    this.fenetres = new Map();     // `${regle.id}|${cle}` → [horodatages]
    this.historique = new Map();   // `regle:id` | `groupe:g` → [{ quand, ev }]
    this.silences = new Map();     // `${regle.id}|${cle}` → dernière alerte
    this.hotes = new Map();        // hote → { premier, dernier, lignes, evenements, alertes, niveauMax, programmes: Map }
    this.compteurs = {};           // regle.id → occurrences
    this.stats = { lignes: 0, decodees: 0, evenements: 0, alertes: 0, parDecodeur: {}, parNiveau: {} };
    this.recents = [];             // dernières alertes
    this.flux = [];                // derniers événements (toute règle non silencieuse)
  }

  // ---- conditions atomiques ----
  correspond(r, ev) {
    if (r.decodeur !== undefined && !this.egal(r.decodeur, ev.decodeur)) return false;
    if (r.programme !== undefined && !this.egal(r.programme, ev.programme)) return false;
    if (r.geste !== undefined && !this.egal(r.geste, ev.geste)) return false;
    if (r.hote !== undefined && !this.egal(r.hote, ev.hote)) return false;
    if (r.message && !r.message.test(ev.message)) return false;
    if (r.champs) for (const [k, re] of Object.entries(r.champs)) { const v = ev.champs[k]; if (v === undefined || !re.test(String(v))) return false; }
    return true;
  }
  egal(attendu, v) { return attendu instanceof RegExp ? attendu.test(v || '') : attendu === v; }

  // ---- conditions composées ----
  frequence(r, ev, t) {
    const cle = `${r.id}|${cleDe(ev, r.meme || ['hote'])}`;
    let f = this.fenetres.get(cle);
    if (!f) { if (this.fenetres.size >= MAX_FENETRES) this.elaguerFenetres(t); f = []; this.fenetres.set(cle, f); }
    const depuis = t - r.fenetre * 1000;
    while (f.length && f[0] < depuis) f.shift();
    f.push(t);
    if (f.length < r.frequence) return false;
    f.length = 0;   // on repart de zéro : une alerte par salve
    return true;
  }
  elaguerFenetres(t) {
    for (const [k, f] of this.fenetres) if (!f.length || t - f[f.length - 1] > 3600e3) this.fenetres.delete(k);
    if (this.fenetres.size >= MAX_FENETRES) { let n = Math.ceil(MAX_FENETRES / 5); for (const k of this.fenetres.keys()) { this.fenetres.delete(k); if (--n <= 0) break; } }
  }
  apres(r, ev, t) {
    const a = r.apres;
    const h = this.historique.get(a.regle ? `regle:${a.regle}` : `groupe:${a.groupe}`);
    if (!h) return false;
    const depuis = t - a.fenetre * 1000;
    const meme = a.meme || ['hote'];
    const cle = cleDe(ev, meme);
    let n = 0;
    for (let i = h.length - 1; i >= 0 && h[i].quand >= depuis; i--) if (cleDe(h[i].ev, meme) === cle && ++n >= (a.frequence || 1)) return true;
    return false;
  }
  premiereFois(r, ev) {
    for (const c of r.fts) if (valeur(ev, c) === undefined || valeur(ev, c) === '') return false;
    const cle = `${r.id}|${cleDe(ev, r.fts)}`;
    if (this.vus.vu(cle)) return false;
    this.vus.noter(cle);
    return true;
  }
  composee(r, ev, t) {
    if (r.frequence && !this.frequence(r, ev, t)) return false;
    if (r.apres && !this.apres(r, ev, t)) return false;
    if (r.fts && !this.premiereFois(r, ev)) return false;
    return true;
  }
  silencieuse(r, ev, t) {
    if (!r.ignorer) return false;
    const cle = `${r.id}|${cleDe(ev, r.meme || ['hote', 'srcip', 'utilisateur'])}`;
    const d = this.silences.get(cle);
    if (d !== undefined && t - d < r.ignorer * 1000) return true;
    if (this.silences.size > MAX_FENETRES) this.silences.clear();
    this.silences.set(cle, t);
    return false;
  }

  historiser(regles, ev, t) {
    for (const r of regles) {
      const cles = [`regle:${r.id}`, ...r.groupes.map(g => `groupe:${g}`)].filter(k => SUIVIS.has(k));
      for (const k of cles) {
        let h = this.historique.get(k);
        if (!h) { h = []; this.historique.set(k, h); }
        // On ne garde que les champs qu'un « même » peut comparer.
        h.push({ quand: t, ev: { hote: ev.hote, decodeur: ev.decodeur, programme: ev.programme, champs: { srcip: ev.champs.srcip, utilisateur: ev.champs.utilisateur, mac: ev.champs.mac, unite: ev.champs.unite } } });
        if (h.length > MAX_HISTORIQUE) h.splice(0, h.length - MAX_HISTORIQUE);
      }
    }
  }

  /**
   * L'arbre : la première racine qui correspond, puis la descente de précision
   * en précision ; les règles composées sont ensuite testées sur toute la chaîne.
   * → { chaine: [règles atomiques], composees: [règles déclenchées], finale }
   */
  evaluer(ev, t, { sansEtat = false } = {}) {
    let chaine = [];
    for (const r of RACINES) { if (this.correspond(r, ev)) { chaine = [r]; break; } }
    if (!chaine.length) return { chaine, composees: [], finale: null };
    for (;;) {
      const enfants = ENFANTS.get(chaine[chaine.length - 1].id) || [];
      const suivant = enfants.find(e => !estComposee(e) && this.correspond(e, ev));
      if (!suivant) break;
      chaine.push(suivant);
    }
    const composees = [];
    const aTester = [...chaine];
    for (let i = 0; i < aTester.length; i++) {
      for (const c of ENFANTS.get(aTester[i].id) || []) {
        if (!estComposee(c) || !this.correspond(c, ev)) continue;
        if (sansEtat ? !(c.frequence || c.apres || c.fts) : !this.composee(c, ev, t)) continue;
        composees.push(c); aTester.push(c);   // une composée peut en nourrir une autre
      }
    }
    const candidates = [...composees, chaine[chaine.length - 1]];
    const finale = candidates.reduce((m, r) => (!m || r.niveau > m.niveau) ? r : m, null);
    return { chaine, composees, finale };
  }

  noterHote(ev, t, niveau, alerte) {
    if (!ev.hote) return;
    let h = this.hotes.get(ev.hote);
    if (!h) {
      if (this.hotes.size >= MAX_HOTES) { const plusVieux = [...this.hotes.entries()].sort((a, b) => a[1].dernier - b[1].dernier)[0]; this.hotes.delete(plusVieux[0]); }
      h = { hote: ev.hote, premier: t, dernier: t, lignes: 0, evenements: 0, alertes: 0, niveauMax: 0, programmes: {} };
      this.hotes.set(ev.hote, h);
    }
    h.dernier = t; h.lignes++;
    if (ev.programme && Object.keys(h.programmes).length < 64) h.programmes[ev.programme] = (h.programmes[ev.programme] || 0) + 1;
    if (niveau > 0) h.evenements++;
    if (alerte) { h.alertes++; if (niveau > h.niveauMax) h.niveauMax = niveau; }
  }

  /** Une ligne de journal → l'événement et, si le niveau le vaut, l'alerte. */
  traiter(ligne, { emetteur = '', quand } = {}) {
    const t = quand ?? this.maintenant();
    this.stats.lignes++;
    const pre = predecoder(ligne, { maintenant: t, emetteur });
    const dec = decoder(pre);
    const ev = { quand: pre.quand, recu: t, emetteur, hote: pre.hote, programme: pre.programme, pid: pre.pid, message: pre.message, decodeur: dec.decodeur, geste: dec.geste, champs: dec.champs, extrait: pre.brut.slice(0, 512) };
    if (dec.decodeur) { this.stats.decodees++; this.stats.parDecodeur[dec.decodeur] = (this.stats.parDecodeur[dec.decodeur] || 0) + 1; }
    const { chaine, composees, finale } = this.evaluer(ev, t);
    if (!finale) { this.noterHote(ev, t, 0, false); return { evenement: null, alerte: null, lue: !!dec.decodeur }; }
    for (const r of [...chaine, ...composees]) this.compteurs[r.id] = (this.compteurs[r.id] || 0) + 1;
    this.historiser([...chaine, ...composees], ev, t);
    const niveau = finale.niveau;
    // Silencieuse ou niveau 0 : comptée, jamais montrée. « ignorer » : l'événement
    // reste dans le flux, mais l'alerte n'est pas répétée pendant le délai.
    const tue = finale.silence || niveau === 0;
    const evenement = { ...ev, regle: finale.id, niveau, gravite: gravite(niveau), groupes: finale.groupes, description: finale.description, chaine: chaine.map(r => r.id), composees: composees.map(r => r.id) };
    const alerte = !tue && niveau >= this.seuil() && !this.silencieuse(finale, ev, t) ? evenement : null;
    this.noterHote(ev, t, tue ? 0 : niveau, !!alerte);
    if (!tue) {
      this.stats.evenements++; this.stats.parNiveau[niveau] = (this.stats.parNiveau[niveau] || 0) + 1;
      this.flux.unshift(evenement); if (this.flux.length > MAX_RECENTS) this.flux.length = MAX_RECENTS;
      try { this.surEvenement(evenement); } catch (e) { this.log.warn?.(`[sentinelle] ${e.message}`); }
    }
    if (alerte) {
      this.stats.alertes++;
      this.recents.unshift(alerte); if (this.recents.length > MAX_RECENTS) this.recents.length = MAX_RECENTS;
      try { this.surAlerte(alerte); } catch (e) { this.log.warn?.(`[sentinelle] ${e.message}`); }
    }
    return { evenement: tue ? null : evenement, alerte, lue: true };
  }

  /** Comme ossec-logtest : ce que la Sentinelle ferait d'une ligne, sans rien retenir. */
  essai(ligne, { emetteur = '' } = {}) {
    const t = this.maintenant();
    const pre = predecoder(ligne, { maintenant: t, emetteur });
    const dec = decoder(pre);
    const ev = { quand: pre.quand, hote: pre.hote, programme: pre.programme, pid: pre.pid, message: pre.message, decodeur: dec.decodeur, geste: dec.geste, champs: dec.champs };
    const { chaine, composees } = this.evaluer(ev, t, { sansEtat: true });
    const r = x => ({ id: x.id, niveau: x.niveau, groupes: x.groupes, description: x.description, ...(x.frequence ? { frequence: x.frequence, fenetre: x.fenetre, meme: x.meme } : {}), ...(x.apres ? { apres: x.apres } : {}), ...(x.fts ? { fts: x.fts } : {}) });
    return {
      predecodage: { quand: pre.quand, hote: pre.hote, programme: pre.programme, pid: pre.pid, message: pre.message },
      decodage: { decodeur: dec.decodeur, geste: dec.geste, champs: dec.champs },
      chaine: chaine.map(r),
      // Les composées listées ici sont celles que cette ligne nourrirait ; elles ne se déclenchent qu'avec la répétition.
      composeesPossibles: composees.map(r),
      // La finale d'une ligne seule : le bout de la chaîne (les composées demandent la répétition).
      finale: chaine.length ? { ...r(chaine[chaine.length - 1]), gravite: gravite(chaine[chaine.length - 1].niveau), silence: !!chaine[chaine.length - 1].silence } : null,
    };
  }

  etat() {
    const hotes = [...this.hotes.values()].sort((a, b) => b.niveauMax - a.niveauMax || b.dernier - a.dernier).slice(0, 200);
    const regles = Object.entries(this.compteurs).map(([id, n]) => ({ id, n })).sort((a, b) => b.n - a.n).slice(0, 60);
    return { stats: this.stats, hotes, regles, seuil: this.seuil(), nbRegles: REGLES.length };
  }
}

export { REGLES, gravite };
