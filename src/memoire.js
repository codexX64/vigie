// SYNAPSE : VIGIE y écrit chaque audit et chaque intervention, et lui demande
// avant le diagnostic suivant ce qu'il en a retenu. Le jeton est dérivé par le
// Hub pour VIGIE seul (cer_<nom>_…) ; SYNAPSE absent ne ralentit rien.
const FILE_MAX = 200, LOT = 50;

export class Memoire {
  constructor({ url, jeton, fetch: f = globalThis.fetch }) {
    Object.assign(this, { url, jeton, fetch: f });
    // Le nom de cerveau est celui que porte le jeton : SYNAPSE n'accepte que lui.
    this.agent = /^cer_([a-z0-9][a-z0-9-]{1,30})_/.exec(jeton || '')?.[1] || 'vigie';
    this.file = []; this.minuteur = null; this.attente = 5000;
    this.etat = { envoyes: 0, echecs: 0, dernierEnvoi: null, erreur: null, perdus: 0 };
  }
  get pret() { return !!(this.url && this.jeton); }
  public() { return { ...this.etat, enAttente: this.file.length, relie: this.pret }; }

  async poster(chemin, corps, delai) {
    const r = await this.fetch(`${this.url}${chemin}`, {
      method: 'POST', redirect: 'error', signal: AbortSignal.timeout(delai),
      headers: { authorization: `Bearer ${this.jeton}`, 'content-type': 'application/json' }, body: JSON.stringify(corps),
    });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json().catch(() => ({}));
  }

  raconter(e) {
    if (!this.pret) return;
    this.file.push({ ...e, tags: [...new Set(['vigie', 'securite', ...(e.tags || [])])].slice(0, 8), occurred_at: e.occurred_at || new Date().toISOString() });
    while (this.file.length > FILE_MAX) { this.file.shift(); this.etat.perdus++; }
    if (!this.minuteur) { this.minuteur = setTimeout(() => this.vider(), 1000); this.minuteur.unref?.(); }
  }

  async vider() {
    this.minuteur = null;
    if (!this.file.length) return;
    const lot = this.file.slice(0, LOT);
    try {
      await this.poster('/v1/ingest/batch', { events: lot }, 15_000);
      this.file.splice(0, lot.length);
      Object.assign(this.etat, { envoyes: this.etat.envoyes + lot.length, dernierEnvoi: new Date().toISOString(), erreur: null });
      this.attente = 5000;
    } catch (e) {
      this.etat.echecs++; this.etat.erreur = String(e.message).slice(0, 160);
      this.attente = Math.min(300_000, this.attente * 2);
    }
    if (this.file.length) { this.minuteur = setTimeout(() => this.vider(), this.etat.erreur ? this.attente : 300); this.minuteur.unref?.(); }
  }

  /** Ce que SYNAPSE a retenu sur la question, en texte ; '' s'il ne sait rien ou ne répond pas. */
  async briefer(question) {
    if (!this.pret) return '';
    try {
      const r = await this.poster('/v1/brief', { agent: this.agent, q: String(question).slice(0, 2000), budget: 1200 }, 5000);
      return String(r?.texte || '').slice(0, 5000);
    } catch { return ''; }
  }

  surAudit(a, priorites) {
    this.raconter({
      kind: 'security.audit', ref: `audit:${a.id}`,
      title: `Audit VIGIE : score ${a.score ?? '—'}/100 (${a.distribution.critique} critique, ${a.distribution.eleve} élevé, ${a.distribution.faible} faible)`,
      body: [
        `Audit ${a.declencheur} terminé, score global ${a.score ?? 'non évalué'}.`,
        ...Object.entries(a.domaines).filter(([, d]) => d.score !== null).map(([k, d]) => `${k} : ${d.score}/100`),
        priorites.length ? `Priorités : ${priorites.map(p => `${p.titre} (${p.sujet || 'global'})`).join(' ; ')}.` : 'Aucune priorité.',
        a.ia?.synthese ? `Synthèse IA : ${a.ia.synthese.slice(0, 1500)}` : '',
      ].filter(Boolean).join('\n'),
      tags: ['audit'], meta: { score: a.score, distribution: a.distribution },
    });
  }

  surIntervention(x) {
    this.raconter({
      kind: 'security.intervention', ref: `action:${x.id}`,
      title: `Intervention VIGIE : ${x.type} sur ${x.cibleNom || x.cible} — ${x.etat}`,
      body: `Service : réseau (MapMyLAN). Problème : ${x.motif || '—'}. Correction : ${x.type}${x.automatique ? ' (réaction rapide automatique)' : ` (par ${x.auteur})`}. Résultat : ${x.resultat || x.etat}.`,
      tags: ['intervention', x.type], meta: { automatique: x.automatique, etat: x.etat },
    });
  }

  surEvenement(e) {
    if (e.gravite !== 'critique' && e.gravite !== 'eleve') return;
    this.raconter({ kind: e.gravite === 'critique' ? 'incident.security' : 'security.alert', ref: `evenement:${e.id}`, title: e.titre.slice(0, 280), body: e.texte, tags: ['veille', e.type], meta: { gravite: e.gravite } });
  }

  arreter() { clearTimeout(this.minuteur); this.minuteur = null; }
}
