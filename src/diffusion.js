// Où partent les alertes de VIGIE, en plus des déclencheurs que le Hub relève :
// une billetterie (Aselia ou autre, format « ticket/v1 », comme MapMyLAN) et
// Telegram (envoi seul, aucun bot qui écoute). Chacune a son seuil de gravité.
import crypto from 'node:crypto';
import { RANG } from './base.js';

const S = (v, max = 512) => String(v ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/[\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]/g, '').trim().slice(0, max);
const echappe = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const URGENCE = { critique: 'p1', eleve: 'p2', faible: 'p3', info: 'p4', safe: 'p4' };
const IMPACT = { critique: 'bloquant', eleve: 'degrade', faible: 'mineur', info: 'mineur', safe: 'mineur' };
const ICONE = { critique: '🔴', eleve: '🟠', faible: '🟡', info: '🔵', safe: '🟢' };

/** Un événement de VIGIE au format ticket/v1. */
export function ticketDe(e, { marqueur = 'ticket', lien = '' } = {}) {
  const cle = String(marqueur || 'ticket').replace(/[^a-z0-9_]/gi, '').slice(0, 32) || 'ticket';
  const brut = `vigie:${e.type}:${e.cle || e.sujet || 'global'}`;
  return {
    [cle]: 1, type: 'incident', titre: S(e.titre, 200) || 'Alerte de sécurité', urgence: URGENCE[e.gravite], impact: IMPACT[e.gravite], portee: e.gravite === 'critique' ? 'service' : 'utilisateur',
    service: 'securite', composant: 'vigie', zone: { site: '', vlan: null, host: S(e.sujet, 64), ip: '', url: '' },
    description: S(e.texte, 20000), symptomes: [], attendu: '', constate: S(e.titre, 1000), actions_faites: e.actions || [], logs: '',
    detecte_le: new Date(e.quand || Date.now()).toISOString(), projet: '', labels: ['securite', 'vigie', e.type.replace(/[^a-z0-9-]/gi, '-').slice(0, 40)],
    metriques: [], liens: lien ? [{ label: 'Ouvrir dans VIGIE', url: lien }] : [],
    dedup_key: brut.length <= 128 ? brut : `vigie:${crypto.createHash('sha256').update(brut).digest('hex').slice(0, 24)}`, source: { systeme: 'vigie', ref: e.id || '' },
  };
}

export class Diffusion {
  constructor({ magasin, fetch: f = globalThis.fetch, tgApi = 'https://api.telegram.org', urlPublique = '' }) {
    Object.assign(this, { magasin, fetch: f, tgApi, urlPublique });
    this.etat = { billetterie: null, telegram: null };
  }

  actif() {
    const b = this.magasin.reglage('billetterie'), t = this.magasin.reglage('telegram');
    return !!((b.url && b.cle) || (t.jeton && t.chat));
  }

  async poster(url, entetes, corps) {
    try {
      return await this.fetch(url, { method: 'POST', redirect: 'error', signal: AbortSignal.timeout(10_000), headers: { 'content-type': 'application/json', ...entetes }, body: JSON.stringify(corps) });
    } catch (e) { throw new Error(e.name === 'TimeoutError' ? 'délai dépassé' : 'injoignable'); }
  }

  async billetterie(e, { forcer = false } = {}) {
    const r = this.magasin.reglage('billetterie');
    const cle = this.magasin.secret('billetterie', 'cle');
    if (!r.url || !cle) return { ok: false, erreur: 'Billetterie non configurée.' };
    if (!forcer && RANG[e.gravite] < RANG[r.seuil]) return { ok: true, ignore: true };
    const nom = /^[A-Za-z0-9-]{1,40}$/.test(r.entete) ? r.entete : 'X-Ticket-Key';
    const t = ticketDe(e, { marqueur: r.marqueur, lien: this.urlPublique ? `${this.urlPublique}/#evenements` : '' });
    try {
      const rep = await this.poster(r.url, { [nom]: cle, 'idempotency-key': crypto.createHash('sha256').update(`${t.dedup_key}|${t.detecte_le.slice(0, 13)}`).digest('hex').slice(0, 32) }, t);
      const out = rep.status === 401 ? { ok: false, erreur: 'Clé refusée par la billetterie.' } : rep.ok ? { ok: true } : { ok: false, erreur: `La billetterie a répondu ${rep.status}.` };
      this.etat.billetterie = { ...out, quand: Date.now() };
      return out;
    } catch (x) { const out = { ok: false, erreur: `Contact impossible : ${x.message}.` }; this.etat.billetterie = { ...out, quand: Date.now() }; return out; }
  }

  async telegram(e, { forcer = false } = {}) {
    const r = this.magasin.reglage('telegram');
    const jeton = this.magasin.secret('telegram', 'jeton');
    if (!jeton || !r.chat) return { ok: false, erreur: 'Telegram non configuré.' };
    if (!forcer && RANG[e.gravite] < RANG[r.seuil]) return { ok: true, ignore: true };
    const texte = `${ICONE[e.gravite] || ''} <b>VIGIE</b> — ${echappe(S(e.titre, 300))}${e.texte ? `\n${echappe(S(e.texte, 1500))}` : ''}`;
    try {
      const rep = await this.poster(`${this.tgApi}/bot${jeton}/sendMessage`, {}, { chat_id: r.chat, text: texte, parse_mode: 'HTML', disable_web_page_preview: true });
      const j = await rep.json().catch(() => ({}));
      const out = j?.ok ? { ok: true } : { ok: false, erreur: rep.status === 401 ? 'Jeton du bot refusé.' : S(j?.description || `Telegram a répondu ${rep.status}.`, 160) };
      this.etat.telegram = { ...out, quand: Date.now() };
      return out;
    } catch (x) { const out = { ok: false, erreur: `Contact impossible : ${x.message}.` }; this.etat.telegram = { ...out, quand: Date.now() }; return out; }
  }

  /** Un événement vers tous les canaux configurés ; un canal en panne n'empêche pas l'autre. */
  async signaler(e) {
    const [b, t] = await Promise.all([this.billetterie(e).catch(() => null), this.telegram(e).catch(() => null)]);
    return { billetterie: b, telegram: t };
  }
}
