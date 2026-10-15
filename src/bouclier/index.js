// Le bouclier de VIGIE : capteurs (syslog de la passerelle, sondes Suricata),
// renseignement (listes de menaces), corrélation, riposte. Assemblé ici, branché
// sur la veille (événements, réaction rapide) et sur l'API.
import crypto from 'node:crypto';
import { Menaces } from './menaces.js';
import { Correlateur } from './correlation.js';
import { Riposte } from './riposte.js';
import { Recepteur } from './recepteur.js';
import { depuisEve, depuisPasserelle } from './journaux.js';
import { PasserelleMapMyLAN } from './passerelle-mml.js';

export const empreinteJeton = j => crypto.createHash('sha256').update(`sonde:${j}`).digest('hex');

export class Bouclier {
  constructor({ cfg, db, magasin, moteur, sources, journal, fetch: f = globalThis.fetch, log = console, maintenant = () => Date.now() }) {
    Object.assign(this, { cfg, db, magasin, moteur, sources, journal, log, maintenant });
    // Lu à chaque observation : gardé cinq secondes plutôt que relu en base des milliers de fois.
    let cache = { t: 0, r: null };
    const reglage = () => {
      const t = Date.now();
      if (!cache.r || t - cache.t > 5000) cache = { t, r: this.magasin.reglage('bouclier') };
      return cache.r;
    };
    this.menaces = new Menaces({ dossier: cfg.donnees, magasin, fetch: f, maintenant, log });
    const signaler = e => moteur.signaler(e);
    // Le routeur que MapMyLAN pilote déjà : la riposte s'en sert quand rien n'est relié directement.
    this.passerelle = { reliee: false, lu: null };
    const passerelleAuto = () => (this.passerelle.reliee && this.passerelle.bouclier ? new PasserelleMapMyLAN({ sources, nom: this.passerelle.nom, hote: this.passerelle.hote }) : null);
    this.riposte = new Riposte({ db, magasin, journal, signaler, maintenant, log, passerelleAuto });
    this.releve = { derniere: null, lues: 0, erreur: null, depuis: null, vus: new Set() };
    this.derniereIpsSyslog = 0;
    this.correlateur = new Correlateur({ menaces: this.menaces, reglage, maintenant, surVerdict: v => this.surVerdict(v).catch(e => log.warn?.(`[bouclier] ${e.message}`)) });
    this.recepteur = new Recepteur({
      port: cfg.syslogPort, emetteurs: () => reglage().emetteurs, log, maintenant,
      surObservation: o => { if (o.type === 'ips') this.derniereIpsSyslog = this.maintenant(); this.correlateur.observer(o); this.sentinelle?.observation(o); },
    });
    this.sondes = {};
    this.sentinelle = null;
  }

  /** La sentinelle lit les lignes de journaux d'hôtes que le bouclier ne reconnaît pas, et reçoit ses observations en flux. */
  brancher(sentinelle) {
    this.sentinelle = sentinelle;
    this.recepteur.surLigne = (texte, emetteur, t) => sentinelle.ligne(texte, emetteur, t);
  }

  async surVerdict(v) {
    const b = await this.riposte.verdict(v);
    // Une machine du réseau : la réaction rapide de la veille décide, sous ses propres règles.
    if (v.interne && this.sources.public().mapmylan?.relie) {
      const a = await this.sources.appareilParIp(v.ip).catch(() => null);
      if (a) await this.moteur.reagir(a, { titre: `comportement de machine compromise (${v.raisons[0] || 'score ' + v.score})` });
    }
    return b;
  }

  /** Des événements EVE d'une sonde Suricata (déjà authentifiée). */
  recevoirEve(lignes, sonde) {
    let lues = 0;
    for (const l of lignes) {
      let o = l;
      if (typeof l === 'string') { try { o = JSON.parse(l); } catch { continue; } }
      const obs = depuisEve(o, `sonde:${sonde}`);
      if (!obs) continue;
      lues++;
      this.correlateur.observer(obs);
    }
    this.sondes[sonde] = { derniere: this.maintenant(), lues: (this.sondes[sonde]?.lues || 0) + lues };
    return lues;
  }
  sondeDuJeton(jeton) {
    if (!/^vgs_[A-Za-z0-9_-]{40,60}$/.test(String(jeton || ''))) return null;
    const e = empreinteJeton(jeton);
    const s = (this.magasin.reglage('bouclier').sondes || []).find(x => crypto.timingSafeEqual(Buffer.from(x.empreinte, 'hex'), Buffer.from(e, 'hex')));
    return s?.nom || null;
  }

  /** Le routeur principal de MapMyLAN, s'il y en a un : relu toutes les cinq minutes. */
  async lirePasserelle() {
    if (!this.sources.public().mapmylan?.relie) { this.passerelle = { reliee: false, lu: this.maintenant() }; return this.passerelle; }
    const avant = this.passerelle;
    try {
      const p = await this.sources.mml('/api/passerelle');
      this.passerelle = { reliee: !!p?.reliee, nom: String(p?.nom || '').slice(0, 80), hote: String(p?.hote || '').slice(0, 253), libelle: String(p?.libelle || '').slice(0, 80), bouclier: !!p?.bouclier, ips: !!p?.ips, lu: this.maintenant(), erreur: null };
    } catch (e) {
      // Un MapMyLAN plus ancien ne connaît pas cette route : rien de relié par lui.
      this.passerelle = e.status === 404 ? { reliee: false, lu: this.maintenant(), ancien: true } : { ...avant, lu: this.maintenant(), erreur: e.message };
    }
    // Une passerelle qui apparaît (ou change) reçoit la liste tout de suite.
    if (this.passerelle.bouclier && (!avant.bouclier || avant.hote !== this.passerelle.hote)) { this.riposte.aSynchroniser = true; this.riposte.synchroniser().catch(() => null); }
    return this.passerelle;
  }

  /**
   * Les alertes de l'IPS de la passerelle, relevées par MapMyLAN chaque minute.
   * Si la passerelle en envoie déjà par syslog, la relève se tait : une même
   * alerte ne compte pas deux fois.
   */
  async releverIps() {
    if (!this.passerelle.ips) return 0;
    const t = this.maintenant();
    if (t - this.derniereIpsSyslog < 15 * 60e3) return 0;
    const depuis = this.releve.depuis ?? t - 10 * 60e3;
    let liste;
    try { liste = await this.sources.mml(`/api/passerelle/ips?depuis=${Math.floor(depuis)}&limite=1000`); } catch (e) { this.releve.erreur = e.message; return 0; }
    this.releve.erreur = null;
    let lues = 0, plusTard = depuis;
    for (const e of Array.isArray(liste) ? liste : []) {
      const cle = e?.id || `${e?.quand}|${e?.src}|${e?.dst}|${e?.sid}`;
      if (this.releve.vus.has(cle)) continue;
      this.releve.vus.add(cle);
      const o = depuisPasserelle(e, `passerelle:${this.passerelle.nom || this.passerelle.hote}`);
      if (!o) continue;
      lues++;
      plusTard = Math.max(plusTard, o.quand);
      this.correlateur.observer(o);
    }
    if (this.releve.vus.size > 5000) this.releve.vus = new Set([...this.releve.vus].slice(-2000));
    // La fenêtre suivante reprend un peu avant : une alerte écrite en retard n'est pas perdue, les vues sont écartées.
    this.releve.depuis = Math.max(depuis, plusTard - 60e3);
    this.releve.lues += lues;
    this.releve.derniere = t;
    return lues;
  }

  etat() {
    const r = this.magasin.reglage('bouclier');
    return {
      mode: r.mode, seuil: r.seuil,
      syslog: { port: this.cfg.syslogPortHote || this.cfg.syslogPort, emetteursDeclares: (r.emetteurs || []).length, ...this.recepteur.stats },
      sondes: (r.sondes || []).map(s => ({ nom: s.nom, cree: s.cree, ...(this.sondes[s.nom] || { derniere: null, lues: 0 }) })),
      listes: this.menaces.public(),
      menaces: this.correlateur.menacesActuelles({ limite: 60, interne: false }),
      internes: this.correlateur.menacesActuelles({ limite: 30, interne: true }),
      alertes: this.correlateur.recentes.slice(0, 60),
      compteurs: this.correlateur.compteurs,
      blocages: this.riposte.blocages({ limite: 150 }),
      actifs: this.riposte.actifs().length,
      unifi: { relie: !!this.riposte.unifi(), directe: !!(r.unifiHote && r.cleUnifi), hote: r.unifiHote || '', fp: r.unifiFp || '', ...this.riposte.etatUnifi },
      passerelle: { ...this.passerelle, releve: { derniere: this.releve.derniere, lues: this.releve.lues, erreur: this.releve.erreur, active: !!this.passerelle.ips && this.maintenant() - this.derniereIpsSyslog >= 15 * 60e3 } },
    };
  }

  async demarrer() {
    await this.recepteur.demarrer().catch(e => this.log.warn?.(`[syslog] port ${this.cfg.syslogPort} : ${e.message}`));
    const listes = () => this.menaces.actualiser().catch(e => this.log.warn?.(`[menaces] ${e.message}`));
    this.tListes = setTimeout(listes, 15_000); this.tListes.unref?.();
    this.iListes = setInterval(listes, 30 * 60e3); this.iListes.unref?.();
    this.iRiposte = setInterval(() => { this.riposte.expirer(); this.riposte.synchroniser().catch(() => null); this.releverIps().catch(() => null); }, 60e3);
    this.iRiposte.unref?.();
    const passerelle = () => this.lirePasserelle().catch(e => this.log.warn?.(`[passerelle] ${e.message}`));
    this.tPasserelle = setTimeout(passerelle, 5_000); this.tPasserelle.unref?.();
    this.iPasserelle = setInterval(passerelle, 5 * 60e3); this.iPasserelle.unref?.();
    return this;
  }
  arreter() { clearTimeout(this.tListes); clearInterval(this.iListes); clearInterval(this.iRiposte); clearTimeout(this.tPasserelle); clearInterval(this.iPasserelle); this.recepteur.arreter(); }
}
