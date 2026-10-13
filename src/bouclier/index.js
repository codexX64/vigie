// Le bouclier de VIGIE : capteurs (syslog de la passerelle, sondes Suricata),
// renseignement (listes de menaces), corrélation, riposte. Assemblé ici, branché
// sur la veille (événements, réaction rapide) et sur l'API.
import crypto from 'node:crypto';
import { Menaces } from './menaces.js';
import { Correlateur } from './correlation.js';
import { Riposte } from './riposte.js';
import { Recepteur } from './recepteur.js';
import { depuisEve } from './journaux.js';

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
    this.riposte = new Riposte({ db, magasin, journal, signaler, maintenant, log });
    this.correlateur = new Correlateur({ menaces: this.menaces, reglage, maintenant, surVerdict: v => this.surVerdict(v).catch(e => log.warn?.(`[bouclier] ${e.message}`)) });
    this.recepteur = new Recepteur({ port: cfg.syslogPort, emetteurs: () => reglage().emetteurs, surObservation: o => this.correlateur.observer(o), log, maintenant });
    this.sondes = {};
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
      unifi: { relie: !!this.riposte.unifi(), hote: r.unifiHote || '', fp: r.unifiFp || '', ...this.riposte.etatUnifi },
    };
  }

  async demarrer() {
    await this.recepteur.demarrer().catch(e => this.log.warn?.(`[syslog] port ${this.cfg.syslogPort} : ${e.message}`));
    const listes = () => this.menaces.actualiser().catch(e => this.log.warn?.(`[menaces] ${e.message}`));
    this.tListes = setTimeout(listes, 15_000); this.tListes.unref?.();
    this.iListes = setInterval(listes, 30 * 60e3); this.iListes.unref?.();
    this.iRiposte = setInterval(() => { this.riposte.expirer(); this.riposte.synchroniser().catch(() => null); }, 60e3);
    this.iRiposte.unref?.();
    return this;
  }
  arreter() { clearTimeout(this.tListes); clearInterval(this.iListes); clearInterval(this.iRiposte); this.recepteur.arreter(); }
}
