// Le cœur de VIGIE : les audits (collecte → règles → score → relecture IA),
// la veille de fond qui compare chaque passe à la précédente, et les actions
// de remédiation — toujours précédées d'un instantané, vérifiées après coup,
// défaites si elles n'ont pas pris.
//
// Deux régimes. Par défaut, VIGIE propose : rien ne s'exécute sans une
// personne (ou un workflow du Hub qu'elle a écrit). La réaction rapide —
// isoler seul un appareil sur un signe d'intrusion — est coupée tant qu'un
// administrateur ne l'a pas allumée, ne vise que les types d'appareils
// choisis, jamais l'infrastructure, et s'arrête au plafond horaire.
import { RANG, TYPES_PROTEGES } from './base.js';
import { evaluer, noter, priorites } from './regles.js';
import { nomAppareil } from './sources.js';

const REPOS_EVENEMENT_MS = 6 * 3600e3;
const ACTIONS = ['quarantine', 'ban', 'unban', 'deep-scan', 'scan'];
const ATTENDU = { quarantine: 'quarantined', ban: 'banned' };
export const LIBELLE_ACTION = { quarantine: 'Mise en quarantaine', ban: 'Bannissement', unban: 'Retour au réseau', 'deep-scan': 'Balayage approfondi', scan: 'Balayage du réseau' };
const PORTS_SENSIBLES = new Set([21, 23, 2375, 3389, 5900, 445, 139, 3306, 5432, 6379, 27017, 9200, 11211]);

export class ErreurAction extends Error {
  constructor(message, status = 409) { super(message); this.status = status; }
}

export class Moteur {
  constructor({ magasin, sources, ia, memoire, diffusion, journal, log = console, maintenant = () => Date.now() }) {
    Object.assign(this, { magasin, sources, ia, memoire, diffusion, journal, log, maintenant });
    this.enCours = null;
    this.passeEnCours = null;
    this.echecs = {};
    this.arrete = false;
  }

  contexte() {
    const v = this.magasin.reglage('veille');
    return {
      maintenant: this.maintenant(), seuilIntrusion: this.magasin.reglage('reaction').seuil,
      synapse: this.memoire.pret, veille: v.actif, veilleMinutes: v.minutes, notifications: this.diffusion.actif(),
    };
  }

  // ---------- audits ----------
  /** Lance un audit ; un seul à la fois. Rend l'identifiant tout de suite, le travail continue. */
  lancer({ declencheur, auteur = '', ia = true }) {
    if (this.enCours) return { id: this.enCours.id, deja: true };
    const id = this.magasin.ouvrirAudit({ declencheur, auteur });
    const travail = this.auditer(id, { ia }).catch(e => {
      this.log.warn?.(`[audit] ${e.message}`);
      this.magasin.fermerAudit(id, { statut: 'echec', erreur: String(e.message).slice(0, 300) });
    }).finally(() => { if (this.enCours?.id === id) this.enCours = null; });
    this.enCours = { id, travail };
    return { id, deja: false };
  }

  async auditer(id, { ia = true } = {}) {
    const precedent = this.magasin.dernierAudit();
    const d = await this.sources.collecter({ tls: this.magasin.reglage('veille').sondeTls });
    if (!d.mapmylan && !d.nexarc && !d.docker) {
      const raisons = Object.entries(d.sources).filter(([, s]) => s.relie && s.ok === false).map(([k, s]) => `${k} : ${s.erreur}`);
      throw new Error(raisons.length ? `Aucune source lisible (${raisons.join(' ; ')}).` : 'Aucune source reliée : installe MapMyLAN depuis le Hub.');
    }
    const constats = evaluer(d, this.contexte()).sort((a, b) => RANG[b.gravite] - RANG[a.gravite]);
    const notes = noter(constats);
    this.magasin.enregistrerConstats(id, constats);
    const sources = { ...d.sources, ...(d.mapmylan ? { mapmylan: { ...d.sources.mapmylan, n: d.mapmylan.appareils.length } } : {}) };
    this.magasin.fermerAudit(id, { statut: 'termine', score: notes.score, domaines: notes.domaines, distribution: notes.distribution, sources });
    const audit = this.magasin.audit(id);
    const prio = priorites(constats);
    this.journal?.ecrire({ acteur: null, action: 'audit.termine', objet: id, details: { score: notes.score, distribution: notes.distribution } });

    // Ce qui est nouveau depuis l'audit précédent et grave : un événement chacun.
    const avant = new Set(precedent ? this.magasin.constats(precedent.id).filter(c => RANG[c.gravite] >= RANG.eleve).map(c => c.cle) : []);
    for (const c of constats.filter(x => RANG[x.gravite] >= RANG.eleve && !avant.has(x.cle)).slice(0, 20)) {
      await this.signaler({ gravite: c.gravite, type: 'constat', titre: c.titre, texte: `${c.sujet ? c.sujet + ' — ' : ''}${c.correction}`, sujet: c.sujet, cle: c.cle });
    }
    await this.signaler({
      gravite: notes.distribution.critique ? 'critique' : notes.distribution.eleve ? 'eleve' : 'info', type: 'audit.termine',
      titre: `Audit terminé : ${notes.score ?? '—'}/100`, texte: `${notes.distribution.critique} critique, ${notes.distribution.eleve} élevé, ${notes.distribution.faible} faible, ${notes.distribution.safe} conforme.${prio.length ? ` Priorité : ${prio[0].titre}.` : ''}`,
      cle: `audit:${id}`, forcer: true, diffuser: false,
    });

    if (ia) await this.relire(id, constats, notes, prio);
    else this.magasin.poserIA(id, { statut: 'aucune', raison: 'non demandée' });
    this.memoire.surAudit(this.magasin.audit(id), prio);
    return this.magasin.audit(id);
  }

  async relire(id, constats, notes, prio) {
    const r = this.ia.reglage();
    if (r.mode === 'aucune') { this.magasin.poserIA(id, { statut: 'aucune' }); return; }
    this.magasin.poserIA(id, { statut: 'en cours', mode: r.mode });
    const memoire = await this.memoire.briefer(`audit de sécurité réseau : ${prio.map(p => p.titre).join(' ; ') || 'aucune priorité'}`);
    let res;
    try { res = await this.ia.relire({ constats, scores: notes, memoire }); } catch (e) { res = { ignore: 'relecture impossible', erreurs: [e.message] }; }
    if (res.ignore) { this.magasin.poserIA(id, { statut: 'ignoree', raison: res.ignore, erreurs: res.erreurs || [] }); return; }
    const parCle = new Map(this.magasin.constats(id).map(c => [c.cle, c.id]));
    for (const [cle, v] of Object.entries(res.verdicts)) if (parCle.has(cle)) this.magasin.verdictIA(parCle.get(cle), v.statut, v.note);
    this.magasin.poserIA(id, { statut: 'faite', moteur: res.moteur, modele: res.modele, synthese: res.synthese, scenarios: res.scenarios, priorites: res.priorites, corrections: res.corrections, erreurs: res.erreurs, memoire: !!memoire });
  }

  // ---------- événements ----------
  /** Un événement : noté, transmis (billetterie, Telegram, SYNAPSE), au plus une fois par six heures et par clé. */
  async signaler({ gravite, type, titre, texte = '', sujet = '', cle = '', forcer = false, diffuser = true }) {
    const memo = this.magasin.memoire('vus', {});
    const t = this.maintenant();
    const k = cle || `${type}:${sujet}:${titre}`;
    if (!forcer && memo[k] && t - memo[k] < REPOS_EVENEMENT_MS) return null;
    memo[k] = t;
    for (const [x, q] of Object.entries(memo)) if (t - q > 2 * REPOS_EVENEMENT_MS) delete memo[x];
    this.magasin.poserMemoire('vus', memo);
    const id = this.magasin.evenement({ gravite, type, titre, texte, sujet, cle: k });
    const e = { id, quand: t, gravite, type, titre, texte, sujet, cle: k };
    this.memoire.surEvenement(e);
    if (diffuser) await this.diffusion.signaler(e).catch(() => null);
    return e;
  }

  // ---------- veille ----------
  /** Une passe de veille : relire les sources, comparer à la passe d'avant, signaler ce qui a changé. */
  async passe() {
    if (this.passeEnCours) return this.passeEnCours;
    this.passeEnCours = this.passeInterne().finally(() => { this.passeEnCours = null; });
    return this.passeEnCours;
  }

  async passeInterne() {
    const d = await this.sources.collecter({ tls: false });
    const ancien = this.magasin.memoire('instantane', null);
    const neuf = { quand: this.maintenant(), appareils: {}, alertes: [], flux: [], nexarc: [], vlans: {} };
    const sorties = [];

    // Une source qui tombe deux passes de suite, puis qui revient.
    for (const [nom, s] of Object.entries(d.sources)) {
      if (!s.relie || nom === 'tls' || nom === 'synapse') continue;
      if (s.ok === false) {
        this.echecs[nom] = (this.echecs[nom] || 0) + 1;
        if (this.echecs[nom] === 2) sorties.push({ gravite: 'faible', type: 'source.panne', titre: `${nom} ne répond plus à VIGIE`, texte: s.erreur || '', cle: `source:${nom}:panne`, forcer: true });
      } else {
        if ((this.echecs[nom] || 0) >= 2) sorties.push({ gravite: 'info', type: 'source.retour', titre: `${nom} répond de nouveau`, cle: `source:${nom}:retour`, forcer: true });
        this.echecs[nom] = 0;
      }
    }

    const m = d.mapmylan;
    if (m) {
      const reaction = this.magasin.reglage('reaction');
      for (const a of m.appareils) {
        const k = a.mac || a.ip || a.id;
        const ports = (a.ports || []).filter(p => !p.state || p.state === 'open').map(p => p.port).sort((x, y) => x - y);
        neuf.appareils[k] = { ip: a.ip, ports, status: a.status, vlan: a.vlan };
        // Signe d'intrusion caractérisé : suspect, hors liste blanche, danger au-delà du seuil — dès la première passe.
        if (a.status === 'suspect' && !a.whitelisted && (a.dangerScore ?? 0) >= reaction.seuil) {
          sorties.push({ gravite: 'critique', type: 'intrusion', titre: `Signe d’intrusion : ${nomAppareil(a)} (danger ${a.dangerScore}/100)`, texte: (a.scoreReasons?.trust || []).slice(0, 3).map(r => r.reason).join(' ; '), sujet: nomAppareil(a), cle: `intrusion:${k}`, appareil: a });
        }
        if (!ancien) continue;
        const v = ancien.appareils?.[k];
        if (!v) {
          sorties.push({ gravite: a.whitelisted ? 'info' : 'faible', type: 'appareil.nouveau', titre: `Nouvel appareil : ${nomAppareil(a)}`, texte: `${a.ip || ''}${a.vendor ? ` · ${a.vendor}` : ''}${ports.length ? ` · ports ${ports.join(', ')}` : ''}`, sujet: nomAppareil(a), cle: `appareil.nouveau:${k}` });
        } else {
          const nouveaux = ports.filter(p => !v.ports.includes(p));
          if (nouveaux.length) sorties.push({ gravite: nouveaux.some(p => PORTS_SENSIBLES.has(p)) ? 'eleve' : 'faible', type: 'port.nouveau', titre: `Port${nouveaux.length > 1 ? 's' : ''} ouvert${nouveaux.length > 1 ? 's' : ''} sur ${nomAppareil(a)} : ${nouveaux.join(', ')}`, texte: `${a.ip || ''} — service apparu depuis la passe précédente.`, sujet: nomAppareil(a), cle: `port.nouveau:${k}:${nouveaux.join('-')}` });
          if (v.vlan !== a.vlan && Number.isInteger(v.vlan) && Number.isInteger(a.vlan)) sorties.push({ gravite: 'info', type: 'config.derive', titre: `${nomAppareil(a)} est passé du VLAN ${v.vlan} au VLAN ${a.vlan}`, sujet: nomAppareil(a), cle: `vlan:${k}:${a.vlan}` });
        }
      }
      for (const v of m.vlans) neuf.vlans[v.id] = { isole: !!v.isolated, nom: v.name };
      if (ancien?.vlans) {
        for (const [idv, v] of Object.entries(ancien.vlans)) {
          const n = neuf.vlans[idv];
          if (!n) sorties.push({ gravite: 'faible', type: 'config.derive', titre: `Le VLAN ${idv} (${v.nom}) a disparu`, cle: `vlan.retire:${idv}` });
          else if (v.isole && !n.isole) sorties.push({ gravite: 'eleve', type: 'config.derive', titre: `Le VLAN ${idv} (${n.nom}) n’est plus isolé`, cle: `vlan.isole:${idv}` });
        }
      }
      // Alertes graves de MapMyLAN jamais vues.
      const vuesA = new Set(ancien?.alertes || []);
      for (const al of m.alertes.filter(x => /^(critical|high)$/.test(x.severity) && !x.acknowledged)) {
        neuf.alertes.push(al.id);
        if (ancien && !vuesA.has(al.id)) sorties.push({ gravite: al.severity === 'critical' ? 'critique' : 'eleve', type: 'alerte.reseau', titre: String(al.message).slice(0, 200), texte: `MapMyLAN · ${al.source}${al.deviceIp ? ` · ${al.deviceIp}` : ''}`, sujet: al.deviceIp || '', cle: `alerte:${al.id}` });
      }
      // Trafic suspect jamais vu.
      const vuesF = new Set(ancien?.flux || []);
      for (const f of (m.flux || []).filter(x => x.suspect)) {
        neuf.flux.push(f.id);
        if (ancien && !vuesF.has(f.id)) sorties.push({ gravite: 'eleve', type: 'trafic.suspect', titre: `Connexion suspecte : ${f.src} → ${f.nom || f.domaine || f.dst}:${f.port}`, texte: f.raison || '', sujet: f.src, cle: `flux:${f.src}:${f.dst}:${f.port}` });
      }
      neuf.alertes = neuf.alertes.slice(-2000); neuf.flux = neuf.flux.slice(-5000);
    }
    if (d.nexarc) {
      const vuesN = new Set(ancien?.nexarc || []);
      for (const al of d.nexarc.alertes.filter(x => x.etat === 'ouverte' && x.sev === 'crit')) {
        neuf.nexarc.push(al.id);
        if (ancien && !vuesN.has(al.id)) sorties.push({ gravite: 'eleve', type: 'alerte.parc', titre: `${al.machine?.host || 'Poste'} : ${String(al.txt).slice(0, 160)}`, texte: 'NEXARC', sujet: al.machine?.host || '', cle: `nexarc:${al.id}` });
      }
    }
    this.magasin.poserMemoire('instantane', neuf);
    for (const s of sorties) {
      const { appareil, ...e } = s;
      const ev = await this.signaler(e);
      if (ev && appareil) await this.reagir(appareil, ev).catch(err => this.log.warn?.(`[réaction] ${err.message}`));
    }
    this.magasin.poserMemoire('derniere_passe', { quand: this.maintenant(), evenements: sorties.length, sources: d.sources });
    return { evenements: sorties.length };
  }

  // ---------- remédiation ----------
  /** La réaction rapide : isoler seul, dans le périmètre fixé d'avance, et le dire. */
  async reagir(a, ev) {
    const r = this.magasin.reglage('reaction');
    const type = String(a.customType || a.type || 'unknown');
    const refus = !r.actif ? 'réaction rapide coupée'
      : a.isMainRouter || TYPES_PROTEGES.includes(type) ? 'équipement d’infrastructure : jamais isolé seul'
        : !r.types.includes(type) ? `type « ${type} » hors du périmètre de réaction`
          : ['quarantined', 'banned'].includes(a.status) ? 'déjà isolé'
            : !this.sources.dansPerimetre(a.ip) ? 'adresse hors du périmètre autorisé'
              : this.magasin.automatiquesRecentes() >= r.parHeure ? `plafond de ${r.parHeure} isolement${r.parHeure > 1 ? 's' : ''} automatique${r.parHeure > 1 ? 's' : ''} par heure atteint`
                : null;
    if (refus) {
      if (r.actif) await this.signaler({ gravite: 'eleve', type: 'reaction.retenue', titre: `Pas d’isolement automatique de ${nomAppareil(a)}`, texte: `${refus}. Décision à prendre dans VIGIE.`, sujet: nomAppareil(a), cle: `retenue:${a.id}` });
      return null;
    }
    const x = await this.executer({ type: 'quarantine', appareil: a.id, motif: `VIGIE : ${ev.titre}`.slice(0, 200), auteur: 'vigie', automatique: true });
    await this.signaler({ gravite: 'critique', type: 'reaction', titre: x.etat === 'appliquee' ? `${nomAppareil(a)} isolé automatiquement` : `Isolement automatique de ${nomAppareil(a)} : ${x.etat}`, texte: `${ev.titre}. ${x.resultat}. Annulable depuis VIGIE (Actions).`, sujet: nomAppareil(a), cle: `reaction:${x.id}`, forcer: true });
    return x;
  }

  /**
   * Une action sur un appareil, par MapMyLAN : instantané, exécution,
   * vérification, et retour à l'état d'avant si elle n'a pas pris.
   */
  async executer({ type, appareil, motif = '', auteur, automatique = false, constat = null, forcer = false }) {
    if (!ACTIONS.includes(type)) throw new ErreurAction('Action inconnue.', 400);
    if (!this.sources.public().mapmylan.relie) throw new ErreurAction('MapMyLAN n’est pas relié : aucune action possible.');
    if (type === 'scan') {
      try { await this.sources.balayer(); } catch (e) { throw new ErreurAction(`MapMyLAN : ${e.message}.`, 502); }
      const x = this.magasin.noterAction({ type, cible: 'reseau', cibleNom: 'réseau', auteur, motif, automatique, etat: 'appliquee', resultat: 'Balayage lancé' });
      this.journal?.ecrire({ acteur: automatique ? null : auteur, action: 'action.scan', objet: 'reseau' });
      return x;
    }
    let avant;
    try { avant = await this.sources.appareil(appareil); } catch (e) { throw new ErreurAction(e.status === 404 ? 'Appareil inconnu de MapMyLAN.' : `MapMyLAN : ${e.message}.`, e.status === 404 ? 404 : 502); }
    const nom = nomAppareil(avant);
    // Le périmètre relu à chaque action : une plage retirée dans MapMyLAN l'est aussitôt pour VIGIE.
    // Sans plages lisibles, aucune action : le repli sur toutes les plages privées ne vaut que pour regarder.
    const plg = await this.sources.mml('/api/devices/scan/ranges').catch(() => null);
    const declarees = Array.isArray(plg) ? plg.filter(x => x?.enabled !== false && x?.cidr) : [];
    if (!declarees.length) throw new ErreurAction('Les plages de MapMyLAN sont illisibles ou vides : VIGIE n’agit pas sans périmètre déclaré.', 409);
    this.sources.perimetre(declarees);
    if (!this.sources.dansPerimetre(avant.ip)) throw new ErreurAction(`${nom} est hors du périmètre autorisé : VIGIE n’agit pas dessus.`, 403);
    if ((type === 'quarantine' || type === 'ban') && (avant.isMainRouter || TYPES_PROTEGES.includes(String(avant.customType || avant.type)))) {
      // La passerelle, un serveur, l'hyperviseur : jamais seul, jamais par un jeton ;
      // seulement une session d'administrateur qui le force après confirmation d'identité.
      if (automatique) throw new ErreurAction('Équipement d’infrastructure : jamais isolé automatiquement.', 403);
      if (!forcer) throw new ErreurAction(`${nom} est un équipement d’infrastructure : l’isoler couperait d’autres appareils. Un administrateur peut le forcer depuis VIGIE, après confirmation de son identité.`, 403);
    }
    const instantane = { status: avant.status, vlan: avant.vlan ?? null, whitelisted: !!avant.whitelisted, ip: avant.ip };
    let etat = 'appliquee', resultat = '';
    try {
      const r = await this.sources.agir(type, appareil, motif);
      resultat = type === 'deep-scan' ? `${(r?.ports || []).length} port${(r?.ports || []).length > 1 ? 's' : ''} relevé${(r?.ports || []).length > 1 ? 's' : ''}${r?.os ? ` · ${r.os}` : ''}` : 'Fait';
    } catch (e) {
      const x = this.magasin.noterAction({ type, cible: appareil, cibleNom: nom, auteur, motif, automatique, etat: 'echec', avant: instantane, resultat: `MapMyLAN : ${e.message}` });
      this.journal?.ecrire({ acteur: automatique ? null : auteur, action: `action.${type}`, objet: appareil, resultat: 'echec', details: { erreur: e.message } });
      this.memoire.surIntervention(x);
      return x;
    }
    // Vérification : l'état attendu est-il là ? Sinon, on défait.
    if (ATTENDU[type] || type === 'unban') {
      let apres = null;
      try { apres = await this.sources.appareil(appareil); } catch { apres = null; }
      const isole = st => ['quarantined', 'banned'].includes(st);
      if (!apres) {
        // Ne pas savoir n'est pas « n'a pas pris » : rien n'est défait, un appareil peut-être compromis reste isolé.
        etat = 'averifier';
        resultat = 'MapMyLAN n’a pas pu être relu après l’action : rien n’a été défait. À vérifier dans MapMyLAN.';
      } else if (!(ATTENDU[type] ? apres.status === ATTENDU[type] : !isole(apres.status))) {
        etat = 'restauree';
        // Défaire seulement ce qui a pris de travers (isolé autrement que demandé) ; sinon rien n'a changé.
        if (type !== 'unban' && isole(apres.status) && !isole(instantane.status)) {
          try { await this.sources.agir('unban', appareil); resultat = `L’état attendu n’a pas été constaté (statut : ${apres.status}) : retour à l’état d’avant.`; }
          catch (e) { etat = 'echec'; resultat = `État attendu non constaté, et retour impossible : ${e.message}. À vérifier dans MapMyLAN.`; }
        } else resultat = `L’état attendu n’a pas été constaté (statut : ${apres.status}) : rien à défaire.`;
      }
    }
    const x = this.magasin.noterAction({ type, cible: appareil, cibleNom: nom, auteur, motif: motif || (constat ? `Constat ${constat}` : ''), automatique, etat, avant: instantane, resultat });
    this.journal?.ecrire({ acteur: automatique ? null : auteur, action: `action.${type}`, objet: appareil, resultat: etat === 'appliquee' ? 'ok' : 'echec', details: { automatique, etat } });
    this.memoire.surIntervention(x);
    return x;
  }

  /** Défaire une isolation : l'appareil revient à l'état noté avant l'action. */
  async annuler(id, auteur) {
    const x = this.magasin.action(id);
    if (!x) throw new ErreurAction('Action inconnue.', 404);
    if (!['appliquee', 'averifier'].includes(x.etat) || !['quarantine', 'ban'].includes(x.type)) throw new ErreurAction('Cette action ne se défait pas.');
    if (['quarantined', 'banned'].includes(x.avant.status)) throw new ErreurAction('L’appareil était déjà isolé avant cette action : rien à défaire.');
    try { await this.sources.agir('unban', x.cible); } catch (e) { throw new ErreurAction(`MapMyLAN : ${e.message}.`, 502); }
    // MapMyLAN remet l'appareil « en ligne » : un statut d'avant comme « suspect » est perdu, on le dit.
    const perdu = x.avant.status && !['online', 'offline', 'quarantined', 'banned'].includes(x.avant.status);
    const y = this.magasin.annulerAction(id, auteur, perdu ? `Appareil rendu au réseau. Son statut d’avant (${x.avant.status}) n’est pas rétabli par MapMyLAN : à revérifier.` : 'Appareil rendu au réseau.');
    this.journal?.ecrire({ acteur: auteur, action: 'action.annulee', objet: x.cible, details: { action: id } });
    this.memoire.surIntervention({ ...y, type: 'unban', motif: `Annulation de ${LIBELLE_ACTION[x.type].toLowerCase()}`, etat: 'appliquee' });
    return y;
  }

  // ---------- horloge ----------
  demarrer() {
    const repris = this.magasin.reprendreInterrompus(this.maintenant());
    if (repris.audits || repris.relectures) this.log.warn?.(`[veille] ${repris.audits} audit(s) et ${repris.relectures} relecture(s) interrompus par l’arrêt précédent, marqués comme tels.`);
    const boucle = async () => {
      if (this.arrete) return;
      const v = this.magasin.reglage('veille');
      if (v.actif) {
        try { await this.passe(); } catch (e) { this.log.warn?.(`[veille] ${e.message}`); }
        // L'audit quotidien, à l'heure dite (heure de la machine), une fois par jour.
        const n = new Date(this.maintenant());
        const jour = `${n.getFullYear()}-${n.getMonth() + 1}-${n.getDate()}`;
        if (v.auditQuotidien && n.getHours() >= v.heure && this.magasin.memoire('audit_quotidien') !== jour && !this.enCours) {
          this.magasin.poserMemoire('audit_quotidien', jour);
          this.lancer({ declencheur: 'quotidien' });
        }
      }
      if (!this.arrete) { this.minuterie = setTimeout(boucle, Math.max(1, v.minutes) * 60e3); this.minuterie.unref?.(); }
    };
    this.minuterie = setTimeout(boucle, 20_000);
    this.minuterie.unref?.();
  }
  async arreter() {
    this.arrete = true; clearTimeout(this.minuterie);
    await Promise.allSettled([this.enCours?.travail, this.passeEnCours]);
  }
}
