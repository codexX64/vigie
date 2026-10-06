// Routes de VIGIE. Trois sortes d'appelants, chacun borné :
//   - une session du socle (l'interface de VIGIE) : lecture pour voir, membre
//     pour lancer un audit ou un balayage, admin pour isoler un appareil et
//     pour les réglages — les secrets sous renfort ;
//   - le Hub, par son jeton : lecture, audits et actions (ses workflows) —
//     jamais les réglages ni les secrets ;
//   - un service voisin, par un jeton dérivé que le Hub lui a donné
//     (cer_<nom>_…, vérifié ici sans rien stocker) : lecture et lancement
//     d'un audit, rien d'autre. C'est ce qui sert la page Vigie de MapMyLAN.
import crypto from 'node:crypto';
import { ErreurHttp, Routeur, lireCorps, valider, egal, repondreJson } from '../socle/src/index.js';
import { REF, GRAVITES, RANG, TYPES_ISOLABLES } from './base.js';
import { MODES_IA, FOURNISSEURS } from './ia.js';
import { priorites, REGLES, DOMAINES } from './regles.js';
import { rapportPdf } from './pdf.js';
import { ErreurAction } from './veille.js';
import { PRIVEES, plages } from './sources.js';
import net from 'node:net';
import { VERSION } from './config.js';

const T = (max, o = {}) => ({ type: 'chaine', max, ...o });
const B = { type: 'booleen' };
const E = (min, max) => ({ type: 'entier', min, max });
const ID_APPAREIL = /^[A-Za-z0-9_-]{1,64}$/;
const CIDR = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
const MODELE = /^[\w.:/-]{1,120}$/;

const S = {
  audit: { ia: B },
  action: { type: T(12, { requis: true, parmi: ['quarantine', 'ban', 'unban', 'deep-scan', 'scan'] }), appareil: T(64, { motif: ID_APPAREIL }), motif: T(200), forcer: B },
  vide: {},
  ia: {
    mode: T(12, { parmi: MODES_IA }), fournisseur: T(12, { parmi: Object.keys(FOURNISSEURS) }), modeleCloud: T(120, { motif: /^([\w.:/-]{1,120})?$/ }),
    modeleLocal: T(120, { motif: /^([\w.:/-]{1,120})?$/ }), cle: T(300, { motif: /^[\x21-\x7e]{20,300}$/ }), retirerCle: B, appelsJour: E(0, 1000), jetonsJour: E(0, 10_000_000),
  },
  essaiIa: { cible: T(8, { requis: true, parmi: ['locale', 'cloud'] }) },
  veille: { actif: B, minutes: E(5, 1440), auditQuotidien: B, heure: E(0, 23), sondeTls: B },
  reaction: { actif: B, types: { type: 'liste', max: 30, de: T(20, { parmi: TYPES_ISOLABLES }) }, parHeure: E(1, 20), seuil: E(50, 100) },
  docker: { jeton: T(300, { motif: /^[\x21-\x7e]{16,300}$/ }), retirerJeton: B },
  perimetre: { exclus: { type: 'liste', max: 100, de: T(18, { motif: CIDR }) } },
  billetterie: { url: T(500, { motif: /^(https?:\/\/\S{3,490})?$/ }), cle: T(300, { motif: /^[\x21-\x7e]{8,300}$/ }), retirerCle: B, entete: T(40, { motif: /^[A-Za-z0-9-]{1,40}$/ }), marqueur: T(32, { motif: /^[a-z0-9_]{1,32}$/i }), seuil: T(10, { parmi: GRAVITES.slice(1) }) },
  telegram: { jeton: T(100, { motif: /^\d{5,15}:[A-Za-z0-9_-]{20,60}$/ }), retirerJeton: B, chat: T(20, { motif: /^(-?\d{1,20})?$/ }), seuil: T(10, { parmi: GRAVITES.slice(1) }) },
  essaiDiffusion: { canal: T(12, { requis: true, parmi: ['billetterie', 'telegram'] }) },
};
const Q = {
  audits: { limite: E(1, 200), statut: T(10, { parmi: ['termine', 'echec', 'en cours'] }) },
  evenements: { limite: E(1, 500), depuis: E(0, 8.64e15), type: T(30, { motif: /^[a-z.]{1,30}$/ }), min: T(10, { parmi: GRAVITES }) },
  constats: { appareil: T(64, { requis: true, motif: ID_APPAREIL }) },
};

/** Le nom d'un jeton dérivé valide (cer_<nom>_<hmac>), ou null. Comparaison à temps constant. */
export function nomDerive(secret, brut) {
  if (!secret || String(secret).length < 16) return null;
  const m = /^cer_([a-z0-9][a-z0-9-]{1,30})_([0-9a-f]{64})$/.exec(String(brut || ''));
  if (!m) return null;
  const attendu = crypto.createHmac('sha256', String(secret)).update('cerveau:' + m[1]).digest();
  const recu = Buffer.from(m[2], 'hex');
  return recu.length === attendu.length && crypto.timingSafeEqual(recu, attendu) ? m[1] : null;
}

/**
 * L'adresse de la billetterie, lue comme une URL (pas comme un préfixe) :
 * https partout, http seulement vers une adresse privée, la machine elle-même
 * ou un conteneur du Hub ; jamais d'identifiants dans l'adresse.
 */
const LOCALES = plages([...PRIVEES, '127.0.0.0/8']);
export function urlBilletterieSure(brute) {
  let u;
  try { u = new URL(brute); } catch { return false; }
  if (u.username || u.password) return false;
  if (u.protocol === 'https:') return true;
  if (u.protocol !== 'http:') return false;
  const hote = u.hostname;
  if (hote === 'localhost' || /^hub-[a-z0-9-]{1,60}$/.test(hote)) return true;
  return net.isIPv4(hote) && LOCALES.check(hote, 'ipv4');
}

export function creerApi({ socle, cfg, magasin, moteur, sources, ia, memoire, diffusion }) {
  const r = new Routeur();
  const { portail, journal, limiteur } = socle;

  // ---- qui appelle ----
  const presente = ctx => { const a = String(ctx.req.headers.authorization || ''); return a.startsWith('Bearer ') ? a.slice(7) : ''; };
  const cleMachine = ctx => [`ip:machine:${ctx.ip}`];
  // Un jeton présenté est vérifié ; un faux compte comme un échec et ne retombe jamais sur la session.
  const appelant = ctx => {
    if (ctx.appelant !== undefined) return ctx.appelant;
    const j = presente(ctx);
    if (!j) return (ctx.appelant = null);
    limiteur.controler(cleMachine(ctx));
    if (egal(j, cfg.jetonHub)) return (ctx.appelant = { type: 'hub', nom: 'hub' });
    const nom = nomDerive(cfg.jetonHub, j);
    if (nom) return (ctx.appelant = { type: 'derive', nom });
    limiteur.echec(cleMachine(ctx));
    journal.rare(`jeton:${ctx.ip}`, { action: 'connexion.jeton', objet: ctx.url.pathname, ip: ctx.ip, resultat: 'refus' });
    throw new ErreurHttp(401, 'Jeton invalide.');
  };
  const session = (ctx, opts = {}) => portail.exiger(ctx, { role: 'lecture', ...opts });
  /** qui : 'derive' (lecture et audit), 'hub' (lecture, audits, actions), sinon session seule. */
  const acces = (ctx, { role = 'lecture', jetons = [] } = {}) => {
    const a = appelant(ctx);
    if (a) {
      if (!jetons.includes(a.type)) throw new ErreurHttp(403, a.type === 'derive' ? 'Ce jeton ne donne que la lecture et le lancement d’un audit.' : 'Réservé à une session de VIGIE.');
      return { type: a.type, nom: a.type === 'derive' ? `service:${a.nom}` : 'hub' };
    }
    const s = session(ctx, { role });
    return { type: 'session', nom: s.compteLigne.identifiant, compte: s.compte, role: s.compteLigne.role };
  };
  const LECTURE = { jetons: ['hub', 'derive'] };
  const corps = async (ctx, schema) => valider(await lireCorps(ctx.req, { limite: 32 * 1024 }), schema);
  const tracer = (ctx, qui, action, objet, details) => journal.ecrire({ acteur: qui.compte ?? null, action, objet, ip: ctx.ip, details: { ...details, par: qui.nom } });
  const actionErreur = e => { if (e instanceof ErreurAction) throw new ErreurHttp(e.status, e.message); throw e; };

  const vueAudit = a => a && { ...a, enCours: moteur.enCours?.id === a.id };
  const etat = () => {
    const dernier = magasin.dernierAudit();
    const ev = magasin.evenements({ limite: 500, depuis: Date.now() - 7 * 86400e3 });
    const iaR = magasin.reglage('ia');
    return {
      version: VERSION, audit: vueAudit(dernier), enCours: moteur.enCours ? vueAudit(magasin.audit(moteur.enCours.id)) : null,
      priorites: dernier ? priorites(magasin.constats(dernier.id)) : [],
      historique: magasin.historique(30), sources: sources.public(), domaines: DOMAINES,
      ia: { mode: iaR.mode, fournisseur: iaR.fournisseur },
      veille: { ...magasin.reglage('veille'), dernierePasse: magasin.memoire('derniere_passe', null) },
      reaction: { actif: magasin.reglage('reaction').actif },
      evenements: { nonAcquittes: ev.filter(e => !e.acquitte && RANG[e.gravite] >= RANG.faible).length, critiques: ev.filter(e => !e.acquitte && e.gravite === 'critique').length },
    };
  };

  r.get('/api/health', () => ({ ok: true }), { public: true });

  // ---- lecture ----
  r.get('/api/etat', ctx => { acces(ctx, LECTURE); return etat(); });
  r.get('/api/audits', ctx => {
    acces(ctx, LECTURE);
    const { limite = 50, statut } = ctx.q;
    return magasin.audits(200).filter(a => !statut || a.statut === statut).slice(0, limite).map(vueAudit);
  }, { requete: Q.audits });
  r.get('/api/audits/:id', ctx => {
    acces(ctx, LECTURE);
    const a = magasin.audit(ctx.params.id) || (() => { throw new ErreurHttp(404, 'Audit inconnu.'); })();
    const constats = magasin.constats(a.id);
    return { audit: vueAudit(a), constats, priorites: priorites(constats), regles: REGLES };
  });
  r.get('/api/audits/:id/pdf', ctx => {
    const qui = acces(ctx, LECTURE);
    const a = magasin.audit(ctx.params.id) || (() => { throw new ErreurHttp(404, 'Audit inconnu.'); })();
    if (a.statut !== 'termine') throw new ErreurHttp(409, 'Cet audit n’est pas terminé.');
    const constats = magasin.constats(a.id);
    const historique = magasin.historique(60).filter(h => h.debut <= a.debut);
    const precedent = magasin.audits(200).find(x => x.statut === 'termine' && x.debut < a.debut) || null;
    const pdf = rapportPdf({ audit: { ...a, priorites: priorites(constats) }, constats, historique, precedent });
    tracer(ctx, qui, 'rapport.exporte', a.id, {});
    ctx.res.writeHead(200, {
      'content-type': 'application/pdf', 'content-length': pdf.length, 'cache-control': 'no-store',
      'content-disposition': `attachment; filename="vigie-audit-${new Date(a.debut).toISOString().slice(0, 16).replace(/[:T]/g, '-')}.pdf"`,
    });
    ctx.res.end(pdf);
  });
  r.get('/api/constats', ctx => {
    acces(ctx, LECTURE);
    const a = magasin.dernierAudit();
    if (!a) return { audit: null, constats: [] };
    return { audit: { id: a.id, debut: a.debut, score: a.score }, constats: magasin.constats(a.id).filter(c => c.sujetId === ctx.q.appareil) };
  }, { requete: Q.constats });
  r.get('/api/evenements', ctx => {
    acces(ctx, LECTURE);
    const { limite = 100, depuis = 0, type, min } = ctx.q;
    return magasin.evenements({ limite: 2000, depuis }).filter(e => (!type || e.type === type) && (!min || RANG[e.gravite] >= RANG[min])).slice(0, limite);
  }, { requete: Q.evenements });
  r.get('/api/actions', ctx => { acces(ctx, { jetons: ['hub'] }); return magasin.actions(100); });

  // ---- audits et veille ----
  r.post('/api/audits', async ctx => {
    const qui = acces(ctx, { role: 'membre', jetons: ['hub', 'derive'] });
    const b = await corps(ctx, S.audit);
    const out = moteur.lancer({ declencheur: qui.type === 'session' ? 'manuel' : qui.nom, auteur: qui.nom, ia: b.ia !== false });
    if (!out.deja) tracer(ctx, qui, 'audit.lance', out.id, {});
    return out;
  });
  r.post('/api/veille/passe', async ctx => {
    const qui = acces(ctx, { role: 'membre', jetons: ['hub'] });
    await corps(ctx, S.vide);
    tracer(ctx, qui, 'veille.passe', null, {});
    return await moteur.passe();
  });
  r.post('/api/evenements/:id/acquitter', async ctx => {
    const qui = acces(ctx, { role: 'membre', jetons: ['hub'] });
    await corps(ctx, S.vide);
    if (!magasin.acquitter(ctx.params.id, qui.nom)) throw new ErreurHttp(404, 'Événement inconnu ou déjà acquitté.');
    tracer(ctx, qui, 'evenement.acquitte', ctx.params.id, {});
    return { ok: true };
  });

  // ---- remédiation ----
  r.post('/api/actions', async ctx => {
    const qui = acces(ctx, { role: 'membre', jetons: ['hub'] });
    const b = await corps(ctx, S.action);
    // Balayer et regarder de près : membre. Couper un appareil du réseau : admin.
    if (!['deep-scan', 'scan'].includes(b.type) && qui.type === 'session' && qui.role !== 'admin') throw new ErreurHttp(403, 'Droits insuffisants : isoler un appareil est réservé aux administrateurs.');
    if (b.type !== 'scan' && !b.appareil) throw new ErreurHttp(400, 'Champ « appareil » : obligatoire.');
    // Forcer l'isolation d'un équipement d'infrastructure : une session d'administrateur, sous renfort ; jamais un jeton.
    if (b.forcer) {
      if (qui.type !== 'session') throw new ErreurHttp(403, 'Forcer une isolation est réservé à une session d’administrateur de VIGIE.');
      portail.exiger(ctx, { role: 'admin', renfort: true });
    }
    const x = await moteur.executer({ type: b.type, appareil: b.appareil, motif: b.motif || '', auteur: qui.nom, forcer: !!b.forcer }).catch(actionErreur);
    tracer(ctx, qui, `action.${b.type}`, b.appareil || 'reseau', { etat: x.etat });
    return x;
  });
  r.post('/api/constats/:id/appliquer', async ctx => {
    const qui = acces(ctx, { role: 'admin', jetons: ['hub'] });
    await corps(ctx, S.vide);
    const c = magasin.constat(ctx.params.id) || (() => { throw new ErreurHttp(404, 'Constat inconnu.'); })();
    if (!c.action) throw new ErreurHttp(409, 'Ce constat ne propose pas d’action automatique : sa correction se fait à la main.');
    const x = await moteur.executer({ type: c.action.type, appareil: c.action.appareil, motif: c.titre.slice(0, 200), auteur: qui.nom, constat: c.id }).catch(actionErreur);
    tracer(ctx, qui, `action.${c.action.type}`, c.action.appareil, { constat: c.id, etat: x.etat });
    return x;
  });
  r.post('/api/actions/:id/annuler', async ctx => {
    const qui = acces(ctx, { role: 'admin', jetons: ['hub'] });
    await corps(ctx, S.vide);
    return await moteur.annuler(ctx.params.id, qui.nom).catch(actionErreur);
  });

  // ---- réglages (session d'administrateur seulement) ----
  const reglages = () => ({
    ia: ia.etat(), veille: magasin.reglage('veille'), reaction: { ...magasin.reglage('reaction'), typesPossibles: TYPES_ISOLABLES },
    docker: { ...magasin.reglagePublic('docker'), url: cfg.dockerUrl || null }, perimetre: { ...magasin.reglage('perimetre'), plages: sources.perimetreCourant.plages },
    billetterie: { ...magasin.reglagePublic('billetterie'), etat: diffusion.etat.billetterie }, telegram: { ...magasin.reglagePublic('telegram'), etat: diffusion.etat.telegram },
    sources: sources.public(), memoire: memoire.public(),
  });
  const admin = (ctx, renfort = false) => { if (appelant(ctx)) throw new ErreurHttp(403, 'Réservé à une session de VIGIE.'); return portail.exiger(ctx, { role: 'admin', renfort }); };

  r.get('/api/reglages', ctx => { admin(ctx); return reglages(); });

  r.put('/api/reglages/ia', async ctx => {
    const s = admin(ctx);
    const b = await corps(ctx, S.ia);
    // Changer de fournisseur enverrait la clé enregistrée à un autre service : renfort, comme pour la clé.
    const changeFournisseur = b.fournisseur && b.fournisseur !== magasin.reglage('ia').fournisseur && magasin.secret('ia', 'cle');
    if (b.cle || b.retirerCle || changeFournisseur) portail.exiger(ctx, { role: 'admin', renfort: true });
    const { cle, retirerCle, ...reste } = b;
    const futur = { ...magasin.reglage('ia'), ...reste };
    if (['cloud', 'les-deux', 'secours'].includes(futur.mode) && !futur.modeleCloud) throw new ErreurHttp(400, 'Choisis le modèle en nuage avant ce mode.');
    if (['cloud', 'les-deux'].includes(futur.mode) && !cle && (retirerCle || !magasin.secret('ia', 'cle'))) throw new ErreurHttp(400, 'Enregistre une clé d’API avant ce mode.');
    if (['locale', 'les-deux', 'secours'].includes(futur.mode) && !cfg.iaLocaleUrl) throw new ErreurHttp(400, 'Aucune IA locale reliée : installe Ollama depuis le Hub.');
    if (cle) magasin.poserSecret('ia', 'cle', cle);
    if (retirerCle) magasin.poserSecret('ia', 'cle', null);
    magasin.poserReglage('ia', reste);
    journal.ecrire({ acteur: s.compte, action: 'reglages.ia', objet: 'ia', ip: ctx.ip, details: { ...reste, cle: !!cle, retirerCle: !!retirerCle } });
    return reglages();
  });
  r.post('/api/reglages/ia/essai', async ctx => {
    admin(ctx);
    const b = await corps(ctx, S.essaiIa);
    try { return await ia.essai(b.cible); } catch (e) { throw new ErreurHttp(502, `IA ${b.cible === 'locale' ? 'locale' : 'en nuage'} : ${e.message}.`); }
  });
  r.put('/api/reglages/veille', async ctx => {
    const s = admin(ctx);
    const b = await corps(ctx, S.veille);
    magasin.poserReglage('veille', b);
    journal.ecrire({ acteur: s.compte, action: 'reglages.veille', objet: 'veille', ip: ctx.ip, details: b });
    return reglages();
  });
  r.put('/api/reglages/reaction', async ctx => {
    // Laisser VIGIE agir seul est la décision la plus lourde : renfort exigé.
    const s = admin(ctx, true);
    const b = await corps(ctx, S.reaction);
    magasin.poserReglage('reaction', b);
    journal.ecrire({ acteur: s.compte, action: 'reglages.reaction', objet: 'reaction', ip: ctx.ip, details: b });
    return reglages();
  });
  r.put('/api/reglages/docker', async ctx => {
    const s = admin(ctx, true);
    const b = await corps(ctx, S.docker);
    if (b.jeton) magasin.poserSecret('docker', 'jeton', b.jeton);
    if (b.retirerJeton) magasin.poserSecret('docker', 'jeton', null);
    journal.ecrire({ acteur: s.compte, action: 'reglages.docker', objet: 'docker', ip: ctx.ip, details: { jeton: !!b.jeton, retirerJeton: !!b.retirerJeton } });
    return reglages();
  });
  r.put('/api/reglages/perimetre', async ctx => {
    const s = admin(ctx, true);
    const b = await corps(ctx, S.perimetre);
    for (const x of b.exclus || []) { const [ip, bits] = x.split('/'); if (ip.split('.').some(n => Number(n) > 255) || (bits !== undefined && Number(bits) > 32)) throw new ErreurHttp(400, `Exclusion invalide : ${x}.`); }
    magasin.poserReglage('perimetre', b);
    journal.ecrire({ acteur: s.compte, action: 'reglages.perimetre', objet: 'perimetre', ip: ctx.ip, details: b });
    return reglages();
  });
  r.put('/api/reglages/billetterie', async ctx => {
    const s = admin(ctx);
    const b = await corps(ctx, S.billetterie);
    if (b.cle || b.retirerCle || b.url !== undefined) portail.exiger(ctx, { role: 'admin', renfort: true });
    const { cle, retirerCle, ...reste } = b;
    if (reste.url && !urlBilletterieSure(reste.url)) throw new ErreurHttp(400, 'Billetterie : https:// exigé hors du réseau local, sans identifiants dans l’adresse.');
    if (cle) magasin.poserSecret('billetterie', 'cle', cle);
    if (retirerCle) magasin.poserSecret('billetterie', 'cle', null);
    magasin.poserReglage('billetterie', reste);
    journal.ecrire({ acteur: s.compte, action: 'reglages.billetterie', objet: 'billetterie', ip: ctx.ip, details: { ...reste, cle: !!cle, retirerCle: !!retirerCle } });
    return reglages();
  });
  r.put('/api/reglages/telegram', async ctx => {
    const s = admin(ctx);
    const b = await corps(ctx, S.telegram);
    if (b.jeton || b.retirerJeton) portail.exiger(ctx, { role: 'admin', renfort: true });
    const { jeton, retirerJeton, ...reste } = b;
    if (jeton) magasin.poserSecret('telegram', 'jeton', jeton);
    if (retirerJeton) magasin.poserSecret('telegram', 'jeton', null);
    magasin.poserReglage('telegram', reste);
    journal.ecrire({ acteur: s.compte, action: 'reglages.telegram', objet: 'telegram', ip: ctx.ip, details: { ...reste, jeton: !!jeton, retirerJeton: !!retirerJeton } });
    return reglages();
  });
  r.post('/api/reglages/diffusion/essai', async ctx => {
    admin(ctx);
    const b = await corps(ctx, S.essaiDiffusion);
    const e = { id: '', quand: Date.now(), gravite: 'info', type: 'essai', titre: 'Message d’essai de VIGIE', texte: 'Si tu lis ceci, les alertes arrivent.', sujet: '', cle: 'essai' };
    const out = await diffusion[b.canal](e, { forcer: true });
    if (!out.ok) throw new ErreurHttp(502, out.erreur);
    return out;
  });

  return {
    async traiter(ctx) {
      const p = ctx.url.pathname;
      if (!p.startsWith('/api/')) return false;
      const t = r.trouver(ctx.req.method, p);
      if (!t) throw new ErreurHttp(404, 'Route inconnue.');
      if (t.methodes) { ctx.res.setHeader('Allow', t.methodes.join(', ')); throw new ErreurHttp(405, 'Méthode non admise.'); }
      if (Object.values(t.params).some(v => !REF.test(v))) throw new ErreurHttp(404, 'Introuvable.');
      ctx.params = t.params;
      const schema = t.route.options?.requete;
      if (!schema && ctx.url.search) throw new ErreurHttp(400, 'Paramètres de requête inattendus.');
      Object.defineProperty(ctx, 'q', { configurable: true, get: () => valider(Object.fromEntries(ctx.url.searchParams), schema || {}) });
      const reponse = await t.route.gestionnaire(ctx);
      if (reponse !== undefined) repondreJson(ctx.res, 200, reponse);
      return true;
    },
    routeur: r,
  };
}
