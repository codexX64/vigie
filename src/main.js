// Démarrage de VIGIE : configuration validée, base, socle commun (comptes,
// sessions, coffre, journal), sources, IA, mémoire, diffusion, moteur de
// veille, et serveur HTTP de l'interface et de l'API.
import http from 'node:http';
import path from 'node:path';
import crypto from 'node:crypto';
import { lireConfigVigie, VERSION } from './config.js';
import { ouvrirBase, Magasin } from './base.js';
import { Sources } from './sources.js';
import { IA } from './ia.js';
import { Memoire } from './memoire.js';
import { Diffusion } from './diffusion.js';
import { Moteur } from './veille.js';
import { creerApi } from './api.js';
import {
  Debit, ErreurHttp, demarrerSocle, entetesSecurite, envelopper, nonceCsp, politiqueContenu,
  repondreErreur, repondreJson, servirFichier,
} from '../socle/src/index.js';

const RACINE = path.resolve(import.meta.dirname, '..');
const CONSOLE = { info: (...a) => console.log(...a), warn: (...a) => console.warn(...a), error: (...a) => console.error(...a) };
const CONTACT_SECURITE = 'https://github.com/CodexX64/vigie/security/advisories/new';

// Le choix d'IA fait dans le Hub s'applique quand il change ; entre deux
// changements, ce qui a été réglé dans VIGIE reste.
function appliquerIaDuHub(cfg, magasin, log) {
  if (!cfg.iaMode) return;
  const empreinte = crypto.createHash('sha256').update(JSON.stringify([cfg.iaMode, cfg.iaFournisseur, cfg.iaModeleCloud, cfg.iaCle || '', cfg.iaAppelsJour])).digest('hex');
  if (magasin.memoire('ia_hub') === empreinte) return;
  magasin.poserReglage('ia', { mode: cfg.iaMode, fournisseur: cfg.iaFournisseur, ...(cfg.iaModeleCloud ? { modeleCloud: cfg.iaModeleCloud } : {}), appelsJour: cfg.iaAppelsJour });
  if (cfg.iaCle) magasin.poserSecret('ia', 'cle', cfg.iaCle);
  magasin.poserMemoire('ia_hub', empreinte);
  log.info?.(`[ia] réglage du Hub appliqué : ${cfg.iaMode}`);
}

export async function demarrer(env = process.env, { log = CONSOLE, fetch: f = globalThis.fetch, sonde } = {}) {
  const cfg = lireConfigVigie(env);
  const db = ouvrirBase(cfg.donnees);
  const socle = await demarrerSocle({ service: { id: 'vigie', nom: 'VIGIE', contactSecurite: CONTACT_SECURITE }, db, dossier: cfg.donnees, env, log });
  const magasin = new Magasin(db, { coffre: socle.coffre });
  appliquerIaDuHub(cfg, magasin, log);

  const sources = new Sources({ cfg, magasin, fetch: f, ...(sonde ? { sonde } : {}) });
  const ia = new IA({ cfg, magasin, fetch: f });
  const memoire = new Memoire({ url: cfg.synapseUrl, jeton: cfg.synapseJeton, fetch: f });
  const diffusion = new Diffusion({ magasin, fetch: f, tgApi: cfg.tgApi, urlPublique: socle.cfg.urlPublique || '' });
  const moteur = new Moteur({ magasin, sources, ia, memoire, diffusion, journal: socle.journal, log });
  const api = creerApi({ socle, cfg, magasin, moteur, sources, ia, memoire, diffusion });
  moteur.demarrer();

  const debit = new Debit({ max: 900 });
  const serveur = http.createServer(envelopper(async (req, res) => {
    try {
      const url = new URL(req.url, 'http://vigie');
      const ctx = socle.portail.contexte(req, res);
      if (!debit.prendre(ctx.ip)) throw new ErreurHttp(429, 'Trop de requêtes.');
      ctx.url = url;
      const nonce = nonceCsp();
      entetesSecurite(res, { secure: ctx.securise, hote: req.headers.host, csp: politiqueContenu({ nonce, secure: ctx.securise, img: ['data:'] }) });
      if (await socle.portail.traiter(req, res, url, ctx)) return;
      if (await api.traiter(ctx)) return;
      if (!['GET', 'HEAD'].includes(req.method)) return repondreJson(res, 405, { error: 'Méthode non admise.' });
      if (url.pathname.startsWith('/socle/') && servirFichier(req, res, path.join(RACINE, 'socle', 'web'), url.pathname.slice(6), { nonce, cache: 'public, max-age=3600' })) return;
      const fichier = url.pathname === '/' ? '/index.html' : url.pathname;
      if (servirFichier(req, res, path.join(RACINE, 'web'), fichier, { nonce, gamme: socle.cfg.gamme })) return;
      repondreJson(res, 404, { error: 'Introuvable.' });
    } catch (e) { repondreErreur(res, e, { journal: log }); }
  }));
  serveur.headersTimeout = 20_000;
  serveur.requestTimeout = 120_000;
  serveur.keepAliveTimeout = 5_000;
  await new Promise(r => serveur.listen(cfg.port, cfg.hote, r));
  log.info?.(`VIGIE ${VERSION} à l’écoute sur ${cfg.hote}:${serveur.address().port}`);

  return {
    serveur, db, socle, magasin, moteur, sources, ia, memoire, diffusion, api, port: serveur.address().port,
    async arreter() {
      await moteur.arreter(); memoire.arreter(); socle.arreter();
      await new Promise(r => serveur.close(r));
      db.close();
    },
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(import.meta.filename)) {
  process.umask(0o077);
  const r = await demarrer().catch(e => { console.error(e.message); process.exit(1); });
  const fin = async sig => { console.log(`${sig} reçu, arrêt propre`); await r.arreter(); process.exit(0); };
  process.on('SIGINT', fin);
  process.on('SIGTERM', fin);
}
