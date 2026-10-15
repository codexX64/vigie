// Riposte : ce que VIGIE bloque, combien de temps, et où.
//
// Trois régimes (réglage « mode ») :
//   - observer   : VIGIE note et signale, ne bloque rien ;
//   - simulation : chaque blocage qui aurait été posé est noté « simulé »,
//                  rien ne part vers la passerelle — pour régler les seuils ;
//   - actif      : les adresses extérieures au-delà du seuil sont bloquées
//                  seules ; une machine du réseau n'est jamais isolée ici
//                  (c'est la réaction rapide de la veille, sous ses règles).
//
// Garde-fous : jamais une adresse privée, jamais une adresse de la liste
// blanche (résolveurs publics, Cloudflare, ce que l'administrateur y ajoute),
// un plafond de blocages automatiques par heure, une durée qui grandit à
// chaque récidive (1 h, 1 jour, 7 jours, 30 jours — comme sshguard), et une
// levée en un clic.
import crypto from 'node:crypto';
import { estPublique, normaliser, EnsembleIp } from './ip.js';
import { Unifi, ErreurUnifi } from './unifi.js';
import { Cloudflare, ErreurCloudflare } from './cloudflare.js';

export const MODES = ['observer', 'simulation', 'actif'];
const DUREES_MIN = [60, 1440, 10080, 43200];
// Ce qui ne doit jamais être coupé : résolveurs DNS publics et réseaux de
// Cloudflare (les tunnels du Hub et de Relay passent par eux).
export const LISTE_BLANCHE_DEFAUT = [
  '1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4', '9.9.9.9', '149.112.112.112', '2606:4700:4700::1111', '2001:4860:4860::8888',
  '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20',
  '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
];

const ref = () => crypto.randomBytes(9).toString('base64url');

export function preparerBase(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS blocages(
      id TEXT PRIMARY KEY, ip TEXT NOT NULL, debut INTEGER NOT NULL, fin INTEGER,
      motif TEXT NOT NULL DEFAULT '', raisons TEXT NOT NULL DEFAULT '[]', score INTEGER NOT NULL DEFAULT 0,
      auteur TEXT NOT NULL, automatique INTEGER NOT NULL DEFAULT 0, etat TEXT NOT NULL,
      recidive INTEGER NOT NULL DEFAULT 0, leve_par TEXT, leve_le INTEGER);
    CREATE INDEX IF NOT EXISTS blocages_ip ON blocages(ip);
    CREATE INDEX IF NOT EXISTS blocages_etat ON blocages(etat, fin);
  `);
}

export class Riposte {
  constructor({ db, magasin, journal = null, signaler = async () => null, maintenant = () => Date.now(), log = console, unifiFabrique = o => new Unifi(o), passerelleAuto = () => null, cloudflareFabrique = o => new Cloudflare(o) }) {
    Object.assign(this, { db, magasin, journal, signaler, maintenant, log, unifiFabrique, passerelleAuto, cloudflareFabrique });
    preparerBase(db);
    this.etatUnifi = this.magasin.memoire('unifi_etat', { ok: null, erreur: null, synchro: null, listes: {}, regles: null });
    // Cloudflare : la liste du compte, la règle par zone, le mode « Under Attack » en cours.
    this.etatCloudflare = this.magasin.memoire('cloudflare_etat', { ok: null, erreur: null, synchro: null, envoyees: 0, zones: [], attaque: null });
    this.aSynchroniser = true;
  }

  reglage() { return this.magasin.reglage('bouclier'); }
  blanche() {
    const r = this.reglage();
    const cle = JSON.stringify(r.listeBlanche);
    if (this.cacheBlanche?.cle !== cle) {
      const e = new EnsembleIp();
      for (const x of [...LISTE_BLANCHE_DEFAUT, ...(r.listeBlanche || [])]) e.ajouter(x);
      this.cacheBlanche = { cle, e: e.figer() };
    }
    return this.cacheBlanche.e;
  }
  /** Pourquoi une adresse ne peut pas être bloquée, ou null. */
  refus(ip) {
    if (!ip) return 'adresse illisible';
    if (!estPublique(ip)) return 'adresse privée ou réservée : jamais bloquée par VIGIE';
    if (this.blanche().contient(ip)) return 'adresse de la liste blanche';
    return null;
  }

  ligne = l => l && { ...l, raisons: JSON.parse(l.raisons || '[]'), automatique: !!l.automatique };
  actif(ip) { return this.ligne(this.db.prepare("SELECT * FROM blocages WHERE ip = ? AND etat IN ('actif', 'simule') AND (fin IS NULL OR fin > ?) ORDER BY debut DESC LIMIT 1").get(ip, this.maintenant())); }
  blocages({ etat = null, limite = 200 } = {}) {
    const l = etat ? this.db.prepare('SELECT * FROM blocages WHERE etat = ? ORDER BY debut DESC LIMIT ?').all(etat, limite) : this.db.prepare('SELECT * FROM blocages ORDER BY debut DESC LIMIT ?').all(limite);
    return l.map(this.ligne);
  }
  actifs() { return this.db.prepare("SELECT * FROM blocages WHERE etat = 'actif' AND (fin IS NULL OR fin > ?) ORDER BY score DESC, debut DESC").all(this.maintenant()).map(this.ligne); }

  /** Un verdict de la corrélation. */
  async verdict(v) {
    const r = this.reglage();
    if (v.interne) {
      await this.signaler({ gravite: 'critique', type: 'bouclier.interne', titre: `Machine du réseau suspecte : ${v.ip} (score ${v.score})`, texte: v.raisons.join(' ; '), sujet: v.ip, cle: `bouclier.interne:${v.ip}`, ip: v.ip });
      return null;
    }
    const refus = this.refus(v.ip);
    if (refus) return null;
    if (r.mode === 'observer') {
      await this.signaler({ gravite: 'faible', type: 'bouclier.menace', titre: `Menace extérieure : ${v.ip} (score ${v.score})`, texte: `${v.raisons.join(' ; ')}. Mode observation : rien n’est bloqué.`, sujet: v.ip, cle: `bouclier.menace:${v.ip}` });
      return null;
    }
    if (this.automatiquesRecents() >= r.autoParHeure) {
      await this.signaler({ gravite: 'eleve', type: 'bouclier.plafond', titre: `Plafond de ${r.autoParHeure} blocages automatiques par heure atteint`, texte: `${v.ip} n’est pas bloquée : à décider dans VIGIE.`, cle: 'bouclier.plafond' });
      return null;
    }
    return this.bloquer({ ip: v.ip, motif: v.raisons[0] || 'score de menace', raisons: v.raisons, score: v.score, auteur: 'vigie', automatique: true });
  }

  automatiquesRecents() { return this.db.prepare('SELECT COUNT(*) n FROM blocages WHERE automatique = 1 AND debut > ?').get(this.maintenant() - 3600e3).n; }

  /** Bloquer (ou simuler) : durée selon les récidives des trente derniers jours. */
  async bloquer({ ip: brute, motif = '', raisons = [], score = 0, auteur, automatique = false, minutes = null }) {
    const ip = normaliser(brute);
    const refus = this.refus(ip);
    if (refus) throw Object.assign(new Error(`${brute} : ${refus}.`), { status: 400 });
    const deja = this.actif(ip);
    if (deja) return deja;
    const r = this.reglage();
    const t = this.maintenant();
    const recidive = this.db.prepare("SELECT COUNT(*) n FROM blocages WHERE ip = ? AND etat IN ('actif', 'expire', 'leve') AND debut > ?").get(ip, t - 30 * 86400e3).n;
    const duree = minutes ?? (r.dureesMinutes || DUREES_MIN)[Math.min(recidive, (r.dureesMinutes || DUREES_MIN).length - 1)];
    const etat = r.mode === 'simulation' && automatique ? 'simule' : 'actif';
    const id = ref();
    this.db.prepare('INSERT INTO blocages(id, ip, debut, fin, motif, raisons, score, auteur, automatique, etat, recidive) VALUES(?,?,?,?,?,?,?,?,?,?,?)')
      .run(id, ip, t, duree ? t + duree * 60e3 : null, String(motif).slice(0, 300), JSON.stringify(raisons.slice(0, 8).map(x => String(x).slice(0, 300))), Math.round(score), auteur, automatique ? 1 : 0, etat, recidive);
    this.journal?.ecrire({ acteur: automatique ? null : auteur, action: etat === 'simule' ? 'bouclier.simule' : 'bouclier.bloque', objet: ip, details: { duree, recidive, automatique, score: Math.round(score) } });
    const b = this.ligne(this.db.prepare('SELECT * FROM blocages WHERE id = ?').get(id));
    const libelle = duree >= 1440 ? `${Math.round(duree / 1440)} jour${duree >= 2880 ? 's' : ''}` : `${Math.round(duree / 60) || 1} h`;
    // Un blocage est la routine du bouclier, pas une alerte : « faible » (automatique)
    // ou « info » (manuel), pour qu'un balayage d'Internet ne fasse pas sonner
    // Telegram cent fois par heure. Ce qui demande quelqu'un reste « élevé » ou « critique ».
    await this.signaler({
      gravite: automatique ? 'faible' : 'info', type: etat === 'simule' ? 'bouclier.simule' : 'bouclier.bloque',
      titre: `${etat === 'simule' ? 'Aurait bloqué' : 'Bloquée'} : ${ip}${duree ? ` pour ${libelle}` : ''}${recidive ? ` (récidive n° ${recidive})` : ''}`,
      texte: raisons.slice(0, 4).join(' ; ') || motif, sujet: ip, cle: `bouclier:${ip}:${id}`,
    });
    if (etat === 'actif') { this.aSynchroniser = true; this.synchroniser().catch(() => null); this.synchroniserCloudflare().catch(() => null); }
    return b;
  }

  async lever(id, qui) {
    const b = this.ligne(this.db.prepare('SELECT * FROM blocages WHERE id = ?').get(id));
    if (!b) throw Object.assign(new Error('Blocage inconnu.'), { status: 404 });
    if (!['actif', 'simule'].includes(b.etat)) throw Object.assign(new Error('Ce blocage n’est plus actif.'), { status: 409 });
    this.db.prepare("UPDATE blocages SET etat = 'leve', leve_par = ?, leve_le = ? WHERE id = ?").run(qui, this.maintenant(), id);
    this.journal?.ecrire({ acteur: qui, action: 'bouclier.leve', objet: b.ip, details: { blocage: id } });
    this.aSynchroniser = true;
    await this.synchroniser().catch(() => null);
    this.synchroniserCloudflare().catch(() => null);
    return this.ligne(this.db.prepare('SELECT * FROM blocages WHERE id = ?').get(id));
  }

  /** Les blocages arrivés à leur fin. */
  expirer() {
    const n = Number(this.db.prepare("UPDATE blocages SET etat = 'expire' WHERE etat IN ('actif', 'simule') AND fin IS NOT NULL AND fin <= ?").run(this.maintenant()).changes);
    this.db.prepare('DELETE FROM blocages WHERE debut < ? AND etat IN (\'expire\', \'leve\')').run(this.maintenant() - 180 * 86400e3);
    if (n) this.aSynchroniser = true;
    return n;
  }

  /**
   * La passerelle qui reçoit les blocages : reliée directement (clé d'API
   * posée dans VIGIE), sinon celle que MapMyLAN pilote déjà — rien à régler.
   */
  unifi() {
    const r = this.reglage();
    const cle = this.magasin.secret('bouclier', 'cleUnifi');
    if (r.unifiHote && cle) return this.unifiFabrique({ hote: r.unifiHote, port: r.unifiPort || 443, fp: r.unifiFp || null, cle });
    return this.passerelleAuto() || null;
  }

  /** La passerelle reçoit la liste des adresses bloquées (les plus menaçantes d'abord, au plafond près). */
  async synchroniser({ forcer = false } = {}) {
    if (!this.aSynchroniser && !forcer) return this.etatUnifi;
    if (this.synchroEnCours) return this.synchroEnCours;
    const u = this.unifi();
    if (!u) return this.etatUnifi;
    this.synchroEnCours = (async () => {
      const r = this.reglage();
      const ips = this.actifs().map(b => b.ip).slice(0, r.maxUnifi);
      try {
        this.aSynchroniser = false;
        const listes = await u.synchroniser(ips);
        let regles = this.etatUnifi.regles;
        try { regles = await u.regles(listes); } catch (e) { regles = { erreur: e.message }; }
        this.etatUnifi = { ok: true, erreur: null, synchro: this.maintenant(), listes, regles, envoyees: ips.length, forme: u.forme, voie: u.forme === 'mapmylan' ? 'mapmylan' : 'directe', passerelle: u.nom || '' };
      } catch (e) {
        this.aSynchroniser = true;
        const avant = this.etatUnifi.ok;
        this.etatUnifi = { ...this.etatUnifi, ok: false, erreur: e instanceof ErreurUnifi || e.code ? e.message : String(e.message || e), essai: this.maintenant(), voie: u.forme === 'mapmylan' ? 'mapmylan' : 'directe', passerelle: u.nom || '' };
        if (avant !== false) await this.signaler({ gravite: 'eleve', type: 'bouclier.passerelle', titre: 'La passerelle UniFi ne reçoit plus les blocages', texte: this.etatUnifi.erreur, cle: 'bouclier.passerelle' });
      }
      this.magasin.poserMemoire('unifi_etat', this.etatUnifi);
      return this.etatUnifi;
    })().finally(() => { this.synchroEnCours = null; });
    return this.synchroEnCours;
  }

  // ---- Cloudflare, en amont ----
  cloudflare() {
    const r = this.reglage();
    const jeton = this.magasin.secret('bouclier', 'cloudflareJeton');
    return jeton ? this.cloudflareFabrique({ jeton, compte: r.cloudflareCompte || '', log: this.log }) : null;
  }

  /** La liste Cloudflare reçoit les adresses bloquées ; chaque zone choisie a sa règle de refus. */
  async synchroniserCloudflare({ forcer = false } = {}) {
    const cf = this.cloudflare();
    if (!cf) return this.etatCloudflare;
    // Une synchronisation en vol : on la laisse finir ; forcée, on repasse derrière elle.
    if (this.cfEnCours) { const x = await this.cfEnCours; if (!forcer) return x; }
    this.cfEnCours = (async () => {
      const r = this.reglage();
      const ips = this.actifs().map(b => b.ip).slice(0, 10_000);
      const cle = ips.join(',');
      if (!forcer && this.etatCloudflare.ok && this.etatCloudflare.cle === cle) return this.etatCloudflare;
      try {
        if (!cf.compte) { const s = await cf.sonder(); this.magasin.poserReglage('bouclier', { cloudflareCompte: s.compte }); }
        const listeId = r.cloudflareListe || await cf.assurerListe();
        if (listeId !== r.cloudflareListe) this.magasin.poserReglage('bouclier', { cloudflareListe: listeId });
        const { envoyees } = await cf.synchroniser(listeId, ips);
        const zones = [];
        for (const z of r.cloudflareZones || []) {
          try { const x = await cf.assurerRegle(z.id); zones.push({ ...z, regle: x.posee, erreur: null }); }
          catch (e) { zones.push({ ...z, regle: false, erreur: e.message }); }
        }
        this.etatCloudflare = { ...this.etatCloudflare, ok: true, erreur: null, synchro: this.maintenant(), envoyees, zones, cle };
      } catch (e) {
        const avant = this.etatCloudflare.ok;
        this.etatCloudflare = { ...this.etatCloudflare, ok: false, erreur: e instanceof ErreurCloudflare ? e.message : String(e.message || e), essai: this.maintenant() };
        if (avant !== false) await this.signaler({ gravite: 'eleve', type: 'bouclier.cloudflare', titre: 'Cloudflare ne reçoit plus les blocages', texte: this.etatCloudflare.erreur, cle: 'bouclier.cloudflare' });
      }
      this.magasin.poserMemoire('cloudflare_etat', this.etatCloudflare);
      return this.etatCloudflare;
    })().finally(() => { this.cfEnCours = null; });
    return this.cfEnCours;
  }

  /** Mode « Under Attack » sur les zones choisies, pour un temps ; l'ancien niveau est rendu ensuite. */
  async modeAttaque(actif, { minutes = 15, auteur = 'vigie', motif = '' } = {}) {
    const cf = this.cloudflare();
    if (!cf) throw Object.assign(new Error('Cloudflare n’est pas relié.'), { status: 409 });
    const r = this.reglage();
    const zones = r.cloudflareZones || [];
    if (!zones.length) throw Object.assign(new Error('Aucune zone Cloudflare choisie.'), { status: 409 });
    const t = this.maintenant();
    if (actif) {
      const avant = this.etatCloudflare.attaque?.avant || {};
      for (const z of zones) { if (!(z.id in avant)) avant[z.id] = await cf.niveau(z.id); await cf.poserNiveau(z.id, 'under_attack'); }
      this.etatCloudflare = { ...this.etatCloudflare, attaque: { depuis: this.etatCloudflare.attaque?.depuis || t, jusqua: t + minutes * 60e3, avant, motif, auteur } };
      this.journal?.ecrire({ acteur: auteur === 'vigie' ? null : auteur, action: 'bouclier.cloudflare.attaque', objet: zones.map(z => z.nom).join(','), details: { minutes, motif } });
    } else {
      const a = this.etatCloudflare.attaque;
      for (const z of zones) await cf.poserNiveau(z.id, a?.avant?.[z.id] && a.avant[z.id] !== 'under_attack' ? a.avant[z.id] : 'medium');
      this.etatCloudflare = { ...this.etatCloudflare, attaque: null };
      this.journal?.ecrire({ acteur: auteur === 'vigie' ? null : auteur, action: 'bouclier.cloudflare.calme', objet: zones.map(z => z.nom).join(',') });
    }
    this.magasin.poserMemoire('cloudflare_etat', this.etatCloudflare);
    return this.etatCloudflare.attaque;
  }

  /** Chaque minute : le mode d'attaque échu est levé. */
  async expirerAttaque() {
    const a = this.etatCloudflare.attaque;
    if (a?.jusqua && this.maintenant() >= a.jusqua) await this.modeAttaque(false, { motif: 'fin du délai' }).catch(e => this.log.warn?.(`[cloudflare] ${e.message}`));
  }

  /**
   * La tempête : beaucoup de sources sur un même port. Les plus bruyantes
   * sont bloquées tout de suite (hors plafond horaire : c'est précisément le
   * moment), l'événement est critique, et si c'est réglé, Cloudflare passe
   * en mode « Under Attack » pour un temps.
   */
  async tempete(tp) {
    const r = this.reglage();
    const bloquees = [];
    if (r.mode === 'actif') {
      for (const { ip } of tp.top.slice(0, r.tempeteBlocages || 20)) {
        if (this.refus(ip) || this.actif(ip)) continue;
        try { bloquees.push((await this.bloquer({ ip, motif: `tempête sur le port ${tp.port}`, raisons: [`tempête : ${tp.sources} sources sur le port ${tp.port}, ${tp.parMinute} lignes en une minute`], score: 1000, auteur: 'vigie', automatique: true })).ip); } catch { /* refusée */ }
      }
    }
    let attaque = null;
    if (r.cloudflareModeAttaque && this.cloudflare() && (r.cloudflareZones || []).length) {
      try { attaque = await this.modeAttaque(true, { minutes: r.tempeteMinutes || 15, motif: `tempête sur le port ${tp.port}` }); }
      catch (e) { this.log.warn?.(`[cloudflare] mode attaque : ${e.message}`); }
    }
    await this.signaler({
      gravite: 'critique', type: 'bouclier.tempete', forcer: true,
      titre: `Tempête sur le port ${tp.port} : ${tp.sources} adresses, ${tp.parMinute} paquets en une minute`,
      texte: `${bloquees.length ? `${bloquees.length} adresses les plus bruyantes bloquées à la frontière` : 'Mode ' + r.mode + ' : rien bloqué'}${attaque ? ' · Cloudflare en mode Under Attack' : ''}. Au-delà de la frontière, un déni de service volumétrique se traite en amont (Cloudflare, fournisseur d’accès).`,
      sujet: `port ${tp.port}`, cle: `bouclier.tempete:${tp.port}`,
    });
    return { bloquees, attaque };
  }

  /** La liste servie aux pare-feu qui lisent une URL (pfSense, OPNsense, MikroTik…). */
  texteListe() {
    const l = this.actifs();
    return `# VIGIE : ${l.length} adresse${l.length > 1 ? 's' : ''} bloquée${l.length > 1 ? 's' : ''}, ${new Date(this.maintenant()).toISOString()}\n${l.map(b => b.ip).join('\n')}\n`;
  }
}
