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
  constructor({ db, magasin, journal = null, signaler = async () => null, maintenant = () => Date.now(), log = console, unifiFabrique = o => new Unifi(o) }) {
    Object.assign(this, { db, magasin, journal, signaler, maintenant, log, unifiFabrique });
    preparerBase(db);
    this.etatUnifi = this.magasin.memoire('unifi_etat', { ok: null, erreur: null, synchro: null, listes: {}, regles: null });
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
    if (etat === 'actif') { this.aSynchroniser = true; this.synchroniser().catch(() => null); }
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
    return this.ligne(this.db.prepare('SELECT * FROM blocages WHERE id = ?').get(id));
  }

  /** Les blocages arrivés à leur fin. */
  expirer() {
    const n = Number(this.db.prepare("UPDATE blocages SET etat = 'expire' WHERE etat IN ('actif', 'simule') AND fin IS NOT NULL AND fin <= ?").run(this.maintenant()).changes);
    this.db.prepare('DELETE FROM blocages WHERE debut < ? AND etat IN (\'expire\', \'leve\')').run(this.maintenant() - 180 * 86400e3);
    if (n) this.aSynchroniser = true;
    return n;
  }

  unifi() {
    const r = this.reglage();
    const cle = this.magasin.secret('bouclier', 'cleUnifi');
    if (!r.unifiHote || !cle) return null;
    return this.unifiFabrique({ hote: r.unifiHote, port: r.unifiPort || 443, fp: r.unifiFp || null, cle });
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
        this.etatUnifi = { ok: true, erreur: null, synchro: this.maintenant(), listes, regles, envoyees: ips.length, forme: u.forme };
      } catch (e) {
        this.aSynchroniser = true;
        const avant = this.etatUnifi.ok;
        this.etatUnifi = { ...this.etatUnifi, ok: false, erreur: e instanceof ErreurUnifi || e.code ? e.message : String(e.message || e), essai: this.maintenant() };
        if (avant !== false) await this.signaler({ gravite: 'eleve', type: 'bouclier.passerelle', titre: 'La passerelle UniFi ne reçoit plus les blocages', texte: this.etatUnifi.erreur, cle: 'bouclier.passerelle' });
      }
      this.magasin.poserMemoire('unifi_etat', this.etatUnifi);
      return this.etatUnifi;
    })().finally(() => { this.synchroEnCours = null; });
    return this.synchroEnCours;
  }

  /** La liste servie aux pare-feu qui lisent une URL (pfSense, OPNsense, MikroTik…). */
  texteListe() {
    const l = this.actifs();
    return `# VIGIE : ${l.length} adresse${l.length > 1 ? 's' : ''} bloquée${l.length > 1 ? 's' : ''}, ${new Date(this.maintenant()).toISOString()}\n${l.map(b => b.ip).join('\n')}\n`;
  }
}
