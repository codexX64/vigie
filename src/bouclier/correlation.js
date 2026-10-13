// Corrélation : chaque observation (alerte IPS, ligne du pare-feu, connexion,
// requête DNS) ajoute des points à l'adresse qui la porte, avec une raison.
// Les points s'effacent de moitié toutes les heures (demi-vie réglable) : une
// adresse qui frappe souvent monte, une rencontre isolée retombe. Au-delà du
// seuil, un verdict part — bloquer une adresse extérieure, ou signaler une
// machine du réseau qui se comporte comme une machine compromise.
//
// Les idées viennent des outils qui font référence, pas leur code :
//   - Suricata / Snort (mode « block offenders » de pfSense) : une alerte de
//     gravité 1 suffit à bloquer la source ; 2 et 3 s'additionnent ;
//   - sshguard / fail2ban : force brute comptée par adresse dans une fenêtre,
//     durée de blocage qui grandit à chaque récidive (riposte.js) ;
//   - psad / portsentry : balayage vertical (beaucoup de ports d'une même
//     cible) et horizontal (un même port sur beaucoup de cibles) ;
//   - CrowdSec : une adresse vue en train d'agir, croisée avec la réputation
//     partagée (les listes de menaces.js), plutôt que des listes aveugles.
import { estPublique, estInterne } from './ip.js';

const FENETRE_MS = 10 * 60e3;
const MAX_ADRESSES = 50_000;
// Ports d'authentification : beaucoup de tentatives = force brute.
export const PORTS_AUTH = new Set([21, 22, 23, 25, 110, 143, 389, 445, 465, 587, 993, 995, 1433, 1521, 2222, 3306, 3389, 5432, 5900, 6379, 8006, 8443, 9200, 11211, 27017]);
// Catégories d'alerte qui disent « la machine interne est compromise », pas « elle est visée ».
const COMPROMISSION = /(malware|trojan|cnc|c2|botnet|coin.?min|miner|ransom|backdoor|exploit.?kit|spyware|worm|beacon|exfil)/i;
const POINTS_IPS = { 1: 100, 2: 40, 3: 10 };

/** Entropie de Shannon d'une chaîne, en bits par caractère. */
export function entropie(s) {
  const n = {};
  for (const c of s) n[c] = (n[c] || 0) + 1;
  return Object.values(n).reduce((h, k) => h - (k / s.length) * Math.log2(k / s.length), 0);
}
/** Un nom qui ressemble à un nom de domaine généré par algorithme (DGA). */
export function semblableDga(domaine) {
  const etiquettes = String(domaine).split('.');
  if (etiquettes.length < 2) return false;
  const l = etiquettes.length > 2 && etiquettes[etiquettes.length - 2].length <= 3 ? etiquettes[etiquettes.length - 3] : etiquettes[etiquettes.length - 2];
  if (!l || l.length < 12 || /^xn--/.test(l)) return false;
  const consonnes = (l.match(/[bcdfghjklmnpqrstvwxz]/g) || []).length / l.length;
  const chiffres = (l.match(/\d/g) || []).length / l.length;
  return entropie(l) >= 3.6 && (consonnes >= 0.62 || chiffres >= 0.25);
}

export class Correlateur {
  constructor({ menaces, reglage = () => ({}), surVerdict = () => {}, maintenant = () => Date.now() }) {
    Object.assign(this, { menaces, reglage, surVerdict, maintenant });
    this.adresses = new Map();      // ip → { score, maj, raisons[], premier, interne, alerte, ports:Map, cibles:Map, auth, verdict }
    this.recentes = [];             // dernières alertes IPS, pour l'interface
    this.compteurs = {};            // type → nombre d'observations
    this.listeesVues = new Map();   // ip → heure du dernier contrôle des listes
  }

  etat(ip, interne) {
    let a = this.adresses.get(ip);
    const t = this.maintenant();
    if (!a) {
      if (this.adresses.size >= MAX_ADRESSES) this.elaguer();
      a = { ip, score: 0, maj: t, premier: t, interne, raisons: [], ports: new Map(), cibles: new Map(), auth: [], verdict: false, vu: 0 };
      this.adresses.set(ip, a);
    }
    // Effacement : demi-vie en minutes.
    const demi = Math.max(5, this.reglage().demiVieMinutes || 60) * 60e3;
    a.score *= 0.5 ** ((t - a.maj) / demi);
    if (a.score < 1) a.score = 0;
    if (a.verdict && a.score < this.seuil(a) / 2) a.verdict = false;
    a.maj = t;
    a.vu++;
    return a;
  }
  seuil(a) { const r = this.reglage(); return a.interne ? (r.seuilInterne || 100) : (r.seuil || 100); }
  elaguer() {
    const tri = [...this.adresses.values()].sort((x, y) => x.score - y.score || x.maj - y.maj);
    for (const a of tri.slice(0, Math.ceil(MAX_ADRESSES / 5))) this.adresses.delete(a.ip);
  }

  ajouter(a, points, raison, o, cle = raison) {
    if (points <= 0) return;
    const t = this.maintenant();
    a.score = Math.min(1000, a.score + points);
    const r = a.raisons.find(x => x.cle === cle);
    if (r) { r.n++; r.der = t; r.points += points; } else a.raisons.unshift({ cle, texte: raison, points, n: 1, der: t, capteur: o?.capteur || '' });
    a.raisons = a.raisons.slice(0, 12);
    if (!a.verdict && a.score >= this.seuil(a)) {
      a.verdict = true;
      this.surVerdict({ ip: a.ip, interne: a.interne, score: Math.round(a.score), raisons: a.raisons.slice(0, 6).map(x => x.texte), observation: o || null });
    }
  }

  /** Les listes de menaces, consultées au plus une fois par heure pour une adresse vue. */
  listes(a, o) {
    const t = this.maintenant();
    if (t - (this.listeesVues.get(a.ip) || 0) < 3600e3) return;
    this.listeesVues.set(a.ip, t);
    if (this.listeesVues.size > MAX_ADRESSES) this.listeesVues.clear();
    for (const l of this.menaces?.ipListee(a.ip) || []) this.ajouter(a, l.poids, `listée par ${l.nom} (${l.sujet})`, o, `liste:${l.id}`);
  }

  observer(o) {
    if (!o) return;
    this.compteurs[o.type] = (this.compteurs[o.type] || 0) + 1;
    const ext = ip => ip && estPublique(ip);
    const int = ip => ip && estInterne(ip);
    const t = this.maintenant();

    if (o.type === 'ips') {
      this.recentes.unshift({ quand: o.quand, src: o.src, dst: o.dst, dport: o.dport, signature: o.signature, gravite: o.gravite, action: o.action, categorie: o.categorie, capteur: o.capteur });
      this.recentes = this.recentes.slice(0, 200);
      const p = POINTS_IPS[o.gravite] ?? 10;
      const sig = `${o.signature || 'alerte'}${o.sid ? ` (sid ${o.sid})` : ''}`;
      const compromission = COMPROMISSION.test(`${o.signature} ${o.categorie}`);
      if (ext(o.src)) { const a = this.etat(o.src, false); this.listes(a, o); this.ajouter(a, p, `IPS : ${sig}`, o, `ips:${o.sid || o.signature}`); }
      if (ext(o.dst) && (int(o.src) || !o.src)) {
        // Une machine du réseau qui parle à l'extérieur et déclenche une signature
        // de compromission : l'extérieur est son serveur de commande.
        const a = this.etat(o.dst, false); this.listes(a, o);
        this.ajouter(a, compromission ? Math.max(p, 100) : Math.round(p / 2), `IPS, destination : ${sig}`, o, `ips-dst:${o.sid || o.signature}`);
      }
      if (int(o.src) && (compromission || int(o.dst))) {
        const a = this.etat(o.src, true);
        this.ajouter(a, compromission ? Math.max(p, 60) : p, int(o.dst) ? `IPS, vers ${o.dst} (réseau interne) : ${sig}` : `IPS : ${sig}`, o, `ips-src:${o.sid || o.signature}`);
      }
      return;
    }

    if (o.type === 'pare-feu' || o.type === 'flux') {
      const entrant = ext(o.src) && !ext(o.dst);
      const sortant = int(o.src) && ext(o.dst);
      if (entrant) {
        const a = this.etat(o.src, false);
        this.listes(a, o);
        if (o.action === 'bloque') this.ajouter(a, 2, 'paquets refusés par le pare-feu', o, 'pf-refus');
        this.fenetre(a, o, t);
      } else if (sortant) {
        // Une machine du réseau qui contacte une adresse listée : l'adresse est
        // bloquée en sortie, et la machine devient suspecte.
        const listees = this.menaces?.ipListee(o.dst) || [];
        if (listees.length) {
          this.listes(this.etat(o.dst, false), o);
          this.ajouter(this.etat(o.src, true), 40, `a contacté ${o.dst}${o.dport ? `:${o.dport}` : ''}, listée par ${listees[0].nom}`, o, `contact:${o.dst}`);
        }
      } else if (int(o.src) && int(o.dst) && o.src !== o.dst) {
        // Mouvement latéral : une machine du réseau qui balaie les autres.
        const a = this.etat(o.src, true);
        this.fenetre(a, o, t, { interne: true });
      }
      return;
    }

    if (['dns', 'tls', 'http'].includes(o.type) && o.domaine) {
      const listes = this.menaces?.domaineListe(o.domaine) || [];
      if (listes.length) {
        const l = listes[0];
        if (int(o.src)) this.ajouter(this.etat(o.src, true), o.type === 'dns' ? 30 : 60, `a demandé ${o.domaine} (${l.nom} : ${l.sujet})`, o, `dom:${o.domaine}`);
        if (ext(o.dst) && o.type !== 'dns') this.ajouter(this.etat(o.dst, false), l.poids, `sert ${o.domaine}, domaine listé par ${l.nom}`, o, `dom:${o.domaine}`);
      } else if (o.type === 'dns' && int(o.src) && semblableDga(o.domaine)) {
        this.ajouter(this.etat(o.src, true), 5, `noms générés par algorithme (ex. ${o.domaine})`, o, 'dga');
      }
    }
  }

  /** Balayages et force brute, comptés dans une fenêtre glissante de dix minutes. */
  fenetre(a, o, t, { interne = false } = {}) {
    const limite = t - FENETRE_MS;
    if (o.dport) a.ports.set(o.dport, t);
    if (o.dst) a.cibles.set(o.dst, t);
    for (const [k, v] of a.ports) if (v < limite) a.ports.delete(k);
    for (const [k, v] of a.cibles) if (v < limite) a.cibles.delete(k);
    if (a.ports.size > 2000) a.ports.clear();
    if (a.cibles.size > 2000) a.cibles.clear();
    const r = this.reglage();
    if (a.ports.size >= (r.balayagePorts || 15)) { this.ajouter(a, 60, `${interne ? 'balaie le réseau interne' : 'balayage de ports'} : ${a.ports.size} ports en dix minutes`, o, 'scan-v'); a.ports.clear(); }
    if (a.cibles.size >= (r.balayageCibles || 12)) { this.ajouter(a, 60, `${interne ? 'balaie le réseau interne' : 'balayage d’adresses'} : ${a.cibles.size} machines en dix minutes`, o, 'scan-h'); a.cibles.clear(); }
    if (o.dport && PORTS_AUTH.has(o.dport)) {
      a.auth = a.auth.filter(x => x > limite);
      a.auth.push(t);
      if (a.auth.length >= (r.forceBrute || 20)) { this.ajouter(a, 60, `force brute : ${a.auth.length} tentatives sur le port ${o.dport} en dix minutes`, o, `brute:${o.dport}`); a.auth = []; }
    }
  }

  /** Les adresses qui ont des points, de la plus menaçante à la moins menaçante. */
  menacesActuelles({ limite = 100, interne = null } = {}) {
    const t = this.maintenant();
    const demi = Math.max(5, this.reglage().demiVieMinutes || 60) * 60e3;
    return [...this.adresses.values()]
      .map(a => ({ ip: a.ip, interne: a.interne, score: Math.round(a.score * 0.5 ** ((t - a.maj) / demi)), raisons: a.raisons.slice(0, 6), premier: a.premier, dernier: a.maj, vu: a.vu, seuil: this.seuil(a) }))
      .filter(a => a.score > 0 && (interne === null || a.interne === interne))
      .sort((x, y) => y.score - x.score).slice(0, limite);
  }
}
