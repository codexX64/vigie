// Adresses et plages, IPv4 et IPv6, en entiers (BigInt pour l'IPv6) : un
// ensemble de plages fusionnées et triées répond par dichotomie, même avec
// des centaines de milliers d'entrées venues des listes de menaces.
import net from 'node:net';

export function versEntier(ip) {
  const v = net.isIP(ip);
  if (v === 4) return { v: 4, n: ip.split('.').reduce((a, x) => a * 256 + Number(x), 0) };
  if (v !== 6) return null;
  let s = ip.toLowerCase();
  const pct = s.indexOf('%');
  if (pct >= 0) s = s.slice(0, pct);
  // ::ffff:192.0.2.1 et ses semblables : la partie IPv4 en deux groupes.
  const m4 = /(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  if (m4) {
    const n4 = versEntier(m4[1]).n;
    s = s.slice(0, -m4[1].length) + `${(n4 >>> 16).toString(16)}:${(n4 & 0xffff).toString(16)}`;
  }
  const [g, d] = s.split('::');
  const gauche = g ? g.split(':') : [], droite = d !== undefined ? (d ? d.split(':') : []) : [];
  const groupes = d !== undefined ? [...gauche, ...Array(8 - gauche.length - droite.length).fill('0'), ...droite] : gauche;
  if (groupes.length !== 8) return null;
  return { v: 6, n: groupes.reduce((a, x) => (a << 16n) + BigInt(parseInt(x || '0', 16)), 0n) };
}

/** « 192.0.2.0/24 », « 2001:db8::/32 » ou une adresse seule → { v, debut, fin } ; null si illisible. */
export function plage(texte) {
  const [ip, bitsT] = String(texte).trim().split('/');
  const e = versEntier(ip);
  if (!e) return null;
  const max = e.v === 4 ? 32 : 128;
  const bits = bitsT === undefined ? max : Number(bitsT);
  if (!Number.isInteger(bits) || bits < 0 || bits > max || (bitsT !== undefined && !/^\d{1,3}$/.test(bitsT))) return null;
  if (e.v === 4) {
    const taille = 2 ** (32 - bits);
    const debut = Math.floor(e.n / taille) * taille;
    return { v: 4, debut, fin: debut + taille - 1 };
  }
  const libres = BigInt(128 - bits);
  const debut = (e.n >> libres) << libres;
  return { v: 6, debut, fin: debut + (1n << libres) - 1n };
}

/** Un ensemble de plages : ajout libre, puis figer() avant de chercher. */
export class EnsembleIp {
  constructor() { this.brut = { 4: [], 6: [] }; this.fige = { 4: [], 6: [] }; this.n = 0; }
  ajouter(texte, etiquette = null) {
    const p = plage(texte);
    if (!p) return false;
    this.brut[p.v].push([p.debut, p.fin, etiquette]);
    this.n++;
    return true;
  }
  figer() {
    for (const v of [4, 6]) {
      const l = this.brut[v].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
      const out = [];
      for (const [d, f, e] of l) {
        const der = out[out.length - 1];
        // Les plages qui se touchent sont fusionnées ; la première étiquette reste.
        const suivant = v === 4 ? der?.[1] + 1 : (der ? der[1] + 1n : null);
        if (der && d <= suivant) { if (f > der[1]) der[1] = f; } else out.push([d, f, e]);
      }
      this.fige[v] = out;
    }
    this.brut = { 4: [], 6: [] };
    return this;
  }
  /** La plage qui contient l'adresse ([debut, fin, étiquette]), ou null. */
  trouver(ip) {
    const e = versEntier(ip);
    if (!e) return null;
    const l = this.fige[e.v];
    let a = 0, b = l.length - 1;
    while (a <= b) {
      const m = (a + b) >> 1;
      if (e.n < l[m][0]) b = m - 1;
      else if (e.n > l[m][1]) a = m + 1;
      else return l[m];
    }
    return null;
  }
  contient(ip) { return !!this.trouver(ip); }
  taille() { return this.fige[4].length + this.fige[6].length; }
}

// Les trois plages de la RFC 1918, écrites par octets comme dans sources.js.
export const RFC1918 = [[[10, 0, 0, 0], 8], [[172, 16, 0, 0], 12], [[192, 168, 0, 0], 16]].map(([o, b]) => `${o.join('.')}/${b}`);

// Ce qui n'est pas une adresse publique : jamais bloqué, jamais compté comme
// un attaquant extérieur. Plages privées, boucle, lien local, CGNAT,
// documentation, multicast, réservées, et leurs équivalents IPv6.
const NON_PUBLIQUES = new EnsembleIp();
for (const p of [...RFC1918, '0.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '192.0.0.0/24', '192.0.2.0/24',
  '192.88.99.0/24', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4',
  '::/127', '::ffff:0:0/96', '64:ff9b:1::/48', '100::/64', '2001:db8::/32', 'fc00::/7', 'fe80::/10', 'ff00::/8']) NON_PUBLIQUES.ajouter(p);
NON_PUBLIQUES.figer();
export const estPublique = ip => !!versEntier(ip) && !NON_PUBLIQUES.contient(ip);

// Les plages privées seules : « interne » au sens du réseau surveillé.
const PRIVEES = new EnsembleIp();
for (const p of [...RFC1918, '100.64.0.0/10', 'fc00::/7', 'fe80::/10']) PRIVEES.ajouter(p);
PRIVEES.figer();
export const estInterne = ip => PRIVEES.contient(ip);

/** Une adresse sous une forme unique (IPv6 compressée, IPv4 telle quelle), ou null. */
export function normaliser(ip) {
  const s = String(ip || '').trim().replace(/^\[|\]$/g, '');
  const e = versEntier(s);
  if (!e) return null;
  if (e.v === 4) return s.split('.').map(Number).join('.');
  const g = Array.from({ length: 8 }, (_, i) => Number((e.n >> BigInt((7 - i) * 16)) & 0xffffn).toString(16));
  // La plus longue suite de zéros devient « :: ».
  let meilleur = [-1, 0];
  for (let i = 0; i < 8;) {
    if (g[i] !== '0') { i++; continue; }
    let j = i;
    while (j < 8 && g[j] === '0') j++;
    if (j - i > meilleur[1] && j - i > 1) meilleur = [i, j - i];
    i = j;
  }
  if (meilleur[0] < 0) return g.join(':');
  return `${g.slice(0, meilleur[0]).join(':')}::${g.slice(meilleur[0] + meilleur[1]).join(':')}`;
}
