// Ce que voient les capteurs, ramené à une seule forme d'observation :
//   { quand, capteur, type, src, dst, sport, dport, proto, action, gravite,
//     signature, sid, categorie, regle, domaine }
// type : 'ips' (alerte de l'IPS : UniFi ou Suricata), 'pare-feu' (ligne du
// pare-feu), 'flux' (connexion vue par la sonde), 'dns' (requête), 'tls' /
// 'http' (nom demandé), 'anomalie' (paquet hors protocole).
//
// Trois formats en entrée :
//   - CEF, que l'application UniFi Network envoie à un serveur SIEM
//     (« Threat Detected and Blocked », champs UNIFI…) ;
//   - les lignes du pare-feu de la passerelle, à la façon iptables
//     ([RÈGLE] … SRC= DST= PROTO= SPT= DPT=) ;
//   - EVE JSON, la sortie de Suricata (alert, dns, tls, http, flow, anomaly).
import { normaliser } from './ip.js';

const entier = v => { const n = Number(v); return Number.isInteger(n) && n >= 0 && n <= 65535 ? n : null; };
const texte = (v, max = 200) => (v === undefined || v === null ? '' : String(v).slice(0, max));
const proto = p => texte(p, 10).toLowerCase() || null;

/** Le message d'une ligne syslog (RFC 3164 ou 5424), sans la priorité ni l'en-tête. */
export function messageSyslog(ligne) {
  let s = String(ligne).replace(/^\s*<\d{1,3}>/, '');
  // RFC 5424 : « 1 2026-10-13T10:00:00Z hôte app pid msgid [sd] message »
  const r5424 = /^1 \S+ \S+ \S+ \S+ \S+ (?:-|(?:\[[^\]]*\])+) ?/.exec(s);
  if (r5424) return s.slice(r5424[0].length);
  // RFC 3164 : « Oct 13 10:00:00 hôte tag: message » — le reste est gardé tel quel s'il ne suit pas la forme.
  const r3164 = /^[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d \S+ /.exec(s);
  if (r3164) s = s.slice(r3164[0].length);
  return s;
}

/** CEF:0|Vendeur|Produit|Version|Id|Nom|Gravité|clé=valeur … → { entete, ext } ou null. */
export function lireCef(msg) {
  const i = msg.indexOf('CEF:');
  if (i < 0) return null;
  const s = msg.slice(i + 4);
  const champs = [];
  let cur = '', k = 0;
  for (; k < s.length && champs.length < 7; k++) {
    const c = s[k];
    if (c === '\\' && (s[k + 1] === '|' || s[k + 1] === '\\')) { cur += s[++k]; continue; }
    if (c === '|') { champs.push(cur); cur = ''; continue; }
    cur += c;
  }
  if (champs.length < 7) return null;
  const ext = {};
  const reste = s.slice(k);
  const re = /([A-Za-z0-9_.]+)=((?:\\.|[^\\])*?)(?=\s+[A-Za-z0-9_.]+=|\s*$)/g;
  let m;
  while ((m = re.exec(reste))) ext[m[1]] = m[2].replace(/\\([=\\n])/g, (_, x) => (x === 'n' ? '\n' : x)).trim();
  const [version, vendeur, produit, versionProduit, id, nom, gravite] = champs;
  return { entete: { version, vendeur, produit, versionProduit, id, nom, gravite: Number(gravite) }, ext };
}

/** Une alerte CEF d'UniFi en observation. */
function depuisCef(cef, capteur, quand) {
  const { entete: h, ext: e } = cef;
  const src = normaliser(e.src), dst = normaliser(e.dst);
  // Les noms des champs d'IPS changent d'une version d'UniFi à l'autre : tout
  // champ UNIFIips…/UNIFIthreat…, ou un nom d'événement qui parle de menace,
  // d'intrusion ou de pot de miel (Honeypot) fait une alerte d'IPS.
  const pot = /honeypot/i.test(`${h.nom} ${e.UNIFIsubCategory || ''}`);
  const ips = pot || Object.keys(e).some(k => /^UNIFI(ips|threat)/i.test(k)) || /threat|intrusion/i.test(`${h.nom} ${e.UNIFIsubCategory || ''}`);
  const pareFeu = /firewall|blocked by|policy/i.test(h.nom) && !ips;
  if (!src && !dst) return null;
  // La gravité de Suricata va de 1 (la plus haute) à 3 ; celle de CEF de 0 à 10.
  const risque = String(e.UNIFIrisk || '').toLowerCase();
  // Un pot de miel touché n'a pas de raison légitime : gravité la plus haute.
  const g = pot || risque === 'high' ? 1 : risque === 'medium' ? 2 : risque === 'low' ? 3 : h.gravite >= 7 ? 1 : h.gravite >= 4 ? 2 : 3;
  return {
    quand, capteur, type: ips ? 'ips' : pareFeu ? 'pare-feu' : 'autre', src, dst, sport: entier(e.spt), dport: entier(e.dpt), proto: proto(e.proto),
    action: /block|drop|reject/i.test(h.nom + ' ' + (e.act || '')) ? 'bloque' : 'alerte', gravite: ips ? g : null,
    signature: texte(e.UNIFIipsSignature || e.UNIFIthreatName || e.UNIFIsignature || e.msg || h.nom), sid: Number(e.UNIFIipsSignatureId || e.UNIFIsignatureId) || null,
    categorie: texte(pot ? 'honeypot' : e.UNIFIipsCategory || e.UNIFIsubCategory || e.UNIFIcategory || e.cat, 80), regle: texte(e.UNIFIpolicyName || e.cs1, 80), domaine: null,
  };
}

/** Une ligne du pare-feu à la façon iptables. */
function depuisPareFeu(msg, capteur, quand) {
  if (!/\bSRC=/.test(msg) || !/\bDST=/.test(msg)) return null;
  const v = k => (new RegExp(`\\b${k}=(\\S*)`).exec(msg) || [])[1];
  const regle = (/\[([^\]]{1,80})\]/.exec(msg) || [])[1] || '';
  // UniFi : « …-D-… » ou « …-B-… » refuse, « …-R-… » / « -REJ » rejette, « …-A-… » laisse passer.
  const action = /-(D|B|R|DROP|REJ|REJECT|BLOCK)(-|$)/i.test(regle) || /\b(DROP|REJECT|BLOCK)\b/.test(msg) ? 'bloque' : /-(A|ACCEPT|RET)(-|$)/i.test(regle) ? 'accepte' : 'inconnu';
  return {
    quand, capteur, type: 'pare-feu', src: normaliser(v('SRC')), dst: normaliser(v('DST')), sport: entier(v('SPT')), dport: entier(v('DPT')), proto: proto(v('PROTO')),
    action, gravite: null, signature: texte((/DESCR="([^"]*)"/.exec(msg) || [])[1] || regle), sid: null, categorie: '', regle, domaine: null,
    entree: texte(v('IN'), 20), sortie: texte(v('OUT'), 20),
  };
}

/** Un événement EVE de Suricata. */
export function depuisEve(o, capteur) {
  if (!o || typeof o !== 'object' || typeof o.event_type !== 'string') return null;
  const quand = Date.parse(o.timestamp) || Date.now();
  const base = { quand, capteur, src: normaliser(o.src_ip), dst: normaliser(o.dest_ip), sport: entier(o.src_port), dport: entier(o.dest_port), proto: proto(o.proto), gravite: null, signature: '', sid: null, categorie: '', regle: '', domaine: null, action: 'alerte' };
  switch (o.event_type) {
    case 'alert': {
      const a = o.alert || {};
      return { ...base, type: 'ips', action: a.action === 'blocked' ? 'bloque' : 'alerte', gravite: [1, 2, 3, 4].includes(a.severity) ? Math.min(a.severity, 3) : 3, signature: texte(a.signature), sid: Number(a.signature_id) || null, categorie: texte(a.category, 80) };
    }
    case 'dns': {
      const d = o.dns || {};
      const nom = d.rrname || d.queries?.[0]?.rrname;
      if (!nom || (d.type && d.type !== 'query' && d.type !== 'request')) return null;
      return { ...base, type: 'dns', domaine: texte(nom, 253).toLowerCase() };
    }
    case 'tls': return o.tls?.sni ? { ...base, type: 'tls', domaine: texte(o.tls.sni, 253).toLowerCase() } : null;
    case 'http': return o.http?.hostname ? { ...base, type: 'http', domaine: texte(o.http.hostname, 253).toLowerCase(), signature: texte(o.http.http_user_agent, 120) } : null;
    case 'flow': return { ...base, type: 'flux', action: o.flow?.state === 'new' ? 'alerte' : 'accepte', octets: (Number(o.flow?.bytes_toserver) || 0) + (Number(o.flow?.bytes_toclient) || 0) };
    case 'anomaly': return { ...base, type: 'anomalie', signature: texte(o.anomaly?.event || o.anomaly?.type) };
    default: return null;
  }
}

/** Une ligne reçue par syslog → observation, ou null si elle ne dit rien d'utile. */
export function lireLigne(ligne, capteur = 'syslog', quand = Date.now()) {
  const msg = messageSyslog(ligne);
  const cef = lireCef(msg);
  if (cef) return depuisCef(cef, capteur, quand);
  const j = msg.indexOf('{"');
  if (j >= 0 && msg.includes('"event_type"')) { try { return depuisEve(JSON.parse(msg.slice(j)), capteur); } catch { /* pas du JSON entier */ } }
  return depuisPareFeu(msg, capteur, quand);
}
