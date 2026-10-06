// Le moteur sans IA. Des règles fixes, confrontées à ce que les sources ont
// rapporté, donnent des constats classés en cinq gravités, puis un score par
// domaine et un score global. Mêmes entrées, même résultat : aucune règle ne
// lit l'heure autrement que par « maintenant », passé en argument.
//
// Chaque constat est rattaché à un contrôle du référentiel Codex64 (REQ/SEC).
// Le conforme se compte aussi : un appareil sans écart dans un domaine reçoit
// un constat « safe » pour ce domaine.
import { GRAVITES, RANG } from './base.js';
import { nomAppareil, estIPv4, plages } from './sources.js';

export const DOMAINES = {
  surface: 'Surface réseau',
  segmentation: 'Segmentation',
  authentification: 'Authentification',
  maj: 'Mises à jour',
  chiffrement: 'Chiffrement',
  journaux: 'Journaux & traçabilité',
};
export const LIBELLE_GRAVITE = { safe: 'Conforme', info: 'Info', faible: 'Faible', eleve: 'Élevé', critique: 'Critique' };

// Ce qu'un constat retire au score de son domaine. Une même règle qui touche
// beaucoup d'appareils pèse au plus trois fois son pire constat.
const PENALITE = { safe: 0, info: 0, faible: 4, eleve: 12, critique: 30 };
const PLAFOND_CRITIQUE = 40;

const INFRA = new Set(['router', 'firewall', 'switch', 'ap']);
const SERVEURS = new Set(['server', 'nas', 'hypervisor', 'docker', 'vm', 'container']);
const OBJETS = new Set(['iot', 'sensor', 'camera', 'tv', 'console', 'voip', 'printer']);
const POSTES = new Set(['pc', 'computer', 'laptop', 'phone', 'tablet']);

const PORTS_BDD = { 3306: 'MySQL', 5432: 'PostgreSQL', 6379: 'Redis', 27017: 'MongoDB', 9200: 'Elasticsearch', 11211: 'Memcached', 5984: 'CouchDB', 1433: 'SQL Server', 1521: 'Oracle', 9042: 'Cassandra', 8086: 'InfluxDB' };
const PORTS_CLAIR = { 21: 'FTP', 23: 'Telnet', 110: 'POP3', 143: 'IMAP', 512: 'rexec', 513: 'rlogin', 514: 'rsh' };
const PORTS_PARTAGE = { 139: 'NetBIOS/SMB', 445: 'SMB', 2049: 'NFS', 548: 'AFP' };
const PORTS_WEB_CLAIR = [80, 8080, 8000, 8081, 8888];
const PORTS_WEB_TLS = [443, 8443, 9443, 4443];

/** Le catalogue des règles : ce que l'interface et le rapport montrent de chacune. */
export const REGLES = {
  'surface.intrusion': { domaine: 'surface', ref: 'SEC-LOG-004', titre: 'Signe d’intrusion sur un appareil' },
  'surface.api-docker': { domaine: 'surface', ref: 'SEC-INFRA-004', titre: 'API Docker ouverte sans authentification' },
  'surface.bdd': { domaine: 'surface', ref: 'SEC-INFRA-003', titre: 'Base de données joignable sur le réseau' },
  'surface.partage': { domaine: 'surface', ref: 'SEC-INFRA-003', titre: 'Partage de fichiers exposé' },
  'surface.upnp': { domaine: 'surface', ref: 'SEC-INFRA-003', titre: 'UPnP actif' },
  'surface.ports': { domaine: 'surface', ref: 'SEC-INFRA-003', titre: 'Beaucoup de ports ouverts' },
  'surface.pare-feu': { domaine: 'surface', ref: 'SEC-INFRA-003', titre: 'Pare-feu du poste inactif' },
  'surface.antivirus': { domaine: 'surface', ref: 'SEC-INFRA-003', titre: 'Antivirus absent ou inactif' },
  'surface.flux-suspect': { domaine: 'surface', ref: 'SEC-LOG-004', titre: 'Trafic sortant suspect' },
  'surface.conteneur': { domaine: 'surface', ref: 'SEC-INFRA-004', titre: 'Conteneur trop privilégié' },
  'surface.conteneur-bdd': { domaine: 'surface', ref: 'SEC-INFRA-003', titre: 'Base de données d’un conteneur publiée' },
  'surface.ok': { domaine: 'surface', ref: 'SEC-INFRA-003', titre: 'Surface sans écart' },
  'segmentation.vlans': { domaine: 'segmentation', ref: 'SEC-INFRA-003', titre: 'Réseau découpé en VLAN' },
  'segmentation.melange': { domaine: 'segmentation', ref: 'SEC-INFRA-003', titre: 'Objets connectés mêlés aux postes et serveurs' },
  'segmentation.isolement': { domaine: 'segmentation', ref: 'SEC-INFRA-003', titre: 'VLAN d’objets ou d’invités non isolé' },
  'segmentation.hors-vlan': { domaine: 'segmentation', ref: 'SEC-INFRA-003', titre: 'Appareils sans VLAN' },
  'segmentation.inter-vlan': { domaine: 'segmentation', ref: 'SEC-INFRA-003', titre: 'Flux sortant d’un VLAN isolé' },
  'segmentation.quarantaine': { domaine: 'segmentation', ref: 'SEC-INFRA-003', titre: 'Appareils isolés' },
  'authentification.clair': { domaine: 'authentification', ref: 'SEC-INFRA-003', titre: 'Protocole à mot de passe en clair' },
  'authentification.vnc': { domaine: 'authentification', ref: 'SEC-INFRA-003', titre: 'VNC ouvert' },
  'authentification.rdp': { domaine: 'authentification', ref: 'SEC-INFRA-003', titre: 'Bureau à distance ouvert' },
  'authentification.ssh': { domaine: 'authentification', ref: 'SEC-INFRA-003', titre: 'SSH ouvert' },
  'authentification.snmp': { domaine: 'authentification', ref: 'SEC-INFRA-003', titre: 'SNMP ouvert' },
  'authentification.admin-http': { domaine: 'authentification', ref: 'SEC-HDR-001', titre: 'Administration sans HTTPS' },
  'authentification.tentatives': { domaine: 'authentification', ref: 'SEC-LOG-004', titre: 'Tentatives de connexion répétées' },
  'authentification.ok': { domaine: 'authentification', ref: 'SEC-INFRA-003', titre: 'Accès sans écart' },
  'maj.cve': { domaine: 'maj', ref: 'SEC-INFRA-003', titre: 'Vulnérabilités connues' },
  'maj.obsolete': { domaine: 'maj', ref: 'SEC-INFRA-003', titre: 'Version en fin de vie' },
  'maj.correctifs': { domaine: 'maj', ref: 'SEC-INFRA-003', titre: 'Correctifs en attente' },
  'maj.image': { domaine: 'maj', ref: 'SEC-INFRA-004', titre: 'Image de conteneur non épinglée' },
  'maj.ok': { domaine: 'maj', ref: 'SEC-INFRA-003', titre: 'À jour' },
  'chiffrement.expire': { domaine: 'chiffrement', ref: 'SEC-INFRA-001', titre: 'Certificat expiré ou proche de l’expiration' },
  'chiffrement.ancien': { domaine: 'chiffrement', ref: 'SEC-INFRA-001', titre: 'TLS 1.0 ou 1.1 accepté' },
  'chiffrement.cle': { domaine: 'chiffrement', ref: 'SEC-INFRA-001', titre: 'Clé de certificat trop courte' },
  'chiffrement.autosigne': { domaine: 'chiffrement', ref: 'SEC-INFRA-001', titre: 'Certificat auto-signé' },
  'chiffrement.http': { domaine: 'chiffrement', ref: 'SEC-HDR-001', titre: 'Service web sans HTTPS' },
  'chiffrement.disque': { domaine: 'chiffrement', ref: 'SEC-INFRA-003', titre: 'Disque non chiffré' },
  'chiffrement.ok': { domaine: 'chiffrement', ref: 'SEC-INFRA-001', titre: 'Chiffrement sans écart' },
  'journaux.alertes': { domaine: 'journaux', ref: 'SEC-LOG-004', titre: 'Alertes non traitées' },
  'journaux.balayage': { domaine: 'journaux', ref: 'SEC-LOG-005', titre: 'Inventaire du réseau à jour' },
  'journaux.trafic': { domaine: 'journaux', ref: 'SEC-LOG-001', titre: 'Collecte du trafic' },
  'journaux.centralisation': { domaine: 'journaux', ref: 'SEC-LOG-003', titre: 'Mémoire centrale des événements' },
  'journaux.veille': { domaine: 'journaux', ref: 'SEC-LOG-004', titre: 'Veille continue' },
  'journaux.agents': { domaine: 'journaux', ref: 'SEC-LOG-005', titre: 'Agent muet' },
  'journaux.notifications': { domaine: 'journaux', ref: 'SEC-LOG-004', titre: 'Alertes transmises' },
};

const typeDe = a => String(a.customType || a.type || 'unknown');
const ouverts = a => (a.ports || []).filter(p => !p.state || p.state === 'open');
const cleSujet = a => `mml:${a.mac || a.ip || a.id}`;
const sujetDe = a => `${nomAppareil(a)}${a.ip && nomAppareil(a) !== a.ip ? ` (${a.ip})` : ''}`;
const listePorts = (ps, noms) => ps.map(p => `${noms?.[p.port] || p.service || 'port'} ${p.port}`).join(', ');

function constat(regle, gravite, { sujet = '', sujetId = null, cle, titre, preuve = {}, correction = '', action = null }) {
  const r = REGLES[regle];
  return { cle: cle || `${regle}:${sujet || 'global'}`, regle, ref: r.ref, domaine: r.domaine, gravite, titre: titre || r.titre, sujet, sujetId, preuve, correction, action };
}

// ---------- versions en fin de vie ----------
const vers = s => (String(s || '').match(/\d+(?:\.\d+){0,2}/)?.[0] || '').split('.').map(Number);
const avant = (v, ref) => { for (let i = 0; i < ref.length; i++) { const a = v[i] ?? 0; if (a !== ref[i]) return a < ref[i]; } return false; };

/** Une version de logiciel ou de système en fin de vie : { gravite, texte } ou null. */
export function finDeVie(produit, version) {
  const p = String(produit || '').toLowerCase(), v = vers(version || produit);
  if (!v.length || Number.isNaN(v[0])) return null;
  if (/openssh/.test(p)) return avant(v, [7, 4]) ? { gravite: 'eleve', texte: `OpenSSH ${v.join('.')} : plus de dix ans de failles corrigées depuis.` } : avant(v, [9, 0]) ? { gravite: 'faible', texte: `OpenSSH ${v.join('.')} : version ancienne.` } : null;
  if (/apache/.test(p) && /http/.test(p)) return avant(v, [2, 4]) ? { gravite: 'eleve', texte: `Apache ${v.join('.')} : branche abandonnée.` } : null;
  if (/nginx/.test(p)) return avant(v, [1, 20]) ? { gravite: 'faible', texte: `nginx ${v.join('.')} : branche plus maintenue.` } : null;
  if (/\biis\b|microsoft-iis/.test(p)) return avant(v, [8, 5]) ? { gravite: 'eleve', texte: `IIS ${v.join('.')} : Windows Server en fin de vie.` } : null;
  if (/samba/.test(p)) return avant(v, [4, 0]) ? { gravite: 'eleve', texte: `Samba ${v.join('.')} : branche abandonnée.` } : null;
  if (/\bphp\b/.test(p)) return avant(v, [7, 0]) ? { gravite: 'eleve', texte: `PHP ${v.join('.')} : sans correctif depuis des années.` } : avant(v, [8, 1]) ? { gravite: 'faible', texte: `PHP ${v.join('.')} : plus maintenu.` } : null;
  if (/openssl/.test(p)) return avant(v, [1, 1]) ? { gravite: 'eleve', texte: `OpenSSL ${v.join('.')} : abandonné.` } : avant(v, [3, 0]) ? { gravite: 'faible', texte: `OpenSSL ${v.join('.')} : fin de vie.` } : null;
  return null;
}
/** Un système d'exploitation en fin de vie, d'après son libellé. */
export function systemeFinDeVie(os) {
  const s = String(os || '');
  if (/windows\s*(xp|vista|7|8(\.1)?)\b|windows server\s*(2003|2008|2012)\b/i.test(s)) return { gravite: 'eleve', texte: `${s.slice(0, 60)} : plus aucun correctif de sécurité.` };
  if (/windows\s*10\b/i.test(s)) return { gravite: 'eleve', texte: 'Windows 10 : fin du support standard en octobre 2025.' };
  if (/centos\s*(linux\s*)?[5-7]\b|debian\s*(gnu\/linux\s*)?([5-9]|10)\b|ubuntu\s*(1[0-8]|20)\.04/i.test(s)) return { gravite: 'eleve', texte: `${s.slice(0, 60)} : distribution en fin de vie.` };
  if (/mac\s*os.*\b(10\.\d+|11|12)\b/i.test(s)) return { gravite: 'faible', texte: `${s.slice(0, 60)} : plus mis à jour par Apple.` };
  return null;
}

// ---------- règles ----------
function surAppareils(d, ctx, out) {
  const m = d.mapmylan;
  for (const a of m.appareils) {
    if (!a.ip && !a.mac) continue;
    const t = typeDe(a), ps = ouverts(a), base = { sujet: sujetDe(a), sujetId: a.id };
    const ici = { surface: 0, authentification: 0, maj: 0, chiffrement: 0 };
    const pousser = c => { out.push(c); if (c.gravite !== 'safe') ici[c.domaine] = (ici[c.domaine] || 0) + 1; };
    const avec = (regle, g, o = {}) => pousser(constat(regle, g, { ...base, ...o, cle: `${regle}:${cleSujet(a)}${o.cle ? ':' + o.cle : ''}` }));

    // Surface
    if (a.status === 'suspect' && !a.whitelisted && (a.dangerScore ?? 0) >= ctx.seuilIntrusion) {
      avec('surface.intrusion', 'critique', {
        preuve: { statut: a.status, danger: a.dangerScore, raisons: (a.scoreReasons?.trust || []).slice(0, 5).map(r => r.reason) },
        correction: 'Isoler l’appareil en quarantaine, puis identifier ce qui tourne dessus (balayage approfondi) avant de le rendre au réseau.',
        action: !INFRA.has(t) && !a.isMainRouter ? { type: 'quarantine', appareil: a.id } : null,
      });
    }
    const docker = ps.filter(p => p.port === 2375);
    if (docker.length) avec('surface.api-docker', 'critique', { preuve: { ports: [2375] }, correction: 'Fermer le port 2375 : l’API Docker sans TLS donne la machine entière à qui s’y connecte. Utiliser le socket local, ou TLS mutuel sur 2376.' });
    const bdd = ps.filter(p => PORTS_BDD[p.port]);
    if (bdd.length) avec('surface.bdd', 'eleve', { preuve: { ports: bdd.map(p => p.port) }, titre: `Base de données joignable : ${listePorts(bdd, PORTS_BDD)}`, correction: 'Lier la base à l’adresse locale (127.0.0.1) ou au réseau des seules applications qui l’utilisent, et filtrer le port au pare-feu.' });
    const partage = ps.filter(p => PORTS_PARTAGE[p.port]);
    if (partage.length && t !== 'nas') avec('surface.partage', partage.some(p => p.port === 139) && !SERVEURS.has(t) ? 'eleve' : 'faible', { preuve: { ports: partage.map(p => p.port) }, titre: `Partage de fichiers exposé : ${listePorts(partage, PORTS_PARTAGE)}`, correction: 'Couper le partage s’il ne sert pas ; sinon, SMB 3 seulement (NetBIOS et SMB 1 désactivés) et accès limité au VLAN qui en a besoin.' });
    if (ps.some(p => p.port === 1900 || p.port === 5000 && /upnp/i.test(p.service || ''))) avec('surface.upnp', INFRA.has(t) || a.isMainRouter ? 'eleve' : 'faible', { preuve: { ports: [1900] }, correction: INFRA.has(t) || a.isMainRouter ? 'Désactiver UPnP sur le routeur : n’importe quel appareil du réseau peut y ouvrir un port vers Internet sans demander.' : 'Désactiver UPnP sur l’appareil s’il n’en a pas l’usage.' });
    if (ps.length > 20) avec('surface.ports', 'faible', { preuve: { n: ps.length }, titre: `${ps.length} ports ouverts`, correction: 'Arrêter les services qui ne servent pas et fermer leurs ports au pare-feu de la machine.' });

    // Authentification
    const clair = ps.filter(p => PORTS_CLAIR[p.port]);
    if (clair.length) avec('authentification.clair', 'eleve', { preuve: { ports: clair.map(p => p.port) }, titre: `Mot de passe en clair : ${listePorts(clair, PORTS_CLAIR)}`, correction: 'Remplacer par la version chiffrée (SSH au lieu de Telnet, SFTP au lieu de FTP, IMAPS/POP3S) et fermer l’ancien port.' });
    const vnc = ps.filter(p => p.port >= 5900 && p.port <= 5903);
    if (vnc.length) avec('authentification.vnc', 'eleve', { preuve: { ports: vnc.map(p => p.port) }, correction: 'VNC n’a qu’un mot de passe et chiffre rarement : le fermer au réseau et passer par un tunnel SSH, un VPN ou la console de NEXARC.' });
    if (ps.some(p => p.port === 3389)) avec('authentification.rdp', a.whitelisted || POSTES.has(t) || SERVEURS.has(t) ? 'faible' : 'eleve', { preuve: { ports: [3389] }, correction: 'Exiger l’authentification au niveau du réseau (NLA), limiter le port 3389 au VLAN d’administration, et ne jamais le publier sur Internet.' });
    if (ps.some(p => p.port === 22)) avec('authentification.ssh', 'info', { preuve: { ports: [22] }, correction: 'Vérifier : authentification par clé seule (PasswordAuthentication no), connexion root interdite, accès limité au VLAN d’administration.' });
    if (ps.some(p => p.port === 161)) avec('authentification.snmp', 'faible', { preuve: { ports: [161] }, correction: 'Passer en SNMPv3 (authentification et chiffrement) ou couper SNMP ; jamais de communauté « public ».' });
    if ((INFRA.has(t) || t === 'nas' || t === 'hypervisor' || a.isMainRouter) && ps.some(p => PORTS_WEB_CLAIR.includes(p.port)) && !ps.some(p => PORTS_WEB_TLS.includes(p.port))) {
      avec('authentification.admin-http', 'faible', { preuve: { ports: ps.filter(p => PORTS_WEB_CLAIR.includes(p.port)).map(p => p.port) }, correction: 'Activer HTTPS sur l’interface d’administration et couper l’accès en HTTP, ou la publier par Relay.' });
    }

    // Mises à jour
    const cves = a.cves || [];
    if (cves.length) {
      const pire = cves.reduce((x, c) => (Number(c.cvss) > Number(x.cvss) ? c : x), cves[0]);
      const s = Number(pire.cvss) || 0;
      const g = s >= 9 ? 'critique' : s >= 7 ? 'eleve' : s >= 4 ? 'faible' : 'info';
      avec('maj.cve', g, {
        preuve: { n: cves.length, pire: pire.cveId, cvss: s, cves: cves.slice(0, 10).map(c => ({ id: c.cveId, cvss: c.cvss, service: c.service })) },
        titre: `${cves.length} vulnérabilité${cves.length > 1 ? 's' : ''} connue${cves.length > 1 ? 's' : ''} (pire : ${pire.cveId}, CVSS ${s})`,
        correction: `Mettre à jour ${pire.service || 'le service concerné'} vers une version corrigée. En attendant, fermer le port s’il n’a pas besoin d’être joignable.`,
        action: { type: 'deep-scan', appareil: a.id },
      });
    }
    for (const p of ps) {
      const f = finDeVie(p.product, p.version);
      if (f) avec('maj.obsolete', f.gravite, { cle: String(p.port), preuve: { port: p.port, produit: p.product, version: p.version }, titre: f.texte, correction: `Mettre ${p.product} à jour vers une version maintenue.`, action: { type: 'deep-scan', appareil: a.id } });
    }
    const sf = systemeFinDeVie(a.os);
    if (sf) avec('maj.obsolete', sf.gravite, { cle: 'os', preuve: { os: a.os }, titre: sf.texte, correction: 'Migrer vers une version maintenue du système, ou isoler la machine dans un VLAN sans accès aux autres.' });

    // Chiffrement : un service web en clair sur une machine qui n'a aucun port chiffré.
    if (!INFRA.has(t) && t !== 'nas' && t !== 'hypervisor' && !a.isMainRouter && ps.some(p => PORTS_WEB_CLAIR.includes(p.port)) && !ps.some(p => PORTS_WEB_TLS.includes(p.port)) && (SERVEURS.has(t) || POSTES.has(t))) {
      avec('chiffrement.http', 'faible', { preuve: { ports: ps.filter(p => PORTS_WEB_CLAIR.includes(p.port)).map(p => p.port) }, correction: 'Servir ce service en HTTPS — le plus simple : une route Relay vers lui, et fermer le port en clair au reste du réseau.' });
    }

    for (const dom of ['surface', 'authentification', 'maj']) {
      if (!ici[dom]) avec(`${dom}.ok`, 'safe');
    }
    ctx.appareilsVus.set(a.id, ici);
  }
}

function surSegmentation(d, out) {
  const { appareils, vlans } = d.mapmylan;
  const n = appareils.length;
  if (vlans.length <= 1) {
    out.push(constat('segmentation.vlans', n >= 8 ? 'eleve' : 'faible', { titre: vlans.length ? 'Un seul VLAN : réseau à plat' : 'Aucun VLAN : réseau à plat', preuve: { vlans: vlans.length, appareils: n }, correction: 'Séparer au moins trois réseaux : postes, serveurs, objets connectés (et invités), avec des règles « tout refuser sauf » entre eux.' }));
    return;
  }
  out.push(constat('segmentation.vlans', 'safe', { titre: `${vlans.length} VLAN déclarés`, preuve: { vlans: vlans.length } }));
  const parVlan = new Map();
  for (const a of appareils) {
    if (!Number.isInteger(a.vlan)) continue;
    const l = parVlan.get(a.vlan) || []; l.push(a); parVlan.set(a.vlan, l);
  }
  for (const v of vlans) {
    const membres = parVlan.get(v.id) || [];
    const objets = membres.filter(a => OBJETS.has(typeDe(a))), sensibles = membres.filter(a => SERVEURS.has(typeDe(a)) || POSTES.has(typeDe(a)));
    const sujet = `VLAN ${v.id} · ${String(v.name || '').slice(0, 40)}`;
    if (objets.length && sensibles.length) {
      out.push(constat('segmentation.melange', objets.some(a => typeDe(a) === 'camera') ? 'eleve' : 'faible', { sujet, cle: `segmentation.melange:${v.id}`, titre: `${objets.length} objet${objets.length > 1 ? 's' : ''} connecté${objets.length > 1 ? 's' : ''} dans le ${sujet} avec ${sensibles.length} poste${sensibles.length > 1 ? 's' : ''} ou serveur${sensibles.length > 1 ? 's' : ''}`,
        preuve: { objets: objets.slice(0, 10).map(sujetDe), sensibles: sensibles.slice(0, 10).map(sujetDe) }, correction: 'Déplacer caméras, télévisions et objets dans un VLAN à eux, isolé, qui ne sort que vers Internet.' }));
    } else if (membres.length) {
      out.push(constat('segmentation.melange', 'safe', { sujet, cle: `segmentation.melange:${v.id}`, titre: `${sujet} : un seul usage`, preuve: { membres: membres.length } }));
    }
    if (/iot|invit|guest|cam|objet|domot/i.test(`${v.name} ${v.description || ''}`)) {
      out.push(constat('segmentation.isolement', v.isolated ? 'safe' : 'faible', { sujet, cle: `segmentation.isolement:${v.id}`, titre: v.isolated ? `${sujet} isolé` : `${sujet} non isolé`, preuve: { isole: !!v.isolated }, correction: v.isolated ? '' : 'Marquer ce VLAN isolé et appliquer sur le routeur une règle qui lui refuse l’accès aux autres réseaux internes.' }));
    }
  }
  const sans = appareils.filter(a => !Number.isInteger(a.vlan));
  if (sans.length) out.push(constat('segmentation.hors-vlan', 'info', { titre: `${sans.length} appareil${sans.length > 1 ? 's' : ''} sans VLAN connu`, preuve: { appareils: sans.slice(0, 20).map(sujetDe) }, correction: 'Relever les VLAN depuis l’équipement (MapMyLAN → VLAN → Relever) ou rattacher ces appareils à la main.' }));
  const isoles = appareils.filter(a => a.status === 'quarantined' || a.status === 'banned');
  if (isoles.length) out.push(constat('segmentation.quarantaine', 'info', { titre: `${isoles.length} appareil${isoles.length > 1 ? 's' : ''} en quarantaine ou banni${isoles.length > 1 ? 's' : ''}`, preuve: { appareils: isoles.slice(0, 20).map(sujetDe) } }));

  // Flux vus par MapMyLAN : un appareil d'un VLAN isolé qui parle à un autre réseau interne.
  if (Array.isArray(d.mapmylan.flux)) {
    const sousReseaux = vlans.filter(v => v.subnet).map(v => ({ v, b: plages([v.subnet]) }));
    const vlanDe = ip => (estIPv4(ip) ? sousReseaux.find(x => x.b.check(ip, 'ipv4'))?.v : null);
    const vus = new Map();
    for (const f of d.mapmylan.flux) {
      const s = vlanDe(f.src), t = vlanDe(f.dst);
      if (!s || !t || s.id === t.id || !s.isolated) continue;
      const k = `${s.id}>${t.id}`;
      const e = vus.get(k) || { s, t, n: 0, exemples: [] };
      e.n++; if (e.exemples.length < 5) e.exemples.push(`${f.src} → ${f.dst}:${f.port}`);
      vus.set(k, e);
    }
    for (const { s, t, n: nb, exemples } of vus.values()) {
      out.push(constat('segmentation.inter-vlan', 'eleve', { sujet: `VLAN ${s.id} → VLAN ${t.id}`, cle: `segmentation.inter-vlan:${s.id}:${t.id}`, titre: `Le VLAN isolé ${s.id} (${s.name}) parle au VLAN ${t.id} (${t.name})`, preuve: { flux: nb, exemples }, correction: 'Ajouter sur le routeur une règle qui refuse ce chemin, puis vérifier qui a ouvert ces connexions.' }));
    }
  }
}

function surReseau(d, ctx, out) {
  const m = d.mapmylan;
  // Alertes de connexions répétées des dernières 24 h.
  const recentes = m.alertes.filter(a => ctx.maintenant - Date.parse(a.createdAt || 0) < 24 * 3600e3);
  const tentatives = recentes.filter(a => /brute|tentative|connexion|login|ssh|auth/i.test(`${a.source} ${a.message}`));
  out.push(tentatives.length
    ? constat('authentification.tentatives', 'eleve', { titre: `${tentatives.length} alerte${tentatives.length > 1 ? 's' : ''} de connexion en 24 h`, preuve: { exemples: tentatives.slice(0, 5).map(a => String(a.message).slice(0, 160)) }, correction: 'Vérifier la source des tentatives, bannir l’appareil s’il n’est pas légitime, et limiter le service visé au VLAN d’administration.' })
    : constat('authentification.ok', 'safe', { cle: 'authentification.tentatives:global', titre: 'Aucune tentative de connexion répétée en 24 h' }));

  // Trafic sortant signalé suspect par MapMyLAN.
  if (Array.isArray(m.flux)) {
    const parSrc = new Map();
    for (const f of m.flux.filter(x => x.suspect)) { const l = parSrc.get(f.src) || []; l.push(f); parSrc.set(f.src, l); }
    for (const [src, l] of parSrc) {
      const a = m.appareils.find(x => x.ip === src);
      out.push(constat('surface.flux-suspect', 'eleve', { sujet: a ? sujetDe(a) : src, sujetId: a?.id ?? null, cle: `surface.flux-suspect:${src}`, titre: `${l.length} connexion${l.length > 1 ? 's' : ''} suspecte${l.length > 1 ? 's' : ''} depuis ${a ? nomAppareil(a) : src}`,
        preuve: { exemples: l.slice(0, 5).map(f => ({ dst: f.dst, port: f.port, nom: f.nom || f.domaine || null, raison: f.raison || null })) }, correction: 'Identifier le programme à l’origine (balayage approfondi, puis sur la machine) ; isoler l’appareil si la destination n’est pas légitime.', action: a ? { type: 'deep-scan', appareil: a.id } : null }));
    }
  }

  // Journaux : alertes non traitées, inventaire, collecte du trafic.
  const vieilles = m.alertes.filter(a => !a.acknowledged && /^(critical|high)$/.test(a.severity) && ctx.maintenant - Date.parse(a.createdAt || 0) > 24 * 3600e3);
  out.push(vieilles.length
    ? constat('journaux.alertes', vieilles.some(a => a.severity === 'critical') || vieilles.length > 10 ? 'eleve' : 'faible', { titre: `${vieilles.length} alerte${vieilles.length > 1 ? 's' : ''} grave${vieilles.length > 1 ? 's' : ''} non acquittée${vieilles.length > 1 ? 's' : ''} depuis plus de 24 h`, preuve: { exemples: vieilles.slice(0, 5).map(a => String(a.message).slice(0, 160)) }, correction: 'Traiter ces alertes dans MapMyLAN : corriger la cause, ou les acquitter avec la raison.' })
    : constat('journaux.alertes', 'safe', { titre: 'Aucune alerte grave en souffrance' }));
  const scan = m.dernierScan;
  const ageScan = scan?.endedAt ? ctx.maintenant - Date.parse(scan.endedAt) : null;
  out.push(!scan || scan.status === 'failed' || ageScan === null || ageScan > 24 * 3600e3
    ? constat('journaux.balayage', 'faible', { titre: !scan ? 'Aucun balayage du réseau enregistré' : scan.status === 'failed' ? 'Le dernier balayage a échoué' : 'Dernier balayage du réseau il y a plus de 24 h', preuve: { statut: scan?.status || null, fin: scan?.endedAt || null }, correction: 'Programmer un balayage au moins quotidien dans MapMyLAN (Réglages → Balayage).' })
    : constat('journaux.balayage', 'safe', { titre: 'Inventaire du réseau de moins de 24 h', preuve: { fin: scan.endedAt, trouves: scan.hostsFound } }));
  if (m.collecte) {
    const c = m.collecte;
    out.push(c.erreur || c.liaisonPerdue
      ? constat('journaux.trafic', 'faible', { titre: 'La collecte du trafic est en panne', preuve: { erreur: String(c.erreur || 'liaison perdue').slice(0, 160) }, correction: 'Vérifier l’équipement source de la collecte dans MapMyLAN (Trafic → état de la collecte).' })
      : c.cible ? constat('journaux.trafic', 'safe', { titre: 'Trafic collecté', preuve: { flux: c.total ?? null, retentionJours: c.retentionJours ?? null } })
        : constat('journaux.trafic', 'info', { titre: 'Aucune collecte du trafic', correction: 'Choisir dans MapMyLAN l’équipement dont lire les connexions : sans lui, ni trafic suspect ni flux entre VLAN ne sont vus.' }));
  } else {
    out.push(constat('journaux.trafic', 'info', { titre: 'Trafic illisible par VIGIE', correction: 'Mettre MapMyLAN à jour (2.1 ou plus) : le trafic s’ouvre alors au jeton de VIGIE.' }));
  }
}

function surParc(d, out) {
  for (const m of d.nexarc.machines) {
    const sujet = `${String(m.host || '?').slice(0, 60)}${m.ip ? ` (${m.ip})` : ''}`, base = { sujet, sujetId: null };
    const cle = r => `${r}:nxr:${m.id}`;
    let surf = 0, maj = 0, chif = 0;
    if (m.fw === 'inactif') { surf++; out.push(constat('surface.pare-feu', 'eleve', { ...base, cle: cle('surface.pare-feu'), correction: 'Réactiver le pare-feu du système (NEXARC → la machine → Pare-feu) ; n’ouvrir que les ports dont elle a besoin.' })); }
    if (['absent', 'inactif'].includes(m.av)) { surf++; out.push(constat('surface.antivirus', 'eleve', { ...base, cle: cle('surface.antivirus'), titre: `Antivirus ${m.av}`, correction: 'Réactiver la protection du système (Defender ou équivalent) et vérifier qu’elle se met à jour.' })); }
    if (m.enc === 'non chiffré') { chif++; out.push(constat('chiffrement.disque', 'faible', { ...base, cle: cle('chiffrement.disque'), correction: 'Activer le chiffrement du disque système (BitLocker, FileVault, LUKS) et garder la clé de secours hors de la machine.' })); }
    const enAttente = d.nexarc.alertes.find(a => a.etat === 'ouverte' && a.regle === 'correctifs' && a.machine?.id === m.id);
    if (enAttente) { maj++; out.push(constat('maj.correctifs', 'eleve', { ...base, cle: cle('maj.correctifs'), titre: String(enAttente.txt || 'Correctifs de sécurité en attente').slice(0, 200), correction: 'Appliquer les correctifs depuis NEXARC (Correctifs) ou sur la machine, puis redémarrer si demandé.' })); }
    else if (m.updates_n > 0) { maj++; out.push(constat('maj.correctifs', 'faible', { ...base, cle: cle('maj.correctifs'), titre: `${m.updates_n} mise${m.updates_n > 1 ? 's' : ''} à jour disponible${m.updates_n > 1 ? 's' : ''}`, correction: 'Planifier les mises à jour depuis NEXARC.' })); }
    const sf = systemeFinDeVie(m.os);
    if (sf) { maj++; out.push(constat('maj.obsolete', sf.gravite, { ...base, cle: cle('maj.obsolete'), titre: sf.texte, preuve: { os: m.os }, correction: 'Migrer vers une version maintenue du système.' })); }
    if (m.source === 'agent' && !m.online) out.push(constat('journaux.agents', 'faible', { ...base, cle: cle('journaux.agents'), preuve: { vu: m.seen ? m.seen * 1000 : null }, correction: 'Vérifier que la machine est allumée et que l’agent NEXARC tourne : une machine muette n’est plus surveillée.' }));
    if (!surf) out.push(constat('surface.ok', 'safe', { ...base, cle: cle('surface.ok') }));
    if (!maj) out.push(constat('maj.ok', 'safe', { ...base, cle: cle('maj.ok') }));
    if (!chif && m.enc && m.enc !== 'inconnu') out.push(constat('chiffrement.ok', 'safe', { ...base, cle: cle('chiffrement.ok'), titre: 'Disque chiffré' }));
  }
}

function surConteneurs(d, out) {
  for (const c of d.docker) {
    const sujet = `conteneur ${c.nom}`, base = { sujet };
    const cle = r => `${r}:ctr:${c.noeud ? c.noeud + '/' : ''}${c.nom}`;
    let surf = 0, maj = 0;
    if (c.privilegie || c.socketDocker) { surf++; out.push(constat('surface.conteneur', 'eleve', { ...base, cle: cle('surface.conteneur'), titre: c.privilegie ? `${c.nom} tourne en mode privilégié` : `${c.nom} a le socket Docker`, correction: 'Retirer --privileged et le montage de /var/run/docker.sock ; donner seulement les capacités nécessaires (cap_add) ou passer par un proxy de socket en lecture.' })); }
    else if (c.reseauHote) { surf++; out.push(constat('surface.conteneur', 'faible', { ...base, cle: cle('surface.conteneur'), titre: `${c.nom} partage le réseau de l’hôte`, correction: 'Le passer sur un réseau Docker et ne publier que ses ports utiles, sauf s’il doit voir le réseau (scanner).' })); }
    const bdd = c.ports.filter(p => p.public && PORTS_BDD[p.prive] && (!p.ip || p.ip === '0.0.0.0' || p.ip === '::'));
    if (bdd.length) { surf++; out.push(constat('surface.conteneur-bdd', 'eleve', { ...base, cle: cle('surface.conteneur-bdd'), titre: `${c.nom} publie ${bdd.map(p => `${PORTS_BDD[p.prive]} sur ${p.public}`).join(', ')}`, preuve: { ports: bdd }, correction: 'Ne pas publier le port de la base (retirer « ports: »), ou le lier à 127.0.0.1 ; les autres conteneurs la joignent par le réseau Docker.' })); }
    const tag = c.image.includes('@sha256:') ? 'digest' : (/:([^/:]+)$/.exec(c.image)?.[1] || 'latest');
    if (tag === 'latest') { maj++; out.push(constat('maj.image', 'faible', { ...base, cle: cle('maj.image'), titre: `${c.nom} : image « ${c.image.slice(0, 80)} » sans version`, correction: 'Épingler l’image sur une version précise (idéalement par empreinte sha256) pour savoir ce qui tourne et le mettre à jour volontairement.' })); }
    if (!surf) out.push(constat('surface.ok', 'safe', { ...base, cle: cle('surface.ok') }));
    if (!maj) out.push(constat('maj.ok', 'safe', { ...base, cle: cle('maj.ok'), titre: `Image épinglée (${tag === 'digest' ? 'empreinte' : tag})` }));
  }
}

function surTls(d, ctx, out) {
  for (const s of d.tls) {
    if (!s.joignable) continue;
    const sujet = `${s.nom} :${s.port}`, base = { sujet, sujetId: s.appareil };
    const cle = r => `${r}:tls:${s.ip}:${s.port}`;
    let n = 0;
    const c = s.cert;
    if (c?.fin) {
      const jours = Math.floor((c.fin - ctx.maintenant) / 86400e3);
      if (jours < 0) { n++; out.push(constat('chiffrement.expire', 'eleve', { ...base, cle: cle('chiffrement.expire'), titre: `Certificat expiré depuis ${-jours} jour${-jours > 1 ? 's' : ''}`, preuve: { fin: c.fin, sujet: c.sujet }, correction: 'Renouveler le certificat et automatiser son renouvellement (Relay ou certbot).' })); }
      else if (jours < 15) { n++; out.push(constat('chiffrement.expire', 'eleve', { ...base, cle: cle('chiffrement.expire'), titre: `Certificat expirant dans ${jours} jour${jours > 1 ? 's' : ''}`, preuve: { fin: c.fin }, correction: 'Renouveler maintenant et vérifier que le renouvellement automatique tourne.' })); }
      else if (jours < 30) { n++; out.push(constat('chiffrement.expire', 'faible', { ...base, cle: cle('chiffrement.expire'), titre: `Certificat expirant dans ${jours} jours`, preuve: { fin: c.fin }, correction: 'Vérifier que le renouvellement automatique est en place.' })); }
    }
    if (s.ancienAccepte) { n++; out.push(constat('chiffrement.ancien', 'eleve', { ...base, cle: cle('chiffrement.ancien'), titre: `${s.ancienAccepte} encore accepté`, preuve: { protocole: s.ancienAccepte }, correction: 'N’accepter que TLS 1.2 et 1.3 dans la configuration du service.' })); }
    if (c?.cle && c.cle < 2048) { n++; out.push(constat('chiffrement.cle', 'eleve', { ...base, cle: cle('chiffrement.cle'), titre: `Clé de ${c.cle} bits`, preuve: { bits: c.cle }, correction: 'Générer une clé RSA de 2048 bits au moins (ou ECDSA P-256) et un nouveau certificat.' })); }
    if (c?.autoSigne) out.push(constat('chiffrement.autosigne', 'info', { ...base, cle: cle('chiffrement.autosigne'), preuve: { sujet: c.sujet }, correction: 'Sur le réseau local, publier le service par Relay pour qu’il porte un certificat de l’autorité locale, installée une fois sur chaque poste.' }));
    if (!n) out.push(constat('chiffrement.ok', 'safe', { ...base, cle: cle('chiffrement.ok'), titre: `${s.protocole || 'TLS'}, certificat valide`, preuve: { protocole: s.protocole, fin: c?.fin || null } }));
  }
}

function surVigie(d, ctx, out) {
  out.push(ctx.synapse
    ? constat('journaux.centralisation', 'safe', { titre: 'Audits et interventions écrits dans SYNAPSE' })
    : constat('journaux.centralisation', 'faible', { titre: 'Aucune mémoire centrale des événements', correction: 'Installer SYNAPSE depuis le Hub : VIGIE y écrit chaque audit et chaque intervention, et le relit avant le suivant.' }));
  out.push(ctx.veille
    ? constat('journaux.veille', 'safe', { titre: `Veille toutes les ${ctx.veilleMinutes} min` })
    : constat('journaux.veille', 'faible', { titre: 'Veille continue coupée', correction: 'Rallumer la veille dans les réglages de VIGIE.' }));
  out.push(ctx.notifications
    ? constat('journaux.notifications', 'safe', { titre: 'Alertes transmises (billetterie ou Telegram)' })
    : constat('journaux.notifications', 'faible', { titre: 'Les alertes ne partent nulle part', correction: 'Relier une billetterie ou Telegram dans les réglages de VIGIE, ou un workflow du Hub sur « Intrusion détectée ».' }));
}

/**
 * Tous les constats d'une collecte. ctx : { maintenant, seuilIntrusion,
 * synapse, veille, veilleMinutes, notifications }.
 */
export function evaluer(d, ctx) {
  const out = [];
  const c = { seuilIntrusion: 85, ...ctx, appareilsVus: new Map() };
  if (d.mapmylan) { surAppareils(d, c, out); surSegmentation(d, out); surReseau(d, c, out); }
  if (d.nexarc) surParc(d, out);
  if (d.docker) surConteneurs(d, out);
  if (d.tls) surTls(d, c, out);
  surVigie(d, c, out);
  // Une même clé n'apparaît qu'une fois : la plus grave l'emporte.
  const parCle = new Map();
  for (const x of out) { const y = parCle.get(x.cle); if (!y || RANG[x.gravite] > RANG[y.gravite]) parCle.set(x.cle, x); }
  return [...parCle.values()];
}

/** Score par domaine (100 = rien à corriger) et global, distribution des gravités. */
export function noter(constats) {
  const distribution = Object.fromEntries(GRAVITES.map(g => [g, 0]));
  const domaines = {};
  for (const k of Object.keys(DOMAINES)) domaines[k] = { score: null, distribution: Object.fromEntries(GRAVITES.map(g => [g, 0])), n: 0 };
  const parRegle = new Map();
  for (const c of constats) {
    distribution[c.gravite]++;
    const d = domaines[c.domaine];
    d.distribution[c.gravite]++; d.n++;
    const l = parRegle.get(c.regle) || []; l.push(PENALITE[c.gravite]); parRegle.set(c.regle, l);
  }
  const retrait = Object.fromEntries(Object.keys(DOMAINES).map(k => [k, 0]));
  for (const [regle, l] of parRegle) {
    const pire = Math.max(...l);
    retrait[REGLES[regle].domaine] += Math.min(l.reduce((a, b) => a + b, 0), pire * 3);
  }
  let somme = 0, nb = 0, critique = false;
  for (const [k, d] of Object.entries(domaines)) {
    if (!d.n) continue;
    let s = Math.max(0, 100 - retrait[k]);
    if (d.distribution.critique) { s = Math.min(s, PLAFOND_CRITIQUE); critique = true; }
    d.score = Math.round(s);
    somme += d.score; nb++;
  }
  let score = nb ? Math.round(somme / nb) : null;
  if (score !== null && critique) score = Math.min(score, 49);
  return { score, domaines, distribution };
}

/** Les trois priorités : les constats les plus graves, une règle à la fois. */
export function priorites(constats, n = 3) {
  const vues = new Set(), out = [];
  for (const c of [...constats].sort((a, b) => RANG[b.gravite] - RANG[a.gravite])) {
    if (RANG[c.gravite] < RANG.faible || vues.has(c.regle)) continue;
    vues.add(c.regle); out.push(c);
    if (out.length === n) break;
  }
  return out;
}
