// Le bouclier : adresses, journaux, listes de menaces, corrélation, riposte,
// passerelle UniFi (TLS épinglé), récepteur syslog, et l'API de bout en bout.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import https from 'node:https';
import dgram from 'node:dgram';
import { execFileSync } from 'node:child_process';
import { Client } from '../socle/essai/client.js';
import { adminComplet } from '../socle/essai/inscription.js';
import { demarrer } from '../src/main.js';
import { ouvrirBase, Magasin } from '../src/base.js';
import { normaliser, plage, EnsembleIp, estPublique, estInterne } from '../src/bouclier/ip.js';
import { messageSyslog, lireCef, lireLigne, depuisEve } from '../src/bouclier/journaux.js';
import { lire, Menaces, FLUX } from '../src/bouclier/menaces.js';
import { Correlateur, semblableDga } from '../src/bouclier/correlation.js';
import { Riposte } from '../src/bouclier/riposte.js';
import { Cloudflare, NOM_LISTE } from '../src/bouclier/cloudflare.js';
import { Unifi, NOMS_LISTES } from '../src/bouclier/unifi.js';
import { observer, requete, empreinte } from '../src/bouclier/tls.js';
import { Recepteur } from '../src/bouclier/recepteur.js';
import { Bouclier } from '../src/bouclier/index.js';
import { depuisPasserelle } from '../src/bouclier/journaux.js';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'bouclier-'));
const silence = { info() {}, warn() {}, error() {} };
const attendre = ms => new Promise(r => setTimeout(r, ms));
// Adresses publiques prises pour l'essai : rien ne sort vers elles.
const ATTAQUANT = '45.155.205.10';
const C2 = '185.220.101.7';
const COFFRE = { scelle: (_k, v) => `s:${v}`, ouvre: (_k, s) => s.slice(2) };
let n = 0;
const magasinNeuf = () => { const db = ouvrirBase(path.join(tmp, `m${++n}`)); return { db, magasin: new Magasin(db, { coffre: COFFRE }) }; };

after(() => fs.rmSync(tmp, { recursive: true, force: true }));

// ---------- adresses ----------
test('adresses : forme unique, plages, ensembles fusionnés, public et interne', () => {
  assert.equal(normaliser('2001:0DB8:0:0:0:0:0:1'), '2001:db8::1');
  assert.equal(normaliser('[2606:4700:4700::1111]'), '2606:4700:4700::1111');
  assert.equal(normaliser('010.1.2.3'), null, 'zéros de tête refusés (lecture octale ambiguë)');
  assert.equal(normaliser('pas une ip'), null);
  assert.deepEqual(plage('192.0.2.77/24'), { v: 4, debut: 3221225984, fin: 3221226239 });
  assert.equal(plage('10.0.0.0/33'), null);
  assert.equal(plage('10.0.0.0/8x'), null);
  const e = new EnsembleIp();
  for (const x of ['198.51.100.0/25', '198.51.100.128/25', '2001:db8::/48', 'nimporte']) e.ajouter(x, 'l');
  e.figer();
  assert.equal(e.taille(), 2, 'deux moitiés contiguës fusionnées, la ligne illisible écartée');
  assert.ok(e.contient('198.51.100.200'));
  assert.ok(e.contient('2001:db8:0:ffff::1'));
  assert.ok(!e.contient('198.51.101.1'));
  assert.ok(estPublique(ATTAQUANT) && estPublique('2a01:4f8::1'));
  for (const x of ['10.1.2.3', '172.20.0.1', [192, 168, 1, 1].join('.'), '127.0.0.1', '100.64.0.1', '169.254.1.1', '192.0.2.1', 'fd00::1', 'fe80::1', '::1', '::ffff:10.0.0.1', '224.0.0.1'])
    assert.ok(!estPublique(x), x);
  assert.ok(estInterne('10.9.1.1') && estInterne('fd00::1') && !estInterne(ATTAQUANT));
});

// ---------- journaux ----------
test('journaux : syslog 3164 et 5424, CEF d’UniFi, pare-feu, EVE de Suricata', () => {
  assert.equal(messageSyslog('<134>Oct 13 10:00:00 udm kernel: [WAN_IN-D-2000] IN=eth8 SRC=1.2.3.4'), 'kernel: [WAN_IN-D-2000] IN=eth8 SRC=1.2.3.4');
  assert.equal(messageSyslog('<14>1 2026-10-13T10:00:00Z udm app - - - bonjour'), 'bonjour');
  assert.equal(messageSyslog('<14>1 2026-10-13T10:00:00Z udm app - - [x a="1"] bonjour'), 'bonjour');

  const cef = `<132>Oct 13 10:00:00 passerelle CEF:0|Ubiquiti|UniFi Network|9.4.19|544|Threat Detected and Blocked|7|src=${ATTAQUANT} spt=51111 dst=10.9.1.20 dpt=22 proto=TCP UNIFIcategory=Attempted Administrator Privilege Gain UNIFIipsSignature=ET SCAN Potential SSH Scan UNIFIipsSignatureId=2001219 UNIFIrisk=high msg=a\\=b`;
  const c = lireCef(messageSyslog(cef));
  assert.equal(c.entete.nom, 'Threat Detected and Blocked');
  assert.equal(c.ext.UNIFIipsSignature, 'ET SCAN Potential SSH Scan');
  assert.equal(c.ext.msg, 'a=b');
  const o = lireLigne(cef, 'syslog:udm', 1);
  assert.deepEqual([o.type, o.src, o.dst, o.dport, o.gravite, o.sid, o.action, o.proto], ['ips', ATTAQUANT, '10.9.1.20', 22, 1, 2001219, 'bloque', 'tcp']);
  assert.equal(lireCef('CEF:0|a|b|'), null, 'en-tête incomplet');
  const pot = lireLigne('<132>Oct 13 10:00:00 passerelle CEF:0|Ubiquiti|UniFi Network|9.4.19|600|Honeypot Triggered|5|UNIFIcategory=Security UNIFIsubCategory=Honeypot src=10.9.30.40 dst=10.9.30.2 dpt=23 msg=Honeypot accessed');
  assert.deepEqual([pot.type, pot.gravite, pot.categorie, pot.src], ['ips', 1, 'honeypot', '10.9.30.40'], 'pot de miel : alerte de gravité 1');
  assert.equal(lireLigne('<132>Oct 13 10:00:00 passerelle CEF:0|Ubiquiti|UniFi Network|9.4.19|101|Admin Accessed UniFi Network|1|UNIFIcategory=System src=10.9.1.10 msg=x').type, 'autre');

  const pf = lireLigne(`<4>Oct 13 10:00:01 udm kernel: [WAN_IN-D-2147483647] IN=eth8 OUT= MAC=aa SRC=${ATTAQUANT} DST=203.0.113.5 LEN=60 PROTO=TCP SPT=40000 DPT=3389 SYN`);
  assert.deepEqual([pf.type, pf.action, pf.src, pf.dport, pf.regle, pf.entree], ['pare-feu', 'bloque', ATTAQUANT, 3389, 'WAN_IN-D-2147483647', 'eth8']);
  assert.equal(lireLigne('<4>Oct 13 10:00:01 udm kernel: [LAN_IN-A-1] SRC=10.9.1.2 DST=10.9.1.3 PROTO=UDP SPT=1 DPT=53').action, 'accepte');
  assert.equal(lireLigne('<4>Oct 13 10:00:01 udm dnsmasq: query A exemple.fr'), null, 'une ligne qui ne dit rien');

  const t = '2026-10-13T10:00:00.000000+0000';
  const a = depuisEve({ timestamp: t, event_type: 'alert', src_ip: ATTAQUANT, src_port: 4444, dest_ip: '10.9.1.9', dest_port: 445, proto: 'TCP', alert: { action: 'allowed', severity: 2, signature: 'ET EXPLOIT SMB', signature_id: 2024218, category: 'Attempted Administrator Privilege Gain' } }, 'sonde:sonde-1');
  assert.deepEqual([a.type, a.gravite, a.sid, a.action, a.capteur], ['ips', 2, 2024218, 'alerte', 'sonde:sonde-1']);
  assert.equal(a.quand, Date.parse(t));
  assert.equal(depuisEve({ event_type: 'dns', src_ip: '10.9.1.9', dns: { type: 'query', rrname: 'Exemple.FR' } }).domaine, 'exemple.fr');
  assert.equal(depuisEve({ event_type: 'dns', dns: { type: 'answer', rrname: 'x.fr' } }), null, 'les réponses ne comptent pas');
  assert.equal(depuisEve({ event_type: 'tls', tls: { sni: 'c2.exemple.net' } }).type, 'tls');
  assert.equal(depuisEve({ event_type: 'flow', src_ip: '10.9.1.9', dest_ip: C2, dest_port: 443, flow: { state: 'new', bytes_toserver: 10, bytes_toclient: 5 } }).octets, 15);
  assert.equal(depuisEve({ event_type: 'stats' }), null);
  assert.equal(depuisEve('texte'), null);
  // EVE relayé par syslog.
  assert.equal(lireLigne(`<14>Oct 13 10:00:00 sonde-1 suricata: {"event_type":"alert","src_ip":"${ATTAQUANT}","dest_ip":"10.9.1.9","alert":{"severity":1,"signature":"x","signature_id":1}}`).gravite, 1);
});

// ---------- listes de menaces ----------
test('listes de menaces : formats, adresses non publiques écartées, cache sur disque, parents de domaine', async () => {
  const sp = lire(FLUX['spamhaus-drop'], `{"cidr":"45.155.205.0/24","sblid":"SBL1"}\n{"cidr":"10.0.0.0/8"}\n{"type":"metadata"}\npas du json`);
  assert.deepEqual(sp.ips, ['45.155.205.0/24']);
  assert.deepEqual(lire(FLUX.feodo, `# commentaire\n${C2}\n10.9.1.1\n\n`).ips, [C2]);
  assert.deepEqual(lire(FLUX.urlhaus, '# x\n127.0.0.1\tmal.exemple.com\n127.0.0.1 localhost\n0.0.0.0 *.Autre.Exemple.org.\n127.0.0.1 -mauvais-.x').domaines, ['mal.exemple.com', 'autre.exemple.org']);

  const { magasin } = magasinNeuf();
  const appels = [];
  const fetch = async url => {
    appels.push(url);
    if (url === FLUX.feodo.url) return new Response(`${C2}\n`);
    if (url === FLUX['spamhaus-drop'].url) return new Response('{"cidr":"45.155.205.0/24"}\n');
    if (url === FLUX.threatfox.url) return new Response('127.0.0.1 c2.exemple.net\n');
    // Une liste qui ne finit jamais : lue morceau par morceau, abandonnée à la taille permise.
    if (url === FLUX['cins-army'].url) {
      let n = 0;
      return new Response(new ReadableStream({ pull(c) { if (++n > 200) return c.close(); c.enqueue(new Uint8Array(1024 * 1024).fill(0x31)); } }));
    }
    return new Response('', { status: 503 });
  };
  const dossier = path.join(tmp, 'menaces');
  const m = new Menaces({ dossier, magasin, fetch, log: silence });
  const faits = await m.actualiser();
  assert.deepEqual(faits.sort(), ['feodo', 'spamhaus-drop', 'threatfox']);
  assert.ok(!appels.includes(FLUX['hagezi-tif'].url), 'une liste non active n’est pas téléchargée');
  assert.deepEqual(m.ipListee(C2).map(x => x.id), ['feodo']);
  assert.equal(m.ipListee(ATTAQUANT)[0].poids, 100);
  assert.deepEqual(m.ipListee('10.0.0.1'), []);
  assert.equal(m.domaineListe('www.c2.exemple.net.')[0].id, 'threatfox', 'un sous-domaine d’un domaine listé');
  assert.deepEqual(m.domaineListe('exemple.net'), [], 'le parent d’un domaine listé ne l’est pas');
  const pub = m.public();
  assert.equal(pub.find(x => x.id === 'urlhaus').erreur, 'HTTP 503');
  assert.match(pub.find(x => x.id === 'cins-army').erreur, /réponse de plus de 40960 Kio/);
  assert.equal(pub.find(x => x.id === 'feodo').entrees, 1);
  // Pas de nouveau téléchargement avant l'échéance ; relu depuis le disque au redémarrage.
  appels.length = 0;
  await m.actualiser();
  assert.ok(!appels.includes(FLUX.feodo.url));
  const m2 = new Menaces({ dossier, magasin, fetch: async () => { throw new Error('hors ligne'); }, log: silence });
  assert.equal(m2.ipListee(C2).length, 1, 'aveugle jamais : la dernière liste reste');
  // Une liste désactivée ne compte plus.
  magasin.poserReglage('bouclier', { listes: { feodo: false } });
  await m2.actualiser();
  assert.deepEqual(m2.ipListee(C2), []);
});

// ---------- corrélation ----------
function correlateur(reglage = {}, listees = {}) {
  let t = Date.parse('2026-10-13T10:00:00Z');
  const verdicts = [];
  const menaces = { ipListee: ip => listees[ip] || [], domaineListe: d => (d.endsWith('mal.exemple.com') ? [{ id: 'urlhaus', nom: 'URLhaus', poids: 100, sujet: 'x' }] : []) };
  const c = new Correlateur({ menaces, reglage: () => ({ seuil: 100, seuilInterne: 100, demiVieMinutes: 60, balayagePorts: 15, balayageCibles: 12, forceBrute: 20, ...reglage }), surVerdict: v => verdicts.push(v), maintenant: () => t });
  return { c, verdicts, avancer: ms => { t += ms; }, maintenant: () => t };
}
const ips = (src, dst, gravite, signature = 'ET x', extra = {}) => ({ type: 'ips', src, dst, dport: 22, gravite, signature, sid: 1, categorie: '', capteur: 'essai', ...extra });

test('corrélation : gravité 1 bloque, 2 et 3 s’additionnent puis s’effacent avec le temps', () => {
  const { c, verdicts, avancer } = correlateur();
  c.observer(ips(ATTAQUANT, '10.9.1.2', 1));
  assert.equal(verdicts.length, 1);
  assert.deepEqual([verdicts[0].ip, verdicts[0].interne, verdicts[0].score], [ATTAQUANT, false, 100]);
  c.observer(ips(ATTAQUANT, '10.9.1.2', 1));
  assert.equal(verdicts.length, 1, 'un verdict par épisode, pas un par paquet');

  const autre = '91.92.93.94';
  c.observer(ips(autre, '10.9.1.2', 2, 'a', { sid: 2 }));
  c.observer(ips(autre, '10.9.1.2', 2, 'b', { sid: 3 }));
  assert.equal(verdicts.length, 1, '80 points : sous le seuil');
  avancer(60 * 60e3);
  c.observer(ips(autre, '10.9.1.2', 3, 'c', { sid: 4 }));
  const s = c.menacesActuelles().find(x => x.ip === autre);
  assert.equal(s.score, 50, 'demi-vie d’une heure : 80 → 40, plus 10');
  assert.equal(s.raisons.length, 3);
  assert.equal(c.recentes.length, 5);
  assert.equal(c.compteurs.ips, 5);
});

test('corrélation : balayages, force brute, listes, serveur de commande, machine interne compromise, DGA', () => {
  const { c, verdicts } = correlateur({}, { [C2]: [{ id: 'feodo', nom: 'Feodo', poids: 100, sujet: 'botnet' }] });
  const pf = (src, dst, dport) => c.observer({ type: 'pare-feu', src, dst, dport, action: 'bloque', capteur: 'udm' });
  // Balayage vertical : 15 ports d'une cible (60) + 15 refus (2 chacun).
  const scan = '80.81.82.83';
  for (let p = 1000; p < 1015; p++) pf(scan, '203.0.113.5', p);
  const s = c.menacesActuelles().find(x => x.ip === scan);
  assert.equal(s.score, 90);
  assert.ok(s.raisons.some(r => /balayage de ports : 15/.test(r.texte)));
  assert.equal(verdicts.length, 0);
  // Force brute : 20 tentatives sur le port 22.
  const brute = '80.81.82.84';
  for (let i = 0; i < 20; i++) pf(brute, '203.0.113.5', 22);
  assert.ok(c.menacesActuelles().find(x => x.ip === brute).raisons.some(r => /force brute : 20 tentatives sur le port 22/.test(r.texte)));
  // Listée par Feodo et vue en entrée : bloquée sur-le-champ.
  pf(C2, '203.0.113.5', 443);
  assert.equal(verdicts.at(-1).ip, C2);
  // Une machine interne qui contacte le serveur de commande : suspecte.
  for (let i = 0; i < 3; i++) c.observer({ type: 'flux', src: '10.9.1.50', dst: C2, dport: 443, capteur: 'sonde' });
  const v = verdicts.find(x => x.ip === '10.9.1.50');
  assert.ok(v?.interne, 'trois contacts : 120 points');
  assert.match(v.raisons[0], /a contacté 185\.220\.101\.7:443, listée par Feodo/);
  // Alerte de compromission émise par une machine interne vers l'extérieur : la destination est un C2.
  c.observer(ips('10.9.1.60', '77.78.79.80', 3, 'ET MALWARE Cobalt Strike Beacon', { categorie: 'A Network Trojan was detected' }));
  assert.ok(verdicts.some(x => x.ip === '77.78.79.80' && !x.interne), 'la destination prend 100 points');
  assert.ok(c.menacesActuelles({ interne: true }).some(x => x.ip === '10.9.1.60' && x.score === 60));
  // Mouvement latéral : une machine qui balaie le réseau interne.
  for (let h = 1; h <= 12; h++) c.observer({ type: 'flux', src: '10.9.1.70', dst: `10.9.1.${100 + h}`, dport: 445, capteur: 'sonde' });
  assert.ok(c.menacesActuelles({ interne: true }).find(x => x.ip === '10.9.1.70').raisons.some(r => /balaie le réseau interne/.test(r.texte)));
  // Domaines : listé (requête DNS puis TLS), généré par algorithme.
  c.observer({ type: 'dns', src: '10.9.1.80', domaine: 'cdn.mal.exemple.com', capteur: 'sonde' });
  c.observer({ type: 'tls', src: '10.9.1.80', dst: '66.67.68.69', domaine: 'cdn.mal.exemple.com', capteur: 'sonde' });
  assert.ok(verdicts.some(x => x.ip === '66.67.68.69'), 'le serveur du domaine listé');
  assert.equal(c.menacesActuelles({ interne: true }).find(x => x.ip === '10.9.1.80').score, 90);
  assert.ok(semblableDga('xjw8qk2v9tzr4mhd.com'));
  assert.ok(!semblableDga('wikipedia.org') && !semblableDga('documentation.exemple.co.uk') && !semblableDga('xn--bcher-kva-something.de'));
  c.observer({ type: 'dns', src: '10.9.1.81', domaine: 'qzxkvbnmwrtplkjh.net', capteur: 'sonde' });
  assert.ok(c.menacesActuelles({ interne: true }).some(x => x.ip === '10.9.1.81' && x.score === 5));
});

// ---------- riposte ----------
function riposte(reglage = {}, unifi = null, cloudflare = null) {
  const { db, magasin } = magasinNeuf();
  magasin.poserReglage('bouclier', reglage);
  let t = Date.parse('2026-10-13T10:00:00Z');
  const signaux = [];
  const r = new Riposte({ db, magasin, signaler: async e => { signaux.push(e); return e; }, maintenant: () => t, log: silence, unifiFabrique: unifi || (() => null), ...(cloudflare ? { cloudflareFabrique: cloudflare } : {}) });
  return { r, magasin, signaux, avancer: ms => { t += ms; } };
}
const verdict = (ip, extra = {}) => ({ ip, interne: false, score: 120, raisons: ['IPS : ET x'], ...extra });

test('riposte : jamais le privé ni la liste blanche, récidive qui allonge, levée, expiration', async () => {
  const { r, signaux, avancer } = riposte({ listeBlanche: ['91.0.0.0/8'] });
  assert.match(r.refus('10.9.1.1'), /privée/);
  assert.match(r.refus('1.1.1.1'), /liste blanche/);
  assert.match(r.refus('104.16.1.1'), /liste blanche/, 'Cloudflare : les tunnels passent par là');
  assert.match(r.refus('91.92.93.94'), /liste blanche/);
  await assert.rejects(r.bloquer({ ip: '10.0.0.1', auteur: 'ana' }), e => e.status === 400);
  assert.equal(await r.verdict(verdict('8.8.8.8')), null);
  assert.equal(await r.verdict(verdict('10.9.1.5', { interne: true })), null, 'une machine du réseau n’est jamais bloquée ici');
  assert.equal(signaux.at(-1).type, 'bouclier.interne');

  const b1 = await r.verdict(verdict(ATTAQUANT));
  assert.deepEqual([b1.etat, b1.fin - b1.debut, b1.recidive, b1.automatique], ['actif', 60 * 60e3, 0, true]);
  assert.equal((await r.verdict(verdict(ATTAQUANT))).id, b1.id, 'déjà bloquée : le même blocage');
  assert.equal(r.texteListe().split('\n')[1], ATTAQUANT);
  const leve = await r.lever(b1.id, 'ana');
  assert.deepEqual([leve.etat, leve.leve_par], ['leve', 'ana']);
  await assert.rejects(r.lever(b1.id, 'ana'), e => e.status === 409);
  await assert.rejects(r.lever('inconnu00000', 'ana'), e => e.status === 404);
  const b2 = await r.verdict(verdict(ATTAQUANT));
  assert.deepEqual([b2.recidive, b2.fin - b2.debut], [1, 1440 * 60e3], 'récidive : un jour');
  avancer(1441 * 60e3);
  assert.equal(r.expirer(), 1);
  assert.equal(r.actifs().length, 0);
  const b3 = await r.verdict(verdict(ATTAQUANT));
  assert.equal(b3.fin - b3.debut, 10080 * 60e3, 'deuxième récidive : sept jours');
  const manuel = await r.bloquer({ ip: '2a01:4f8:0:0::5', auteur: 'ana', minutes: 30 });
  assert.deepEqual([manuel.ip, manuel.fin - manuel.debut, manuel.automatique], ['2a01:4f8::5', 30 * 60e3, false]);
  assert.match(r.texteListe(), /^# VIGIE : 2 adresses bloquées/);
});

test('bouclier : des journaux d’un émetteur non déclaré ne font rien bloquer ni isoler seul, une source authentifiée si', async () => {
  // Corrélation : la fiabilité suit les capteurs qui ont apporté les points.
  const { c, verdicts } = correlateur();
  c.observer(ips(ATTAQUANT, '10.9.1.2', 1, 'ET x', { verifie: false }));
  assert.equal(verdicts[0].fiable, false, 'syslog sans émetteur déclaré');
  c.observer(ips('91.92.93.95', '10.9.1.2', 1));
  assert.equal(verdicts[1].fiable, true, 'sonde ou relève de MapMyLAN');
  // Riposte : signalé, jamais bloqué seul.
  const a = riposte({ mode: 'actif' });
  assert.equal(await a.r.verdict(verdict(ATTAQUANT, { fiable: false })), null);
  assert.equal(a.r.blocages().length, 0);
  assert.equal(a.signaux[0].type, 'bouclier.signalee');
  assert.match(a.signaux[0].texte, /émetteur non déclaré/);
  assert.equal((await a.r.verdict(verdict(ATTAQUANT, { fiable: true }))).etat, 'actif');
  // Tempête faite de lignes non vérifiées : rien bloqué.
  const t = await a.r.tempete({ port: 22, sources: 60, parMinute: 900, paquets: 900, top: [{ ip: '80.2.2.2', n: 30 }], fiable: false });
  assert.deepEqual(t.bloquees, []);
  assert.match(a.signaux.at(-1).texte, /^Rien bloqué/);
});

test('riposte : observer, simulation, plafond horaire', async () => {
  const o = riposte({ mode: 'observer' });
  assert.equal(await o.r.verdict(verdict(ATTAQUANT)), null);
  assert.match(o.signaux[0].texte, /Mode observation/);
  assert.equal(o.signaux[0].gravite, 'faible', 'une menace de plus n’est pas une alerte');
  assert.equal(o.r.blocages().length, 0);

  const s = riposte({ mode: 'simulation' });
  const b = await s.r.verdict(verdict(ATTAQUANT));
  assert.equal(b.etat, 'simule');
  assert.equal(s.r.actifs().length, 0, 'rien ne part vers la passerelle');
  assert.match(s.signaux[0].titre, /^Aurait bloqué/);
  assert.equal(s.signaux[0].gravite, 'faible', 'un blocage automatique ne fait pas sonner Telegram');
  assert.equal((await s.r.bloquer({ ip: '80.1.1.1', auteur: 'ana' })).etat, 'actif', 'un blocage manuel reste réel');

  const p = riposte({ autoParHeure: 2 });
  for (const ip of ['80.1.1.1', '80.1.1.2', '80.1.1.3']) await p.r.verdict(verdict(ip));
  assert.equal(p.r.actifs().length, 2);
  assert.equal(p.signaux.at(-1).type, 'bouclier.plafond');
});

test('riposte : la passerelle reçoit la liste, une panne est signalée une fois puis retentée', async () => {
  const envois = [];
  let panne = false;
  const faux = { forme: 'chaines', async synchroniser(l) { if (panne) throw new Error('injoignable'); envois.push(l); return { 4: { id: 'l4', n: l.length }, 6: { id: 'l6', n: 0 } }; }, async regles() { return { entrant: true, sortant: true, regles: [] }; } };
  const { r, magasin, signaux } = riposte({ unifiHote: '10.9.1.1', maxUnifi: 2 }, () => faux);
  assert.equal(r.unifi(), null, 'sans clé, rien');
  magasin.poserSecret('bouclier', 'cleUnifi', 'cle-unifi-essai-0123456789');
  await r.bloquer({ ip: '80.1.1.1', auteur: 'ana' });
  await r.bloquer({ ip: '80.1.1.2', auteur: 'ana' });
  await r.bloquer({ ip: '80.1.1.3', auteur: 'ana' });
  const e = await r.synchroniser({ forcer: true });
  assert.equal(e.ok, true);
  assert.equal(envois.at(-1).length, 2, 'plafond de la passerelle');
  assert.equal(magasin.memoire('unifi_etat').envoyees, 2);
  panne = true;
  await r.synchroniser({ forcer: true });
  await r.synchroniser({ forcer: true });
  assert.equal(signaux.filter(x => x.type === 'bouclier.passerelle').length, 1);
  assert.equal(r.aSynchroniser, true);
  panne = false;
  assert.equal((await r.synchroniser()).ok, true);
});

// ---------- UniFi, TLS épinglé ----------
function certificat() {
  const d = path.join(tmp, 'cert');
  fs.mkdirSync(d, { recursive: true });
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-days', '2', '-subj', '/CN=unifi.essai', '-keyout', path.join(d, 'k.pem'), '-out', path.join(d, 'c.pem')], { stdio: 'ignore' });
  return { key: fs.readFileSync(path.join(d, 'k.pem')), cert: fs.readFileSync(path.join(d, 'c.pem')) };
}

test('UniFi : empreinte vérifiée avant toute requête, listes créées puis mises à jour, règles repérées', async () => {
  const CLE = 'cle-unifi-essai-0123456789';
  const vues = [];
  const listes = [];
  let refuseChaines = true;
  const srv = https.createServer(certificat(), (req, res) => {
    let corps = '';
    req.on('data', d => { corps += d; });
    req.on('end', () => {
      vues.push({ m: req.method, u: req.url, cle: req.headers['x-api-key'] });
      const j = (s, o) => { res.writeHead(s, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)); };
      if (req.headers['x-api-key'] !== CLE) return j(401, { message: 'non' });
      const base = '/proxy/network/integration/v1';
      if (req.url === `${base}/sites?limit=50`) return j(200, { data: [{ id: 'site1', internalReference: 'default' }] });
      if (req.url.startsWith(`${base}/sites/site1/traffic-matching-lists`)) {
        if (req.method === 'GET') return j(200, { data: listes });
        const b = JSON.parse(corps);
        if (refuseChaines && typeof b.items[0] === 'string') return j(400, { message: 'items: objet attendu' });
        if (req.method === 'POST') { const l = { id: `tml${listes.length + 1}`, ...b }; listes.push(l); return j(201, l); }
        const l = listes.find(x => req.url.endsWith(`/${x.id}`));
        Object.assign(l, b);
        return j(200, l);
      }
      if (req.url.startsWith(`${base}/sites/site1/firewall/policies`)) {
        return j(200, { data: [
          { id: 'p1', name: 'VIGIE entrée', enabled: true, action: { type: 'BLOCK' }, source: { zoneId: 'z', trafficFilter: { type: 'IP_ADDRESS', ipAddressFilter: { type: 'TRAFFIC_MATCHING_LIST', trafficMatchingListId: 'tml1' } } }, destination: { zoneId: 'y' } },
          { id: 'p2', name: 'autre', enabled: true, action: { type: 'ALLOW' }, source: {}, destination: {} },
        ] });
      }
      j(404, {});
    });
  });
  await new Promise(r => srv.listen(0, '127.0.0.1', r));
  const port = srv.address().port;
  try {
    const vu = await observer('127.0.0.1', port);
    assert.match(vu.fp, /^sha256:[0-9a-f]{64}$/);
    assert.equal(vu.sujet, 'unifi.essai');
    assert.equal(vues.length, 0, 'la sonde ne fait que lire le certificat');

    // Une autre empreinte : la connexion est coupée avant que la clé parte.
    const faux = 'sha256:' + 'ab'.repeat(32);
    await assert.rejects(requete({ hote: '127.0.0.1', port, fp: faux }, { chemin: '/proxy/network/integration/v1/sites?limit=50', entetes: { 'X-API-KEY': CLE } }), e => e.code === 'EEMPREINTE');
    await assert.rejects(new Unifi({ hote: '127.0.0.1', port, fp: faux, cle: CLE }).site(), e => e.code === 'EEMPREINTE');
    // Sans empreinte, un certificat autosigné est refusé par la vérification ordinaire.
    await assert.rejects(new Unifi({ hote: '127.0.0.1', port, fp: null, cle: CLE }).site());
    assert.equal(vues.length, 0, 'aucune requête n’a atteint la passerelle');
    assert.equal(empreinte(vu.fp.replace('sha256:', 'SHA256 ').toUpperCase()), vu.fp, 'empreinte collée dans une autre forme');

    await assert.rejects(new Unifi({ hote: '127.0.0.1', port, fp: vu.fp, cle: 'mauvaise-cle-0123456789' }).site(), e => e.status === 401);
    const u = new Unifi({ hote: '127.0.0.1', port, fp: vu.fp, cle: CLE });
    const l = await u.synchroniser([ATTAQUANT, '80.1.1.0/24', '2a01:4f8::5']);
    assert.equal(u.forme, 'objets', 'la forme refusée par la passerelle est abandonnée');
    assert.deepEqual(listes.map(x => [x.name, x.type, x.items.map(i => i.value)]), [
      [NOMS_LISTES[4], 'IPV4_ADDRESSES', [ATTAQUANT, '80.1.1.0/24']],
      [NOMS_LISTES[6], 'IPV6_ADDRESSES', ['2a01:4f8::5']],
    ]);
    assert.deepEqual(listes[0].items[1], { type: 'SUBNET', value: '80.1.1.0/24' });
    assert.deepEqual([l[4].id, l[6].id, l[4].n], ['tml1', 'tml2', 2]);
    await u.synchroniser([]);
    assert.deepEqual(listes[0].items, [{ type: 'IP_ADDRESS', value: '192.0.2.1' }], 'liste vide : une adresse de documentation');
    assert.equal(listes.length, 2, 'mises à jour, pas recréées');
    const rg = await u.regles(l);
    assert.deepEqual([rg.entrant, rg.sortant, rg.regles.map(x => x.nom)], [true, false, ['VIGIE entrée']]);
    assert.deepEqual((await u.essai()).listes.map(x => x.nom), [NOMS_LISTES[4], NOMS_LISTES[6]]);
    assert.ok(vues.every(v => v.cle === CLE || v.cle === 'mauvaise-cle-0123456789'));
  } finally { srv.close(); }
});

// ---------- récepteur syslog ----------
const portLibre = () => new Promise(r => { const s = net.createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });

test('récepteur : UDP et TCP (lignes et cadrage par longueur), émetteurs filtrés', async () => {
  const lues = [];
  let emetteurs = [];
  const port = await portLibre();
  const rc = await new Recepteur({ port, hote: '127.0.0.1', emetteurs: () => emetteurs, surObservation: o => lues.push(o), log: silence }).demarrer();
  try {
    const ligne = `<4>Oct 13 10:00:01 udm kernel: [WAN_IN-D-1] SRC=${ATTAQUANT} DST=203.0.113.5 PROTO=TCP SPT=1 DPT=22`;
    const u = dgram.createSocket('udp4');
    await new Promise(r => u.send(`${ligne}\n${ligne}\nbruit`, port, '127.0.0.1', r));
    for (let i = 0; i < 50 && lues.length < 2; i++) await attendre(10);
    assert.equal(lues.length, 2);
    assert.equal(lues[0].capteur, 'syslog:127.0.0.1');
    assert.equal(rc.stats.ignorees, 1);

    const s = net.connect(port, '127.0.0.1');
    await new Promise(r => s.once('connect', r));
    s.write(`${ligne}\n${Buffer.byteLength(ligne)} ${ligne}${Buffer.byteLength(ligne)} ${ligne}`);
    for (let i = 0; i < 50 && lues.length < 5; i++) await attendre(10);
    assert.equal(lues.length, 5);
    s.destroy();

    emetteurs = ['10.9.1.1'];
    await new Promise(r => u.send(ligne, port, '127.0.0.1', r));
    for (let i = 0; i < 50 && !rc.stats.refusees; i++) await attendre(10);
    assert.equal(rc.stats.refusees, 1, 'un émetteur non déclaré n’est pas lu');
    assert.equal(rc.stats.dernierRefus, '127.0.0.1');
    assert.equal(lues.length, 5);
    u.close();
  } finally { rc.arreter(); }
  // Un émetteur non déclaré qui inonde ne fait pas déborder la passerelle déclarée.
  const vues = [];
  const r2 = new Recepteur({ emetteurs: () => ['10.9.1.1'], surObservation: o => vues.push(o), log: silence, maintenant: () => 1000 });
  const l2 = `<4>Oct 13 10:00:01 udm kernel: [WAN_IN-D-1] SRC=${ATTAQUANT} DST=203.0.113.5 PROTO=TCP SPT=1 DPT=22`;
  for (let i = 0; i < 5000; i++) r2.ligne(l2, '10.9.1.66');
  r2.ligne(l2, '10.9.1.1');
  assert.deepEqual([vues.length, r2.stats.refusees, r2.stats.debordees], [1, 5000, 0]);
});

// ---------- la passerelle par MapMyLAN ----------
test('passerelle par MapMyLAN : reliée seule, liste confiée, alertes de l’IPS relevées sans doublon, syslog et clé directe prioritaires', async () => {
  const { db, magasin } = magasinNeuf();
  const appels = [];
  let passerelle = { reliee: true, nom: 'routeur', hote: '10.9.1.1', constructeur: 'unifi', libelle: 'Ubiquiti · UniFi', bouclier: true, ips: true };
  let panne = false, ancien = false;
  const alertes = [
    { id: 'e1', quand: Date.now() - 5000, src: ATTAQUANT, dst: '10.9.1.20', dport: 22, gravite: 1, signature: 'ET SCAN Potential SSH Scan', sid: 2001219, action: 'blocked' },
    { id: 'e2', quand: Date.now() - 4000, src: 'pas une ip', dst: null },
  ];
  const sources = {
    public: () => ({ mapmylan: { relie: true } }),
    appareilParIp: async () => null,
    mml: async (chemin, o = {}) => {
      appels.push([o.methode || 'GET', chemin, o.corps]);
      if (chemin === '/api/passerelle') { if (ancien) throw Object.assign(new Error('Route inconnue.'), { status: 404 }); return passerelle; }
      if (chemin.startsWith('/api/passerelle/ips?')) return alertes;
      if (chemin === '/api/passerelle/bouclier') {
        if (panne) throw Object.assign(new Error('Équipement injoignable : délai dépassé.'), { status: 502 });
        return { passerelle: 'routeur', groupes: { 4: { id: 'g4', nom: 'VIGIE bloquees IPv4', n: o.corps.ips.length }, 6: { id: 'g6', nom: 'VIGIE bloquees IPv6', n: 0 } }, regles: { entrant: true, sortant: false, regles: [{ nom: 'VIGIE entree', actif: true }] } };
      }
      throw Object.assign(new Error('inconnu'), { status: 404 });
    },
  };
  const signaux = [];
  const moteur = { signaler: async e => { signaux.push(e); return e; }, reagir: async () => null };
  const b = new Bouclier({ cfg: { donnees: path.join(tmp, 'passerelle'), syslogPort: 0 }, db, magasin, moteur, sources, fetch: async () => new Response('', { status: 404 }), log: silence });
  assert.equal(b.riposte.unifi(), null, 'rien avant d’avoir lu MapMyLAN');
  assert.equal(await b.releverIps(), 0);

  await b.lirePasserelle();
  assert.equal(b.riposte.unifi().forme, 'mapmylan', 'le routeur de MapMyLAN, sans rien régler');
  assert.equal(await b.releverIps(), 1, 'une alerte lisible sur deux');
  assert.match(appels.find(a => a[1].startsWith('/api/passerelle/ips?'))[1], /^\/api\/passerelle\/ips\?depuis=\d+&limite=1000$/);
  await attendre(20);
  const e = await b.riposte.synchroniser({ forcer: true });
  assert.deepEqual(appels.filter(a => a[0] === 'PUT').at(-1), ['PUT', '/api/passerelle/bouclier', { ips: [ATTAQUANT] }], 'l’attaquant vu par l’IPS est bloqué à la frontière');
  assert.deepEqual([e.ok, e.voie, e.passerelle, e.listes[4].nom, e.regles.sortant], [true, 'mapmylan', 'routeur', 'VIGIE bloquees IPv4', false]);
  const vue = b.etat();
  assert.deepEqual([vue.unifi.relie, vue.unifi.directe, vue.passerelle.reliee, vue.passerelle.releve.lues, vue.passerelle.releve.active], [true, false, true, 1, true]);
  assert.equal(vue.alertes[0].capteur, 'passerelle:routeur');

  // La même alerte relue : pas comptée deux fois.
  const score = b.correlateur.menacesActuelles()[0].score;
  assert.equal(await b.releverIps(), 0);
  assert.equal(b.correlateur.menacesActuelles()[0].score, score);
  // Des journaux syslog arrivent : la relève se tait.
  const avant = appels.length;
  b.derniereIpsSyslog = Date.now();
  assert.equal(await b.releverIps(), 0);
  assert.equal(appels.length, avant, 'aucune relève pendant que syslog parle');
  assert.equal(b.etat().passerelle.releve.active, false);

  // MapMyLAN en panne : dit une fois, nommé.
  panne = true;
  const ko = await b.riposte.synchroniser({ forcer: true });
  assert.match(ko.erreur, /^MapMyLAN : Équipement injoignable/);
  assert.equal(signaux.filter(x => x.type === 'bouclier.passerelle').length, 1);
  panne = false;

  // Une clé d'API posée dans VIGIE passe avant MapMyLAN.
  magasin.poserReglage('bouclier', { unifiHote: '10.9.1.1', unifiFp: 'sha256:' + 'ab'.repeat(32) });
  magasin.poserSecret('bouclier', 'cleUnifi', 'cle-unifi-essai-0123456789');
  assert.notEqual(b.riposte.unifi().forme, 'mapmylan');
  magasin.poserSecret('bouclier', 'cleUnifi', null);
  assert.equal(b.riposte.unifi().forme, 'mapmylan');

  // Un routeur qui ne sait pas tenir de liste, puis un MapMyLAN trop ancien.
  passerelle = { ...passerelle, constructeur: 'routeros', bouclier: false, ips: false };
  await b.lirePasserelle();
  assert.equal(b.riposte.unifi(), null);
  ancien = true;
  await b.lirePasserelle();
  assert.deepEqual([b.passerelle.reliee, b.passerelle.ancien], [false, true]);
  b.arreter();
});

test('alerte de l’IPS relue par MapMyLAN : même forme qu’une alerte syslog', () => {
  const o = depuisPasserelle({ quand: 1, src: ATTAQUANT, dst: '10.9.1.20', dport: 22, proto: 'TCP', gravite: 4, signature: 'x', sid: 7, categorie: 'Misc', action: 'blocked' }, 'passerelle:r');
  assert.deepEqual([o.type, o.gravite, o.action, o.proto, o.sid, o.capteur], ['ips', 3, 'bloque', 'tcp', 7, 'passerelle:r']);
  assert.equal(depuisPasserelle({ src: 'x', dst: 'y' }), null);
  assert.equal(depuisPasserelle(null), null);
});

// ---------- l'API, de bout en bout ----------
let vigie, admin;
const JETON_HUB = 'jeton-du-hub-pour-le-bouclier-0123456789';
const INSTALL = 'jeton-d-installation-du-bouclier';
const avec = (jeton, methode, chemin, corps) => new Client(vigie.port).req(methode, chemin, corps, { entetes: { authorization: `Bearer ${jeton}` }, origine: null });

before(async () => {
  process.umask(0o077);
  const fetchMenaces = async url => (url === FLUX.feodo.url ? new Response(`${C2}\n`) : new Response('', { status: 404 }));
  vigie = await demarrer({ DATA_DIR: path.join(tmp, 'api'), PORT: '0', HOTE: '127.0.0.1', VIGIE_HUB_TOKEN: JETON_HUB, SOCLE_JETON_INSTALLATION: INSTALL, VIGIE_SYSLOG_PORT: '0', VIGIE_SYSLOG_PORT_HOTE: '5514' }, { log: silence, fetchMenaces });
  admin = new Client(vigie.port);
  await adminComplet(admin, { jeton: INSTALL });
});
after(async () => { await vigie?.arreter(); });

test('API : une sonde envoie ses alertes, l’attaquant est bloqué, levé, exporté', async () => {
  // Jeton de sonde : session d'administrateur seulement.
  assert.equal((await avec(JETON_HUB, 'POST', '/api/bouclier/sondes', { nom: 'sonde-1' })).status, 403);
  const s = await admin.post('/api/bouclier/sondes', { nom: 'sonde-1' });
  assert.equal(s.status, 200, JSON.stringify(s.json));
  assert.match(s.json.jeton, /^vgs_/);
  assert.ok(!JSON.stringify(vigie.magasin.reglage('bouclier')).includes(s.json.jeton), 'seule l’empreinte est gardée');

  const eve = (jeton, evenements) => avec(jeton, 'POST', '/api/sonde/eve', { evenements });
  assert.equal((await eve('vgs_' + 'x'.repeat(44), [])).status, 401);
  assert.equal((await eve(JETON_HUB, [])).status, 401, 'le jeton du Hub n’est pas un jeton de sonde');
  assert.equal((await eve(s.json.jeton, [JSON.parse('{"event_type":"alert","x":{"__proto__":{"pollue":1}}}')])).status, 400, 'clés interdites');
  const alerte = { timestamp: new Date().toISOString(), event_type: 'alert', src_ip: ATTAQUANT, dest_ip: '10.9.1.9', dest_port: 22, proto: 'TCP', alert: { severity: 1, signature: 'ET SCAN SSH', signature_id: 2001219, category: 'Attempted' } };
  const r = await eve(s.json.jeton, [alerte, JSON.stringify({ event_type: 'dns', src_ip: '10.9.1.9', dns: { type: 'query', rrname: 'exemple.fr' } }), 'pas du json', { event_type: 'stats' }]);
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal(r.json.lues, 2);
  let b;
  for (let i = 0; i < 50; i++) { b = (await admin.get('/api/bouclier')).json; if (b.blocages.length) break; await attendre(10); }
  assert.equal(b.blocages[0].ip, ATTAQUANT);
  assert.equal(b.blocages[0].etat, 'actif');
  assert.equal(b.sondes[0].nom, 'sonde-1');
  assert.equal(b.sondes[0].lues, 2);
  assert.equal(b.syslog.port, 5514, 'le port publié sur l’hôte');
  assert.equal(b.alertes[0].signature, 'ET SCAN SSH');
  assert.equal(b.mode, 'actif');
  const rg = (await admin.get('/api/reglages')).json.bouclier;
  assert.deepEqual(rg.sondes.map(x => Object.keys(x).sort()), [['cree', 'nom']], 'réglages : ni empreinte ni jeton de sonde');
  assert.equal(rg.cleUnifi, false);
  assert.ok(rg.listeBlancheDefaut.includes('1.1.1.1'));
  assert.ok(!('cleUnifi' in b.unifi) && !JSON.stringify(b).includes('empreinte'), 'ni secret ni empreinte de jeton dans la vue');
  assert.equal((await avec(JETON_HUB, 'GET', '/api/bouclier')).status, 200);

  // Blocage manuel : jamais une adresse privée.
  const priv = await admin.post('/api/bouclier/bloquer', { ip: '10.9.1.9' });
  assert.equal(priv.status, 400);
  assert.match(priv.json.erreur || priv.texte, /privée/);
  const m = await avec(JETON_HUB, 'POST', '/api/bouclier/bloquer', { ip: '2a01:4f8::7', minutes: 30, motif: 'vu par le Hub' });
  assert.equal(m.status, 200, JSON.stringify(m.json));
  assert.equal(m.json.auteur, 'hub');

  // Levée.
  const l = await admin.post(`/api/bouclier/blocages/${b.blocages[0].id}/lever`, {});
  assert.equal(l.status, 200);
  assert.equal(l.json.etat, 'leve');

  // Liste exportée pour un pare-feu qui lit une URL.
  assert.equal((await new Client(vigie.port).get('/api/bouclier/liste.txt')).status, 401);
  const j = await admin.post('/api/bouclier/jeton-liste', {});
  assert.match(j.json.jeton, /^vgl_/);
  const t = await new Client(vigie.port).get(j.json.chemin);
  assert.equal(t.status, 200);
  assert.match(t.entetes['content-type'], /^text\/plain/);
  assert.deepEqual(t.texte.trim().split('\n').slice(1), ['2a01:4f8::7']);
  assert.equal((await new Client(vigie.port).get('/api/bouclier/liste.txt?jeton=vgl_faux')).status, 401);
  assert.equal((await avec(JETON_HUB, 'GET', '/api/bouclier/liste.txt')).status, 200);

  // Sonde retirée : son jeton ne vaut plus rien.
  assert.equal((await admin.post('/api/bouclier/sondes/retirer', { nom: 'sonde-1' })).status, 200);
  assert.equal((await eve(s.json.jeton, [alerte])).status, 401);
});

test('API : réglages du bouclier validés, listes actualisées, passerelle déclarée', async () => {
  const ok = await admin.put('/api/reglages/bouclier', { mode: 'simulation', seuil: 150, listeBlanche: ['91.0.0.0/8', '2a01:4f8::/32'], emetteurs: ['10.9.1.1'], listes: { 'cins-army': false } });
  assert.equal(ok.status, 200, JSON.stringify(ok.json));
  assert.equal(ok.json.mode, 'simulation');
  for (const mauvais of [{ mode: 'riposte' }, { seuil: 5 }, { listeBlanche: ['pas une plage'] }, { listes: { feodo: 'oui' } }, { listesPropres: [{ nom: 'x', type: 'ip', url: 'http://non-chiffre.exemple' }] }, { inconnu: 1 }])
    assert.equal((await admin.put('/api/reglages/bouclier', mauvais)).status, 400, JSON.stringify(mauvais));
  assert.equal((await avec(JETON_HUB, 'PUT', '/api/reglages/bouclier', { mode: 'observer' })).status, 403);

  const a = await admin.post('/api/bouclier/listes/actualiser', {});
  assert.equal(a.status, 200);
  assert.ok(a.json.faits.includes('feodo'));
  assert.equal(a.json.listes.find(x => x.id === 'cins-army').active, false);
  assert.equal(vigie.bouclier.menaces.ipListee(C2)[0].id, 'feodo');

  assert.equal((await admin.put('/api/bouclier/unifi', { hote: '127.0.0.1', fp: 'pas une empreinte' })).status, 400);
  const u = await admin.put('/api/bouclier/unifi', { hote: '127.0.0.1', port: 1, fp: 'sha256:' + 'cd'.repeat(32), cle: 'cle-unifi-essai-0123456789' });
  assert.equal(u.status, 200, JSON.stringify(u.json));
  assert.equal(u.json.unifi.relie, true);
  assert.equal(u.json.unifi.ok, false, 'injoignable : dit, pas caché');
  assert.equal(vigie.magasin.secret('bouclier', 'cleUnifi'), 'cle-unifi-essai-0123456789');
  assert.ok(!JSON.stringify(vigie.magasin.reglage('bouclier')).includes('cle-unifi-essai'), 'clé scellée en base');
  const x = await admin.put('/api/bouclier/unifi', { retirer: true });
  assert.equal(x.json.unifi.relie, false);
  assert.equal(vigie.magasin.secret('bouclier', 'cleUnifi'), '');
  const sd = await admin.post('/api/bouclier/unifi/sonde', { hote: '127.0.0.1', port: 1 });
  assert.equal(sd.status, 502);
  assert.match(JSON.stringify(sd.json), /Passerelle injoignable/);
});


// ---------- Cloudflare et la tempête ----------
/** Un faux Cloudflare : l'API v4 telle que VIGIE l'appelle, et ce qu'elle retient. */
function fauxCloudflare() {
  const etat = { listes: [], items: null, regles: {}, niveau: { zone1: 'medium' }, appels: [] };
  const rep = (result) => new Response(JSON.stringify({ success: true, result, errors: [] }), { status: 200, headers: { 'content-type': 'application/json' } });
  const fetch = async (url, o = {}) => {
    const u = new URL(url); const p = u.pathname.replace('/client/v4', ''); const m = o.method || 'GET';
    etat.appels.push(`${m} ${p}`);
    if (o.headers.authorization !== 'Bearer jeton-cloudflare-de-test-0123456789') return new Response(JSON.stringify({ success: false, errors: [{ code: 10000, message: 'Authentication error' }] }), { status: 401 });
    if (p === '/user/tokens/verify') return rep({ status: 'active' });
    if (p === '/zones') return rep([{ id: 'zone1', name: 'exemple.fr', account: { id: 'compte1' }, plan: { legacy_id: 'free' } }]);
    if (p === '/accounts') return rep([{ id: 'compte1' }]);
    if (p === '/accounts/compte1/rules/lists' && m === 'GET') return rep(etat.listes);
    if (p === '/accounts/compte1/rules/lists' && m === 'POST') { const l = { id: 'liste1', name: JSON.parse(o.body).name }; etat.listes.push(l); return rep(l); }
    if (p === '/accounts/compte1/rules/lists/liste1/items' && m === 'PUT') { etat.items = JSON.parse(o.body); return rep({ operation_id: 'op1' }); }
    if (p === '/zones/zone1/rulesets/phases/http_request_firewall_custom/entrypoint' && m === 'GET') return etat.regles.zone1 ? rep({ id: 'rs1', rules: etat.regles.zone1 }) : new Response(JSON.stringify({ success: false, errors: [{ code: 10000, message: 'not found' }] }), { status: 404 });
    if (p === '/zones/zone1/rulesets/phases/http_request_firewall_custom/entrypoint' && m === 'PUT') { etat.regles.zone1 = JSON.parse(o.body).rules; return rep({ id: 'rs1' }); }
    if (p === '/zones/zone1/settings/security_level' && m === 'GET') return rep({ value: etat.niveau.zone1 });
    if (p === '/zones/zone1/settings/security_level' && m === 'PATCH') { etat.niveau.zone1 = JSON.parse(o.body).value; return rep({ value: etat.niveau.zone1 }); }
    return new Response(JSON.stringify({ success: false, errors: [{ code: 1, message: `inattendu ${m} ${p}` }] }), { status: 400 });
  };
  return { etat, fabrique: o => new Cloudflare({ ...o, fetch }) };
}

test('cloudflare : jeton sondé, liste créée et remplie (IPv6 en /64), règle posée une fois par zone, mode Under Attack rendu après le délai', async () => {
  const cf = fauxCloudflare();
  const { r, magasin, signaux, avancer } = riposte({ cloudflareZones: [{ id: 'zone1', nom: 'exemple.fr' }] }, null, cf.fabrique);
  assert.equal(r.cloudflare(), null, 'sans jeton, rien');
  magasin.poserSecret('bouclier', 'cloudflareJeton', 'jeton-cloudflare-de-test-0123456789');
  const s = await r.cloudflare().sonder();
  assert.equal(s.compte, 'compte1'); assert.equal(s.zones[0].nom, 'exemple.fr');
  await r.bloquer({ ip: ATTAQUANT, auteur: 'ana' });
  await r.bloquer({ ip: '2a02:1234:5:6:7:8:9:a', auteur: 'ana' });
  const e = await r.synchroniserCloudflare({ forcer: true });
  assert.equal(e.ok, true, e.erreur); assert.equal(e.envoyees, 2);
  assert.deepEqual(cf.etat.items.map(x => x.ip), [ATTAQUANT, '2a02:1234:5:6::/64']);
  assert.equal(cf.etat.listes[0].name, NOM_LISTE); assert.equal(magasin.reglage('bouclier').cloudflareListe, 'liste1');
  assert.equal(cf.etat.regles.zone1[0].expression, `(ip.src in $${NOM_LISTE})`);
  assert.deepEqual(e.zones, [{ id: 'zone1', nom: 'exemple.fr', regle: true, erreur: null }]);
  // Une deuxième synchronisation sans changement ne rappelle pas Cloudflare ; la règle n'est pas doublée.
  const n = cf.etat.appels.length;
  await r.synchroniserCloudflare();
  assert.equal(cf.etat.appels.length, n);
  await r.synchroniserCloudflare({ forcer: true });
  assert.equal(cf.etat.regles.zone1.length, 1);
  // Mode Under Attack, à la main, puis levé par le temps : l'ancien niveau revient.
  await r.modeAttaque(true, { minutes: 15, auteur: 'ana' });
  assert.equal(cf.etat.niveau.zone1, 'under_attack');
  avancer(10 * 60e3); await r.expirerAttaque(); assert.equal(cf.etat.niveau.zone1, 'under_attack', 'pas encore');
  avancer(6 * 60e3); await r.expirerAttaque(); assert.equal(cf.etat.niveau.zone1, 'medium', 'rendu');
  assert.equal(r.etatCloudflare.attaque, null);
  // Un jeton qui tombe : une alerte, une seule.
  magasin.poserSecret('bouclier', 'cloudflareJeton', 'jeton-faux-mais-assez-long-0123456789');
  await r.bloquer({ ip: '185.220.101.9', auteur: 'ana' });
  await r.synchroniserCloudflare({ forcer: true }); await r.synchroniserCloudflare({ forcer: true });
  assert.equal(signaux.filter(x => x.type === 'bouclier.cloudflare').length, 1);
  assert.equal(r.etatCloudflare.ok, false); assert.match(r.etatCloudflare.erreur, /Authentication/);
});

test('tempête : des dizaines de sources sur un même port en une minute → événement critique, les plus bruyantes bloquées hors plafond, Cloudflare en mode Under Attack', async () => {
  const cf = fauxCloudflare();
  const { r, magasin, signaux, avancer } = riposte({ autoParHeure: 3, tempeteSources: 30, tempeteLignes: 300, tempeteBlocages: 10, cloudflareModeAttaque: true, cloudflareZones: [{ id: 'zone1', nom: 'exemple.fr' }] }, null, cf.fabrique);
  magasin.poserSecret('bouclier', 'cloudflareJeton', 'jeton-cloudflare-de-test-0123456789');
  const tempetes = [];
  let t = Date.parse('2026-10-13T10:00:00Z');
  const c = new Correlateur({ menaces: null, reglage: () => magasin.reglage('bouclier'), maintenant: () => t, surVerdict: () => {}, surTempete: tp => tempetes.push(tp) });
  // Quarante adresses, dix paquets chacune sur le 443 en trente secondes : tempête.
  for (let i = 0; i < 40; i++) for (let k = 0; k < 10; k++) { c.observer({ type: 'pare-feu', quand: t, src: `45.155.205.${i + 1}`, dst: '10.9.1.2', dport: 443, action: 'bloque', capteur: 'x' }); t += 75; }
  assert.equal(tempetes.length, 1);
  // Signalée dès que les seuils sont franchis (trente sources, trois cents lignes), pas à la fin de la salve.
  assert.equal(tempetes[0].port, 443); assert.ok(tempetes[0].sources >= 30 && tempetes[0].paquets >= 300, JSON.stringify(tempetes[0]));
  assert.equal(tempetes[0].top.length, tempetes[0].sources);
  // Une deuxième salve dans les dix minutes : pas de deuxième signalement.
  for (let i = 0; i < 40; i++) for (let k = 0; k < 10; k++) { c.observer({ type: 'pare-feu', quand: t, src: `45.155.205.${i + 1}`, dst: '10.9.1.2', dport: 443, action: 'bloque', capteur: 'x' }); t += 75; }
  assert.equal(tempetes.length, 1);
  // La riposte : dix blocages malgré le plafond de trois par heure, l'événement, le mode Under Attack.
  const out = await r.tempete(tempetes[0]);
  assert.equal(out.bloquees.length, 10);
  assert.equal(r.actifs().length, 10);
  assert.equal(cf.etat.niveau.zone1, 'under_attack');
  const ev = signaux.find(x => x.type === 'bouclier.tempete');
  assert.ok(ev && ev.gravite === 'critique' && /port 443/.test(ev.titre) && /10 adresses/.test(ev.texte) && /Under Attack/.test(ev.texte), JSON.stringify(ev));
  avancer(16 * 60e3); await r.expirerAttaque(); assert.equal(cf.etat.niveau.zone1, 'medium');
});
