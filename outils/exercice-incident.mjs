// Exercice du runbook d'incident (SECURITY.md, « Incident runbook ») sur une
// instance lancée comme en production, reliée à de faux voisins : chaque geste
// de confinement et de reprise est joué par son vrai chemin, et son effet
// vérifié. Dure une vingtaine de secondes.
//   node outils/exercice-incident.mjs
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
const RACINE = path.resolve(import.meta.dirname, '..');
const { Client, connexion } = await import(`${RACINE}/socle/essai/client.js`);
const { adminComplet, membreInvite, MDP_ESSAI } = await import(`${RACINE}/socle/essai/inscription.js`);
const { fauxServices, JETON_TG } = await import(`${RACINE}/test/faux.js`);

const D = fs.mkdtempSync(path.join(os.tmpdir(), 'exercice-incident-')), DONNEES = path.join(D, 'data');
const PORT = 19000 + crypto.randomInt(1000), JETON = crypto.randomBytes(24).toString('base64url');
const SOCLE_CLE = crypto.randomBytes(32).toString('base64');
const faux = fauxServices();
await new Promise(r => faux.serveur.listen(0, '127.0.0.1', r));
const EXT = `http://127.0.0.1:${faux.serveur.address().port}`;
const rapport = [];
let proc, sortie = '';
const fin = async code => { try { proc?.kill('SIGKILL'); } catch { /* déjà arrêté */ } faux.serveur.close(); fs.rmSync(D, { recursive: true, force: true }); process.exit(code); };
const note = async (ok, quoi) => { rapport.push(`${ok ? 'OK ' : 'ÉCHEC'} ${quoi}`); if (!ok) { console.log(rapport.join('\n')); console.log(sortie.slice(-2000)); await fin(1); } };
const cli = (args, entree) => spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', 'src/cli.js', ...args], { cwd: RACINE, env: { PATH: process.env.PATH, DATA_DIR: DONNEES, VIGIE_HUB_TOKEN: 'x'.repeat(32) }, input: entree });

async function demarrer(env) {
  sortie = '';
  proc = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', 'src/main.js'], { cwd: RACINE, env: {
    PATH: process.env.PATH, PORT: String(PORT), HOTE: '127.0.0.1', DATA_DIR: DONNEES, SOCLE_CLE, SOCLE_JETON_INSTALLATION: JETON, VIGIE_SYSLOG_PORT: '0',
    MAPMYLAN_URL: `${EXT}/mml`, MAPMYLAN_JETON: faux.jetons.mml, VIGIE_TELEGRAM_API: `${EXT}/tg`, ...env,
  } });
  proc.stdout.on('data', d => { sortie += d; }); proc.stderr.on('data', d => { sortie += d; });
  for (let i = 0; i < 100; i++) {
    if ((await fetch(`http://127.0.0.1:${PORT}/api/health`).then(x => x.status, () => 0)) === 200) return true;
    await new Promise(r => setTimeout(r, 200));
  }
  return false;
}
const arreter = () => new Promise(r => { proc.on('exit', r); proc.kill('SIGTERM'); });
const hub = jeton => ({ entetes: { authorization: `Bearer ${jeton}` }, origine: null });

const HUB1 = crypto.randomBytes(24).toString('base64url'), HUB2 = crypto.randomBytes(24).toString('base64url');
await note(await demarrer({ VIGIE_HUB_TOKEN: HUB1 }), 'démarrage : jeton du Hub n° 1');
const admin = new Client(PORT);
const { auth } = await adminComplet(admin, { jeton: JETON });
const { client: membre } = await membreInvite(admin, () => new Client(PORT), { identifiant: 'bruno' });
await note((await admin.put('/api/reglages/telegram', { jeton: JETON_TG, chat: '-100123', seuil: 'eleve' })).status === 200, 'Telegram relié');
const audit = await membre.post('/api/audits', { ia: false });
await note(audit.status === 200, 'le membre lance un audit');
for (let i = 0; i < 100 && (await admin.get('/api/etat')).json.enCours; i++) await new Promise(r => setTimeout(r, 50));

// 1. Détecter
await note((await membre.post('/api/actions', { type: 'quarantine', appareil: 'intrus' })).status === 403, 'un geste interdit (isolement par un membre) est refusé');
const journal = (await admin.get('/api/compte/admin/journal')).json;
await note(journal.lignes.some(l => l.action === 'acces.refuse') && journal.integrite.ok, 'détecter : le refus est au journal, chaîne intacte');
// 2. Fermer toutes les sessions sauf la sienne
await note((await admin.post('/api/compte/admin/sessions/fermer-tout')).status === 200, 'toutes les sessions fermées');
await note((await membre.get('/api/etat')).status === 401 && (await admin.get('/api/etat')).status === 200, 'la session du membre est morte, pas celle de l’administrateur');
// 3. Couper le Hub
await arreter();
await note(await demarrer({ VIGIE_HUB_TOKEN: HUB2 }), 'redéploiement : jeton du Hub n° 2');
await note((await new Client(PORT).req('GET', '/api/etat', undefined, hub(HUB1))).status === 401 && (await new Client(PORT).req('GET', '/api/etat', undefined, hub(HUB2))).status === 200, 'l’ancien jeton du Hub ne vaut plus rien, le nouveau ouvre');
// 4. Retirer les secrets des réglages (ils se révoquent aussi chez leurs fournisseurs)
const retrait = cli(['secrets', 'retirer']);
await note(retrait.status === 0 && /telegram\.jeton/.test(String(retrait.stdout)), 'secrets retirés en ligne de commande, service en marche');
const essai = await admin.post('/api/reglages/diffusion/essai', { canal: 'telegram' });
await note(essai.status === 502 && /non configuré/.test(essai.json?.error || ''), 'plus aucune alerte ne part avec l’ancien jeton Telegram');
// 5. Forcer un nouveau mot de passe
const comptes = (await admin.get('/api/compte/admin/comptes')).json.comptes;
const bruno = comptes.find(x => x.identifiant === 'bruno');
const reinit = await admin.post(`/api/compte/admin/comptes/${bruno.id}/reinit`);
await note(reinit.status === 200, 'lien de réinitialisation émis pour le membre');
const nouveau = MDP_ESSAI + ' après incident';
await note((await new Client(PORT).post('/api/compte/jeton', { usage: 'reinit', jeton: reinit.json.lien.split('#reinit=')[1], motDePasse: nouveau })).status === 200, 'le membre pose un nouveau mot de passe');
await note((await connexion(new Client(PORT), 'bruno', MDP_ESSAI + ' bruno')).status === 401, 'l’ancien mot de passe ne vaut plus rien');
await note((await connexion(new Client(PORT), 'bruno', nouveau)).json?.etape === 'second', 'le nouveau ouvre, et le second facteur reste exigé');
// 6. Restaurer depuis une sauvegarde
const paire = crypto.generateKeyPairSync('rsa', { modulusLength: 3072, publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } });
const sauv = cli(['sauvegarde'], paire.publicKey);
await note(sauv.status === 0 && sauv.stdout.length > 0, 'sauvegarde chiffrée tirée pendant que le service tourne');
await note((await admin.get('/api/compte/admin/journal')).json.lignes.some(l => l.action === 'sauvegarde.faite'), 'la sauvegarde est inscrite au journal');
await arreter();
const prive = path.join(D, 'prive.pem'), restauree = path.join(D, 'restauree.db');
fs.writeFileSync(prive, paire.privateKey);
await note(cli(['restaurer', prive, restauree], sauv.stdout).status === 0, 'restaurée ailleurs avec la clé privée seule');
for (const f of ['vigie.db', 'vigie.db-wal', 'vigie.db-shm']) fs.rmSync(path.join(DONNEES, f), { force: true });
fs.copyFileSync(restauree, path.join(DONNEES, 'vigie.db'));
fs.chmodSync(path.join(DONNEES, 'vigie.db'), 0o600);
await note(await demarrer({ VIGIE_HUB_TOKEN: HUB2 }), 'redémarrage sur la base restaurée');
const c = new Client(PORT);
const options = await c.post('/api/compte/connexion/cle/options');
await note((await c.post('/api/compte/connexion/cle', { reponse: auth.signer(options.json, c.origine) })).json?.niveau === 'complet', 'l’administrateur se reconnecte avec sa clé d’accès');
await note((await c.get('/api/audits')).json.some(a => a.id === audit.json.id && a.auteur === 'bruno'), 'les audits sont revenus');
// 7. Vérifier la chaîne du journal
const apres = (await c.get('/api/compte/admin/journal')).json;
await note(apres.integrite.ok && ['sessions.toutes_fermees', 'secrets.retires', 'compte.reinit_emis'].every(a => apres.lignes.some(l => l.action === a)), 'base restaurée : chaîne du journal intacte, chaque geste d’avant la sauvegarde inscrit');
await arreter();
console.log(`Exercice du runbook d'incident, ${new Date().toISOString()}\n${rapport.join('\n')}\n${rapport.length} vérifications réussies.`);
await fin(0);
