// Une VIGIE de démonstration contre de faux voisins (test/faux.js) : deux
// audits (le second relu par l'IA locale), des événements de veille, des
// actions — et la porte du socle à ouvrir.
//   node outils/vitrine.mjs 8197
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { demarrer } from '../src/main.js';
import { fauxServices, fausseSonde, JETON_DOCKER } from '../test/faux.js';

const port = Number(process.argv[2] || 8197);
const dossier = fs.mkdtempSync(path.join(os.tmpdir(), 'vigie-vitrine-'));
const faux = fauxServices();
await new Promise(r => faux.serveur.listen(0, '127.0.0.1', r));
const ext = `http://127.0.0.1:${faux.serveur.address().port}`;
const jeton = 'jeton-installation-de-la-vitrine-vigie';
const vigie = await demarrer({
  DATA_DIR: path.join(dossier, 'data'), PORT: String(port), HOTE: '127.0.0.1', SOCLE_JETON_INSTALLATION: jeton, VIGIE_HUB_TOKEN: 'jeton-du-hub-de-la-vitrine-0123456789',
  MAPMYLAN_URL: ext + '/mml', MAPMYLAN_JETON: faux.jetons.mml, NEXARC_URL: ext + '/nxr', NEXARC_JETON: faux.jetons.nxr, DOCKER_CONTROL_URL: ext + '/dck',
  IA_LOCALE_URL: ext + '/ollama', IA_LOCALE_MODELE: 'qwen3:8b', SYNAPSE_URL: ext + '/syn', SYNAPSE_JETON: faux.jetons.syn,
}, { log: { info() {}, warn() {}, error() {} }, sonde: fausseSonde });
const fin = async x => { await vigie.moteur.enCours?.travail; return x; };
vigie.magasin.poserSecret('docker', 'jeton', JETON_DOCKER);
// Un premier audit plus propre, pour la courbe : la caméra n'avait pas encore Telnet.
const camera = faux.etat.appareils.find(a => a.id === 'camera');
const ports = camera.ports; camera.ports = ports.filter(p => p.port !== 23);
await fin(vigie.moteur.lancer({ declencheur: 'quotidien', ia: false }));
camera.ports = ports;
await vigie.moteur.passe();
faux.etat.appareils.push({ id: 'neuf', ip: '192.0.2.77', mac: 'AA:00:00:00:00:77', hostname: 'imprimante-etage-2-salle-de-reunion-principale', type: 'printer', vlan: 1, status: 'online', dangerScore: 10, whitelisted: false, ports: [{ port: 9100, state: 'open', service: 'jetdirect' }], cves: [] });
await vigie.moteur.passe();
vigie.magasin.poserReglage('ia', { mode: 'locale' });
await fin(vigie.moteur.lancer({ declencheur: 'manuel', auteur: 'ana' }));
await vigie.moteur.executer({ type: 'deep-scan', appareil: 'camera', auteur: 'ana' });
faux.etat.actionPrend = false;
await vigie.moteur.executer({ type: 'quarantine', appareil: 'camera', motif: 'Telnet ouvert', auteur: 'ana' });
faux.etat.actionPrend = true;
await vigie.moteur.executer({ type: 'quarantine', appareil: 'intrus', motif: 'Signe d’intrusion', auteur: 'vigie', automatique: true });
console.log(`VIGIE de démonstration sur http://localhost:${port} — jeton d’installation : ${jeton}`);
