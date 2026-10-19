// Administration de VIGIE en ligne de commande, dans le conteneur :
//   docker exec <vigie> node src/cli.js <commande>
//
// Chaque geste laisse sa trace au journal de sécurité, chaîné comme celui du
// service, qui tourne pendant ce temps : la base est en WAL, les deux écrivent
// sans se bloquer.
//
// La sauvegarde est chiffrée pour une clé publique dont la clé privée ne vit
// pas sur la machine de VIGIE : qui prend la machine ne relit pas les
// sauvegardes. Elle garde les secrets scellés sous SOCLE_CLE : sans une copie
// de cette clé, une base restaurée ne rouvre ni les secrets TOTP ni ceux des
// réglages (clé d'IA, Telegram, billetterie, UniFi, Cloudflare).
import fs from 'node:fs';
import { lireConfigVigie, VERSION } from './config.js';
import { ouvrirBase, Magasin, SCELLES } from './base.js';
import { Journal, sauvegarder, dechiffrer } from '../socle/src/index.js';

const [, , cmd, ...rest] = process.argv;

function die(m) { console.error('erreur : ' + m); process.exit(1); }

// Sur la machine qui garde la clé privée : aucune base, aucune configuration.
function restaurer(prive, cible) {
  if (!prive || !cible) die('usage : restaurer <clé-privée.pem> <cible.db> < vigie.sauv');
  if (fs.existsSync(cible)) die(`${cible} existe déjà : la restauration écrit un fichier neuf`);
  let lu;
  try { lu = dechiffrer(fs.readFileSync(0), fs.readFileSync(prive, 'utf8')); } catch (e) { die(`sauvegarde illisible avec cette clé (${e.message})`); }
  if (lu.entete.service !== 'vigie') die(`sauvegarde de ${lu.entete.service}, pas de VIGIE`);
  fs.writeFileSync(cible, lu.base, { mode: 0o600, flag: 'wx' });
  process.stderr.write(`Base de VIGIE ${lu.entete.version} du ${lu.entete.date} restaurée dans ${cible}.\n`);
}
if (cmd === 'restaurer') { restaurer(rest[0], rest[1]); process.exit(0); }

function usage() {
  console.log(`VIGIE — administration

  secrets retirer [${Object.keys(SCELLES).join('|')}]
                                oublie les secrets des réglages (tous, ou ceux d'un canal) :
                                runbook d'incident ; les révoquer aussi chez leur fournisseur
  sauvegarde < clé-publique.pem > vigie.sauv
  restaurer <clé-privée.pem> <cible.db> < vigie.sauv     (sur une autre machine)

Les comptes humains se gèrent dans l'interface.`);
}

const db = ouvrirBase(lireConfigVigie().donnees);
const journal = new Journal(db);
const trace = (action, objet, details) => journal.ecrire({ action, objet, details: { par: 'ligne de commande', ...details } });

// Un secret retiré n'a pas besoin de la clé : il est effacé, pas rescellé. Le
// service en marche relit les réglages à chaque usage.
function retirerSecrets(quoi) {
  if (quoi && !SCELLES[quoi]) die(`canal inconnu : ${quoi}`);
  const magasin = new Magasin(db, { coffre: null });
  const retires = [];
  for (const [nom, champs] of Object.entries(SCELLES)) {
    if (quoi && nom !== quoi) continue;
    const r = magasin.reglage(nom);
    for (const champ of champs) if (r[champ]) { magasin.poserSecret(nom, champ, null); retires.push(`${nom}.${champ}`); }
  }
  trace('secrets.retires', quoi || 'tous', { retires });
  console.log(retires.length ? `retirés : ${retires.join(', ')} — révoque-les aussi chez leur fournisseur (clé d'IA, bot Telegram, clé UniFi, jeton Cloudflare, billetterie)` : 'rien à retirer');
}

async function sauvegarde() {
  if (process.stdout.isTTY) die('redirige la sortie : node src/cli.js sauvegarde < sauvegarde.pub > vigie.sauv');
  let sortie;
  try { sortie = await sauvegarder(db, fs.readFileSync(0, 'utf8'), { service: 'vigie', version: VERSION }); } catch (e) { die(e.message); }
  trace('sauvegarde.faite', null, { octets: sortie.length });
  process.stdout.write(sortie);
}

switch (cmd) {
  case 'secrets':
    if (rest[0] === 'retirer') retirerSecrets(rest[1]);
    else usage();
    break;
  case 'sauvegarde': await sauvegarde(); break;
  default: usage();
}
db.close();
