// Parcours réel de VIGIE dans Chromium (clé d'accès virtuelle) : installation
// par la porte du socle, chaque page et ses dialogues, contrôle de mise en page
// à chaque largeur. Contre la vitrine (outils/vitrine.mjs) :
//   node outils/parcours-navigateur.mjs http://localhost:8197 JETON DOSSIER
import { chromium } from 'playwright';
import fs from 'node:fs';
import { chevauchements, LARGEURS } from '../socle/essai/mise-en-page.mjs';

const [base, jeton, sortie = '/tmp/captures-vigie'] = process.argv.slice(2);
fs.mkdirSync(sortie, { recursive: true });
const navigateur = await chromium.launch();
const contexte = await navigateur.newContext({ viewport: { width: 1280, height: 860 } });
const page = await contexte.newPage();
const erreurs = [];
page.on('console', m => { if (m.type() === 'error' && !/Failed to load resource.*(404|401)/.test(m.text())) erreurs.push(m.text()); });
page.on('pageerror', e => erreurs.push(String(e)));
page.on('response', r => { if (r.status() === 400 || r.status() >= 500) erreurs.push(`${r.status()} ${r.request().method()} ${new URL(r.url()).pathname}`); });
const cdp = await contexte.newCDPSession(page);
await cdp.send('WebAuthn.enable');
await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });

const rapport = [];
async function controle(nom) {
  for (const w of LARGEURS) {
    await page.setViewportSize({ width: w, height: w < 500 ? 780 : 900 });
    await page.waitForTimeout(250);
    rapport.push({ ecran: nom, largeur: w, defauts: await page.evaluate(chevauchements) });
    if ([360, 768, 1280].includes(w)) await page.screenshot({ path: `${sortie}/${nom}-${w}.png`, fullPage: true });
  }
  await page.setViewportSize({ width: 1280, height: 860 });
  await page.waitForTimeout(150);
}
const aller = async (titre, entete = titre) => {
  await page.getByRole('button', { name: titre, exact: true }).first().click();
  await page.getByRole('heading', { name: entete, exact: true }).first().waitFor();
  await page.waitForTimeout(400);
};
const dialogue = () => page.getByRole('dialog').last();
const fermer = async () => { await dialogue().getByRole('button', { name: /^(Annuler|Fermer)$/ }).last().click(); await page.waitForTimeout(200); };

await page.goto(base);
await page.getByText('Premier compte').waitFor();
await controle('installation');
await page.getByLabel('Jeton d’installation').fill(jeton);
await page.getByLabel('Identifiant').fill('ana');
await page.getByLabel('Mot de passe').fill('phrase de passe pour la vigie de la vitrine');
await page.getByRole('button', { name: 'Créer le compte' }).click();
await page.getByRole('button', { name: /Créer la clé maintenant/ }).click();
await page.getByText('J’ai rangé ces codes en lieu sûr.').click();
await page.getByRole('button', { name: 'Terminer' }).click();
await page.getByRole('heading', { name: 'Posture de sécurité', exact: true }).waitFor();
await page.waitForTimeout(800);
await controle('tableau');
await aller('Constats');
await controle('constats');
await page.locator('.flowrow.cliquable').first().click();
await dialogue().waitFor();
await page.waitForTimeout(300);
await controle('fiche-constat');
await fermer();
await page.getByRole('button', { name: 'Par hôte' }).click();
await page.locator('details.hote').first().locator('summary').click();
await page.waitForTimeout(300);
await controle('constats-hotes');
await aller('Historique');
await controle('historique');
await aller('Événements');
await controle('evenements');
await aller('Actions');
await controle('actions');
await aller('Réglages');
await controle('reglages');
await aller('Sécurité');
await controle('securite');
await aller('Comptes');
await controle('comptes');

const defauts = rapport.filter(r => r.defauts.length);
fs.writeFileSync(`${sortie}/rapport.json`, JSON.stringify({ rapport, erreurs }, null, 2));
console.log(`écrans×largeurs contrôlés : ${rapport.length}, avec défauts : ${defauts.length}, erreurs console : ${erreurs.length}`);
for (const r of defauts) for (const d of r.defauts.slice(0, 4)) console.log(`  ${r.ecran} @${r.largeur} — ${d.type} : ${d.detail}`);
for (const e of erreurs) console.log('  console :', e);
await navigateur.close();
process.exit(defauts.length || erreurs.length ? 1 : 0);
