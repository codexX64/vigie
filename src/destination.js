// Une adresse saisie par quelqu'un (billetterie, liste de menaces ajoutée) est
// relue au moment d'y envoyer quoi que ce soit : son nom est résolu, et aucune
// des adresses obtenues ne doit être interdite (lien local et métadonnées d'un
// nuage, multicast, réservé). Une adresse écrite en chiffres l'est sans DNS.
import dns from 'node:dns/promises';
import { estInterdite, versEntier } from './bouclier/ip.js';

export class DestinationInterdite extends Error {}

const nomHote = url => new URL(url).hostname.replace(/^\[|\]$/g, '');

/** Vrai si l'adresse, écrite en chiffres, est interdite (contrôle à l'enregistrement, sans DNS). */
export const litteraleInterdite = url => { try { return estInterdite(nomHote(url)); } catch { return true; } };

export async function verifierDestination(url, { resoudre = h => dns.lookup(h, { all: true, verbatim: true }) } = {}) {
  const h = nomHote(url);
  const adresses = versEntier(h) || /^::ffff:/i.test(h) ? [h] : (await resoudre(h).catch(() => [])).map(a => a.address);
  if (!adresses.length) throw new DestinationInterdite(`${h} ne se résout pas`);
  const mauvaise = adresses.find(estInterdite);
  if (mauvaise) throw new DestinationInterdite(`${h} mène à ${mauvaise} : lien local, métadonnées ou adresse réservée, refusée`);
}
