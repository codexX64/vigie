// Cloudflare, en amont de la frontière : les adresses que VIGIE bloque vont
// aussi dans une liste du compte Cloudflare, qu'une règle du pare-feu
// applicatif de chaque zone refuse — un attaquant est coupé avant même de
// toucher le tunnel ou la fibre. En tempête, VIGIE peut passer les zones en
// mode « Under Attack » (défi à chaque visiteur) le temps que ça passe.
//
// API v4, sans dépendance. Le jeton doit avoir : Compte → Listes de filtres
// (Account Filter Lists) → Modifier ; Zone → Zone → Lire ; Zone → Pare-feu
// WAF (Zone WAF) → Modifier ; Zone → Paramètres de zone → Modifier (mode
// Under Attack). Offre gratuite : une liste de 10 000 adresses, 5 règles.
import { normaliser } from './ip.js';

const API = 'https://api.cloudflare.com/client/v4';
export const NOM_LISTE = 'vigie_bloquees';
const DESCRIPTION_REGLE = 'VIGIE : adresses bloquées';
export class ErreurCloudflare extends Error {}

export class Cloudflare {
  constructor({ jeton, compte = '', fetch: f = globalThis.fetch, log = console }) {
    Object.assign(this, { jeton, compte, fetch: f, log });
  }

  async appel(methode, chemin, corps) {
    let res;
    try {
      res = await this.fetch(API + chemin, { method: methode, signal: AbortSignal.timeout(20_000), headers: { authorization: `Bearer ${this.jeton}`, 'content-type': 'application/json', 'user-agent': 'VIGIE (defensive network monitor)' }, body: corps === undefined ? undefined : JSON.stringify(corps) });
    } catch (e) { throw new ErreurCloudflare(`Cloudflare injoignable : ${e.message}`); }
    let j = null;
    try { j = await res.json(); } catch { /* corps vide */ }
    if (!res.ok || !j?.success) {
      const m = j?.errors?.map(e => `${e.code} ${e.message}`).join(' ; ') || `HTTP ${res.status}`;
      throw Object.assign(new ErreurCloudflare(`Cloudflare : ${m}`), { status: res.status, codes: (j?.errors || []).map(e => e.code) });
    }
    return j;
  }

  /** Le jeton est-il valable, et pour quel compte ? → { compte, zones } */
  async sonder() {
    const v = await this.appel('GET', '/user/tokens/verify');
    if (v.result?.status !== 'active') throw new ErreurCloudflare(`Cloudflare : jeton ${v.result?.status || 'inconnu'}.`);
    const zones = (await this.appel('GET', '/zones?per_page=50&status=active')).result.map(z => ({ id: z.id, nom: z.name, compte: z.account?.id || '', offre: z.plan?.legacy_id || z.plan?.name || '' }));
    let compte = this.compte;
    if (!compte) {
      const comptes = (await this.appel('GET', '/accounts?per_page=5')).result;
      compte = comptes[0]?.id || zones[0]?.compte || '';
    }
    if (!compte) throw new ErreurCloudflare('Cloudflare : aucun compte lisible avec ce jeton (droit Compte → Paramètres du compte → Lire).');
    this.compte = compte;
    return { compte, zones };
  }

  /** La liste du compte qui porte les adresses de VIGIE, créée au besoin. → id */
  async assurerListe() {
    const listes = (await this.appel('GET', `/accounts/${this.compte}/rules/lists`)).result || [];
    const l = listes.find(x => x.name === NOM_LISTE);
    if (l) return l.id;
    const c = await this.appel('POST', `/accounts/${this.compte}/rules/lists`, { name: NOM_LISTE, kind: 'ip', description: 'Adresses bloquées par VIGIE (synchronisée, ne pas éditer à la main)' });
    return c.result.id;
  }

  /** Remplace le contenu de la liste : IPv4 telles quelles, IPv6 par /64 (la granularité des listes Cloudflare). */
  async synchroniser(listeId, ips) {
    const items = [];
    const vus = new Set();
    for (const brute of ips) {
      const ip = normaliser(brute);
      if (!ip) continue;
      const v = ip.includes(':') ? `${ip.split(':').slice(0, 4).join(':')}::/64` : ip;
      if (vus.has(v)) continue;
      vus.add(v);
      items.push({ ip: v, comment: 'VIGIE' });
      if (items.length >= 10_000) break;
    }
    const r = await this.appel('PUT', `/accounts/${this.compte}/rules/lists/${listeId}/items`, items);
    return { envoyees: items.length, operation: r.result?.operation_id || null };
  }

  /** La règle « bloquer ce qui est dans la liste », posée une fois par zone. → { posee, creee } */
  async assurerRegle(zoneId) {
    const expression = `(ip.src in $${NOM_LISTE})`;
    let ensemble = null;
    try { ensemble = (await this.appel('GET', `/zones/${zoneId}/rulesets/phases/http_request_firewall_custom/entrypoint`)).result; }
    catch (e) { if (e.status !== 404) throw e; }
    if (ensemble?.rules?.some(r => r.description === DESCRIPTION_REGLE || r.expression === expression)) return { posee: true, creee: false };
    const regle = { action: 'block', expression, description: DESCRIPTION_REGLE, enabled: true };
    if (ensemble?.id) await this.appel('POST', `/zones/${zoneId}/rulesets/${ensemble.id}/rules`, regle);
    else await this.appel('PUT', `/zones/${zoneId}/rulesets/phases/http_request_firewall_custom/entrypoint`, { rules: [regle] });
    return { posee: true, creee: true };
  }

  /** Niveau de sécurité d'une zone (essentially_off … under_attack). */
  async niveau(zoneId) { return (await this.appel('GET', `/zones/${zoneId}/settings/security_level`)).result?.value || ''; }
  async poserNiveau(zoneId, valeur) { await this.appel('PATCH', `/zones/${zoneId}/settings/security_level`, { value: valeur }); return valeur; }
}
