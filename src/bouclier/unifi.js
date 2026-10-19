// La passerelle UniFi par son API officielle d'intégration
// (UniFi Network 9 et plus) : clé d'API créée dans Paramètres → Control Plane
// → Integrations, envoyée dans X-API-KEY, et rien d'autre.
//
// VIGIE y tient deux listes d'adresses (« Traffic Matching Lists ») :
// « VIGIE · bloquées IPv4 » et « … IPv6 ». Deux règles du pare-feu, posées une
// fois dans l'interface d'UniFi, refusent ces listes en entrée et en sortie ;
// ensuite, bloquer ou lever une adresse ne touche que la liste — jamais les
// règles, jamais le reste de la configuration.
import { requete } from './tls.js';

export const NOMS_LISTES = { 4: 'VIGIE · bloquées IPv4', 6: 'VIGIE · bloquées IPv6' };
const BASE = '/proxy/network/integration/v1';

export class ErreurUnifi extends Error {
  constructor(message, status = 0) { super(message); this.status = status; }
}

export class Unifi {
  constructor({ hote, port = 443, fp, cle }) { Object.assign(this, { hote, port, fp, cle }); this.forme = null; }

  async appel(methode, chemin, corps = null) {
    const r = await requete({ hote: this.hote, port: this.port, fp: this.fp }, { methode, chemin: BASE + chemin, entetes: { 'X-API-KEY': this.cle }, corps });
    if (r.status === 401 || r.status === 403) throw new ErreurUnifi('clé d’API refusée par la passerelle', r.status);
    if (r.status === 404) throw new ErreurUnifi(`${chemin} : inconnu de cette version d’UniFi Network (9.0 ou plus requis)`, 404);
    if (r.status >= 400) throw new ErreurUnifi(`${methode} ${chemin} : ${r.status} ${String(r.json?.message || r.json?.error || r.brut).slice(0, 200)}`, r.status);
    return r.json;
  }
  donnees = j => (Array.isArray(j) ? j : Array.isArray(j?.data) ? j.data : []);

  async site() {
    if (this.siteId) return this.siteId;
    const sites = this.donnees(await this.appel('GET', '/sites?limit=50'));
    if (!sites.length) throw new ErreurUnifi('aucun site sur cette passerelle');
    const s = sites.find(x => x.internalReference === 'default' || x.name === 'Default') || sites[0];
    this.siteId = s.id;
    return s.id;
  }

  async essai() {
    const site = await this.site();
    const listes = this.donnees(await this.appel('GET', `/sites/${site}/traffic-matching-lists?limit=200`));
    return { site, listes: listes.filter(l => Object.values(NOMS_LISTES).includes(l.name)).map(l => ({ id: l.id, nom: l.name, n: (l.items || []).length })) };
  }

  // La forme des éléments d'une liste : de simples chaînes, ou des objets
  // { type, value } selon la version. La première qui passe est retenue.
  items(ips, forme) {
    if (forme === 'objets') return ips.map(ip => ({ type: ip.includes('/') ? 'SUBNET' : 'IP_ADDRESS', value: ip }));
    return ips;
  }
  async ecrire(site, existante, v, ips) {
    const essayer = async forme => {
      const corps = { type: v === 4 ? 'IPV4_ADDRESSES' : 'IPV6_ADDRESSES', name: NOMS_LISTES[v], items: this.items(ips, forme) };
      return existante ? this.appel('PUT', `/sites/${site}/traffic-matching-lists/${existante.id}`, corps) : this.appel('POST', `/sites/${site}/traffic-matching-lists`, corps);
    };
    const formes = this.forme ? [this.forme] : ['chaines', 'objets'];
    let derniere;
    for (const f of formes) {
      try { const r = await essayer(f); this.forme = f; return r; } catch (e) { derniere = e; if (e.status !== 400) throw e; }
    }
    throw derniere;
  }

  /**
   * Rend les deux listes égales à ce que VIGIE bloque. Une liste vide garde une
   * adresse de documentation : UniFi refuse une liste sans élément.
   */
  async synchroniser(ips) {
    const site = await this.site();
    const toutes = this.donnees(await this.appel('GET', `/sites/${site}/traffic-matching-lists?limit=200`));
    const out = {};
    for (const v of [4, 6]) {
      const miennes = ips.filter(ip => (v === 4 ? !ip.includes(':') : ip.includes(':')));
      const existante = toutes.find(l => l.name === NOMS_LISTES[v]);
      const items = miennes.length ? miennes : [v === 4 ? '192.0.2.1' : '2001:db8::1'];
      const r = await this.ecrire(site, existante, v, items);
      out[v] = { id: existante?.id || r?.id || r?.data?.id || null, n: miennes.length };
    }
    return out;
  }

  /** Les règles du pare-feu qui citent nos listes : sans elles, une liste ne bloque rien. */
  async regles(listes) {
    const site = await this.site();
    const politiques = this.donnees(await this.appel('GET', `/sites/${site}/firewall/policies?limit=500`));
    const ids = Object.values(listes).map(l => l?.id).filter(Boolean);
    const citent = politiques.filter(p => ids.some(id => JSON.stringify(p).includes(id)));
    return {
      total: politiques.length,
      entrant: citent.some(p => /BLOCK|REJECT/.test(JSON.stringify(p.action || '')) && JSON.stringify(p.source || '').match(new RegExp(ids.join('|') || '^$'))),
      sortant: citent.some(p => /BLOCK|REJECT/.test(JSON.stringify(p.action || '')) && JSON.stringify(p.destination || '').match(new RegExp(ids.join('|') || '^$'))),
      regles: citent.map(p => ({ nom: p.name, actif: p.enabled !== false })),
    };
  }
}
