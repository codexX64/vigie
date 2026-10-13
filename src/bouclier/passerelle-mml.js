// La passerelle par MapMyLAN : quand MapMyLAN pilote déjà le routeur principal
// (relié par le Hub, certificat épinglé chez lui), VIGIE n'a rien à régler.
// Elle lui confie la liste des adresses à refuser, et lit par lui les alertes
// de l'IPS. Les identifiants du routeur restent dans MapMyLAN.
//
// Même forme que Unifi (unifi.js) pour la riposte : synchroniser(ips), regles().
export class PasserelleMapMyLAN {
  constructor({ sources, nom = '', hote = '' }) {
    Object.assign(this, { sources, nom, hote });
    this.forme = 'mapmylan';
    this.dernieresRegles = null;
  }

  async synchroniser(ips) {
    let r;
    try { r = await this.sources.mml('/api/passerelle/bouclier', { methode: 'PUT', corps: { ips } }); } catch (e) { throw new Error(`MapMyLAN : ${e.message}`); }
    this.dernieresRegles = r?.regles || null;
    const g = r?.groupes || {};
    return { 4: g[4] || null, 6: g[6] || null };
  }

  async regles() { return this.dernieresRegles; }
}
