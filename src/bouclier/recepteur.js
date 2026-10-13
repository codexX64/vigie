// Récepteur syslog (UDP et TCP) : la passerelle UniFi y envoie ses détections
// (SIEM → CEF) et les lignes de son pare-feu ; une sonde Suricata peut y
// envoyer son EVE JSON. Seuls les émetteurs déclarés sont écoutés — à défaut,
// les adresses privées : un journal se falsifie, et VIGIE agit sur ce qu'il lit.
import dgram from 'node:dgram';
import net from 'node:net';
import { EnsembleIp, normaliser, RFC1918 } from './ip.js';
import { lireLigne } from './journaux.js';

const LIGNE_MAX = 16 * 1024;
const PAR_SECONDE = 3000;

export class Recepteur {
  constructor({ port, hote = '0.0.0.0', emetteurs = () => [], surObservation, log = console, maintenant = () => Date.now() }) {
    Object.assign(this, { port, hote, emetteurs, surObservation, log, maintenant });
    this.stats = { recues: 0, lues: 0, refusees: 0, ignorees: 0, debordees: 0, derniere: null, parEmetteur: {}, dernierRefus: null };
    this.fenetre = { t: 0, n: 0 };
  }

  autorise(ip) {
    const liste = this.emetteurs();
    const cle = liste.join(',');
    if (this.cacheEmetteurs?.cle !== cle) {
      const e = new EnsembleIp();
      for (const x of liste.length ? liste : [...RFC1918, '127.0.0.0/8', 'fc00::/7', '::1/128']) e.ajouter(x);
      this.cacheEmetteurs = { cle, e: e.figer() };
    }
    return !!ip && this.cacheEmetteurs.e.contient(ip);
  }

  ligne(texte, emetteur) {
    this.stats.recues++;
    const t = this.maintenant();
    if (t - this.fenetre.t >= 1000) this.fenetre = { t, n: 0 };
    if (++this.fenetre.n > PAR_SECONDE) { this.stats.debordees++; return; }
    // Le dernier émetteur refusé est montré : derrière un relais de Docker, la passerelle peut arriver sous une autre adresse.
    if (!this.autorise(emetteur)) { this.stats.refusees++; this.stats.dernierRefus = emetteur; return; }
    const o = lireLigne(texte.slice(0, LIGNE_MAX), `syslog:${emetteur}`, t);
    if (!o) { this.stats.ignorees++; return; }
    this.stats.lues++;
    this.stats.derniere = t;
    this.stats.parEmetteur[emetteur] = t;
    try { this.surObservation(o); } catch (e) { this.log.warn?.(`[syslog] ${e.message}`); }
  }

  async demarrer() {
    if (!this.port) return this;
    // Toutes les adresses : une socket IPv6 qui reçoit aussi l'IPv4, ou l'IPv4
    // seule quand l'hôte n'a pas d'IPv6. Une adresse précise : sa famille.
    const lier = (type, hote) => new Promise((ok, ko) => {
      const u = dgram.createSocket({ type, ...(type === 'udp6' ? { ipv6Only: false } : {}) });
      const echec = e => { try { u.close(); } catch { /* déjà fermée */ } ko(e); };
      u.once('error', echec);
      u.bind(this.port, hote, () => { u.off('error', echec); ok(u); });
    });
    if (this.hote === '0.0.0.0') this.udp = await lier('udp6', '::').catch(() => lier('udp4', '0.0.0.0'));
    else this.udp = await lier(net.isIPv6(this.hote) ? 'udp6' : 'udp4', this.hote);
    this.udp.on('message', (buf, r) => { const em = normaliser(r.address.replace(/^::ffff:/, '')); for (const l of buf.toString('utf8').split('\n')) if (l.trim()) this.ligne(l, em); });
    this.udp.on('error', e => this.log.warn?.(`[syslog] UDP : ${e.message}`));
    // TCP : une ligne par message, ou le cadrage par longueur (RFC 6587).
    this.tcp = net.createServer(s => {
      const em = normaliser(String(s.remoteAddress || '').replace(/^::ffff:/, ''));
      if (!this.autorise(em)) { this.stats.refusees++; this.stats.dernierRefus = em; s.destroy(); return; }
      let tampon = '';
      s.setTimeout(300_000, () => s.destroy());
      s.on('data', d => {
        tampon += d.toString('utf8');
        if (tampon.length > 4 * LIGNE_MAX) tampon = tampon.slice(-LIGNE_MAX);
        for (;;) {
          const m = /^(\d{1,5}) /.exec(tampon);
          if (m && tampon.length >= m[0].length + Number(m[1])) { this.ligne(tampon.slice(m[0].length, m[0].length + Number(m[1])), em); tampon = tampon.slice(m[0].length + Number(m[1])); continue; }
          const i = tampon.indexOf('\n');
          if (m || i < 0) break;
          const l = tampon.slice(0, i); tampon = tampon.slice(i + 1);
          if (l.trim()) this.ligne(l, em);
        }
      });
      s.on('error', () => s.destroy());
    });
    this.tcp.maxConnections = 32;
    await new Promise((ok, ko) => { this.tcp.once('error', ko); this.tcp.listen(this.port, this.hote, () => { this.tcp.off('error', ko); ok(); }); });
    this.log.info?.(`[syslog] à l’écoute sur ${this.hote}:${this.port} (UDP et TCP)`);
    return this;
  }
  adresse() { return { udp: this.udp?.address()?.port ?? null, tcp: this.tcp?.address()?.port ?? null }; }
  arreter() { try { this.udp?.close(); } catch { /* fermé */ } try { this.tcp?.close(); } catch { /* fermé */ } }
}
