// Ce que VIGIE lit, et la seule chose qu'il fait sur le réseau : demander à
// MapMyLAN d'agir. Chaque source a son jeton à elle, donné par le Hub ; une
// source absente ou muette laisse son domaine « non évalué », jamais faux.
//
// Le périmètre : les plages que MapMyLAN déclare balayer, moins les exclusions
// des réglages. VIGIE ne sonde ni n'isole rien en dehors.
import net from 'node:net';
import tls from 'node:tls';

const DELAI = 15_000;
const MAX_SONDES_TLS = 60;
const PARALLELE_TLS = 6;
const PORTS_TLS = new Set([443, 8443, 9443, 4443, 636, 993, 995, 465, 5986]);
const PRIVEES = [[[10, 0, 0, 0], 8], [[172, 16, 0, 0], 12], [[192, 168, 0, 0], 16], [[100, 64, 0, 0], 10]].map(([o, b]) => `${o.join('.')}/${b}`);

export const estIPv4 = s => net.isIPv4(String(s || ''));

/** Une liste d'adresses et de plages en BlockList ; les entrées invalides sont ignorées. */
export function plages(liste) {
  const b = new net.BlockList();
  for (const x of liste || []) {
    const [ip, bits] = String(x).trim().split('/');
    if (!estIPv4(ip)) continue;
    if (bits === undefined) b.addAddress(ip, 'ipv4');
    else if (/^\d{1,2}$/.test(bits) && Number(bits) <= 32) b.addSubnet(ip, Number(bits), 'ipv4');
  }
  return b;
}

export class ErreurSource extends Error {
  constructor(message, status = 0) { super(message); this.status = status; }
}

export class Sources {
  constructor({ cfg, magasin, fetch: f = globalThis.fetch, sonde = sonderTls }) {
    Object.assign(this, { cfg, magasin, fetch: f, sonde });
    this.etat = {};
    this.perimetreCourant = { plages: [], exclus: [] };
  }

  /** Quelles sources sont reliées, et ce que la dernière lecture en a dit. */
  public() {
    const relie = {
      mapmylan: !!(this.cfg.mapmylanUrl && this.cfg.mapmylanJeton),
      nexarc: !!(this.cfg.nexarcUrl && this.cfg.nexarcJeton),
      docker: !!(this.cfg.dockerUrl && this.magasin.secret('docker', 'jeton')),
      synapse: !!(this.cfg.synapseUrl && this.cfg.synapseJeton),
    };
    return Object.fromEntries(Object.entries(relie).map(([k, v]) => [k, { relie: v, ...(this.etat[k] || {}) }]));
  }

  async appel(base, jeton, chemin, { methode = 'GET', corps, delai = DELAI } = {}) {
    let r;
    try {
      r = await this.fetch(base + chemin, {
        method: methode, redirect: 'error', signal: AbortSignal.timeout(delai),
        headers: { authorization: `Bearer ${jeton}`, accept: 'application/json', ...(corps !== undefined ? { 'content-type': 'application/json' } : {}) },
        body: corps === undefined ? undefined : JSON.stringify(corps),
      });
    } catch (e) {
      throw new ErreurSource(e.name === 'TimeoutError' ? 'délai dépassé' : 'injoignable');
    }
    const j = await r.json().catch(() => null);
    if (r.status === 401) throw new ErreurSource('jeton refusé', 401);
    if (r.status === 403) throw new ErreurSource('droit refusé', 403);
    if (!r.ok) throw new ErreurSource(String(j?.error || `HTTP ${r.status}`).slice(0, 160), r.status);
    return j;
  }

  mml(chemin, o) { return this.appel(this.cfg.mapmylanUrl, this.cfg.mapmylanJeton, chemin, o); }

  noter(nom, ok, erreur = null, n = null) {
    this.etat[nom] = { ok, quand: Date.now(), erreur: erreur ? String(erreur).slice(0, 160) : null, ...(n !== null ? { n } : {}) };
  }

  // ---- lectures ----
  async lireMapmylan() {
    const [appareils, vlans, stats, alertes, plagesScan, dernierScan] = await Promise.all([
      this.mml('/api/devices'), this.mml('/api/vlans'), this.mml('/api/stats'),
      this.mml('/api/alerts?limit=300'), this.mml('/api/devices/scan/ranges'), this.mml('/api/devices/scans/latest'),
    ]);
    // Le trafic n'est ouvert aux jetons qu'à partir de MapMyLAN 2.1 : une
    // version plus ancienne refuse, et les règles qui en dépendent se taisent.
    let flux = null, collecte = null;
    try {
      [flux, collecte] = await Promise.all([this.mml(`/api/traffic/flows?limite=3000&depuis=${Date.now() - 24 * 3600e3}`), this.mml('/api/traffic/state')]);
    } catch (e) { if (!(e instanceof ErreurSource) || ![401, 403, 404].includes(e.status)) throw e; }
    return {
      appareils: Array.isArray(appareils) ? appareils : [], vlans: Array.isArray(vlans) ? vlans : [], stats: stats || {},
      alertes: Array.isArray(alertes) ? alertes : [], plages: Array.isArray(plagesScan) ? plagesScan : [], dernierScan: dernierScan || null,
      flux: Array.isArray(flux) ? flux : null, collecte: collecte || null,
    };
  }

  async lireNexarc() {
    const e = await this.appel(this.cfg.nexarcUrl, this.cfg.nexarcJeton, '/api/state');
    return { machines: Array.isArray(e?.machines) ? e.machines : [], alertes: Array.isArray(e?.alertes) ? e.alertes : [], correctifs: Array.isArray(e?.patches) ? e.patches : [] };
  }

  async lireDocker() {
    const r = await this.appel(this.cfg.dockerUrl, this.magasin.secret('docker', 'jeton'), '/api/containers');
    const l = Array.isArray(r) ? r : Array.isArray(r?.items) ? r.items : Array.isArray(r?.containers) ? r.containers : [];
    return l.slice(0, 2000).map(c => ({
      nom: String(c.name || c.nm || c.Names?.[0] || '').replace(/^\//, '').slice(0, 120),
      image: String(c.image || c.Image || '').slice(0, 200),
      etat: String(c.state || c.State || c.status || '').toLowerCase().slice(0, 40),
      ports: portsConteneur(c.ports ?? c.Ports ?? c.port),
      privilegie: c.privileged === true || c.HostConfig?.Privileged === true,
      reseauHote: c.networkMode === 'host' || c.HostConfig?.NetworkMode === 'host',
      socketDocker: JSON.stringify(c.mounts || c.Mounts || '').includes('docker.sock'),
      redemarrages: Number.isInteger(c.restartCount) ? c.restartCount : null,
      noeud: String(c.node || '').slice(0, 80),
    }));
  }

  /** Le périmètre autorisé : les plages balayées par MapMyLAN (sinon les plages privées), moins les exclusions. */
  perimetre(plagesScan) {
    const declarees = (plagesScan || []).filter(p => p.enabled !== false).map(p => p.cidr).filter(Boolean);
    const exclus = this.magasin.reglage('perimetre').exclus;
    this.perimetreCourant = { plages: declarees.length ? declarees : PRIVEES, exclus };
    return this.perimetreCourant;
  }

  dansPerimetre(ip, p = this.perimetreCourant) {
    if (!estIPv4(ip)) return false;
    return plages(p.plages).check(ip, 'ipv4') && !plages(p.exclus).check(ip, 'ipv4');
  }

  /** Les points TLS à sonder : ports chiffrés connus ouverts sur un appareil du périmètre. */
  ciblesTls(appareils) {
    const out = [];
    for (const a of appareils) {
      if (!this.dansPerimetre(a.ip)) continue;
      for (const p of a.ports || []) {
        if (p.state && p.state !== 'open') continue;
        if (PORTS_TLS.has(p.port) || /https|ssl|tls/i.test(p.service || '')) out.push({ ip: a.ip, port: p.port, appareil: a.id, nom: nomAppareil(a) });
      }
    }
    return out.slice(0, MAX_SONDES_TLS);
  }

  async sonderTout(cibles) {
    const res = [];
    let i = 0;
    const ouvrier = async () => { while (i < cibles.length) { const c = cibles[i++]; res.push({ ...c, ...(await this.sonde(c.ip, c.port)) }); } };
    await Promise.all(Array.from({ length: Math.min(PARALLELE_TLS, cibles.length) }, ouvrier));
    return res;
  }

  /** Une passe complète de collecte. Chaque source échoue seule. */
  async collecter({ tls: avecTls = this.magasin.reglage('veille').sondeTls } = {}) {
    const d = { quand: Date.now(), mapmylan: null, nexarc: null, docker: null, tls: null, sources: {} };
    const lire = async (nom, relie, fn) => {
      if (!relie) { d.sources[nom] = { relie: false }; return null; }
      try {
        const v = await fn();
        this.noter(nom, true);
        d.sources[nom] = { relie: true, ok: true };
        return v;
      } catch (e) {
        this.noter(nom, false, e.message);
        d.sources[nom] = { relie: true, ok: false, erreur: String(e.message).slice(0, 160) };
        return null;
      }
    };
    const rel = this.public();
    [d.mapmylan, d.nexarc, d.docker] = await Promise.all([
      lire('mapmylan', rel.mapmylan.relie, () => this.lireMapmylan()),
      lire('nexarc', rel.nexarc.relie, () => this.lireNexarc()),
      lire('docker', rel.docker.relie, () => this.lireDocker()),
    ]);
    d.perimetre = this.perimetre(d.mapmylan?.plages);
    if (d.mapmylan) {
      this.noter('mapmylan', true, null, d.mapmylan.appareils.length);
      if (avecTls) d.tls = await this.sonderTout(this.ciblesTls(d.mapmylan.appareils));
    }
    d.sources.tls = { relie: !!avecTls, ok: d.tls !== null, n: d.tls?.length ?? 0 };
    d.sources.synapse = { relie: rel.synapse.relie };
    return d;
  }

  // ---- actions (par MapMyLAN) ----
  async appareil(id) { return this.mml(`/api/devices/${encodeURIComponent(id)}`); }
  async agir(type, id, motif = '') {
    const chemin = { quarantine: 'quarantine', ban: 'ban', unban: 'unban', 'deep-scan': 'deep-scan' }[type];
    if (!chemin) throw new ErreurSource('action inconnue');
    const corps = type === 'quarantine' || type === 'ban' ? { reason: String(motif).slice(0, 200) || 'VIGIE' } : {};
    return this.mml(`/api/devices/${encodeURIComponent(id)}/${chemin}`, { methode: 'POST', corps, delai: type === 'deep-scan' ? 180_000 : DELAI });
  }
  async balayer() { return this.mml('/api/devices/scan', { methode: 'POST', corps: {} }); }
}

export const nomAppareil = a => String(a.customName || a.hostname || a.ip || a.mac || a.id || '?').slice(0, 80);

function portsConteneur(v) {
  if (Array.isArray(v)) {
    return v.slice(0, 50).map(p => (typeof p === 'object' && p
      ? { public: Number(p.PublicPort ?? p.public ?? p.hostPort) || null, prive: Number(p.PrivatePort ?? p.private ?? p.containerPort) || null, ip: String(p.IP ?? p.ip ?? p.hostIp ?? '') }
      : analysePort(String(p)))).filter(Boolean);
  }
  if (typeof v === 'string') return v.split(',').map(x => analysePort(x.trim())).filter(Boolean).slice(0, 50);
  return [];
}
// « 0.0.0.0:8080->80/tcp », « 8080:80 », « 80/tcp »
function analysePort(s) {
  const m = /^(?:\[?([0-9a-f.:]*)\]?:)?(\d+)?(?:->|:)?(\d+)?/i.exec(s);
  if (!m || (!m[2] && !m[3])) return null;
  const pub = m[3] ? Number(m[2]) : null;
  return { public: pub || null, prive: Number(m[3] || m[2]) || null, ip: m[1] || (pub ? '0.0.0.0' : '') };
}

/**
 * Sonde TLS d'un point : certificat, protocole négocié, et si un protocole
 * obsolète (TLS 1.0 ou 1.1) est encore accepté. Aucune donnée applicative
 * n'est envoyée ; la poignée de main suffit.
 */
export async function sonderTls(ip, port, { delai = 4000 } = {}) {
  const poignee = opts => new Promise(resolve => {
    let fini = false;
    const s = tls.connect({ host: ip, port, rejectUnauthorized: false, timeout: delai, ...opts }, () => {
      if (fini) return; fini = true;
      const c = s.getPeerCertificate();
      const out = { ok: true, protocole: s.getProtocol(), cert: c && c.valid_to ? {
        sujet: String(c.subject?.CN || '').slice(0, 200), emetteur: String(c.issuer?.CN || c.issuer?.O || '').slice(0, 200),
        debut: Date.parse(c.valid_from) || null, fin: Date.parse(c.valid_to) || null,
        autoSigne: !!(c.issuer && c.subject && JSON.stringify(c.issuer) === JSON.stringify(c.subject)),
        cle: c.bits || null, noms: String(c.subjectaltname || '').slice(0, 400),
      } : null };
      s.destroy(); resolve(out);
    });
    const echec = e => { if (fini) return; fini = true; s.destroy(); resolve({ ok: false, erreur: String(e?.code || e?.message || 'échec').slice(0, 80) }); };
    s.on('error', echec);
    s.on('timeout', () => echec({ code: 'délai dépassé' }));
  });
  const moderne = await poignee({});
  if (!moderne.ok) return { joignable: false, erreur: moderne.erreur };
  const ancien = await poignee({ minVersion: 'TLSv1', maxVersion: 'TLSv1.1', ciphers: 'DEFAULT@SECLEVEL=0' });
  return { joignable: true, protocole: moderne.protocole, cert: moderne.cert, ancienAccepte: ancien.ok ? ancien.protocole : null };
}
