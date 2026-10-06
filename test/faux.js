// Faux voisins de VIGIE, sur un seul serveur HTTP : MapMyLAN (/mml), NEXARC
// (/nxr), docker-control (/dck), Ollama (/ollama), Anthropic (/anthropic),
// SYNAPSE (/syn), Telegram (/tg) et une billetterie (/ticket). Les essais et
// la vitrine s'en servent ; l'état est modifiable entre deux appels.
import http from 'node:http';
import crypto from 'node:crypto';

export const SEMENCE_MML = 'semence-du-jeton-mapmylan-pour-les-essais';
export const SEMENCE_NXR = 'jeton-hub-de-nexarc-pour-les-essais-0123';
export const SEMENCE_SYN = 'jeton-hub-de-synapse-pour-les-essais-0123';
export const JETON_DOCKER = 'jeton-docker-control-essai-0123456789';
export const CLE_IA = 'sk-ant-essai-0123456789abcdefghij';
export const JETON_TG = '123456:jeton-telegram-de-test-abcdefgh';
export const CLE_TICKET = 'cle-billetterie-essai-0123';
export const derive = (secret, nom) => `cer_${nom}_${crypto.createHmac('sha256', secret).update('cerveau:' + nom).digest('hex')}`;

const il_y_a = ms => new Date(Date.now() - ms).toISOString();

export function etatInitial() {
  const p = (port, service, product = null, version = null) => ({ id: `p${port}`, port, protocol: 'tcp', state: 'open', service, product, version });
  return {
    appareils: [
      { id: 'routeur', ip: '192.0.2.1', mac: 'AA:00:00:00:00:01', hostname: 'passerelle', customName: null, vendor: 'Ubiquiti', type: 'router', customType: null, vlan: 1, status: 'online', trustScore: 90, activityScore: 50, vulnScore: 10, dangerScore: 5, whitelisted: true, isMainRouter: true, os: null, ports: [p(53, 'domain'), p(80, 'http'), p(1900, 'upnp')], cves: [], interfaces: [] },
      { id: 'nas', ip: '192.0.2.10', mac: 'AA:00:00:00:00:10', hostname: 'nas', customName: 'NAS', vendor: 'Synology', type: 'nas', vlan: 1, status: 'online', trustScore: 80, dangerScore: 10, whitelisted: true, isMainRouter: false, ports: [p(22, 'ssh', 'OpenSSH', '9.6'), p(445, 'microsoft-ds'), p(443, 'https')], cves: [], interfaces: [] },
      { id: 'serveur', ip: '192.0.2.11', mac: 'AA:00:00:00:00:11', hostname: 'srv-app', type: 'server', vlan: 1, status: 'online', trustScore: 70, dangerScore: 20, whitelisted: true, isMainRouter: false, ports: [p(22, 'ssh', 'OpenSSH', '7.2p2'), p(6379, 'redis'), p(80, 'http', 'nginx', '1.18.0')], cves: [], interfaces: [] },
      { id: 'poste', ip: '192.0.2.20', mac: 'AA:00:00:00:00:20', hostname: 'poste-compta', type: 'pc', vlan: 1, status: 'online', trustScore: 60, dangerScore: 30, whitelisted: true, isMainRouter: false, os: 'Windows 10 Pro', ports: [p(3389, 'ms-wbt-server')], cves: [{ id: 'c1', cveId: 'CVE-2019-0708', cvss: 9.8, severity: 'critical', description: 'BlueKeep', service: 'ms-wbt-server' }], interfaces: [] },
      { id: 'camera', ip: '192.0.2.50', mac: 'AA:00:00:00:00:50', hostname: 'cam-entree', type: 'camera', vlan: 1, status: 'online', trustScore: 40, dangerScore: 40, whitelisted: false, isMainRouter: false, ports: [p(23, 'telnet'), p(80, 'http'), p(554, 'rtsp')], cves: [], interfaces: [] },
      { id: 'intrus', ip: '192.0.2.66', mac: 'AA:00:00:00:00:66', hostname: null, type: 'phone', vlan: 1, status: 'suspect', trustScore: 5, dangerScore: 92, whitelisted: false, isMainRouter: false, scoreReasons: { trust: [{ reason: 'Balayage de ports vers le réseau', delta: -40 }] }, ports: [], cves: [], interfaces: [] },
      { id: 'dehors', ip: '10.9.9.9', mac: 'AA:00:00:00:09:09', hostname: 'hors-plage', type: 'pc', vlan: null, status: 'online', dangerScore: 0, whitelisted: false, isMainRouter: false, ports: [], cves: [], interfaces: [] },
    ],
    vlans: [{ id: 1, name: 'LAN', subnet: '192.0.2.0/24', isolated: false, color: '#888888' }, { id: 30, name: 'IoT', subnet: '198.51.100.0/24', isolated: false, color: '#888888' }],
    alertes: [
      { id: 'a1', severity: 'high', source: 'scanner', message: 'Tentatives de connexion SSH répétées depuis 192.0.2.66', deviceIp: '192.0.2.66', acknowledged: false, createdAt: il_y_a(3600e3) },
      { id: 'a2', severity: 'critical', source: 'regles', message: 'Port Telnet ouvert sur une caméra', deviceIp: '192.0.2.50', acknowledged: false, createdAt: il_y_a(3 * 86400e3) },
    ],
    plages: [{ cidr: '192.0.2.0/24', label: 'LAN', enabled: true }],
    dernierScan: { id: 's1', type: 'full', subnet: '192.0.2.0/24', status: 'complete', hostsFound: 7, startedAt: il_y_a(3700e3), endedAt: il_y_a(3600e3), error: null },
    flux: [{ id: 'f1', src: '192.0.2.66', dst: '203.0.113.9', port: 4444, proto: 'tcp', premier: Date.now() - 600e3, dernier: Date.now() - 60e3, octets: 1200, paquets: 10, vues: 3, sens: 'sortant', suspect: true, raison: 'Port de contrôle à distance connu' }],
    collecte: { cible: { id: 'routeur', nom: 'passerelle', hote: '192.0.2.1', port: 22 }, total: 1, retentionJours: 30, erreur: null },
    traficOuvert: true,
    actionPrend: true,
    machines: [
      { id: 'm1', host: 'POSTE-COMPTA', ip: '192.0.2.20', os: 'Windows 10 Pro', oskind: 'windows', role: 'poste', online: true, risk: 70, av: 'actif', fw: 'inactif', enc: 'non chiffré', patch: 'retard', updates_n: 4, source: 'agent', seen: Math.floor(Date.now() / 1000) },
      { id: 'm2', host: 'srv-app', ip: '192.0.2.11', os: 'Debian GNU/Linux 12', oskind: 'linux', role: 'serveur', online: false, risk: 10, av: 'inconnu', fw: 'actif', enc: 'chiffré', patch: 'ok', updates_n: 0, source: 'agent', seen: Math.floor(Date.now() / 1000) - 86400 },
    ],
    alertesNxr: [{ id: 'n1', regle: 'correctifs', sev: 'warn', txt: '3 correctif(s) de sécurité en attente depuis plus de 7 jour(s).', etat: 'ouverte', machine: { id: 'm1', host: 'POSTE-COMPTA', ip: '192.0.2.20' } }],
    conteneurs: [
      { name: 'hub-mapmylan', image: 'ghcr.io/codexx64/mapmylan:2.1.0', state: 'running', ports: [] },
      { name: 'base-essai', image: 'postgres:latest', state: 'running', ports: [{ IP: '0.0.0.0', PublicPort: 5432, PrivatePort: 5432 }] },
      { name: 'outil', image: 'outil@sha256:' + 'a'.repeat(64), state: 'running', privileged: true, ports: [] },
    ],
    ia: { reponse: null, appels: [], cloud: [] },
    synapse: { lots: [], briefs: [] },
    telegram: [], tickets: [], actions: [],
  };
}

export function fauxServices(etat = etatInitial()) {
  const jetonMml = derive(SEMENCE_MML, 'vigie'), jetonNxr = derive(SEMENCE_NXR, 'vigie'), jetonSyn = derive(SEMENCE_SYN, 'vigie');
  const serveur = http.createServer((req, res) => {
    let corps = '';
    req.on('data', d => { corps += d; });
    req.on('end', () => {
      const u = new URL(req.url, 'http://x');
      const json = (s, o) => { res.writeHead(s, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)); };
      const b = (() => { try { return JSON.parse(corps || '{}'); } catch { return {}; } })();
      const auth = req.headers.authorization || '';
      const p = u.pathname;
      if (p.startsWith('/mml/')) {
        if (auth !== `Bearer ${jetonMml}`) return json(401, { error: 'Jeton invalide.' });
        const q = p.slice(4);
        if (q === '/api/devices') return json(200, etat.appareils);
        if (q === '/api/vlans') return json(200, etat.vlans);
        if (q === '/api/stats') return json(200, { total: etat.appareils.length });
        if (q === '/api/alerts') return json(200, etat.alertes);
        if (q === '/api/devices/scan/ranges') return json(200, etat.plages);
        if (q === '/api/devices/scans/latest') return json(200, etat.dernierScan);
        if (q === '/api/traffic/flows') return etat.traficOuvert ? json(200, etat.flux) : json(403, { error: 'Session requise.' });
        if (q === '/api/traffic/state') return etat.traficOuvert ? json(200, etat.collecte) : json(403, { error: 'Session requise.' });
        if (q === '/api/devices/scan' && req.method === 'POST') { etat.actions.push({ type: 'scan' }); return json(200, { ok: true }); }
        const m = /^\/api\/devices\/([^/]+)(?:\/([a-z-]+))?$/.exec(q);
        const a = m && etat.appareils.find(x => x.id === m[1]);
        if (m && !a) return json(404, { error: 'Appareil inconnu.' });
        if (m && !m[2] && req.method === 'GET') {
          if (etat.muet === a.id) return json(500, { error: 'MapMyLAN occupé.' });
          return json(200, { ...a, history: [] });
        }
        if (m && req.method === 'POST') {
          etat.actions.push({ type: m[2], id: a.id, corps: b });
          if (m[2] === 'deep-scan') return json(200, { ip: a.ip, ports: a.ports.map(x => ({ port: x.port, service: x.service })) });
          if (etat.actionPrend) a.status = m[2] === 'quarantine' ? 'quarantined' : m[2] === 'ban' ? 'banned' : 'online';
          if (etat.muetApresAction) etat.muet = a.id;
          return json(200, { ok: true, output: '' });
        }
        return json(404, { error: 'Route inconnue.' });
      }
      if (p === '/nxr/api/state') {
        if (auth !== `Bearer ${jetonNxr}`) return json(401, { error: 'Jeton de service invalide.' });
        return json(200, { machines: etat.machines, alertes: etat.alertesNxr, patches: [] });
      }
      if (p === '/dck/api/containers') {
        if (auth !== `Bearer ${JETON_DOCKER}`) return json(401, { error: 'unauthorized' });
        return json(200, { items: etat.conteneurs });
      }
      if (p === '/ollama/api/chat') {
        etat.ia.appels.push(b);
        const contenu = etat.ia.reponse ?? JSON.stringify({ verdicts: [{ n: 1, statut: 'confirme', note: 'Balayage de ports et port 4444 : compromission probable.' }, { n: 2, statut: 'nuancé', note: 'Voir https://exemple.invalid/piege' }], synthese: 'Un appareil inconnu balaie le réseau. <script>x</script>', scenarios: [{ titre: 'Intrusion depuis un téléphone', constats: [1, 2], explication: 'Le même appareil.' }], priorites: [{ titre: 'Isoler 192.0.2.66', pourquoi: 'Signe d’intrusion', constats: [1] }], corrections: [{ n: 1, etapes: ['Isoler', 'Analyser'] }] });
        return json(200, { message: { role: 'assistant', content: contenu }, prompt_eval_count: 900, eval_count: 300 });
      }
      if (p === '/anthropic/v1/messages') {
        if (req.headers['x-api-key'] !== CLE_IA) return json(401, { error: { message: 'invalid x-api-key' } });
        etat.ia.cloud.push(b);
        const texte = `Voici l’analyse :\n${JSON.stringify({ verdicts: [{ n: 1, statut: 'confirme', note: 'Confirmé par le nuage.' }], synthese: 'Synthèse rédigée par le modèle en nuage.', scenarios: [], priorites: [], corrections: [] })}`;
        return json(200, { content: [{ type: 'text', text: texte }], usage: { input_tokens: 1500, output_tokens: 400 } });
      }
      if (p.startsWith('/syn/')) {
        if (auth !== `Bearer ${jetonSyn}`) return json(401, { error: 'jeton' });
        if (p === '/syn/v1/ingest/batch') { etat.synapse.lots.push(...(b.events || [])); return json(200, { results: (b.events || []).map((_, i) => ({ id: i + 1 })) }); }
        if (p === '/syn/v1/brief') { etat.synapse.briefs.push(b); return json(200, { texte: 'Audit précédent : la caméra de l’entrée avait déjà Telnet ouvert.' }); }
      }
      if (p.startsWith('/tg/')) {
        if (!p.includes(`/bot${JETON_TG}/`)) return json(401, { ok: false, description: 'Unauthorized' });
        etat.telegram.push(b);
        return json(200, { ok: true, result: {} });
      }
      if (p === '/ticket') {
        if (req.headers['x-ticket-key'] !== CLE_TICKET) return json(401, { erreur: 'clé' });
        etat.tickets.push(b);
        return json(201, { id: etat.tickets.length });
      }
      json(404, { error: 'inconnu' });
    });
  });
  return { serveur, etat, jetons: { mml: jetonMml, nxr: jetonNxr, syn: jetonSyn } };
}

/** La sonde TLS des essais : un certificat expiré et TLS 1.0 accepté sur le NAS. */
export async function fausseSonde(ip, port) {
  if (ip === '192.0.2.10' && port === 443) return { joignable: true, protocole: 'TLSv1.2', ancienAccepte: 'TLSv1', cert: { sujet: 'nas', emetteur: 'nas', debut: Date.now() - 800 * 86400e3, fin: Date.now() - 3 * 86400e3, autoSigne: true, cle: 2048 } };
  return { joignable: false, erreur: 'ECONNREFUSED' };
}
