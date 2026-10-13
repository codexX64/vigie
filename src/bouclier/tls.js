// TLS vers la passerelle UniFi : son certificat est autosigné, son empreinte
// SHA-256, lue par une sonde et confirmée par un administrateur, devient son
// identité. Chaque connexion la revérifie avant d'écrire quoi que ce soit — la
// clé d'API ne part jamais vers une autre machine.
import tls from 'node:tls';
import https from 'node:https';
import net from 'node:net';

export function empreinte(certOuFp) {
  const brut = typeof certOuFp === 'string' ? certOuFp : (certOuFp?.fingerprint256 || '');
  return 'sha256:' + String(brut).replace(/^\s*sha-?256\s*[:=]?\s*/i, '').replace(/[^0-9a-fA-F]/g, '').toLowerCase();
}
export const empreinteValide = fp => /^sha256:[0-9a-f]{64}$/.test(empreinte(fp));

/**
 * La sonde : lire le certificat présenté, sans rien envoyer. Seule connexion
 * sans vérification, atteinte seulement par un administrateur sous renfort ;
 * elle ne rend que l'empreinte, le sujet et l'échéance.
 */
export function observer(hote, port, { timeout = 8000 } = {}) {
  return new Promise((resolve, reject) => {
    const s = tls.connect({ host: hote, port, servername: net.isIP(hote) ? undefined : hote, timeout, rejectUnauthorized: false }, () => {
      const c = s.getPeerCertificate(false);
      const autorite = s.authorized;
      s.end(); setTimeout(() => s.destroy(), 1000).unref();
      if (!c?.raw) return reject(new Error('aucun certificat présenté'));
      resolve({ fp: empreinte(c), sujet: String(c.subject?.CN || c.subject?.O || '').slice(0, 200), expire: c.valid_to || '', autorite });
    });
    s.once('timeout', () => { s.destroy(); reject(new Error('délai dépassé')); });
    s.once('error', reject);
  });
}

function connecter({ hote, port, fp }, { timeout = 15000 } = {}) {
  return new Promise((resolve, reject) => {
    const epingle = !!fp;
    if (epingle && !empreinteValide(fp)) return reject(new Error('empreinte invalide'));
    const s = tls.connect({ host: hote, port, servername: net.isIP(hote) ? undefined : hote, timeout, rejectUnauthorized: !epingle }, () => {
      s.setTimeout(0);
      if (epingle && empreinte(s.getPeerCertificate(false)) !== empreinte(fp)) {
        s.destroy();
        return reject(Object.assign(new Error('le certificat de la passerelle n’est plus celui épinglé'), { code: 'EEMPREINTE' }));
      }
      resolve(s);
    });
    s.once('timeout', () => { s.destroy(); reject(new Error('délai dépassé')); });
    s.once('error', reject);
  });
}

/** Une requête HTTPS sur une socket dont l'identité est vérifiée d'abord. */
export function requete({ hote, port, fp }, { methode = 'GET', chemin, entetes = {}, corps = null, timeout = 15000 }) {
  return new Promise((resolve, reject) => {
    const donnees = corps === null ? null : Buffer.from(JSON.stringify(corps));
    const req = https.request({
      host: hote, port, method: methode, path: chemin, timeout,
      headers: { Accept: 'application/json', ...(donnees ? { 'Content-Type': 'application/json', 'Content-Length': donnees.length } : {}), ...entetes },
      createConnection: (_o, rappel) => { connecter({ hote, port, fp }, { timeout }).then(s => rappel(null, s), rappel); },
    }, res => {
      const morceaux = []; let n = 0;
      res.on('data', d => { n += d.length; if (n > 8 * 1024 * 1024) req.destroy(new Error('réponse trop grande')); else morceaux.push(d); });
      res.on('end', () => {
        const brut = Buffer.concat(morceaux).toString('utf8');
        let json = null; try { json = brut ? JSON.parse(brut) : null; } catch { /* pas du JSON */ }
        resolve({ status: res.statusCode, json, brut: brut.slice(0, 2000) });
      });
    });
    req.on('timeout', () => req.destroy(new Error('délai dépassé')));
    req.on('error', reject);
    if (donnees) req.write(donnees);
    req.end();
  });
}
