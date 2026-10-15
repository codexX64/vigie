// Pré-décodage d'une ligne de journal d'hôte, à la façon des analyseurs
// d'événements (OSSEC, Wazuh) : avant de chercher ce que la ligne dit, on
// sépare ce que tout journal porte — l'heure, l'hôte, le programme, son
// numéro de processus — du message lui-même. Les décodeurs (decodeurs.js) ne
// voient ensuite que le message, avec le programme comme première clé.
//
// Formats reconnus : syslog RFC 3164 (« Oct 14 10:00:00 hote prog[123]: … »),
// RFC 5424 (« 1 2026-10-14T10:00:00Z hote prog 123 - - … »), une ligne nue
// (« prog[123]: … » ou juste le message), et journald export (« hote prog[123]: »).

const MOIS = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
const PROG = /^([A-Za-z0-9_./-]{1,64})(?:\[(\d{1,10})\])?:\s/;

/** Date d'un en-tête 3164 (sans année : la plus proche dans le passé). */
function date3164(mois, jour, hms, maintenant) {
  const d = new Date(maintenant);
  const [h, m, s] = hms.split(':').map(Number);
  const c = new Date(Date.UTC(d.getUTCFullYear(), MOIS[mois], Number(jour), h, m, s));
  if (c.getTime() > maintenant + 86400e3) c.setUTCFullYear(c.getUTCFullYear() - 1);
  return c.getTime();
}

/**
 * → { quand, hote, programme, pid, message, brut }. hote et programme valent
 * '' quand la ligne ne les porte pas ; le message n'est jamais vide.
 */
export function predecoder(ligne, { maintenant = Date.now(), emetteur = '' } = {}) {
  const brut = String(ligne).replace(/\r?\n$/, '').slice(0, 8192);
  let s = brut.replace(/^\s*<\d{1,3}>/, '');
  let quand = maintenant, hote = '', programme = '', pid = null;

  // RFC 5424 : VERSION TIMESTAMP HOST APP PROCID MSGID [SD] MSG
  let m = /^1 (\S+) (\S+) (\S+) (\S+) (\S+) (?:-|(?:\[[^\]]*\])+) ?/.exec(s);
  if (m) {
    const t = Date.parse(m[1]); if (!Number.isNaN(t)) quand = t;
    hote = m[2] === '-' ? '' : m[2]; programme = m[3] === '-' ? '' : m[3]; pid = m[4] === '-' ? null : Number(m[4]) || null;
    s = s.slice(m[0].length);
  } else {
    // RFC 3164 : « Mmm dd hh:mm:ss hote … »
    m = /^([A-Z][a-z]{2}) {1,2}(\d{1,2}) (\d\d:\d\d:\d\d) (\S+) /.exec(s);
    if (m && MOIS[m[1]] !== undefined) { quand = date3164(m[1], m[2], m[3], maintenant); hote = m[4]; s = s.slice(m[0].length); }
    else {
      // ISO en tête (« 2026-10-14T10:00:00+00:00 hote … »), journald ou rsyslog moderne.
      m = /^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?) (\S+) /.exec(s);
      if (m) { const t = Date.parse(m[1]); if (!Number.isNaN(t)) quand = t; hote = m[2]; s = s.slice(m[0].length); }
    }
    const p = PROG.exec(s);
    if (p) { programme = p[1]; pid = p[2] ? Number(p[2]) : null; s = s.slice(p[0].length); }
  }
  // Un hôte qui se présente par son adresse IPv4 ou en « ::ffff: » : on garde la forme simple.
  hote = hote.replace(/^::ffff:/, '').slice(0, 253);
  if (!hote && emetteur) hote = emetteur;
  // journald : « hote nom_unite[pid]: » déjà couvert ; « kernel: [ 123.456] message » → on enlève l'horodatage noyau.
  if (programme === 'kernel') s = s.replace(/^\[\s*\d+\.\d+\]\s*/, '');
  return { quand, hote, programme, pid, message: s.trim(), brut };
}
