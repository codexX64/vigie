// Le rapport PDF, écrit à la main : deux polices standard (Helvetica et sa
// graisse, présentes dans tout lecteur), du texte, des rectangles et des
// tracés. Aucune dépendance, aucune métadonnée d'auteur.
import zlib from 'node:zlib';
import { DOMAINES, LIBELLE_GRAVITE, REGLES } from './regles.js';
import { GRAVITES } from './base.js';

// ---------- écriture ----------
// Largeurs Helvetica / Helvetica-Bold (AFM, millièmes de cadratin) de 32 à 126.
const L_REG = [278,278,355,556,556,889,667,191,333,333,389,584,278,333,278,278,556,556,556,556,556,556,556,556,556,556,278,278,584,584,584,556,1015,667,667,722,722,667,611,778,722,278,500,667,556,833,722,778,667,778,722,667,611,722,667,944,667,667,611,278,278,278,469,556,333,556,556,500,556,556,278,556,556,222,222,500,222,833,556,556,556,556,333,500,278,556,500,722,500,500,500,334,260,334,584];
const L_GRAS = [278,333,474,556,556,889,722,238,333,333,389,584,278,333,278,278,556,556,556,556,556,556,556,556,556,556,333,333,584,584,584,611,975,722,722,722,722,667,611,778,722,278,556,722,611,833,722,778,667,778,722,667,611,722,667,944,667,667,611,333,278,333,584,556,333,556,611,556,611,556,333,611,611,278,278,556,278,889,611,611,611,611,389,556,333,611,556,778,556,556,500,389,280,389,584];
// Unicode → WinAnsi (octet) pour ce qui sort de Latin-1 ; largeur en millièmes.
const SPECIAUX = { '’': [0x92, 222], '‘': [0x91, 222], '“': [0x93, 333], '”': [0x94, 333], '—': [0x97, 1000], '–': [0x96, 556], '…': [0x85, 1000], '€': [0x80, 556], 'œ': [0x9c, 944], 'Œ': [0x8c, 1000], '•': [0x95, 350], '™': [0x99, 1000] };

function octet(c) {
  if (SPECIAUX[c]) return SPECIAUX[c][0];
  const n = c.codePointAt(0);
  if (n >= 32 && n <= 126) return n;
  if (n >= 160 && n <= 255) return n;
  if (n === 0x202f || n === 0x2009) return 32; // espaces fines
  return 63; // « ? »
}
function largeurCar(c, gras) {
  if (SPECIAUX[c]) return SPECIAUX[c][1];
  const n = c.codePointAt(0);
  const t = gras ? L_GRAS : L_REG;
  if (n >= 32 && n <= 126) return t[n - 32];
  if (n === 0xab || n === 0xbb) return 556;
  if (n === 0xb7) return 278;
  if (n === 0xb0) return 400;
  if (n === 0xa0) return 278;
  const base = c.normalize('NFD')[0];
  const b = base.codePointAt(0);
  return b >= 32 && b <= 126 ? t[b - 32] : 556;
}
export const largeur = (s, taille, gras = false) => [...String(s)].reduce((a, c) => a + largeurCar(c, gras), 0) * taille / 1000;

const chaine = s => {
  const o = [...String(s)].map(octet);
  return '(' + Buffer.from(o).toString('latin1').replace(/[\\()]/g, m => '\\' + m).replace(/[\r\n]/g, ' ') + ')';
};
const rvb = h => { const n = parseInt(h.slice(1), 16); return [(n >> 16) / 255, ((n >> 8) & 255) / 255, (n & 255) / 255].map(x => x.toFixed(3)).join(' '); };

export class Pdf {
  constructor({ titre = 'Document' } = {}) {
    this.L = 595.28; this.H = 841.89; this.marge = 46;
    this.titre = titre; this.pages = []; this.nouvellePage();
  }
  nouvellePage() { this.flux = []; this.pages.push(this.flux); this.y = this.marge; }
  // y depuis le haut de la page.
  Y(y) { return (this.H - y).toFixed(2); }
  texte(x, y, s, { taille = 10, gras = false, couleur = '#14161A' } = {}) {
    this.flux.push(`BT /${gras ? 'F2' : 'F1'} ${taille} Tf ${rvb(couleur)} rg ${x.toFixed(2)} ${this.Y(y)} Td ${chaine(s)} Tj ET`);
  }
  rect(x, y, l, h, couleur) { this.flux.push(`${rvb(couleur)} rg ${x.toFixed(2)} ${this.Y(y + h)} ${l.toFixed(2)} ${h.toFixed(2)} re f`); }
  trait(x1, y1, x2, y2, couleur = '#E5E5E0', epaisseur = 0.6) { this.flux.push(`${rvb(couleur)} RG ${epaisseur} w ${x1.toFixed(2)} ${this.Y(y1)} m ${x2.toFixed(2)} ${this.Y(y2)} l S`); }
  polyligne(points, couleur, epaisseur = 1.2) {
    if (points.length < 2) return;
    this.flux.push(`${rvb(couleur)} RG ${epaisseur} w 1 J 1 j ${points.map(([x, y], i) => `${x.toFixed(2)} ${this.Y(y)} ${i ? 'l' : 'm'}`).join(' ')} S`);
  }
  arc(cx, cy, r, de, a, couleur, epaisseur) {
    const n = Math.max(2, Math.ceil(Math.abs(a - de) / 4));
    const pts = Array.from({ length: n + 1 }, (_, i) => { const t = (de + (a - de) * i / n) * Math.PI / 180; return [cx + r * Math.cos(t), cy + r * Math.sin(t)]; });
    this.flux.push(`${rvb(couleur)} RG ${epaisseur} w 1 J ${pts.map(([x, y], i) => `${x.toFixed(2)} ${this.Y(y)} ${i ? 'l' : 'm'}`).join(' ')} S`);
  }
  /** Coupe un texte en lignes qui tiennent dans la largeur. */
  couper(s, l, taille, gras = false) {
    const out = [];
    for (const para of String(s || '').split(/\n/)) {
      let ligne = '';
      for (const mot of para.split(/\s+/).filter(Boolean)) {
        const essai = ligne ? `${ligne} ${mot}` : mot;
        if (largeur(essai, taille, gras) <= l) { ligne = essai; continue; }
        if (ligne) out.push(ligne);
        // Un mot plus long que la ligne est coupé au caractère.
        let m = mot;
        while (largeur(m, taille, gras) > l) {
          let i = m.length; while (i > 1 && largeur(m.slice(0, i), taille, gras) > l) i--;
          out.push(m.slice(0, i)); m = m.slice(i);
        }
        ligne = m;
      }
      out.push(ligne);
    }
    return out;
  }
  /** Réserve une hauteur ; change de page si elle ne tient pas. */
  place(h) { if (this.y + h > this.H - this.marge - 20) this.nouvellePage(); }
  paragraphe(s, { taille = 9.5, gras = false, couleur = '#3E434A', x = this.marge, l = this.L - 2 * this.marge, interligne = 1.38 } = {}) {
    for (const ligne of this.couper(s, l, taille, gras)) {
      this.place(taille * interligne);
      this.texte(x, this.y + taille, ligne, { taille, gras, couleur });
      this.y += taille * interligne;
    }
  }

  fin(pied) {
    const objets = [];
    const ajout = s => { objets.push(s); return objets.length; };
    const catalogue = ajout(null), pagesId = ajout(null);
    const f1 = ajout('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>');
    const f2 = ajout('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>');
    const ids = [];
    this.pages.forEach((flux, i) => {
      const p = new Pdf(); p.flux = [...flux];
      if (pied) {
        const t = pied(i + 1, this.pages.length);
        p.texte(this.marge, this.H - 26, t, { taille: 7.5, couleur: '#858B93' });
      }
      const brut = zlib.deflateSync(Buffer.from(p.flux.join('\n'), 'latin1'));
      const contenu = ajout({ dict: `<< /Length ${brut.length} /Filter /FlateDecode >>`, flux: brut });
      ids.push(ajout(`<< /Type /Page /Parent ${pagesId} 0 R /MediaBox [0 0 ${this.L} ${this.H}] /Resources << /Font << /F1 ${f1} 0 R /F2 ${f2} 0 R >> >> /Contents ${contenu} 0 R >>`));
    });
    objets[catalogue - 1] = `<< /Type /Catalog /Pages ${pagesId} 0 R >>`;
    objets[pagesId - 1] = `<< /Type /Pages /Kids [${ids.map(i => `${i} 0 R`).join(' ')}] /Count ${ids.length} >>`;
    const d = new Date();
    const date = `D:${d.toISOString().replace(/[-:T]/g, '').slice(0, 14)}Z`;
    // Les métadonnées sont en PDFDocEncoding, pas en WinAnsi : le titre part en UTF-16.
    const titre = `<FEFF${Buffer.from(this.titre, 'utf16le').swap16().toString('hex').toUpperCase()}>`;
    const info = ajout(`<< /Title ${titre} /Producer (VIGIE) /CreationDate (${date}) >>`);
    const morceaux = [Buffer.from('%PDF-1.4\n%\xe2\xe3\xcf\xd3\n', 'latin1')];
    let pos = morceaux[0].length;
    const xref = [];
    objets.forEach((o, i) => {
      xref.push(pos);
      const tete = Buffer.from(`${i + 1} 0 obj\n`, 'latin1');
      const corps = typeof o === 'string' ? Buffer.from(`${o}\nendobj\n`, 'latin1')
        : Buffer.concat([Buffer.from(`${o.dict}\nstream\n`, 'latin1'), o.flux, Buffer.from('\nendstream\nendobj\n', 'latin1')]);
      morceaux.push(tete, corps); pos += tete.length + corps.length;
    });
    const table = `xref\n0 ${objets.length + 1}\n0000000000 65535 f \n${xref.map(p => `${String(p).padStart(10, '0')} 00000 n \n`).join('')}trailer\n<< /Size ${objets.length + 1} /Root ${catalogue} 0 R /Info ${info} 0 R >>\nstartxref\n${pos}\n%%EOF\n`;
    morceaux.push(Buffer.from(table, 'latin1'));
    return Buffer.concat(morceaux);
  }
}

// ---------- le rapport ----------
export const COULEUR = { safe: '#2F8F5B', info: '#3B6FD8', faible: '#B7791F', eleve: '#D9622B', critique: '#C8322B' };
const ENCRE = '#14161A', DOUX = '#3E434A', PALE = '#858B93', FILET = '#E5E5E0', PUITS = '#F1F1ED';
export const couleurScore = s => (s === null || s === undefined ? PALE : s >= 80 ? COULEUR.safe : s >= 60 ? COULEUR.faible : s >= 40 ? COULEUR.eleve : COULEUR.critique);
const date = t => new Date(t).toLocaleString('fr-FR', { timeZone: 'UTC', dateStyle: 'long', timeStyle: 'short' }) + ' UTC';
const STATUT_IA = { confirme: 'confirmé par l’IA', nuance: 'nuancé par l’IA', ecarte: 'écarté par l’IA (faux positif probable)' };

function titreSection(doc, t) {
  // Un titre ne reste jamais seul en bas de page : il emmène au moins une ligne.
  doc.place(80);
  doc.y += 14;
  doc.texte(doc.marge, doc.y + 12, t, { taille: 13, gras: true, couleur: ENCRE });
  doc.y += 20;
  doc.trait(doc.marge, doc.y, doc.L - doc.marge, doc.y);
  doc.y += 10;
}

const DATES = new Set(['fin', 'debut', 'vu', 'quand']);
function preuveTexte(p) {
  if (!p || typeof p !== 'object') return '';
  const parts = [];
  for (const [k, v] of Object.entries(p)) {
    if (v === null || v === undefined || v === '') continue;
    if (DATES.has(k) && typeof v === 'number') { parts.push(`${k} : ${new Date(v).toISOString().slice(0, 16).replace('T', ' ')} UTC`); continue; }
    const val = Array.isArray(v) ? v.slice(0, 6).map(x => (typeof x === 'object' ? Object.values(x).filter(y => y !== null && y !== undefined).join(' ') : x)).join(', ')
      : typeof v === 'object' ? JSON.stringify(v).slice(0, 120) : String(v);
    parts.push(`${k} : ${val}`);
  }
  return parts.join(' · ').slice(0, 600);
}

/**
 * Le rapport d'un audit : synthèse, graphiques, puis chaque constat.
 * audit : ligne d'audit ; constats ; historique : [{ debut, score }].
 */
export function rapportPdf({ audit, constats, historique = [], precedent = null }) {
  const doc = new Pdf({ titre: `Rapport d’audit VIGIE — ${new Date(audit.debut).toISOString().slice(0, 10)}` });
  const M = doc.marge, LARG = doc.L - 2 * M;

  // En-tête
  doc.texte(M, doc.y + 10, 'VIGIE', { taille: 9, gras: true, couleur: PALE });
  doc.texte(M, doc.y + 34, 'Rapport d’audit de sécurité', { taille: 22, gras: true, couleur: ENCRE });
  doc.texte(M, doc.y + 52, `${date(audit.debut)} · déclenché par ${audit.declencheur}${audit.auteur ? ` (${audit.auteur})` : ''} · réf. ${audit.id}`, { taille: 9, couleur: PALE });
  doc.y += 70;

  // Score et domaines
  const cx = M + 62, cy = doc.y + 64, r = 50;
  doc.arc(cx, cy, r, 135, 405, PUITS, 11);
  if (audit.score !== null) doc.arc(cx, cy, r, 135, 135 + 270 * audit.score / 100, couleurScore(audit.score), 11);
  const s = audit.score === null ? '—' : String(audit.score);
  doc.texte(cx - largeur(s, 30, true) / 2, cy + 8, s, { taille: 30, gras: true, couleur: ENCRE });
  doc.texte(cx - largeur('SCORE / 100', 7.5) / 2, cy + 22, 'SCORE / 100', { taille: 7.5, couleur: PALE });
  if (precedent?.score !== null && precedent?.score !== undefined && audit.score !== null) {
    const dlt = audit.score - precedent.score;
    const t = dlt === 0 ? 'stable depuis le dernier audit' : `${dlt > 0 ? '+' : ''}${dlt} depuis le dernier audit`;
    doc.texte(cx - largeur(t, 8) / 2, cy + 64, t, { taille: 8, couleur: dlt < 0 ? COULEUR.eleve : dlt > 0 ? COULEUR.safe : PALE });
  }
  const x0 = M + 150, lb = LARG - 150 - 40;
  let yd = doc.y + 6;
  for (const [k, nom] of Object.entries(DOMAINES)) {
    const d = audit.domaines[k];
    const ne = d?.score === null || d?.score === undefined;
    const v = ne ? 'non évalué' : String(d.score);
    const lv = largeur(v, ne ? 7.5 : 9, !ne);
    doc.texte(x0, yd + 9, nom, { taille: 9, couleur: DOUX });
    doc.texte(x0 + lb + 34 - lv, yd + 9, v, { taille: ne ? 7.5 : 9, gras: !ne, couleur: ne ? PALE : ENCRE });
    doc.rect(x0, yd + 13, lb + 34, 5, PUITS);
    if (!ne) doc.rect(x0, yd + 13, (lb + 34) * d.score / 100, 5, couleurScore(d.score));
    yd += 22;
  }
  doc.y = Math.max(cy + 76, yd) + 8;

  // Distribution
  const dist = audit.distribution || {};
  const total = GRAVITES.reduce((a, g) => a + (dist[g] || 0), 0) || 1;
  let xb = M;
  for (const g of GRAVITES) {
    const l = LARG * (dist[g] || 0) / total;
    if (l > 0) doc.rect(xb, doc.y, l, 9, COULEUR[g]);
    xb += l;
  }
  doc.y += 22;
  let xl = M;
  for (const g of [...GRAVITES].reverse()) {
    const t = `${dist[g] || 0} ${LIBELLE_GRAVITE[g]}`;
    doc.rect(xl, doc.y - 6, 7, 7, COULEUR[g]);
    doc.texte(xl + 11, doc.y, t, { taille: 9, couleur: DOUX });
    xl += largeur(t, 9) + 30;
  }
  doc.y += 10;

  // Évolution
  const pts = historique.filter(h => h.score !== null && h.score !== undefined);
  if (pts.length >= 2) {
    titreSection(doc, 'Évolution du score');
    doc.place(80);
    const hx = M, hy = doc.y, hl = LARG, hh = 60;
    for (const v of [0, 50, 100]) { const y = hy + hh - hh * v / 100; doc.trait(hx, y, hx + hl, y, FILET, 0.4); doc.texte(hx + hl + 4, y + 3, String(v), { taille: 6.5, couleur: PALE }); }
    const t0 = pts[0].debut, t1 = pts.at(-1).debut || t0 + 1;
    doc.polyligne(pts.map(p => [hx + hl * ((p.debut - t0) / Math.max(1, t1 - t0)), hy + hh - hh * p.score / 100]), '#1B2AFF', 1.4);
    doc.y = hy + hh + 8;
    doc.texte(M, doc.y + 6, new Date(t0).toISOString().slice(0, 10), { taille: 7, couleur: PALE });
    const fin = new Date(t1).toISOString().slice(0, 10);
    doc.texte(M + LARG - largeur(fin, 7), doc.y + 6, fin, { taille: 7, couleur: PALE });
    doc.y += 12;
  }

  // Priorités et synthèse
  const ia = audit.ia || {};
  const graves = constats.filter(c => c.gravite !== 'safe');
  // Les priorités du moteur ; les pistes de l'IA viennent à part, avec sa synthèse.
  const prio = (audit.priorites || []).map(p => ({ titre: p.titre, texte: `${p.sujet ? p.sujet + ' — ' : ''}${p.correction}` }));
  titreSection(doc, 'Priorités du moment');
  if (!prio.length) doc.paragraphe('Aucun écart à corriger en priorité.');
  prio.forEach((p, i) => {
    doc.place(30);
    doc.texte(M, doc.y + 10, `${i + 1}.`, { taille: 10, gras: true, couleur: ENCRE });
    doc.paragraphe(p.titre, { taille: 10, gras: true, couleur: ENCRE, x: M + 16, l: LARG - 16 });
    if (p.texte) doc.paragraphe(p.texte, { x: M + 16, l: LARG - 16 });
    doc.y += 4;
  });
  if (ia.synthese) {
    titreSection(doc, `Synthèse rédigée par l’IA (${ia.moteur === 'locale' ? 'locale' : ia.moteur === 'cloud' ? 'en nuage' : 'locale et en nuage'})`);
    doc.paragraphe(ia.synthese);
    for (const p of ia.priorites || []) {
      doc.place(24);
      doc.paragraphe(`Piste : ${p.titre}`, { taille: 9, gras: true, couleur: DOUX });
      if (p.pourquoi) doc.paragraphe(p.pourquoi, { taille: 9 });
    }
    for (const sc of ia.scenarios || []) {
      doc.y += 4;
      doc.paragraphe(`Scénario : ${sc.titre}`, { gras: true, couleur: ENCRE });
      doc.paragraphe(sc.explication);
    }
    doc.y += 2;
    doc.paragraphe('La relecture de l’IA n’a changé ni les gravités ni le score : ils viennent du moteur de règles.', { taille: 7.5, couleur: PALE });
  }

  // Sources
  titreSection(doc, 'Sources lues');
  const NOMS = { mapmylan: 'MapMyLAN', nexarc: 'NEXARC', docker: 'docker-control', tls: 'Sondes TLS', synapse: 'SYNAPSE' };
  for (const [k, v] of Object.entries(audit.sources || {})) {
    const t = !v.relie ? 'non reliée' : v.ok === false ? `en échec : ${v.erreur || 'inconnu'}` : v.ok ? `lue${v.n !== undefined ? ` (${v.n})` : ''}` : 'reliée';
    doc.place(14);
    doc.texte(M, doc.y + 9, NOMS[k] || k, { taille: 9, gras: true, couleur: DOUX });
    doc.texte(M + 110, doc.y + 9, t, { taille: 9, couleur: v.ok === false ? COULEUR.eleve : DOUX });
    doc.y += 14;
  }

  // Détail
  titreSection(doc, `Détail des écarts (${graves.length})`);
  if (!graves.length) doc.paragraphe('Aucun écart : tous les contrôles évalués sont conformes.');
  for (const c of graves) {
    doc.place(56);
    const g = LIBELLE_GRAVITE[c.gravite].toUpperCase();
    const lg = largeur(g, 7, true) + 10;
    doc.rect(M, doc.y + 1, lg, 11, COULEUR[c.gravite]);
    doc.texte(M + 5, doc.y + 9, g, { taille: 7, gras: true, couleur: '#FFFFFF' });
    doc.texte(M + lg + 8, doc.y + 9, `${DOMAINES[c.domaine]} · ${c.ref}`, { taille: 7.5, couleur: PALE });
    doc.y += 16;
    doc.paragraphe(c.titre, { taille: 10, gras: true, couleur: ENCRE });
    if (c.sujet) doc.paragraphe(`Concerne : ${c.sujet}`, { taille: 8.5 });
    const pv = preuveTexte(c.preuve);
    if (pv) doc.paragraphe(`Preuve : ${pv}`, { taille: 8, couleur: PALE });
    if (c.correction) doc.paragraphe(`Correction : ${c.correction}`, { taille: 8.5 });
    const etapes = ia.corrections?.[c.cle];
    if (etapes?.length) etapes.forEach((e, i) => doc.paragraphe(`${i + 1}. ${e}`, { taille: 8.5, x: M + 12, l: LARG - 12 }));
    if (c.ia) doc.paragraphe(`${STATUT_IA[c.ia.statut] || c.ia.statut}${c.ia.note ? ` — ${c.ia.note}` : ''}`, { taille: 8, couleur: c.ia.statut === 'ecarte' ? PALE : '#1B2AFF' });
    doc.y += 6;
    doc.trait(M, doc.y, doc.L - M, doc.y, '#EDEDE8', 0.4);
    doc.y += 6;
  }

  // Conformes, en une ligne chacun
  const conformes = constats.filter(c => c.gravite === 'safe');
  if (conformes.length) {
    titreSection(doc, `Contrôles conformes (${conformes.length})`);
    for (const c of conformes) {
      doc.place(12);
      doc.rect(M, doc.y + 3, 5, 5, COULEUR.safe);
      const t = `${c.sujet ? c.sujet + ' — ' : ''}${c.titre}`;
      const l = doc.couper(t, LARG - 120, 8)[0];
      doc.texte(M + 10, doc.y + 8.5, l, { taille: 8, couleur: DOUX });
      doc.texte(doc.L - M - largeur(c.ref, 7), doc.y + 8.5, c.ref, { taille: 7, couleur: PALE });
      doc.y += 11.5;
    }
  }

  // Annexe : le référentiel des règles
  titreSection(doc, 'Règles appliquées');
  const vues = new Set(constats.map(c => c.regle));
  for (const [id, r] of Object.entries(REGLES)) {
    if (!vues.has(id)) continue;
    doc.place(12);
    doc.texte(M, doc.y + 8.5, id, { taille: 7.5, couleur: PALE });
    doc.texte(M + 150, doc.y + 8.5, doc.couper(r.titre, LARG - 230, 8)[0], { taille: 8, couleur: DOUX });
    doc.texte(doc.L - M - largeur(r.ref, 7.5), doc.y + 8.5, r.ref, { taille: 7.5, couleur: PALE });
    doc.y += 11.5;
  }

  return doc.fin((n, total) => `VIGIE · audit ${audit.id} · ${new Date(audit.debut).toISOString().slice(0, 16).replace('T', ' ')} UTC · page ${n} / ${total}`);
}
