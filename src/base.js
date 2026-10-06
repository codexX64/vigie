// Base de VIGIE : audits et leurs constats, événements de la veille, actions
// de remédiation (avec l'état d'avant, pour les défaire), compteurs de l'IA et
// réglages. Les secrets des réglages (clé d'IA en nuage, jeton docker-control)
// sont scellés par le Coffre du socle : la base seule ne les rend pas.
import { DatabaseSync } from 'node:sqlite';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const REF = /^[A-Za-z0-9_-]{12}$/;
export const nouvelleRef = () => crypto.randomBytes(9).toString('base64url');

export const GRAVITES = ['safe', 'info', 'faible', 'eleve', 'critique'];
export const RANG = Object.fromEntries(GRAVITES.map((g, i) => [g, i]));
// Les types d'appareils que la réaction rapide peut isoler par défaut : jamais
// l'infrastructure (routeur, pare-feu, commutateur, serveur, NAS, hyperviseur).
export const TYPES_ISOLABLES = ['unknown', 'iot', 'sensor', 'phone', 'tablet', 'pc', 'computer', 'laptop', 'camera', 'tv', 'console', 'voip', 'printer'];
export const TYPES_PROTEGES = ['router', 'firewall', 'switch', 'ap', 'server', 'nas', 'hypervisor', 'docker', 'vm', 'container'];

const MAX_AUDITS = 200;
const MAX_EVENEMENTS = 5000;

export function ouvrirBase(dossier) {
  fs.mkdirSync(dossier, { recursive: true, mode: 0o700 });
  const fichier = path.join(dossier, 'vigie.db');
  fs.closeSync(fs.openSync(fichier, 'a', 0o600));
  for (const f of [fichier, fichier + '-wal', fichier + '-shm']) if (fs.existsSync(f)) fs.chmodSync(f, 0o600);
  const db = new DatabaseSync(fichier);
  db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000; PRAGMA synchronous = NORMAL;');
  db.exec(`
    CREATE TABLE IF NOT EXISTS audits(
      id TEXT PRIMARY KEY, debut INTEGER NOT NULL, fin INTEGER, statut TEXT NOT NULL,
      declencheur TEXT NOT NULL, auteur TEXT NOT NULL DEFAULT '',
      score INTEGER, domaines TEXT NOT NULL DEFAULT '{}', distribution TEXT NOT NULL DEFAULT '{}',
      sources TEXT NOT NULL DEFAULT '{}', ia TEXT NOT NULL DEFAULT '{}', erreur TEXT);
    CREATE TABLE IF NOT EXISTS constats(
      id TEXT PRIMARY KEY, audit_id TEXT NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
      cle TEXT NOT NULL, regle TEXT NOT NULL, ref TEXT NOT NULL, domaine TEXT NOT NULL,
      gravite TEXT NOT NULL, titre TEXT NOT NULL, sujet TEXT NOT NULL DEFAULT '', sujet_id TEXT,
      preuve TEXT NOT NULL DEFAULT '{}', correction TEXT NOT NULL DEFAULT '', action TEXT,
      ia_statut TEXT, ia_note TEXT);
    CREATE INDEX IF NOT EXISTS constats_audit ON constats(audit_id);
    CREATE TABLE IF NOT EXISTS evenements(
      id TEXT PRIMARY KEY, quand INTEGER NOT NULL, gravite TEXT NOT NULL, type TEXT NOT NULL,
      titre TEXT NOT NULL, texte TEXT NOT NULL DEFAULT '', sujet TEXT NOT NULL DEFAULT '',
      cle TEXT NOT NULL DEFAULT '', acquitte INTEGER, acquitte_par TEXT);
    CREATE INDEX IF NOT EXISTS evenements_quand ON evenements(quand);
    CREATE TABLE IF NOT EXISTS actions(
      id TEXT PRIMARY KEY, quand INTEGER NOT NULL, type TEXT NOT NULL, cible TEXT NOT NULL,
      cible_nom TEXT NOT NULL DEFAULT '', auteur TEXT NOT NULL, motif TEXT NOT NULL DEFAULT '',
      automatique INTEGER NOT NULL DEFAULT 0, etat TEXT NOT NULL, avant TEXT NOT NULL DEFAULT '{}',
      resultat TEXT NOT NULL DEFAULT '', annulee_par TEXT, annulee_le INTEGER);
    CREATE TABLE IF NOT EXISTS ia_usage(jour TEXT PRIMARY KEY, appels INTEGER NOT NULL, jetons INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS reglages(cle TEXT PRIMARY KEY, valeur TEXT NOT NULL);
  `);
  return db;
}

export const DEFAUTS = {
  // L'IA : aucune par défaut. Locale = l'Ollama que le Hub relie ; en nuage =
  // une clé à soi. « les-deux » : la locale relit, le nuage tranche et rédige ;
  // « secours » : la locale, et le nuage seulement si elle échoue.
  ia: { mode: 'aucune', fournisseur: 'anthropic', modeleCloud: '', modeleLocal: '', cle: null, appelsJour: 20, jetonsJour: 200000 },
  veille: { actif: true, minutes: 15, auditQuotidien: true, heure: 3, sondeTls: true },
  // Réaction rapide : coupée tant que l'administrateur ne l'a pas allumée.
  // seuil : score de danger (MapMyLAN) à partir duquel un appareil suspect est isolé.
  reaction: { actif: false, types: TYPES_ISOLABLES, parHeure: 3, seuil: 85 },
  docker: { jeton: null },
  // Adresses (IPv4 ou CIDR) que VIGIE ne sonde pas et sur lesquelles il n'agit jamais.
  perimetre: { exclus: [] },
  // Billetterie (Aselia ou autre) au format ticket/v1, et Telegram : à partir de quelle gravité.
  billetterie: { url: '', cle: null, entete: 'X-Ticket-Key', marqueur: 'ticket', seuil: 'eleve' },
  telegram: { jeton: null, chat: '', seuil: 'eleve' },
};
const SCELLES = { ia: ['cle'], docker: ['jeton'], billetterie: ['cle'], telegram: ['jeton'] };

const json = (s, defaut) => { try { return s ? JSON.parse(s) : defaut; } catch { return defaut; } };

export class Magasin {
  constructor(db, { coffre }) { this.db = db; this.coffre = coffre; }

  // ---- réglages ----
  reglage(nom) {
    const l = this.db.prepare('SELECT valeur FROM reglages WHERE cle = ?').get(nom);
    return { ...DEFAUTS[nom], ...json(l?.valeur, {}) };
  }
  poserReglage(nom, valeur) {
    const fusion = { ...this.reglage(nom), ...valeur };
    this.db.prepare('INSERT INTO reglages(cle, valeur) VALUES(?, ?) ON CONFLICT(cle) DO UPDATE SET valeur = excluded.valeur').run(nom, JSON.stringify(fusion));
    return fusion;
  }
  secret(nom, champ) {
    const s = this.reglage(nom)[champ];
    return s ? this.coffre.ouvre(`${nom}.${champ}`, s) : '';
  }
  poserSecret(nom, champ, clair) {
    this.poserReglage(nom, { [champ]: clair ? this.coffre.scelle(`${nom}.${champ}`, clair) : null });
  }
  /** Les réglages tels qu'une interface peut les lire : un secret dit seulement s'il est posé. */
  reglagePublic(nom) {
    const r = this.reglage(nom);
    for (const champ of SCELLES[nom] || []) r[champ] = !!r[champ];
    return r;
  }
  /** Un état interne (mémoire de la veille), hors des réglages publics. */
  memoire(nom, defaut = null) { return json(this.db.prepare('SELECT valeur FROM reglages WHERE cle = ?').get(`_${nom}`)?.valeur, defaut); }
  poserMemoire(nom, valeur) { this.db.prepare('INSERT INTO reglages(cle, valeur) VALUES(?, ?) ON CONFLICT(cle) DO UPDATE SET valeur = excluded.valeur').run(`_${nom}`, JSON.stringify(valeur)); }

  // ---- audits ----
  ouvrirAudit({ declencheur, auteur = '' }) {
    const id = nouvelleRef();
    this.db.prepare("INSERT INTO audits(id, debut, statut, declencheur, auteur) VALUES(?, ?, 'en cours', ?, ?)").run(id, Date.now(), declencheur, auteur);
    return id;
  }
  enregistrerConstats(auditId, constats) {
    const ins = this.db.prepare(`INSERT INTO constats(id, audit_id, cle, regle, ref, domaine, gravite, titre, sujet, sujet_id, preuve, correction, action)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`);
    this.db.exec('BEGIN');
    try {
      for (const c of constats) ins.run(nouvelleRef(), auditId, c.cle, c.regle, c.ref, c.domaine, c.gravite, c.titre.slice(0, 300), String(c.sujet || '').slice(0, 200),
        c.sujetId ?? null, JSON.stringify(c.preuve || {}), String(c.correction || '').slice(0, 4000), c.action ? JSON.stringify(c.action) : null);
      this.db.exec('COMMIT');
    } catch (e) { this.db.exec('ROLLBACK'); throw e; }
  }
  fermerAudit(id, { statut, score = null, domaines = {}, distribution = {}, sources = {}, erreur = null }) {
    this.db.prepare('UPDATE audits SET fin = ?, statut = ?, score = ?, domaines = ?, distribution = ?, sources = ?, erreur = ? WHERE id = ?')
      .run(Date.now(), statut, score, JSON.stringify(domaines), JSON.stringify(distribution), JSON.stringify(sources), erreur, id);
    // Les plus anciens partent : l'historique reste borné.
    this.db.prepare('DELETE FROM audits WHERE id NOT IN (SELECT id FROM audits ORDER BY debut DESC, rowid DESC LIMIT ?)').run(MAX_AUDITS);
  }
  poserIA(id, ia) { this.db.prepare('UPDATE audits SET ia = ? WHERE id = ?').run(JSON.stringify(ia), id); }
  /** Au démarrage : un audit ou une relecture qu'un arrêt a coupés ne restent pas « en cours » pour toujours. */
  reprendreInterrompus(maintenant = Date.now()) {
    const n = this.db.prepare("UPDATE audits SET statut = 'echec', fin = ?, erreur = 'interrompu par un redémarrage de VIGIE' WHERE statut = 'en cours'").run(maintenant).changes;
    let ia = 0;
    for (const a of this.db.prepare("SELECT id, ia FROM audits WHERE ia LIKE '%\"en cours\"%'").all()) {
      const v = json(a.ia, {});
      if (v.statut === 'en cours') { this.poserIA(a.id, { statut: 'ignoree', raison: 'relecture interrompue par un redémarrage' }); ia++; }
    }
    return { audits: n, relectures: ia };
  }
  verdictIA(constatId, statut, note) { this.db.prepare('UPDATE constats SET ia_statut = ?, ia_note = ? WHERE id = ?').run(statut, note, constatId); }

  ligneAudit(a) {
    return a && { id: a.id, debut: a.debut, fin: a.fin, statut: a.statut, declencheur: a.declencheur, auteur: a.auteur, score: a.score,
      domaines: json(a.domaines, {}), distribution: json(a.distribution, {}), sources: json(a.sources, {}), ia: json(a.ia, {}), erreur: a.erreur };
  }
  audit(id) { return this.ligneAudit(this.db.prepare('SELECT * FROM audits WHERE id = ?').get(id)); }
  dernierAudit() { return this.ligneAudit(this.db.prepare("SELECT * FROM audits WHERE statut = 'termine' ORDER BY debut DESC, rowid DESC LIMIT 1").get()); }
  auditEnCours() { return this.ligneAudit(this.db.prepare("SELECT * FROM audits WHERE statut = 'en cours' ORDER BY debut DESC, rowid DESC LIMIT 1").get()); }
  audits(limite = 50) { return this.db.prepare('SELECT * FROM audits ORDER BY debut DESC, rowid DESC LIMIT ?').all(limite).map(a => this.ligneAudit(a)); }
  /** Score et date des audits terminés, du plus ancien au plus récent : la tendance. */
  historique(limite = 60) {
    return this.db.prepare("SELECT debut, score FROM audits WHERE statut = 'termine' ORDER BY debut DESC, rowid DESC LIMIT ?").all(limite).reverse();
  }

  ligneConstat(c) {
    return c && { id: c.id, auditId: c.audit_id, cle: c.cle, regle: c.regle, ref: c.ref, domaine: c.domaine, gravite: c.gravite, titre: c.titre,
      sujet: c.sujet, sujetId: c.sujet_id, preuve: json(c.preuve, {}), correction: c.correction, action: json(c.action, null), ia: c.ia_statut ? { statut: c.ia_statut, note: c.ia_note } : null };
  }
  constats(auditId) {
    return this.db.prepare(`SELECT * FROM constats WHERE audit_id = ? ORDER BY CASE gravite WHEN 'critique' THEN 0 WHEN 'eleve' THEN 1 WHEN 'faible' THEN 2 WHEN 'info' THEN 3 ELSE 4 END, domaine, titre`).all(auditId).map(c => this.ligneConstat(c));
  }
  constat(id) { return this.ligneConstat(this.db.prepare('SELECT * FROM constats WHERE id = ?').get(id)); }

  // ---- événements de la veille ----
  evenement({ gravite, type, titre, texte = '', sujet = '', cle = '' }) {
    const id = nouvelleRef();
    this.db.prepare('INSERT INTO evenements(id, quand, gravite, type, titre, texte, sujet, cle) VALUES(?,?,?,?,?,?,?,?)')
      .run(id, Date.now(), gravite, type, titre.slice(0, 300), String(texte).slice(0, 2000), String(sujet).slice(0, 200), String(cle).slice(0, 300));
    this.db.prepare('DELETE FROM evenements WHERE id NOT IN (SELECT id FROM evenements ORDER BY quand DESC LIMIT ?)').run(MAX_EVENEMENTS);
    return id;
  }
  evenements({ limite = 100, depuis = 0 } = {}) {
    return this.db.prepare('SELECT * FROM evenements WHERE quand >= ? ORDER BY quand DESC LIMIT ?').all(depuis, limite)
      .map(e => ({ id: e.id, quand: e.quand, gravite: e.gravite, type: e.type, titre: e.titre, texte: e.texte, sujet: e.sujet, acquitte: e.acquitte || null, acquittePar: e.acquitte_par || null }));
  }
  acquitter(id, qui) {
    return this.db.prepare('UPDATE evenements SET acquitte = ?, acquitte_par = ? WHERE id = ? AND acquitte IS NULL').run(Date.now(), qui, id).changes > 0;
  }

  // ---- actions de remédiation ----
  noterAction({ type, cible, cibleNom = '', auteur, motif = '', automatique = false, etat, avant = {}, resultat = '' }) {
    const id = nouvelleRef();
    this.db.prepare('INSERT INTO actions(id, quand, type, cible, cible_nom, auteur, motif, automatique, etat, avant, resultat) VALUES(?,?,?,?,?,?,?,?,?,?,?)')
      .run(id, Date.now(), type, cible, cibleNom, auteur, motif.slice(0, 300), automatique ? 1 : 0, etat, JSON.stringify(avant), String(resultat).slice(0, 1000));
    return this.action(id);
  }
  ligneAction(a) {
    return a && { id: a.id, quand: a.quand, type: a.type, cible: a.cible, cibleNom: a.cible_nom, auteur: a.auteur, motif: a.motif, automatique: !!a.automatique,
      etat: a.etat, avant: json(a.avant, {}), resultat: a.resultat, annuleePar: a.annulee_par || null, annuleeLe: a.annulee_le || null };
  }
  action(id) { return this.ligneAction(this.db.prepare('SELECT * FROM actions WHERE id = ?').get(id)); }
  actions(limite = 100) { return this.db.prepare('SELECT * FROM actions ORDER BY quand DESC LIMIT ?').all(limite).map(a => this.ligneAction(a)); }
  annulerAction(id, qui, resultat) {
    this.db.prepare("UPDATE actions SET etat = 'annulee', annulee_par = ?, annulee_le = ?, resultat = ? WHERE id = ?").run(qui, Date.now(), String(resultat).slice(0, 1000), id);
    return this.action(id);
  }
  /** Les isolements automatiques de la dernière heure : la réaction rapide est bornée. */
  automatiquesRecentes(ms = 3600e3) { return this.db.prepare('SELECT COUNT(*) n FROM actions WHERE automatique = 1 AND quand > ?').get(Date.now() - ms).n; }

  // ---- compteurs de l'IA (plafond quotidien) ----
  usageIA(jour = new Date().toISOString().slice(0, 10)) { return this.db.prepare('SELECT appels, jetons FROM ia_usage WHERE jour = ?').get(jour) || { appels: 0, jetons: 0 }; }
  compterIA(jetons, jour = new Date().toISOString().slice(0, 10)) {
    this.db.prepare('INSERT INTO ia_usage(jour, appels, jetons) VALUES(?, 1, ?) ON CONFLICT(jour) DO UPDATE SET appels = appels + 1, jetons = jetons + excluded.jetons').run(jour, Math.max(0, Math.round(jetons || 0)));
    this.db.prepare('DELETE FROM ia_usage WHERE jour < ?').run(new Date(Date.now() - 90 * 86400e3).toISOString().slice(0, 10));
  }
}
