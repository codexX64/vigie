// Renseignement sur les menaces : des listes publiques d'adresses et de
// domaines malveillants (serveurs de commande de botnets, réseaux détournés,
// sources de force brute, sites de logiciels malveillants), téléchargées
// toutes les quelques heures et gardées sur le volume, pour qu'un
// redémarrage sans Internet ne laisse pas VIGIE aveugle.
//
// Ces listes ne bloquent rien à elles seules : elles pèsent dans le score
// d'une adresse que VIGIE voit vraiment passer (corrélation.js). C'est
// l'approche d'un « bouncer » : on bloque ce qui frappe, pas un million
// d'adresses par précaution — le pare-feu d'une passerelle n'en tiendrait pas autant.
import fs from 'node:fs';
import path from 'node:path';
import { EnsembleIp, estPublique } from './ip.js';
import { lireBorne } from '../lecture.js';
import { verifierDestination } from '../destination.js';

// id → définition. « poids » : ce qu'une présence sur la liste ajoute au score
// d'une adresse vue (100 = blocage immédiat).
export const FLUX = {
  'spamhaus-drop': { nom: 'Spamhaus DROP', type: 'ip', format: 'spamhaus', url: 'https://www.spamhaus.org/drop/drop_v4.json', poids: 100, defaut: true, sujet: 'réseaux détournés ou tenus par des criminels' },
  'feodo': { nom: 'abuse.ch Feodo Tracker', type: 'ip', format: 'lignes', url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt', poids: 100, defaut: true, sujet: 'serveurs de commande de botnets (Dridex, Emotet, QakBot…)' },
  'et-compromis': { nom: 'Emerging Threats, adresses compromises', type: 'ip', format: 'lignes', url: 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt', poids: 60, defaut: true, sujet: 'machines compromises connues' },
  'cins-army': { nom: 'CINS Army', type: 'ip', format: 'lignes', url: 'https://cinsscore.com/list/ci-badguys.txt', poids: 50, defaut: true, sujet: 'adresses au comportement hostile relevé par des capteurs' },
  'blocklist-de': { nom: 'blocklist.de', type: 'ip', format: 'lignes', url: 'https://lists.blocklist.de/lists/all.txt', poids: 40, defaut: true, sujet: 'force brute SSH, mail, web relevée par des pots de miel' },
  'urlhaus': { nom: 'abuse.ch URLhaus', type: 'domaine', format: 'hosts', url: 'https://urlhaus.abuse.ch/downloads/hostfile/', poids: 100, defaut: true, sujet: 'domaines qui distribuent des logiciels malveillants' },
  'threatfox': { nom: 'abuse.ch ThreatFox', type: 'domaine', format: 'hosts', url: 'https://threatfox.abuse.ch/downloads/hostfile/', poids: 100, defaut: true, sujet: 'domaines de commande et de vol de données' },
  'hagezi-tif': { nom: 'HaGeZi Threat Intelligence (moyenne)', type: 'domaine', format: 'lignes', url: 'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.medium-onlydomains.txt', poids: 80, defaut: false, sujet: 'hameçonnage, arnaques, logiciels malveillants (≈ 300 000 domaines, beaucoup de mémoire)' },
};

const TAILLE_MAX = 40 * 1024 * 1024;
const DOMAINE = /^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$/;

/** Les entrées d'une liste, selon son format. Les adresses non publiques sont toujours écartées. */
export function lire(def, texte) {
  const ips = [], domaines = [];
  if (def.format === 'spamhaus') {
    for (const l of texte.split('\n')) {
      let o; try { o = JSON.parse(l); } catch { continue; }
      if (o?.cidr) ips.push(o.cidr);
    }
  } else {
    for (let l of texte.split('\n')) {
      l = l.replace(/[#;].*$/, '').trim();
      if (!l) continue;
      if (def.format === 'hosts') { const c = l.split(/\s+/); l = c[1] || c[0]; }
      else l = l.split(/\s+/)[0];
      if (def.type === 'ip') ips.push(l);
      else { const d = l.toLowerCase().replace(/^\*\./, '').replace(/\.$/, ''); if (DOMAINE.test(d) && d !== 'localhost') domaines.push(d); }
    }
  }
  return { ips: ips.filter(x => estPublique(x.split('/')[0])), domaines };
}

export class Menaces {
  constructor({ dossier, magasin, fetch: f = globalThis.fetch, maintenant = () => Date.now(), log = console, resoudre }) {
    Object.assign(this, { dossier: path.join(dossier, 'menaces'), magasin, fetch: f, maintenant, log, resoudre });
    fs.mkdirSync(this.dossier, { recursive: true, mode: 0o700 });
    this.ip = new Map();        // id → EnsembleIp
    this.dom = new Map();       // id → Set
    this.etat = this.magasin.memoire('menaces_etat', {});
    for (const id of Object.keys(this.definitions())) this.charger(id);
  }

  definitions() {
    const r = this.magasin.reglage('bouclier');
    const propres = Object.fromEntries((r.listesPropres || []).map((l, i) => [`propre-${i + 1}`, { nom: l.nom, type: l.type, format: 'lignes', url: l.url, poids: l.poids, defaut: true, sujet: 'liste ajoutée par un administrateur', propre: true }]));
    return { ...FLUX, ...propres };
  }
  actives() {
    const r = this.magasin.reglage('bouclier');
    const defs = this.definitions();
    return Object.fromEntries(Object.entries(defs).filter(([id, d]) => r.listes?.[id] ?? d.defaut));
  }

  fichier(id) { return path.join(this.dossier, `${id}.txt`); }
  charger(id, texte = null) {
    const def = this.definitions()[id];
    if (!def) return;
    if (texte === null) { try { texte = fs.readFileSync(this.fichier(id), 'utf8'); } catch { return; } }
    const { ips, domaines } = lire(def, texte);
    if (def.type === 'ip') { const e = new EnsembleIp(); for (const x of ips) e.ajouter(x, id); this.ip.set(id, e.figer()); this.dom.delete(id); }
    else { this.dom.set(id, new Set(domaines)); this.ip.delete(id); }
    return def.type === 'ip' ? ips.length : domaines.length;
  }

  /** Télécharge les listes actives dont la dernière lecture date de plus de `heures`. */
  async actualiser({ forcer = false } = {}) {
    const heures = this.magasin.reglage('bouclier').listesHeures;
    const faits = [];
    for (const [id, def] of Object.entries(this.actives())) {
      const e = this.etat[id] || {};
      if (!forcer && e.maj && this.maintenant() - e.maj < heures * 3600e3 && (this.ip.has(id) || this.dom.has(id))) continue;
      try {
        // Une liste ajoutée par un administrateur : son adresse relue à chaque téléchargement, sans redirection.
        if (def.propre) await verifierDestination(def.url, this.resoudre ? { resoudre: this.resoudre } : {});
        const reponse = await this.fetch(def.url, { signal: AbortSignal.timeout(60_000), redirect: def.propre ? 'error' : 'follow', headers: { 'User-Agent': 'VIGIE (defensive network monitor)' } });
        if (!reponse.ok) throw new Error(`HTTP ${reponse.status}`);
        // Lue morceau par morceau, abandonnée au-delà de la taille permise : jamais entière en mémoire d'abord.
        const texte = (await lireBorne(reponse, TAILLE_MAX)).toString('utf8');
        const n = this.charger(id, texte);
        if (!n) throw new Error('liste vide ou illisible');
        fs.writeFileSync(this.fichier(id), texte, { mode: 0o600 });
        this.etat[id] = { maj: this.maintenant(), n, erreur: null };
        faits.push(id);
      } catch (err) {
        this.etat[id] = { ...e, erreur: String(err.message).slice(0, 200), essai: this.maintenant() };
        this.log.warn?.(`[menaces] ${id} : ${err.message}`);
      }
    }
    // Une liste retirée ne compte plus.
    const actives = this.actives();
    for (const id of [...this.ip.keys(), ...this.dom.keys()]) if (!actives[id]) { this.ip.delete(id); this.dom.delete(id); }
    this.magasin.poserMemoire('menaces_etat', this.etat);
    return faits;
  }

  /** Les listes où figure une adresse : [{ id, nom, poids, sujet }]. */
  ipListee(ip) {
    if (!estPublique(ip)) return [];
    const defs = this.definitions(), out = [];
    for (const [id, e] of this.ip) if (e.contient(ip)) out.push({ id, nom: defs[id]?.nom || id, poids: defs[id]?.poids ?? 50, sujet: defs[id]?.sujet || '' });
    return out;
  }
  /** Les listes où figure un domaine ou l'un de ses parents. */
  domaineListe(nom) {
    const d = String(nom || '').toLowerCase().replace(/\.$/, '');
    if (!d) return [];
    const parents = d.split('.').map((_, i, t) => t.slice(i).join('.')).filter(x => x.includes('.'));
    const defs = this.definitions(), out = [];
    for (const [id, s] of this.dom) if (parents.some(p => s.has(p))) out.push({ id, nom: defs[id]?.nom || id, poids: defs[id]?.poids ?? 50, sujet: defs[id]?.sujet || '' });
    return out;
  }

  public() {
    const actives = this.actives();
    return Object.entries(this.definitions()).map(([id, d]) => ({
      id, nom: d.nom, type: d.type, sujet: d.sujet, poids: d.poids, url: d.url, propre: !!d.propre, active: !!actives[id],
      entrees: this.ip.get(id)?.taille() ?? this.dom.get(id)?.size ?? 0, maj: this.etat[id]?.maj || null, erreur: this.etat[id]?.erreur || null,
    }));
  }
}
