// Page Bouclier : ce que la passerelle et les listes de menaces voient, ce que
// VIGIE bloque, et le branchement (UniFi, syslog, listes, export). La partie
// vivante se repeint toutes les quinze secondes ; les réglages, une fois.
//
// Rien n'est injecté comme balisage : tout passe par h(), qui écrit du texte.
import { h, icone, toast, confirmer, dialogue } from '/socle/compte.js';

const MODES = {
  observer: 'Observer — signale, ne bloque rien',
  simulation: 'Simulation — note ce qu’il aurait bloqué',
  actif: 'Actif — bloque seul les adresses extérieures',
};
const ETAT = { actif: 'bloquée', simule: 'simulée', leve: 'levée', expire: 'expirée' };
const DUREES = [['', 'Durée selon les récidives'], ['60', '1 heure'], ['1440', '1 jour'], ['10080', '7 jours'], ['43200', '30 jours'], ['525600', '1 an']];

const duree = ms => {
  if (ms <= 0) return 'échue';
  const m = Math.round(ms / 60e3);
  if (m < 60) return `${m} min`;
  if (m < 2880) return `${Math.round(m / 60)} h`;
  return `${Math.round(m / 1440)} j`;
};
const depuis = t => (!t ? 'jamais' : Date.now() - t < 60e3 ? 'à l’instant' : `il y a ${duree(Date.now() - t)}`);
const lignes = v => v.split(/[\s,;]+/).map(x => x.trim()).filter(Boolean);
const barre = (score, seuil) => {
  const b = h('div', { class: 'bar menace-barre' }, h('i'));
  b.firstChild.style.width = `${Math.min(100, Math.round(score / seuil * 100))}%`;
  b.firstChild.className = score >= seuil ? 's-mauvais' : score >= seuil / 2 ? 's-faible' : 's-moyen';
  return b;
};

export async function pageBouclier({ api, admin, sur, quand, interrupteur, suivre, recharger }) {
  let etat = await api.get('/api/bouclier');
  const reglages = admin ? (await api.get('/api/reglages')).bouclier : null;

  const lede = h('p', { class: 'lede' });
  const figs = h('div', { class: 'figs' });
  const avis = h('div', {});
  const menaces = h('div', {});
  const blocages = h('div', {});
  const alertes = h('div', {});
  const internes = h('div', {});
  let tousBlocages = false;

  const bloquer = (ip = '') => sur(async () => {
    const champ = h('input', { class: 'field mono', value: ip, placeholder: '203.0.113.7 ou 2001:db8::7', autocomplete: 'off', spellcheck: 'false', 'aria-label': 'Adresse' });
    const temps = h('select', { class: 'field mt9', 'aria-label': 'Durée' }, DUREES.map(([v, t]) => h('option', { value: v, text: t })));
    const motif = h('input', { class: 'field mt9', maxlength: 200, placeholder: 'motif (facultatif)', 'aria-label': 'Motif' });
    const fait = await dialogue({
      titre: 'Bloquer une adresse', texte: 'Une adresse publique seulement : VIGIE refuse le réseau local, les résolveurs DNS publics, Cloudflare et la liste blanche.',
      contenu: [champ, temps, motif],
      boutons: [{ texte: 'Annuler', classe: 'flat', valeur: false }, { texte: 'Bloquer', classe: 'danger solid', agir: async () => {
        try {
          await api.post('/api/bouclier/bloquer', { ip: champ.value.trim(), ...(temps.value ? { minutes: Number(temps.value) } : {}), ...(motif.value.trim() ? { motif: motif.value.trim() } : {}) });
          return true;
        } catch (e) { toast(e.message, true); return false; }
      } }],
    });
    if (fait) { toast('Adresse bloquée.'); await peindre(); }
  })();

  function peindre_() {
    const e = etat;
    const maintenant = Date.now();
    const actifs = e.blocages.filter(b => ['actif', 'simule'].includes(b.etat) && (!b.fin || b.fin > maintenant));
    const bloquees = new Set(actifs.map(b => b.ip));
    const recues = e.syslog.lues + e.sondes.reduce((a, s) => a + s.lues, 0);
    lede.textContent = `${MODES[e.mode]} · seuil ${e.seuil} · ${e.listes.filter(l => l.active && l.entrees).length} listes de menaces chargées`;

    const fig = (titre, valeur, detail, ic, chaud = false) => h('div', { class: 'fig' }, h('div', { class: `tile ${chaud ? 'warn' : ''}` }, icone(ic, 15)), h('span', { text: titre }), h('strong', { text: String(valeur) }), h('div', { class: 'delta', text: detail }));
    figs.replaceChildren(
      fig('Bloquées', e.actifs, e.mode === 'actif' ? 'sur la passerelle et la liste' : `mode ${e.mode}`, 'bouclier', e.actifs > 0),
      fig('Menaces suivies', e.menaces.length, e.menaces[0] ? `la plus haute : ${e.menaces[0].score}` : 'aucune adresse notée', 'oeil'),
      fig('Alertes IPS', e.compteurs.ips || 0, `${(e.compteurs['pare-feu'] || 0).toLocaleString('fr-FR')} lignes de pare-feu`, 'eclair', (e.compteurs.ips || 0) > 0),
      fig('Machines suspectes', e.internes.filter(x => x.score >= x.seuil / 2).length, 'du réseau local', 'alerte', e.internes.some(x => x.score >= x.seuil)));

    const notes = [];
    if (!recues) notes.push(['warn', 'Aucun journal reçu pour l’instant : la passerelle n’envoie encore rien à VIGIE. Voir « Journaux de la passerelle » plus bas.']);
    else if (e.syslog.derniere && maintenant - e.syslog.derniere > 30 * 60e3) notes.push(['warn', `Plus aucun journal de la passerelle depuis ${duree(maintenant - e.syslog.derniere)}.`]);
    if (e.syslog.lues && !e.syslog.emetteursDeclares) notes.push(['warn', 'Toute adresse privée peut envoyer des journaux à VIGIE, donc lui faire bloquer une adresse : déclare la passerelle UniFi dans « Liste blanche et émetteurs ».']);
    if (!e.unifi.relie) notes.push(['', 'Passerelle UniFi non reliée : les blocages restent dans VIGIE et dans la liste exportée, rien n’est coupé à la frontière.']);
    else if (e.unifi.ok === false) notes.push(['warn', `La passerelle ne reçoit plus les blocages : ${e.unifi.erreur}`]);
    else if (e.unifi.regles && !e.unifi.regles.erreur && (!e.unifi.regles.entrant || !e.unifi.regles.sortant)) notes.push(['warn', `Listes envoyées, mais ${!e.unifi.regles.entrant && !e.unifi.regles.sortant ? 'aucune règle du pare-feu ne les cite' : `la règle ${!e.unifi.regles.entrant ? 'd’entrée' : 'de sortie'} manque`} : elles ne bloquent rien tant que les règles ne sont pas posées (Passerelle UniFi, plus bas).`]);
    if (e.mode !== 'actif') notes.push(['', e.mode === 'observer' ? 'Mode observation : VIGIE signale, ne bloque rien.' : 'Mode simulation : VIGIE note ce qu’il aurait bloqué, rien ne part vers la passerelle.']);
    avis.replaceChildren(...notes.map(([c, t]) => h('div', { class: 'card mb12' }, h('div', { class: 'notice' }, h('span', { class: `itile ${c ? 'g-eleve' : 'g-info'}` }, icone(c ? 'alerte' : 'oeil', 15)), h('div', {}, h('p', { text: t }))))));

    menaces.replaceChildren(...(e.menaces.length ? e.menaces.map(m => h('div', { class: 'flowrow', 'data-donnee': '' },
      h('span', { class: `itile ${m.score >= m.seuil ? 'g-critique' : m.score >= m.seuil / 2 ? 'g-eleve' : 'g-faible'}` }, icone('oeil', 15)),
      h('div', { class: 'grow1' }, h('strong', { class: 'ip', text: m.ip }),
        barre(m.score, m.seuil),
        h('small', { text: `${m.score} / ${m.seuil} · ${m.raisons.slice(0, 3).map(r => r.n > 1 ? `${r.texte} (×${r.n})` : r.texte).join(' · ')}` }),
        h('small', { text: `vue ${m.vu} fois · dernière ${depuis(m.dernier)}` })),
      h('div', { class: 'fin' }, bloquees.has(m.ip) ? h('span', { class: 'tag held' }, h('i', { class: 'd' }), 'bloquée')
        : admin ? h('button', { class: 'btn sm', type: 'button', onclick: () => bloquer(m.ip) }, 'Bloquer') : null)))
      : [h('p', { class: 'vide', text: 'Aucune adresse extérieure notée. Elles apparaissent ici dès qu’une alerte, un balayage ou une liste de menaces les signale.' })]));

    const montres = (tousBlocages ? e.blocages : actifs).slice(0, 80);
    blocages.replaceChildren(...(montres.length ? montres.map(b => h('div', { class: 'flowrow', 'data-donnee': '' },
      h('span', { class: `itile ${b.etat === 'actif' ? 'g-critique' : ''}` }, icone(b.automatique ? 'eclair' : 'bouclier', 15)),
      h('div', { class: 'grow1' }, h('strong', { class: 'ip', text: b.ip }),
        h('span', { class: `tag ${['actif', 'simule'].includes(b.etat) ? (b.etat === 'actif' ? 'held' : 'warn') : 'idle'}` }, h('i', { class: 'd' }),
          ['actif', 'simule'].includes(b.etat) ? `${ETAT[b.etat]} · ${b.fin ? `encore ${duree(b.fin - maintenant)}` : 'sans fin'}` : `${ETAT[b.etat] || b.etat}${b.leve_par ? ` par ${b.leve_par}` : ''}`),
        h('small', { text: [b.automatique ? 'VIGIE' : `par ${b.auteur}`, quand(b.debut), b.recidive ? `récidive n° ${b.recidive}` : ''].filter(Boolean).join(' · ') }),
        h('small', { text: b.raisons.slice(0, 3).join(' · ') || b.motif })),
      h('div', { class: 'fin' },
        admin && ['actif', 'simule'].includes(b.etat) ? h('button', { class: 'btn sm', type: 'button', onclick: sur(async () => {
          if (!(await confirmer(`Lever le blocage de ${b.ip} ?`, 'L’adresse sort de la liste de la passerelle à la prochaine synchronisation (quelques secondes). Une récidive la bloquera plus longtemps.', { oui: 'Lever' }))) return;
          await api.post(`/api/bouclier/blocages/${b.id}/lever`, {}); toast('Blocage levé.'); await peindre();
        }) }, 'Lever') : null)))
      : [h('p', { class: 'vide', text: tousBlocages ? 'Aucun blocage.' : 'Aucune adresse bloquée en ce moment.' })]));

    alertes.replaceChildren(...(e.alertes.length ? e.alertes.slice(0, 40).map(a => h('div', { class: 'flowrow', 'data-donnee': '' },
      h('span', { class: `itile ${a.gravite === 1 ? 'g-critique' : a.gravite === 2 ? 'g-eleve' : 'g-faible'}` }, icone('eclair', 15)),
      h('div', { class: 'grow1' }, h('strong', { text: a.signature || 'alerte' }),
        h('small', { class: 'mono', text: `${a.src || '?'} → ${a.dst || '?'}${a.dport ? `:${a.dport}` : ''}` }),
        h('small', { text: [a.categorie, a.capteur, quand(a.quand)].filter(Boolean).join(' · ') })),
      h('div', { class: 'fin' }, h('span', { class: `tag ${a.action === 'bloque' ? '' : 'warn'}` }, h('i', { class: 'd' }), a.action === 'bloque' ? 'coupée par l’IPS' : `gravité ${a.gravite}`))))
      : [h('p', { class: 'vide', text: 'Aucune alerte d’IPS reçue. Sur la passerelle UniFi : CyberSecure → Intrusion Prevention activé, et la catégorie « Intrusion Prevention » envoyée au serveur SIEM.' })]));

    internes.replaceChildren(...(e.internes.length ? e.internes.map(m => h('div', { class: 'flowrow', 'data-donnee': '' },
      h('span', { class: `itile ${m.score >= m.seuil ? 'g-critique' : 'g-eleve'}` }, icone('alerte', 15)),
      h('div', { class: 'grow1' }, h('strong', { class: 'ip', text: m.ip }), barre(m.score, m.seuil),
        h('small', { text: m.raisons.slice(0, 3).map(r => r.texte).join(' · ') })),
      h('div', { class: 'fin' }, h('span', { class: 'note', text: `${m.score} / ${m.seuil}` }))))
      : [h('p', { class: 'vide', text: 'Aucune machine du réseau ne se comporte comme une machine compromise.' })]));
  }
  async function peindre() { etat = await api.get('/api/bouclier'); peindre_(); }
  peindre_();
  suivre(peindre, 15000);

  const page = h('div', { class: 'page' },
    h('div', { class: 'headrow' },
      h('div', {}, h('h1', { class: 'title', text: 'Bouclier' }), lede),
      h('div', { class: 'actions' },
        admin ? h('button', { class: 'btn', type: 'button', onclick: sur(async () => { const o = await api.post('/api/bouclier/listes/actualiser', {}); toast(o.faits.length ? `${o.faits.length} liste${o.faits.length > 1 ? 's' : ''} actualisée${o.faits.length > 1 ? 's' : ''}.` : 'Aucune liste téléchargée : voir les erreurs plus bas.', !o.faits.length); await peindre(); }) }, icone('liste', 15), 'Actualiser les listes') : null,
        admin ? h('button', { class: 'btn solid', type: 'button', onclick: () => bloquer() }, icone('bouclier', 15), 'Bloquer une adresse') : null)),
    figs, avis,
    h('div', { class: 'split' },
      h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Menaces extérieures' }), h('span', { class: 'note', text: 'score effacé de moitié chaque heure' })), menaces),
      h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Blocages' }), h('span', { class: 'note' }, h('span', { class: 'row' }, h('span', { text: 'Historique' }), interrupteur(false, 'Historique des blocages', v => { tousBlocages = v; peindre_(); })))), blocages)),
    h('div', { class: 'split mt12' },
      h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Alertes de l’IPS' }), h('span', { class: 'note', text: 'les plus récentes' })), alertes),
      h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Machines du réseau' }), h('span', { class: 'note', text: 'isolement : réaction rapide' })), internes)),
    admin ? h('div', { class: 'grille mt12' },
      carteMode(), carteUnifi(), carteSyslog(), carteListes(), carteBlanche(), carteExport(), carteSondes()) : null);
  return page;

  // ---------- réglages ----------
  // Enregistrer puis repeindre la page entière : les cartes montrent l'état que le serveur a retenu.
  function enregistrer(corps, message) {
    return sur(async () => { await api.put('/api/reglages/bouclier', corps()); toast(message); await recharger(); });
  }

  function carteMode() {
    const r = reglages;
    const mode = h('select', { class: 'field', 'aria-label': 'Mode' }, Object.entries(MODES).map(([v, t]) => h('option', { value: v, text: t, selected: v === r.mode })));
    const nombre = (v, min, max, libelle) => h('input', { class: 'field', type: 'number', min, max, value: v, 'aria-label': libelle });
    const seuil = nombre(r.seuil, 30, 1000, 'Seuil extérieur');
    const seuilInterne = nombre(r.seuilInterne, 30, 1000, 'Seuil interne');
    const demi = nombre(r.demiVieMinutes, 5, 1440, 'Demi-vie');
    const ports = nombre(r.balayagePorts, 5, 1000, 'Ports');
    const cibles = nombre(r.balayageCibles, 3, 1000, 'Machines');
    const brute = nombre(r.forceBrute, 3, 1000, 'Tentatives');
    const parHeure = nombre(r.autoParHeure, 1, 2000, 'Blocages par heure');
    const max = nombre(r.maxUnifi, 10, 10000, 'Adresses sur la passerelle');
    const durees = h('input', { class: 'field mono', value: r.dureesMinutes.join(', '), 'aria-label': 'Durées' });
    const deux = (a, b) => h('div', { class: 'deux' }, a, b);
    const corps = () => ({
      mode: mode.value, seuil: Number(seuil.value), seuilInterne: Number(seuilInterne.value), demiVieMinutes: Number(demi.value),
      balayagePorts: Number(ports.value), balayageCibles: Number(cibles.value), forceBrute: Number(brute.value),
      autoParHeure: Number(parHeure.value), maxUnifi: Number(max.value), dureesMinutes: lignes(durees.value).map(Number),
    });
    const sauver = enregistrer(corps, 'Bouclier enregistré.');
    return h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Mode et seuils' }), h('span', { class: 'note', text: r.mode })), h('div', { class: 'cardbody' },
      h('p', { class: 'hint mt0', text: 'Chaque observation ajoute des points à l’adresse qui la porte : alerte d’IPS de gravité 1 = 100, 2 = 40, 3 = 10 ; balayage ou force brute = 60 ; présence sur une liste de menaces = son poids. Au seuil, l’adresse extérieure est bloquée ; une machine du réseau est signalée (et isolée seulement par la réaction rapide, si elle est allumée).' }),
      h('label', { class: 'lbl mt9', text: 'Mode' }), mode,
      h('label', { class: 'lbl mt9', text: 'Seuils : extérieur · machine du réseau' }), deux(seuil, seuilInterne),
      h('label', { class: 'lbl mt9', text: 'Demi-vie du score (minutes)' }), demi,
      h('label', { class: 'lbl mt9', text: 'En dix minutes : ports d’une cible · machines visées' }), deux(ports, cibles),
      h('label', { class: 'lbl mt9', text: 'Force brute : tentatives sur un port d’authentification en dix minutes' }), brute,
      h('label', { class: 'lbl mt9', text: 'Blocages automatiques par heure · adresses tenues par la passerelle' }), deux(parHeure, max),
      h('label', { class: 'lbl mt9', text: 'Durées des blocages successifs (minutes)' }), durees,
      h('div', { class: 'actions mt12' }, h('button', { class: 'btn solid', type: 'button', onclick: async () => {
        if (mode.value === 'actif' && r.mode !== 'actif' && !(await confirmer('Laisser VIGIE bloquer seul ?', 'Une adresse extérieure qui dépasse le seuil sera coupée à la frontière sans attendre personne. Jamais une adresse du réseau local, jamais la liste blanche ; chaque blocage se lève en un clic.', { danger: true, oui: 'Passer en actif' }))) return;
        await sauver();
      } }, 'Enregistrer'))));
  }

  function carteUnifi() {
    const r = reglages;
    const u = etat.unifi;
    const hote = h('input', { class: 'field mono', value: r.unifiHote, placeholder: 'adresse IP de la passerelle UniFi', autocomplete: 'off', spellcheck: 'false', 'aria-label': 'Adresse de la passerelle' });
    const port = h('input', { class: 'field', type: 'number', min: 1, max: 65535, value: r.unifiPort || 443, 'aria-label': 'Port' });
    const cle = h('input', { class: 'field mono', type: 'password', placeholder: r.cleUnifi ? 'clé enregistrée — en coller une autre pour la remplacer' : 'clé d’API UniFi', autocomplete: 'off', 'aria-label': 'Clé d’API' });
    const fp = h('p', { class: 'mono hint mt0 coupe', text: r.unifiFp ? `Certificat épinglé : ${r.unifiFp}` : 'Aucun certificat épinglé.' });
    let empreinte = r.unifiFp || '';
    const lire = sur(async () => {
      const o = await api.post('/api/bouclier/unifi/sonde', { hote: hote.value.trim(), port: Number(port.value) || 443 });
      const ok = await confirmer('Est-ce bien ta passerelle ?', `Certificat présenté par ${hote.value.trim()} : « ${o.sujet || 'sans nom'} », valable jusqu’au ${o.expire || '?'} — empreinte ${o.fp}. S’il est confirmé, VIGIE n’enverra sa clé qu’à une machine qui présente exactement ce certificat.`, { oui: 'C’est elle' });
      if (!ok) return;
      empreinte = o.fp;
      fp.textContent = `Certificat à épingler : ${o.fp}`;
      toast('Certificat retenu : colle la clé d’API puis enregistre.');
    });
    const etatTexte = !u.relie ? 'non reliée' : u.ok === false ? 'erreur' : u.ok ? 'synchronisée' : 'reliée';
    const regles = u.regles && !u.regles.erreur ? u.regles : null;
    return h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Passerelle UniFi' }), h('span', { class: `note ${u.ok === false ? 'erreur' : ''}`, text: etatTexte })), h('div', { class: 'cardbody' },
      h('p', { class: 'hint mt0', text: 'VIGIE tient deux listes d’adresses sur la passerelle UniFi (« VIGIE · bloquées IPv4 » et « … IPv6 ») par l’API officielle d’UniFi Network (9.0 ou plus). Il ne touche ni aux règles ni au reste de la configuration.' }),
      u.relie ? h('div', { class: 'etat-unifi' },
        h('small', { text: u.ok ? `${u.envoyees ?? 0} adresse${u.envoyees > 1 ? 's' : ''} envoyée${u.envoyees > 1 ? 's' : ''} · ${quand(u.synchro)}` : u.erreur || 'pas encore synchronisée' }),
        regles ? h('small', { text: `Règles qui citent les listes : entrée ${regles.entrant ? 'oui' : 'NON'} · sortie ${regles.sortant ? 'oui' : 'NON'}${regles.regles?.length ? ` (${regles.regles.map(x => x.nom).join(', ')})` : ''}` }) : null) : null,
      h('label', { class: 'lbl mt9', text: '1. Adresse et port de la passerelle' }), h('div', { class: 'deux' }, hote, port),
      h('div', { class: 'actions mt9' }, h('button', { class: 'btn sm', type: 'button', onclick: lire }, 'Lire son certificat')), fp,
      h('label', { class: 'lbl mt9', text: '2. Clé d’API — UniFi Network → Paramètres → Control Plane → Integrations → Create API Key' }), cle,
      u.relie ? h('div', { class: 'actions mt12' },
        h('button', { class: 'btn sm', type: 'button', onclick: sur(async () => { const o = await api.post('/api/bouclier/unifi/synchroniser', {}); toast(o.ok ? 'Passerelle synchronisée.' : o.erreur, !o.ok); await peindre(); }) }, 'Synchroniser'),
        h('button', { class: 'btn sm', type: 'button', onclick: sur(async () => {
          if (!(await confirmer('Délier la passerelle ?', 'La clé est effacée de VIGIE. Les listes restent sur la passerelle UniFi telles quelles : vide-les ou supprime les règles là-bas si tu ne veux plus qu’elles bloquent.', { danger: true, oui: 'Délier' }))) return;
          etat = await api.put('/api/bouclier/unifi', { retirer: true }); toast('Passerelle déliée.'); await recharger();
        }) }, 'Délier')) : null,
      h('div', { class: 'actions mt9' },
        h('button', { class: 'btn solid', type: 'button', onclick: sur(async () => {
          if (!empreinte) throw new Error('Lis d’abord le certificat de la passerelle.');
          etat = await api.put('/api/bouclier/unifi', { hote: hote.value.trim(), port: Number(port.value) || 443, fp: empreinte, ...(cle.value.trim() ? { cle: cle.value.trim() } : {}) });
          toast(etat.unifi.ok ? 'Passerelle reliée : listes créées.' : `Enregistrée, mais : ${etat.unifi.erreur || 'pas de réponse'}`, etat.unifi.ok === false);
          await recharger();
        }) }, 'Enregistrer')),
      h('details', { class: 'mt12' }, h('summary', { text: '3. Les règles à poser une fois dans UniFi (sans elles, les listes ne bloquent rien)' }),
        h('ol', { class: 'etapes' },
          h('li', { text: 'Paramètres → Policy Engine (ou Firewall & Security selon la version) → Create Policy.' }),
          h('li', { text: '« VIGIE entrée » : action Block, zone source External, source = la liste « VIGIE · bloquées IPv4 », destination : toutes les zones internes. Journalisation (Syslog) cochée.' }),
          h('li', { text: '« VIGIE sortie » : action Block, zones sources internes, destination = la même liste, zone External. Une machine infectée ne joint plus son serveur de commande.' }),
          h('li', { text: 'Les deux mêmes pour « VIGIE · bloquées IPv6 » si l’IPv6 est actif.' }),
          h('li', { text: 'Placer ces règles avant les règles d’autorisation, puis « Synchroniser » ici : VIGIE vérifie qu’elles existent.' })))));
  }

  function carteSyslog() {
    const s = etat.syslog;
    const emetteurs = Object.entries(s.parEmetteur || {});
    return h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Journaux de la passerelle' }), h('span', { class: `note ${!s.lues ? 'erreur' : ''}`, text: s.lues ? `dernier ${depuis(s.derniere)}` : 'rien reçu' })), h('div', { class: 'cardbody' },
      h('p', { class: 'hint mt0', text: 'C’est par là que VIGIE voit : alertes de l’IPS (le Suricata intégré à la passerelle UniFi), pot de miel, refus du pare-feu.' }),
      h('dl', { class: 'preuve' },
        h('dt', { text: 'Serveur' }), h('dd', { text: 'adresse IP locale de la machine de VIGIE' }),
        h('dt', { text: 'Port' }), h('dd', { text: `${s.port || '—'} (UDP ou TCP)` }),
        h('dt', { text: 'Reçues · lues' }), h('dd', { text: `${s.recues.toLocaleString('fr-FR')} · ${s.lues.toLocaleString('fr-FR')}` }),
        h('dt', { text: 'Refusées' }), h('dd', { text: `${s.refusees} (émetteur non déclaré)${s.dernierRefus ? ` · dernier : ${s.dernierRefus}` : ''}${s.debordees ? ` · ${s.debordees} au-delà de 3 000/s` : ''}` }),
        ...emetteurs.flatMap(([ip, t]) => [h('dt', { text: 'Émetteur' }), h('dd', { text: `${ip} · ${depuis(t)}` })])),
      h('ol', { class: 'etapes' },
        h('li', { text: 'UniFi Network → Paramètres → Control Plane → Integrations → Activity Logging (Syslog) : « SIEM Server », l’adresse et le port ci-dessus. Catégories Security : Firewall, Honeypot, Intrusion Prevention (format CEF).' }),
        h('li', { text: 'Paramètres → CyberSecure → Traffic Logging : « SIEM Server », même adresse et même port (lignes du pare-feu : balayages, force brute).' }),
        h('li', { text: 'CyberSecure → Intrusion Prevention : mode « Prévention » (IPS) sur tous les réseaux, catégories au maximum. Le pot de miel (Honeypot) sur les réseaux internes : une machine qui le touche est presque toujours compromise.' }),
        h('li', { text: 'Seuls les émetteurs déclarés (carte « Liste blanche et émetteurs ») sont lus ; sans liste, toute adresse privée l’est.' }))));
  }

  function carteListes() {
    const choix = Object.fromEntries(etat.listes.map(l => [l.id, l.active]));
    const toutes = h('div', {}, etat.listes.map(l => h('div', { class: 'reglage-ligne' },
      h('div', {}, h('strong', { text: `${l.nom}${l.propre ? ' (ajoutée)' : ''}` }),
        h('small', { text: `${l.sujet} · poids ${l.poids}` }),
        h('small', { class: l.erreur ? 'erreur-texte' : '', text: l.erreur ? `erreur : ${l.erreur}` : l.entrees ? `${l.entrees.toLocaleString('fr-FR')} ${l.type === 'ip' ? 'plage' : 'domaine'}${l.entrees > 1 ? 's' : ''} · ${quand(l.maj)}` : 'pas encore téléchargée' })),
      interrupteur(l.active, l.nom, v => { choix[l.id] = v; }))));
    const nom = h('input', { class: 'field', maxlength: 60, placeholder: 'nom', 'aria-label': 'Nom de la liste' });
    const type = h('select', { class: 'field', 'aria-label': 'Type' }, h('option', { value: 'ip', text: 'adresses IP' }), h('option', { value: 'domaine', text: 'domaines' }));
    const url = h('input', { class: 'field mono', placeholder: 'https://…', autocomplete: 'off', spellcheck: 'false', 'aria-label': 'Adresse de la liste' });
    const poids = h('input', { class: 'field', type: 'number', min: 5, max: 100, value: 50, 'aria-label': 'Poids' });
    return h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Listes de menaces' }), h('span', { class: 'note', text: `toutes les ${reglages.listesHeures} h` })), h('div', { class: 'cardbody' },
      h('p', { class: 'hint mt0', text: 'Réputation partagée (abuse.ch, Spamhaus, Emerging Threats…). Une liste ne bloque rien seule : elle pèse dans le score d’une adresse que VIGIE voit vraiment passer — on bloque ce qui frappe, pas un million d’adresses par précaution.' }),
      toutes,
      h('div', { class: 'actions mt12' }, h('button', { class: 'btn solid', type: 'button', onclick: enregistrer(() => ({ listes: choix }), 'Listes enregistrées : téléchargement lancé.') }, 'Enregistrer')),
      h('details', { class: 'mt12' }, h('summary', { text: 'Ajouter une liste (texte, une entrée par ligne, en HTTPS)' }),
        h('div', { class: 'deux mt9' }, nom, type), h('div', { class: 'mt9' }, url), h('label', { class: 'lbl mt9', text: 'Poids (100 = blocage dès qu’elle est vue)' }), poids,
        h('div', { class: 'actions mt9' },
          (reglages.listesPropres || []).length ? h('button', { class: 'btn sm', type: 'button', onclick: enregistrer(() => ({ listesPropres: [] }), 'Listes ajoutées retirées.') }, 'Retirer les listes ajoutées') : null,
          h('button', { class: 'btn sm', type: 'button', onclick: enregistrer(() => ({ listesPropres: [...(reglages.listesPropres || []), { nom: nom.value.trim(), type: type.value, url: url.value.trim(), poids: Number(poids.value) }] }), 'Liste ajoutée.') }, 'Ajouter')))));
  }

  function carteBlanche() {
    const blanche = h('textarea', { class: 'field mono', rows: 4, placeholder: '203.0.113.0/24', spellcheck: 'false', 'aria-label': 'Liste blanche' });
    blanche.value = (reglages.listeBlanche || []).join('\n');
    const emetteurs = h('textarea', { class: 'field mono', rows: 2, placeholder: 'adresse de la passerelle UniFi', spellcheck: 'false', 'aria-label': 'Émetteurs' });
    emetteurs.value = (reglages.emetteurs || []).join('\n');
    return h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Liste blanche et émetteurs' })), h('div', { class: 'cardbody' },
      h('label', { class: 'lbl', text: 'Jamais bloquées (une adresse ou plage par ligne) — tes IP publiques, ton VPN, tes services en ligne' }), blanche,
      h('p', { class: 'hint', text: `Toujours protégées, sans rien écrire : le réseau local et les adresses réservées, ${reglages.listeBlancheDefaut.length} plages de résolveurs DNS publics et de Cloudflare (le tunnel du Hub passe par là).` }),
      h('label', { class: 'lbl mt9', text: 'Émetteurs de journaux acceptés — vide : toute adresse privée' }), emetteurs,
      h('p', { class: 'hint', text: 'Un journal se falsifie : n’écouter que la passerelle évite qu’une machine du réseau fasse bloquer une adresse en inventant des alertes.' }),
      h('div', { class: 'actions mt12' }, h('button', { class: 'btn solid', type: 'button', onclick: enregistrer(() => ({ listeBlanche: lignes(blanche.value), emetteurs: lignes(emetteurs.value) }), 'Enregistré.') }, 'Enregistrer'))));
  }

  function carteExport() {
    const sortie = h('div', {});
    return h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Liste pour un autre pare-feu' }), h('span', { class: 'note', text: reglages.jetonListe ? 'jeton posé' : 'aucun jeton' })), h('div', { class: 'cardbody' },
      h('p', { class: 'hint mt0', text: 'Les adresses bloquées en texte, une par ligne, pour un pare-feu qui lit une URL (pfSense ou OPNsense en alias « URL Table », MikroTik…). Le jeton est dans l’adresse : ces pare-feu n’envoient pas d’en-tête.' }),
      sortie,
      h('div', { class: 'actions mt12' }, h('button', { class: 'btn', type: 'button', onclick: sur(async () => {
        if (reglages.jetonListe && !(await confirmer('Nouveau jeton ?', 'L’ancienne adresse cesse de fonctionner aussitôt.', { oui: 'Remplacer' }))) return;
        const o = await api.post('/api/bouclier/jeton-liste', {});
        reglages.jetonListe = true;
        sortie.replaceChildren(h('p', { class: 'hint', text: 'Montrée une seule fois :' }), h('p', { class: 'mono coupe', text: location.origin + o.chemin }));
      }) }, reglages.jetonListe ? 'Nouveau jeton' : 'Créer l’adresse'))));
  }

  function carteSondes() {
    const nom = h('input', { class: 'field mono', maxlength: 40, placeholder: 'nom-de-la-sonde', autocomplete: 'off', 'aria-label': 'Nom' });
    const sortie = h('div', {});
    const liste = etat.sondes;
    return h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Sondes (facultatif)' }), h('span', { class: 'note', text: liste.length ? `${liste.length}` : 'aucune' })), h('div', { class: 'cardbody' },
      h('p', { class: 'hint mt0', text: 'Une sonde Suricata placée ailleurs sur le réseau peut envoyer son EVE JSON à POST /api/sonde/eve, avec son propre jeton. Sans sonde déclarée, cette entrée refuse tout.' }),
      liste.map(s => h('div', { class: 'reglage-ligne' }, h('div', {}, h('strong', { class: 'ip', text: s.nom }), h('small', { text: `${s.lues.toLocaleString('fr-FR')} événements · dernier ${depuis(s.derniere)}` })),
        h('button', { class: 'btn sm', type: 'button', onclick: sur(async () => { if (!(await confirmer(`Retirer la sonde ${s.nom} ?`, 'Son jeton cesse de fonctionner aussitôt.', { danger: true, oui: 'Retirer' }))) return; await api.post('/api/bouclier/sondes/retirer', { nom: s.nom }); toast('Sonde retirée.'); await recharger(); }) }, 'Retirer'))),
      h('div', { class: 'deux mt9' }, nom, h('button', { class: 'btn', type: 'button', onclick: sur(async () => {
        const o = await api.post('/api/bouclier/sondes', { nom: nom.value.trim() });
        sortie.replaceChildren(h('p', { class: 'hint', text: `Jeton de ${o.nom}, montré une seule fois :` }), h('p', { class: 'mono coupe', text: o.jeton }));
        nom.value = '';
      }) }, 'Créer un jeton')), sortie));
  }
}
