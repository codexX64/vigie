// Page Sentinelle : les journaux des hôtes du réseau, lus en direct. Le flux
// (SSE) montre tout ce qui bouge — observations du bouclier et événements de
// la sentinelle — ; les alertes gardées, les hôtes, les sources d'attaque et
// les règles les plus déclenchées viennent de /api/sentinelle.
import { h, icone, toast } from '/socle/compte.js';

const GRAV = n => (n >= 13 ? 'critique' : n >= 10 ? 'eleve' : n >= 7 ? 'faible' : 'info');
const LIB = { info: 'info', faible: 'faible', eleve: 'élevé', critique: 'critique' };
const duree = ms => {
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s} s`;
  if (s < 3600) return `${Math.round(s / 60)} min`;
  if (s < 86400) return `${Math.round(s / 3600)} h`;
  return `${Math.round(s / 86400)} j`;
};
const depuis = t => (!t ? 'jamais' : Date.now() - t < 60e3 ? 'à l’instant' : `il y a ${duree(Date.now() - t)}`);
const heure = t => new Date(t).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
const pluriel = (n, mot) => `${n.toLocaleString('fr-FR')} ${mot}${n > 1 ? 's' : ''}`;
const chip = n => h('span', { class: `chip g-${GRAV(n)}`, text: `niv. ${n}` });
const GROUPES_LIB = { 'force-brute': 'force brute', compromission: 'compromission', balayage: 'balayage', 'web-attaque': 'attaque web', 'premiere-fois': 'première fois', integrite: 'intégrité', 'compte-admin': 'compte admin', 'utilisateur-invalide': 'compte inexistant', 'deni-de-service': 'déni de service', 'commande-suspecte': 'commande suspecte', persistance: 'persistance', exfiltration: 'exfiltration', 'nouvel-appareil': 'nouvel appareil', ecoute: 'écoute', 'blocage-cible': 'blocage par la cible' };

export async function pageSentinelle({ api, admin, sur, quand, interrupteur, suivre, recharger, aller, params = null }) {
  let etat = await api.get('/api/sentinelle');
  const reglages = admin ? (await api.get('/api/reglages')).sentinelle : null;

  const lede = h('p', { class: 'lede' });
  const figs = h('div', { class: 'figs' });
  const avis = h('div', {});
  const direct = h('div', { class: 'direct' });
  const alertes = h('div', {});
  const hotes = h('div', {});
  const sources = h('div', {});
  const regles = h('div', {});
  let niveauMin = 7;
  let pause = false;
  let fluxOk = false;

  // Le direct
  const ligneDirect = m => {
    if (m.genre === 'bouclier') {
      const g = m.type === 'ips' ? (m.gravite === 1 ? 'critique' : m.gravite === 2 ? 'eleve' : 'faible') : 'info';
      return h('div', { class: `dl g-${g}`, 'data-niv': m.type === 'ips' ? 10 : 1 },
        h('span', { class: 'dh mono', text: heure(m.quand) }),
        h('span', { class: 'dq', text: m.type === 'ips' ? 'IPS' : m.type === 'pare-feu' ? 'pare-feu' : m.type }),
        h('span', { class: 'dt' }, h('b', { class: 'mono', text: `${m.src || '?'} → ${m.dst || '?'}${m.dport ? ':' + m.dport : ''}` }), ' ', m.signature || (m.action === 'bloque' ? 'refusé' : m.action || ''), h('small', { text: ` · ${m.capteur || ''}` })));
    }
    const u = m.champs || {};
    return h('div', { class: `dl g-${GRAV(m.niveau)}`, 'data-niv': m.niveau },
      h('span', { class: 'dh mono', text: heure(m.quand) }),
      h('span', { class: 'dq', text: String(m.niveau) }),
      h('span', { class: 'dt' }, h('b', { text: m.hote || m.emetteur || '?' }), h('small', { text: ` ${m.programme || m.decodeur || ''} ` }), m.description,
        h('small', { text: [u.srcip && `depuis ${u.srcip}`, u.utilisateur && `compte ${u.utilisateur}`, u.url && u.url.slice(0, 60), u.commande && u.commande.slice(0, 60)].filter(Boolean).map(x => ' · ' + x).join('') })));
  };
  const filtrer = () => { let n = 0; for (const l of direct.children) { l.hidden = Number(l.dataset.niv) < niveauMin; if (!l.hidden) n++; } direct.classList.toggle('tout-filtre', !n && direct.children.length > 0); };
  let source = null;
  const ouvrir = () => {
    if (!('EventSource' in window)) return;
    source = new EventSource('/api/sentinelle/flux');
    const sur_ = ev => {
      if (!page.isConnected) { source.close(); return; }
      if (pause) return;
      let m; try { m = JSON.parse(ev.data); } catch { return; }
      const l = ligneDirect(m); l.hidden = Number(l.dataset.niv) < niveauMin;
      direct.prepend(l);
      while (direct.children.length > 150) direct.lastChild.remove();
      if (!l.hidden) direct.classList.remove('tout-filtre'); else if (!direct.classList.contains('tout-filtre') && ![...direct.children].some(x => !x.hidden)) direct.classList.add('tout-filtre');
    };
    source.addEventListener('sentinelle', sur_);
    source.addEventListener('bouclier', sur_);
    source.onopen = () => { fluxOk = true; temoin.className = 'tag held'; temoin.lastChild.textContent = 'en direct'; };
    source.onerror = () => { fluxOk = false; temoin.className = 'tag warn'; temoin.lastChild.textContent = 'reconnexion…'; };
    // Page quittée, flux fermé : sinon chaque visite garde sa connexion et le
    // navigateur, à six par hôte, finit par ne plus rien charger.
    const garde = setInterval(() => { if (!page.isConnected) { source.close(); clearInterval(garde); } }, 1000);
  };
  const temoin = h('span', { class: 'tag idle' }, h('i', { class: 'd' }), 'connexion…');
  const selNiveau = h('select', { class: 'field sm', 'aria-label': 'Niveau minimum du direct', onchange: () => { niveauMin = Number(selNiveau.value); filtrer(); } },
    [[1, 'tout'], [3, 'niveau 3 et plus'], [5, 'niveau 5 et plus'], [7, 'niveau 7 et plus (alertes)'], [10, 'niveau 10 et plus']].map(([v, t]) => h('option', { value: v, text: t, selected: v === niveauMin })));
  const btnPause = h('button', { class: 'btn sm', type: 'button', onclick: () => { pause = !pause; btnPause.textContent = pause ? 'Reprendre' : 'Pause'; } }, 'Pause');

  // Les vues
  let peindre_ = () => {
    const e = etat;
    const s = e.stats;
    const b = e.bilan;
    const max24 = Math.max(0, ...Object.keys(b.parNiveau).map(Number));
    lede.textContent = `${e.actif ? 'active' : 'éteinte'} · alerte dès le niveau ${e.seuil}, événement dès ${e.seuilEvenement} · ${e.nbRegles} règles, ${e.decodeurs.length} décodeurs`;
    const fig = (titre, valeur, detail, ic, chaud = false) => h('div', { class: 'fig' }, h('div', { class: `tile ${chaud ? 'warn' : ''}` }, icone(ic, 15)), h('span', { text: titre }), h('strong', { text: String(valeur) }), h('div', { class: 'delta', text: detail }));
    figs.replaceChildren(
      fig('Hôtes suivis', e.hotes.length, e.hotes[0] ? `dernier : ${depuis(Math.max(...e.hotes.map(x => x.dernier)))}` : 'aucun journal reçu', 'serveur'),
      fig('Alertes (24 h)', b.total, max24 ? `la plus haute : niveau ${max24} (${LIB[GRAV(max24)]})` : 'rien à signaler', 'alerte', max24 >= 10),
      fig('Lignes analysées', s.lignes.toLocaleString('fr-FR'), `${s.decodees.toLocaleString('fr-FR')} décodées · ${s.evenements.toLocaleString('fr-FR')} événements`, 'journal'),
      fig('Hôte le plus exposé', e.hotes[0]?.hote || '—', e.hotes[0] ? `niveau max ${e.hotes[0].niveauMax} · ${e.hotes[0].alertes} alertes` : '', 'eclair', (e.hotes[0]?.niveauMax || 0) >= 12));

    const notes = [];
    if (!e.actif) notes.push(['warn', 'La sentinelle est éteinte : les journaux d’hôtes reçus sont ignorés.']);
    else if (!e.hotes.length) notes.push(['', 'Aucun journal d’hôte reçu. Envoie les journaux de tes machines (rsyslog, journald, NAS, hyperviseur, routeur) au port syslog de VIGIE : carte « Brancher un hôte » plus bas.']);
    if (e.hotes.some(x => x.niveauMax >= 12)) notes.push(['warn', `Signes de compromission sur ${e.hotes.filter(x => x.niveauMax >= 12).map(x => x.hote).join(', ')} : voir les alertes, puis le Bouclier (machines du réseau).`]);
    avis.replaceChildren(...notes.slice(0, 1).map(([c, t]) => h('div', { class: 'card mb12' }, h('div', { class: 'notice' }, h('span', { class: `itile ${c ? 'g-eleve' : 'g-info'}` }, icone(c ? 'alerte' : 'oeil', 15)), h('div', {}, h('p', { text: t }))))));

    alertes.replaceChildren(...(e.recentes.length ? e.recentes.slice(0, 40).map(a => h('div', { class: 'flowrow', 'data-donnee': '' },
      h('span', { class: `itile g-${GRAV(a.niveau)}` }, icone(a.niveau >= 10 ? 'eclair' : 'alerte', 15)),
      h('div', { class: 'grow1' }, h('strong', { text: a.description }),
        h('small', { text: [a.hote, a.programme, a.srcip && `depuis ${a.srcip}`, a.utilisateur && `compte ${a.utilisateur}`].filter(Boolean).join(' · ') }),
        h('small', { class: 'mono coupe', text: a.extrait.slice(0, 160) }),
        h('small', { text: `${a.groupes.filter(g => GROUPES_LIB[g]).map(g => GROUPES_LIB[g]).join(', ') || a.groupes[0]} · ${quand(a.quand)}` })),
      h('div', { class: 'fin' }, chip(a.niveau))))
      : [h('p', { class: 'vide', text: `Aucune alerte de niveau ${e.seuil} ou plus. Les connexions ordinaires, les tâches planifiées et les requêtes servies restent sous ce seuil.` })]));

    hotes.replaceChildren(...(e.hotes.length ? e.hotes.slice(0, 40).map(x => h('div', { class: 'flowrow', 'data-donnee': '' },
      h('span', { class: `itile ${x.niveauMax >= 12 ? 'g-critique' : x.niveauMax >= 10 ? 'g-eleve' : x.niveauMax >= 7 ? 'g-faible' : ''}` }, icone('serveur', 15)),
      h('div', { class: 'grow1' }, h('strong', { class: 'ip', text: x.hote }),
        h('small', { text: `${pluriel(x.lignes, 'ligne')} · ${pluriel(x.evenements, 'événement')} · ${pluriel(x.alertes, 'alerte')} · dernière ${depuis(x.dernier)}` }),
        h('small', { text: Object.entries(x.programmes).sort((a, b) => b[1] - a[1]).slice(0, 6).map(([p, n]) => `${p} ${n}`).join(' · ') })),
      h('div', { class: 'fin' }, x.niveauMax ? chip(x.niveauMax) : h('span', { class: 'dim', text: 'calme' }))))
      : [h('p', { class: 'vide', text: 'Aucun hôte n’a encore envoyé de journal.' })]));

    const src = b.parSource || [];
    sources.replaceChildren(...(src.length ? src.slice(0, 30).map(x => h('div', { class: 'flowrow', 'data-donnee': '' },
      h('span', { class: `itile g-${GRAV(x.niveau)}` }, icone('oeil', 15)),
      h('div', { class: 'grow1' }, h('strong', { class: 'ip', text: x.srcip }), h('small', { text: `${pluriel(x.n, 'alerte')} en 24 h` })),
      h('div', { class: 'fin' }, chip(x.niveau))))
      : [h('p', { class: 'vide', text: 'Aucune adresse source dans les alertes des dernières 24 h.' })]));

    regles.replaceChildren(...(e.regles.length ? e.regles.slice(0, 20).map(r => h('div', { class: 'regle-ligne' }, h('span', { class: 'mono', text: r.id }), h('b', { text: r.n.toLocaleString('fr-FR') })))
      : [h('p', { class: 'vide', text: 'Aucune règle déclenchée pour l’instant.' })]));
  };
  async function peindre() { etat = await api.get('/api/sentinelle'); peindre_(); }
  suivre(peindre, 15000);

  // L'essentiel sur une page : chiffres, avis, le direct en court, cinq
  // alertes, cinq hôtes. Chaque liste a sa page (#sentinelle?vue=…), hors du
  // menu, avec un retour ; les réglages et l'essai aussi.
  const TITRES = { direct: 'En direct', alertes: 'Alertes', hotes: 'Hôtes', sources: 'Sources et règles', reglages: admin ? 'Réglages de la sentinelle' : 'Brancher un hôte' };
  const vue = TITRES[params?.get?.('vue')] ? params.get('vue') : 'ensemble';
  const ouvrirVue = k => aller(`sentinelle?vue=${k}`);
  const voirPlus = k => h('button', { class: 'btn sm flat', type: 'button', onclick: () => ouvrirVue(k) }, 'Tout voir');
  const carte = (titre, note, corps) => h('div', { class: 'card' }, h('header', {}, h('h2', { text: titre }), note), corps);
  const apercuAlertes = h('div', {}), apercuHotes = h('div', {});
  const noteAlertes = h('span', { class: 'note' }), noteHotes = h('span', { class: 'note' });
  const peindreApercus = () => {
    apercuAlertes.replaceChildren(...(etat.recentes.length ? etat.recentes.slice(0, 5).map(a => h('div', { class: 'ligne-courte' },
      h('span', { class: `pastille g-${GRAV(a.niveau)}` }), h('strong', { text: a.hote || '?' }), h('span', { class: 'tronque', text: a.description }), chip(a.niveau)))
      : [h('p', { class: 'vide', text: 'Aucune alerte.' })]));
    apercuHotes.replaceChildren(...(etat.hotes.length ? etat.hotes.slice(0, 5).map(x => h('div', { class: 'ligne-courte' },
      h('span', { class: `pastille g-${x.niveauMax ? GRAV(x.niveauMax) : 'safe'}` }), h('strong', { class: 'ip', text: x.hote }), h('span', { class: 'tronque', text: `${pluriel(x.alertes, 'alerte')} · ${depuis(x.dernier)}` }), x.niveauMax ? chip(x.niveauMax) : h('span', { class: 'dim', text: 'calme' })))
      : [h('p', { class: 'vide', text: 'Aucun hôte.' })]));
    const n = (x, total) => (total > 5 ? `5 sur ${total}` : total ? String(total) : '');
    noteAlertes.textContent = n(0, etat.recentes.length); noteHotes.textContent = n(0, etat.hotes.length);
  };
  const peindreAvant = peindre_;
  peindre_ = () => { peindreAvant(); peindreApercus(); };

  const retour = h('button', { class: 'btn sm flat', type: 'button', onclick: () => aller('sentinelle') }, icone('retour', 14), 'Sentinelle');
  const tete = (titre, actions = []) => h('div', { class: 'headrow' },
    h('div', {}, vue !== 'ensemble' ? h('div', { class: 'fil' }, retour) : null, h('h1', { class: 'title', text: titre }), vue === 'ensemble' ? lede : null),
    h('div', { class: 'actions' }, ...actions));
  const directCtl = h('span', { class: 'note direct-ctl' }, temoin, selNiveau, btnPause);

  let corps;
  if (vue === 'ensemble') {
    direct.classList.add('court');
    corps = [
      tete('Sentinelle', [admin ? h('button', { class: 'btn', type: 'button', onclick: () => ouvrirVue('reglages') }, icone('reglages', 15), 'Réglages') : h('button', { class: 'btn', type: 'button', onclick: () => ouvrirVue('reglages') }, icone('serveur', 15), 'Brancher un hôte')]),
      figs, avis,
      h('div', { class: 'card mb12' }, h('header', {}, h('h2', { text: 'En direct' }), h('span', { class: 'row' }, temoin, voirPlus('direct'))), direct),
      h('div', { class: 'split' },
        carte('Dernières alertes', h('span', { class: 'row' }, noteAlertes, voirPlus('alertes')), apercuAlertes),
        carte('Hôtes les plus exposés', h('span', { class: 'row' }, noteHotes, voirPlus('hotes')), apercuHotes)),
      h('div', { class: 'mt12 actions' }, h('button', { class: 'btn sm', type: 'button', onclick: () => ouvrirVue('sources') }, icone('oeil', 14), 'Sources d’attaque et règles'))];
  } else if (vue === 'reglages') {
    corps = [tete(TITRES.reglages), admin ? h('div', { class: 'grille' }, carteReglages(), carteEssai(), carteBrancher()) : h('div', { class: 'grille' }, carteBrancher())];
  } else {
    const panneau = {
      direct: () => carte('En direct', directCtl, direct),
      alertes: () => carte('Alertes', h('span', { class: 'note', text: `niveau ${etat.seuil} et plus` }), alertes),
      hotes: () => carte('Hôtes', h('span', { class: 'note', text: 'par exposition' }), hotes),
      sources: () => h('div', {},
        h('div', { class: 'split' },
          carte('Sources d’attaque', h('span', { class: 'note', text: '24 h' }), sources),
          carte('Règles les plus déclenchées', h('span', { class: 'note', text: 'depuis le démarrage' }), h('div', { class: 'cardbody' }, regles))),
        carteRegles()),
    }[vue]();
    corps = [tete(TITRES[vue], [admin && vue !== 'direct' ? h('button', { class: 'btn', type: 'button', onclick: () => { ouvrirVue('reglages'); } }, icone('jouer', 15), 'Essayer une ligne') : null]), panneau];
  }
  const page = h('div', { class: 'page' }, ...corps);
  peindre_();
  ouvrir();
  return page;

  // Réglages
  function enregistrer(corps, message) { return sur(async () => { await api.put('/api/reglages/sentinelle', corps()); toast(message); await recharger(); }); }
  function carteReglages() {
    const r = reglages;
    const nombre = (v, min, max, libelle) => h('input', { class: 'field', type: 'number', min, max, value: v, 'aria-label': libelle });
    const seuil = nombre(r.seuil, 1, 15, 'Seuil des alertes');
    const seuilEv = nombre(r.seuilEvenement, 1, 15, 'Seuil des événements');
    const retention = nombre(r.retentionJours, 1, 365, 'Rétention');
    const actif = interrupteur(r.actif, 'Sentinelle active');
    const correler = interrupteur(r.correler, 'Nourrir le bouclier');
    return h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Réglages' }), h('span', { class: 'note', text: r.actif ? 'active' : 'éteinte' })), h('div', { class: 'cardbody' },
      h('p', { class: 'hint mt0', text: 'Chaque ligne reçoit un niveau de 0 à 15 : 3 une connexion réussie, 5 un mot de passe refusé, 8 une première fois ou un compte créé, 10 une force brute, 12 un compte probablement forcé ou ajouté aux administrateurs, 13 et plus une compromission corrélée.' }),
      h('div', { class: 'reglage-ligne' }, h('div', {}, h('strong', { text: 'Analyser les journaux d’hôtes' }), h('small', { text: 'Les lignes que le bouclier ne reconnaît pas (ni passerelle, ni sonde) passent à la sentinelle.' })), actif),
      h('div', { class: 'reglage-ligne' }, h('div', {}, h('strong', { text: 'Nourrir le bouclier' }), h('small', { text: 'Niveau 10 et plus : l’adresse source prend 60 à 120 points ; un hôte qui montre une compromission est noté machine suspecte.' })), correler),
      h('label', { class: 'lbl mt9', text: 'Alerte gardée dès le niveau · événement de VIGIE (diffusé) dès le niveau' }), h('div', { class: 'deux' }, seuil, seuilEv),
      h('label', { class: 'lbl mt9', text: 'Rétention des alertes (jours)' }), retention,
      h('div', { class: 'actions mt12' }, h('button', { class: 'btn solid', type: 'button', onclick: enregistrer(() => ({ actif: actif.valeur(), correler: correler.valeur(), seuil: Number(seuil.value), seuilEvenement: Number(seuilEv.value), retentionJours: Number(retention.value) }), 'Sentinelle enregistrée.') }, 'Enregistrer'))));
  }

  // Essai d'une ligne
  var essai;
  function carteEssai() {
    const ligne = h('textarea', { class: 'field mono', rows: 3, placeholder: '<38>Oct 15 10:00:01 serveur sshd[1234]: Failed password for root from 203.0.113.7 port 51234 ssh2', spellcheck: 'false', 'aria-label': 'Ligne de journal' });
    const sortie = h('div', { class: 'mt9' });
    const lancer = sur(async () => {
      const o = await api.post('/api/sentinelle/essai', { ligne: ligne.value });
      const d = o.decodage, p = o.predecodage;
      const champs = Object.entries(d.champs).map(([k, v]) => `${k}=${v}`).join(' · ');
      sortie.replaceChildren(
        h('dl', { class: 'preuve' },
          h('dt', { text: 'Hôte · programme' }), h('dd', { text: `${p.hote || '—'} · ${p.programme || '—'}${p.pid ? `[${p.pid}]` : ''}` }),
          h('dt', { text: 'Décodeur · geste' }), h('dd', { text: `${d.decodeur || 'aucun'} · ${d.geste}` }),
          h('dt', { text: 'Champs' }), h('dd', { text: champs || '—' }),
          h('dt', { text: 'Chaîne' }), h('dd', { text: o.chaine.map(r => `${r.id} (${r.niveau})`).join(' → ') || 'aucune règle' }),
          h('dt', { text: 'Avec répétition' }), h('dd', { text: o.composeesPossibles.map(r => `${r.id} (${r.niveau}${r.frequence ? `, ${r.frequence}× en ${r.fenetre} s` : r.apres ? ', après ' + (r.apres.regle || r.apres.groupe) : r.fts ? ', première fois' : ''})`).join(' · ') || '—' })),
        o.finale ? h('div', { class: 'row mt9' }, chip(o.finale.niveau), h('span', { text: o.finale.silence ? `${o.finale.description} — silencieuse (comptée, jamais montrée)` : o.finale.description })) : h('p', { class: 'hint', text: 'Aucune règle ne correspond : la ligne est comptée pour l’hôte, rien d’autre.' }));
    });
    essai = h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Essayer une ligne' }), h('span', { class: 'note', text: 'rien n’est retenu' })), h('div', { class: 'cardbody' },
      h('p', { class: 'hint mt0', text: 'Colle une ligne de journal telle que ton hôte l’envoie : la sentinelle montre ce qu’elle en décode et quelle règle elle retient.' }),
      ligne, h('div', { class: 'actions mt9' }, h('button', { class: 'btn solid', type: 'button', onclick: lancer }, icone('jouer', 15), 'Analyser')), sortie));
    return essai;
  }

  // Brancher un hôte
  function carteBrancher() {
    const port = etat.port || 5514;
    const bloc = (titre, texte) => h('details', { class: 'mt9' }, h('summary', { text: titre }), h('pre', { class: 'mono coupe conf', text: texte }));
    return h('div', { class: 'card' }, h('header', {}, h('h2', { text: 'Brancher un hôte' }), h('span', { class: 'note', text: `syslog ${port}` })), h('div', { class: 'cardbody' },
      h('p', { class: 'hint mt0', text: `Chaque machine envoie ses journaux au port syslog de VIGIE (UDP ou TCP, port ${port}), le même que la passerelle. Déclare ses adresses dans « Émetteurs » du Bouclier si tu as restreint la liste. Les lignes de la passerelle vont au bouclier, les autres à la sentinelle.` }),
      bloc('Linux (rsyslog)', `# /etc/rsyslog.d/90-vigie.conf\n*.* @@ADRESSE_DE_VIGIE:${port}   # TCP ; un seul @ pour UDP\n# puis : systemctl restart rsyslog`),
      bloc('Linux (journald seul)', `# /etc/systemd/journal-upload.conf n’envoie pas en syslog : installe rsyslog, ou\n# un relais : journalctl -f -o short | logger -n ADRESSE_DE_VIGIE -P ${port} -T`),
      bloc('Synology DSM', `Centre de journaux → Envoi des journaux → Serveur : ADRESSE_DE_VIGIE, port ${port}, protocole TCP, format BSD.\nCoche « Connexion » et « Système » : les échecs de connexion et les blocages automatiques arrivent.`),
      bloc('Proxmox VE', `# /etc/rsyslog.d/90-vigie.conf (rsyslog est présent)\n*.* @@ADRESSE_DE_VIGIE:${port}\n# pvedaemon, pveproxy, sshd, sudo : tout part.`),
      bloc('Docker (conteneurs)', `# daemon.json : {"log-driver":"syslog","log-opts":{"syslog-address":"tcp://ADRESSE_DE_VIGIE:${port}","tag":"{{.Name}}"}}\n# Les lignes arrivent avec le nom du conteneur comme programme.`),
      bloc('OpenWrt / UniFi (dropbear)', `# OpenWrt : System → Logging → External system log server : ADRESSE_DE_VIGIE, port ${port}\n# UniFi : Réglages → System → Remote logging (SIEM) : déjà branché pour le bouclier ; les journaux système y passent aussi.`)));
  }

  // Référence des règles
  function carteRegles() {
    const corps = h('div', {});
    const det = h('details', { class: 'card mt12 regles-ref', ontoggle: sur(async () => {
      if (!det.open || corps.children.length) return;
      const liste = await api.get('/api/sentinelle/regles');
      const familles = new Map();
      for (const r of liste) { const f = r.id.split('.')[0]; if (!familles.has(f)) familles.set(f, []); familles.get(f).push(r); }
      corps.replaceChildren(...[...familles].map(([f, rs]) => h('div', { class: 'famille' }, h('h3', { text: f }), rs.map(r => h('div', { class: 'regle-ligne' },
        h('span', {}, chip(r.niveau), ' ', h('span', { class: 'mono', text: r.id }), r.silence ? h('small', { text: ' silencieuse' }) : null, r.si ? h('small', { text: ` ← ${r.si}` }) : null),
        h('small', { text: `${r.description}${r.frequence ? ` — ${r.frequence}× en ${r.fenetre} s${r.meme ? ', même ' + r.meme.join('+') : ''}` : ''}${r.apres ? ` — après ${r.apres.regle || r.apres.groupe} (${r.apres.fenetre} s)` : ''}${r.fts ? ` — première fois (${r.fts.join('+')})` : ''}` }))))));
    }) }, h('summary', {}, h('h2', { text: `Les ${etat.nbRegles} règles` }), h('span', { class: 'note', text: 'niveau, parente, répétition' })), h('div', { class: 'cardbody' }, corps));
    return det;
  }
}
