// L'exercice : un réseau attaqué pour de faux, pour regarder le bouclier
// travailler sans attendre une vraie attaque. Des observations inventées
// (alertes d'IPS, balayages, force brute, serveur de commande, pot de miel,
// noms générés) entrent dans la corrélation comme celles des capteurs, avec
// la marque « exercice ».
//
// Ce qu'un exercice ne fait jamais : envoyer une adresse à la passerelle ou à
// la liste exportée, isoler une machine (réaction rapide), prévenir Telegram,
// la billetterie ou SYNAPSE, apparaître aux jetons du Hub. Les machines du
// réseau inventées vivent dans 10.254.0.0/16 ; les attaquants, dans des plages
// d'hébergeurs connus pour leurs abus — rien ne leur est envoyé.

// Millisecondes entre deux scénarios.
export const INTENSITES = { calme: 3000, normale: 1000, attaque: 250 };

const HEBERGEURS = ['45.155.205', '193.32.162', '141.98.11', '80.94.95', '91.240.118', '185.220.101', '103.145.13', '179.43.180', '62.204.41', '194.26.29', '87.120.84', '218.92.0'];
const INTERNE = '10.254';
const PASSERELLE = `${INTERNE}.0.1`;
const POT_DE_MIEL = `${INTERNE}.0.250`;

const SIGNATURES = {
  1: [
    ['ET EXPLOIT Possible ETERNALBLUE Probe MS17-010', 'Attempted Administrator Privilege Gain', 445],
    ['ET EXPLOIT Apache log4j RCE Attempt (CVE-2021-44228)', 'Attempted Administrator Privilege Gain', 443],
    ['ET EXPLOIT Fortinet FortiOS SSL VPN Path Traversal (CVE-2018-13379)', 'Web Application Attack', 443],
    ['ET WEB_SERVER ThinkPHP RCE Exploitation Attempt', 'Web Application Attack', 80],
  ],
  2: [
    ['ET SCAN Potential SSH Scan', 'Attempted Information Leak', 22],
    ['ET SCAN Suspicious inbound to MSSQL port 1433', 'Potentially Bad Traffic', 1433],
    ['ET WEB_SERVER /etc/passwd Detected in URI', 'Attempted Information Leak', 80],
    ['ET SCAN Zmap User-Agent (Inbound)', 'Detection of a Network Scan', 443],
  ],
  3: [
    ['ET SCAN NMAP OS Detection Probe', 'Attempted Information Leak', 0],
    ['ET INFO Inbound RDP Connection', 'Misc activity', 3389],
    ['ET POLICY Possible Telnet Connection Attempt', 'Potential Corporate Privacy Violation', 23],
    ['GPL ICMP_INFO PING *NIX', 'Misc activity', 0],
  ],
};
const C2 = [
  ['ET MALWARE Cobalt Strike Beacon Observed', 'A Network Trojan was detected'],
  ['ET MALWARE Win32/Emotet CnC Activity (POST)', 'A Network Trojan was detected'],
  ['ET MALWARE QakBot CnC Checkin', 'Malware Command and Control Activity Detected'],
];
const PORTS_FORCE_BRUTE = [22, 22, 3389, 445, 21, 5900, 8006];

export class Exercice {
  constructor({ bouclier, maintenant = () => Date.now(), aleatoire = Math.random }) {
    Object.assign(this, { bouclier, maintenant, aleatoire });
    this.vide();
  }

  vide() {
    this.actif = false; this.debut = null; this.fin = null; this.intensite = null;
    this.observations = 0; this.scenarios = {};
  }

  // ---- hasard ----
  entre(a, b) { return a + Math.floor(this.aleatoire() * (b - a + 1)); }
  un(l) { return l[Math.floor(this.aleatoire() * l.length)]; }
  attaquant() {
    for (let i = 0; i < 20; i++) {
      const ip = `${this.un(HEBERGEURS)}.${this.entre(2, 250)}`;
      if (!this.bouclier.riposte.refus(ip)) return ip;
    }
    return `${HEBERGEURS[0]}.${this.entre(2, 250)}`;
  }
  // Un attaquant qui revient souvent : une petite troupe tirée au départ, plus des inconnus.
  frappeur() { return this.aleatoire() < 0.6 ? this.un(this.troupe) : this.attaquant(); }
  machine() { return this.un(this.machines); }
  nomGenere() {
    const l = 'bcdfghjklmnpqrstvwxz0123456789';
    return Array.from({ length: this.entre(14, 22) }, () => l[Math.floor(this.aleatoire() * l.length)]).join('') + this.un(['.com', '.net', '.top', '.xyz', '.info']);
  }

  emettre(o) {
    this.observations++;
    this.bouclier.correlateur.observer({ quand: this.maintenant(), capteur: 'exercice', proto: 'tcp', action: 'alerte', gravite: null, signature: '', sid: null, categorie: '', regle: '', domaine: null, sport: this.entre(1024, 65000), ...o, exercice: true });
  }

  // ---- scénarios ----
  scenarios_() {
    return [
      [30, 'bruit', () => { for (let i = this.entre(1, 3); i > 0; i--) this.emettre({ type: 'pare-feu', src: this.attaquant(), dst: PASSERELLE, dport: this.un([23, 80, 443, 8080, 5060, 1900]), action: 'bloque', regle: 'WAN_IN-D-2147483647' }); }],
      [14, 'balayage', () => {
        const ip = this.frappeur(), n = this.entre(8, 30), base = this.entre(1, 60000);
        for (let i = 0; i < n; i++) this.emettre({ type: 'pare-feu', src: ip, dst: PASSERELLE, dport: ((base + i * 37) % 65535) + 1, action: 'bloque', regle: 'WAN_IN-D-2147483647' });
      }],
      [14, 'force-brute', () => {
        const ip = this.frappeur(), port = this.un(PORTS_FORCE_BRUTE), cible = this.machine();
        for (let i = this.entre(10, 35); i > 0; i--) this.emettre({ type: 'pare-feu', src: ip, dst: cible, dport: port, action: this.aleatoire() < 0.7 ? 'bloque' : 'accepte' });
      }],
      [26, 'ips', () => {
        const r = this.aleatoire(), g = r < 0.15 ? 1 : r < 0.5 ? 2 : 3;
        const [signature, categorie, port] = this.un(SIGNATURES[g]);
        this.emettre({ type: 'ips', src: this.frappeur(), dst: this.machine(), dport: port || null, gravite: g, signature, categorie, sid: 2000000 + this.entre(1000, 99999), action: this.aleatoire() < 0.5 ? 'bloque' : 'alerte' });
      }],
      [4, 'serveur de commande', () => {
        const m = this.machine(), c2 = this.un(this.c2), [signature, categorie] = this.un(C2);
        this.emettre({ type: 'flux', src: m, dst: c2, dport: 443 });
        if (this.aleatoire() < 0.6) this.emettre({ type: 'ips', src: m, dst: c2, dport: 443, gravite: this.un([1, 2]), signature, categorie, sid: 2000000 + this.entre(1000, 99999) });
      }],
      [3, 'pot de miel', () => this.emettre({ type: 'ips', src: this.machine(), dst: POT_DE_MIEL, dport: this.un([22, 23, 445, 3389]), gravite: 1, signature: 'Honeypot accessed', categorie: 'honeypot' })],
      [4, 'noms générés', () => { const m = this.machine(); for (let i = this.entre(3, 8); i > 0; i--) this.emettre({ type: 'dns', src: m, dst: PASSERELLE, dport: 53, proto: 'udp', domaine: this.nomGenere() }); }],
      [5, 'domaine listé', () => {
        const m = this.machine(), d = this.un(this.domaines);
        this.emettre({ type: 'dns', src: m, dst: PASSERELLE, dport: 53, proto: 'udp', domaine: `cdn.${d}` });
        if (this.aleatoire() < 0.5) this.emettre({ type: 'tls', src: m, dst: this.un(this.c2), dport: 443, domaine: `cdn.${d}` });
      }],
    ];
  }

  tour() {
    if (!this.actif) return;
    if (this.maintenant() >= this.fin) { this.arreter(); return; }
    const l = this.scenarios_();
    let r = this.aleatoire() * l.reduce((a, [p]) => a + p, 0);
    const [, nom, jouer] = l.find(([p]) => (r -= p) < 0) || l[0];
    this.scenarios[nom] = (this.scenarios[nom] || 0) + 1;
    jouer();
  }

  demarrer({ minutes = 10, intensite = 'normale' } = {}) {
    this.arreter();
    this.vide();
    const t = this.maintenant();
    Object.assign(this, { actif: true, debut: t, fin: t + minutes * 60e3, intensite });
    this.troupe = Array.from({ length: 12 }, () => this.attaquant());
    this.machines = Array.from({ length: 14 }, (_, i) => `${INTERNE}.10.${20 + i * 3}`);
    this.c2 = Array.from({ length: 4 }, () => this.attaquant());
    this.domaines = Array.from({ length: 4 }, () => `${this.un(['update', 'cdn', 'telemetry', 'sync'])}-${this.entre(100, 999)}.${this.un(['top', 'xyz', 'click'])}`);
    this.bouclier.menaces.poserExercice({ ips: this.c2, domaines: this.domaines });
    this.minuteur = setInterval(() => { try { this.tour(); } catch { /* un scénario raté n'arrête pas l'exercice */ } }, INTENSITES[intensite] || INTENSITES.normale);
    this.minuteur.unref?.();
    this.tour();
    return this.etat();
  }

  arreter() {
    clearInterval(this.minuteur);
    this.minuteur = null;
    if (this.actif) this.bouclier.menaces.retirerExercice();
    this.actif = false;
    return this.etat();
  }

  /** Tout ce que l'exercice a laissé : adresses notées, alertes, blocages, événements. */
  effacer() {
    this.arreter();
    const adresses = this.bouclier.correlateur.effacerExercice();
    const blocages = this.bouclier.riposte.effacerExercice();
    const evenements = Number(this.bouclier.db.prepare("DELETE FROM evenements WHERE type LIKE 'exercice.%'").run().changes);
    this.vide();
    return { adresses, blocages, evenements };
  }

  etat() {
    return {
      actif: this.actif, debut: this.debut, fin: this.fin, intensite: this.intensite, observations: this.observations, scenarios: { ...this.scenarios },
      blocages: this.bouclier.riposte.actifsExercice(),
      adresses: [...this.bouclier.correlateur.adresses.values()].filter(a => a.exercice).length,
    };
  }
}
