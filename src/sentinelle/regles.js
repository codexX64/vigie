// Les règles de la Sentinelle : ce qui, dans un journal d'hôte, mérite un
// niveau. L'échelle va de 0 à 15, comme dans les analyseurs d'événements
// classiques : 0 ignoré ; 2-4 information et erreurs mineures ; 5-7 erreurs
// d'utilisateur, attaques de faible portée, mots suspects ; 8 première fois
// vue ; 9-10 erreurs de source invalide, tentatives répétées (force brute) ;
// 11-12 intégrité, événement important ; 13-14 schéma d'attaque, corrélation ;
// 15 attaque grave.
//
// Une règle : { id, niveau, groupes, description,
//   decodeur / geste / programme / champs / message / hote : les conditions ;
//   si : l'identifiant de la règle qu'elle précise (arbre : testée seulement
//        quand sa parente a correspondu) ;
//   frequence + fenetre (s) + meme : « n fois en t secondes, même X » ;
//   apres : { regle | groupe, fenetre, meme } : « après qu'une autre alerte
//        ait été levée pour la même clé » ;
//   ignorer : secondes de silence après une alerte de même clé ;
//   fts : champs dont la première combinaison vue déclenche (first time seen) ;
//   silence : vrai → comptée, jamais signalée (sert de parente). }
// Les gestes sont ceux de decodeurs.js. `champs` compare des regex aux champs.

const ROOT = /^(?:root|admin|administrator|toor|pve-?root)$/i;
const URL_SUSPECTE = /(?:\.\.[\\/]|%2e%2e|\/etc\/(?:passwd|shadow)|\/proc\/self|<script|%3cscript|union[+ %]select|select.+from|information_schema|\.(?:env|git|svn|htpasswd|bak|sql|old|swp)(?:\/|$|\?)|wp-(?:login|admin|config)|xmlrpc\.php|phpmyadmin|\/cgi-bin\/|\/shell|cmd=|exec\(|eval\(|base64_decode|\$\{jndi:|\/actuator\/|\/\.aws\/|\/\.ssh\/|id_rsa|\/console$|\/_ignition|\/vendor\/phpunit|\/wp-content\/uploads\/.*\.php|\/\?s=index|\/boaform\/|\/HNAP1|\/GponForm|\/manager\/html|%00|\x00|\/\.\.;\/)/i;
const UA_OUTIL = /(?:sqlmap|nikto|nmap|masscan|zgrab|nuclei|gobuster|dirbuster|wpscan|hydra|metasploit|python-requests\/|go-http-client|curl\/|libwww-perl)/i;
const CMD_SUSPECTE = /(?:curl|wget)[^|;]*\|\s*(?:ba)?sh|nc\s+-[a-z]*e\s|\/dev\/tcp\/|base64\s+(?:-d|--decode)|chmod\s+[0-7]*[1357]{3}\s+\/tmp|\/tmp\/[^\s]+\s*&?$|python[23]?\s+-c\s+['"]import\s+(?:socket|pty)|mkfifo|socat\s+.*exec|\bxmrig\b|\bminerd\b|kinsing|\/etc\/(?:shadow|sudoers)|authorized_keys|crontab\s+-|iptables\s+-F|setenforce\s+0|history\s+-c|unset\s+HISTFILE|\.bash_history|tcpdump\s|LD_PRELOAD=|insmod\s|nohup\s.*&\s*$/i;
const MOTS_MAUVAIS = /\b(?:denied|refused|unauthorized|forbidden|rejected|fatal|panic|exploit|attack|rootkit|backdoor|malware|trojan|virus|compromis|intrusion|tamper|segfault|corrupt(?:ed|ion)|possible break-?in attempt|BREAK-IN)\b/i;
const SERVICE_CRITIQUE = /(?:ssh|sshd|docker|containerd|nginx|apache2|httpd|caddy|traefik|fail2ban|crowdsec|ufw|firewalld|nftables|iptables|wg-quick|openvpn|unbound|dnsmasq|pihole|pve-?\w*|corosync|smbd|nfs|postgres\w*|mariadb|mysql|redis|vaultwarden|home-?assistant|grafana|prometheus|rsyslog|syslog-ng|auditd|apparmor|clamav|zfs-\w+|mdmonitor|smartd|cron)/i;

export const REGLES = [
  // Bruit assumé : niveau 0, la ligne est comptée et oubliée
  { id: 'bruit.session', niveau: 0, groupes: ['bruit'], geste: /^session\.(?:ouverte|fermee)$/, decodeur: /^(?:cron|pam)$/, champs: { application: /^(?:cron|crond|systemd-user|sudo)$/ }, description: 'session de tâche planifiée' },
  { id: 'bruit.cron', niveau: 0, groupes: ['bruit'], geste: 'planif.commande', champs: { commande: /^(?:\s*\[ -x \/usr\/lib\/php|run-parts|\/usr\/lib\/sysstat|test -x|command -v debian-sa1|\/usr\/bin\/certbot|cd \/ && run-parts)/ }, description: 'tâche planifiée de maintenance' },
  { id: 'bruit.dns', niveau: 0, groupes: ['bruit', 'dns'], geste: 'dns.requete', silence: true, description: 'résolution DNS ordinaire' },

  // SSH
  { id: 'ssh.echec', niveau: 5, groupes: ['auth', 'auth-echec', 'ssh'], decodeur: /^(?:sshd|dropbear)$/, geste: 'auth.echec', description: 'mot de passe ou clé SSH refusé' },
  { id: 'ssh.echec-root', niveau: 7, groupes: ['auth', 'auth-echec', 'ssh'], si: 'ssh.echec', champs: { utilisateur: ROOT }, ignorer: 60, description: 'tentative SSH sur un compte d’administration' },
  { id: 'ssh.invalide', niveau: 5, groupes: ['auth', 'auth-echec', 'ssh', 'utilisateur-invalide'], decodeur: /^(?:sshd|dropbear)$/, geste: 'auth.invalide', description: 'connexion SSH sur un compte inexistant' },
  { id: 'ssh.limite', niveau: 8, groupes: ['auth', 'auth-echec', 'ssh'], decodeur: 'sshd', geste: 'auth.limite', description: 'SSH a coupé : trop d’essais d’authentification' },
  { id: 'ssh.sonde', niveau: 3, groupes: ['reseau', 'sonde', 'ssh'], decodeur: /^(?:sshd|dropbear)$/, geste: 'reseau.sonde', ignorer: 60, description: 'connexion SSH sans authentification (balayage, sonde)' },
  { id: 'ssh.sonde.rafale', niveau: 8, groupes: ['reseau', 'sonde', 'ssh', 'balayage'], si: 'ssh.sonde', frequence: 10, fenetre: 120, meme: ['srcip'], ignorer: 300, description: 'balayage SSH : dix sondes de la même adresse' },
  { id: 'ssh.ouverte', niveau: 3, groupes: ['auth', 'auth-succes', 'ssh'], decodeur: /^(?:sshd|dropbear)$/, geste: 'auth.succes', description: 'session SSH ouverte' },
  { id: 'ssh.ouverte-root', niveau: 9, groupes: ['auth', 'auth-succes', 'ssh', 'compte-admin'], si: 'ssh.ouverte', champs: { utilisateur: ROOT }, ignorer: 300, description: 'session SSH ouverte directement en administrateur' },
  { id: 'ssh.ouverte-motdepasse-admin', niveau: 10, groupes: ['auth', 'auth-succes', 'ssh', 'compte-admin'], si: 'ssh.ouverte-root', champs: { methode: /^password$/ }, ignorer: 300, description: 'administrateur entré par mot de passe (pas de clé)' },
  { id: 'ssh.premiere-source', niveau: 8, groupes: ['auth', 'auth-succes', 'ssh', 'premiere-fois'], si: 'ssh.ouverte', fts: ['hote', 'utilisateur', 'srcip'], description: 'première connexion SSH de cette adresse pour cet utilisateur sur cet hôte' },
  { id: 'ssh.force-brute', niveau: 10, groupes: ['auth', 'auth-echec', 'ssh', 'force-brute'], si: 'ssh.echec', frequence: 8, fenetre: 120, meme: ['srcip'], ignorer: 120, description: 'force brute SSH : huit échecs de la même adresse en deux minutes' },
  { id: 'ssh.force-brute.invalides', niveau: 10, groupes: ['auth', 'auth-echec', 'ssh', 'force-brute', 'utilisateur-invalide'], si: 'ssh.invalide', frequence: 6, fenetre: 120, meme: ['srcip'], ignorer: 120, description: 'énumération de comptes SSH : six comptes inexistants de la même adresse' },
  { id: 'ssh.force-brute.compte', niveau: 10, groupes: ['auth', 'auth-echec', 'ssh', 'force-brute'], si: 'ssh.echec', frequence: 8, fenetre: 300, meme: ['hote', 'utilisateur'], ignorer: 300, description: 'force brute SSH sur un même compte depuis plusieurs adresses' },
  { id: 'ssh.force-brute.distribuee', niveau: 11, groupes: ['auth', 'auth-echec', 'ssh', 'force-brute', 'distribuee'], si: 'ssh.echec', frequence: 30, fenetre: 300, meme: ['hote'], ignorer: 300, description: 'force brute SSH distribuée : trente échecs sur l’hôte en cinq minutes' },
  { id: 'ssh.succes-apres-force-brute', niveau: 12, groupes: ['auth', 'auth-succes', 'ssh', 'force-brute', 'compromission'], si: 'ssh.ouverte', apres: { groupe: 'force-brute', fenetre: 1800, meme: ['srcip'] }, description: 'connexion SSH réussie après une force brute de la même adresse : compte probablement forcé' },
  { id: 'ssh.succes-apres-echecs', niveau: 10, groupes: ['auth', 'auth-succes', 'ssh', 'compromission'], si: 'ssh.ouverte', apres: { regle: 'ssh.echec', fenetre: 600, meme: ['srcip', 'utilisateur'], frequence: 3 }, description: 'connexion SSH réussie après plusieurs échecs du même compte depuis la même adresse' },

  // Autres authentifications (services, NAS, hyperviseur, VPN, courrier…)
  { id: 'auth.echec', niveau: 5, groupes: ['auth', 'auth-echec'], geste: 'auth.echec', description: 'authentification refusée' },
  { id: 'auth.echec-admin', niveau: 7, groupes: ['auth', 'auth-echec'], si: 'auth.echec', champs: { utilisateur: ROOT }, ignorer: 60, description: 'authentification refusée sur un compte d’administration' },
  { id: 'auth.invalide', niveau: 5, groupes: ['auth', 'auth-echec', 'utilisateur-invalide'], geste: 'auth.invalide', description: 'authentification sur un compte inexistant' },
  { id: 'auth.limite', niveau: 8, groupes: ['auth', 'auth-echec', 'blocage-cible'], geste: 'auth.limite', ignorer: 300, description: 'la cible a bloqué l’adresse elle-même (trop d’essais)' },
  { id: 'auth.force-brute', niveau: 10, groupes: ['auth', 'auth-echec', 'force-brute'], si: 'auth.echec', frequence: 8, fenetre: 180, meme: ['srcip'], ignorer: 180, description: 'force brute : huit refus de la même adresse en trois minutes' },
  { id: 'auth.force-brute.compte', niveau: 10, groupes: ['auth', 'auth-echec', 'force-brute'], si: 'auth.echec', frequence: 10, fenetre: 300, meme: ['hote', 'utilisateur'], ignorer: 300, description: 'force brute sur un même compte' },
  { id: 'auth.force-brute.invalides', niveau: 10, groupes: ['auth', 'auth-echec', 'force-brute', 'utilisateur-invalide'], si: 'auth.invalide', frequence: 6, fenetre: 180, meme: ['srcip'], ignorer: 180, description: 'énumération de comptes : six comptes inexistants de la même adresse' },
  { id: 'auth.force-brute.distribuee', niveau: 11, groupes: ['auth', 'auth-echec', 'force-brute', 'distribuee'], si: 'auth.echec', frequence: 40, fenetre: 300, meme: ['hote'], ignorer: 300, description: 'force brute distribuée sur l’hôte' },
  { id: 'auth.succes', niveau: 3, groupes: ['auth', 'auth-succes'], geste: 'auth.succes', description: 'authentification réussie' },
  { id: 'auth.succes-admin', niveau: 6, groupes: ['auth', 'auth-succes', 'compte-admin'], si: 'auth.succes', champs: { utilisateur: ROOT }, ignorer: 600, description: 'session d’administration ouverte' },
  { id: 'auth.premiere-source', niveau: 8, groupes: ['auth', 'auth-succes', 'premiere-fois'], si: 'auth.succes', fts: ['hote', 'decodeur', 'utilisateur', 'srcip'], description: 'première connexion de cette adresse pour cet utilisateur sur ce service' },
  { id: 'auth.succes-apres-force-brute', niveau: 12, groupes: ['auth', 'auth-succes', 'force-brute', 'compromission'], si: 'auth.succes', apres: { groupe: 'force-brute', fenetre: 1800, meme: ['srcip'] }, description: 'authentification réussie après une force brute de la même adresse : compte probablement forcé' },
  { id: 'auth.succes-apres-echecs', niveau: 10, groupes: ['auth', 'auth-succes', 'compromission'], si: 'auth.succes', apres: { groupe: 'auth-echec', fenetre: 600, meme: ['srcip', 'utilisateur'], frequence: 3 }, description: 'authentification réussie après plusieurs échecs du même compte depuis la même adresse' },
  { id: 'vpn.poignee', niveau: 0, groupes: ['bruit', 'vpn'], geste: 'vpn.poignee', silence: true, description: 'poignée de main VPN' },
  { id: 'vpn.poignee.rafale', niveau: 6, groupes: ['vpn', 'sonde'], si: 'vpn.poignee', frequence: 30, fenetre: 60, meme: ['srcip'], ignorer: 300, description: 'rafale de poignées de main VPN de la même adresse' },

  // Élévation de privilèges
  { id: 'priv.commande', niveau: 3, groupes: ['priv', 'sudo'], geste: 'priv.commande', description: 'commande exécutée avec élévation' },
  { id: 'priv.commande.suspecte', niveau: 11, groupes: ['priv', 'sudo', 'commande-suspecte', 'compromission'], si: 'priv.commande', champs: { commande: CMD_SUSPECTE }, description: 'commande élevée au profil d’un post-exploitation (téléchargement exécuté, coquille inversée, effacement de traces, mineur…)' },
  { id: 'priv.premiere-fois', niveau: 4, groupes: ['priv', 'sudo', 'premiere-fois'], si: 'priv.commande', fts: ['hote', 'utilisateur'], description: 'première élévation de cet utilisateur sur cet hôte' },
  { id: 'priv.echec', niveau: 5, groupes: ['priv', 'sudo', 'priv-echec'], geste: 'priv.echec', description: 'élévation refusée (mot de passe faux)' },
  { id: 'priv.interdit', niveau: 8, groupes: ['priv', 'sudo', 'priv-echec'], si: 'priv.echec', champs: { raison: /NOT in sudoers|not allowed/i }, description: 'élévation tentée par un compte qui n’y a pas droit' },
  { id: 'priv.echec.rafale', niveau: 10, groupes: ['priv', 'sudo', 'priv-echec', 'force-brute'], si: 'priv.echec', frequence: 3, fenetre: 300, meme: ['hote', 'utilisateur'], ignorer: 300, description: 'trois élévations refusées pour le même compte : devinette de mot de passe local' },
  { id: 'priv.coquille-root', niveau: 6, groupes: ['priv', 'sudo'], si: 'priv.commande', champs: { commande: /^(?:\/bin\/|\/usr\/bin\/)?(?:bash|sh|zsh|fish|su)\b|^(?:\/usr\/bin\/)?sudo\s+-[is]\b|^-i$/, cible: ROOT }, ignorer: 600, description: 'coquille d’administration ouverte par élévation' },

  // Comptes et groupes
  { id: 'compte.cree', niveau: 8, groupes: ['compte', 'integrite'], geste: 'compte.cree', description: 'nouveau compte utilisateur' },
  { id: 'compte.cree.id-zero', niveau: 14, groupes: ['compte', 'integrite', 'compromission'], si: 'compte.cree', champs: { id: /^0$/ }, description: 'compte créé avec l’identifiant 0 : porte dérobée administrateur' },
  { id: 'compte.supprime', niveau: 8, groupes: ['compte', 'integrite'], geste: 'compte.supprime', description: 'compte utilisateur supprimé' },
  { id: 'compte.modifie', niveau: 5, groupes: ['compte', 'integrite'], geste: 'compte.modifie', description: 'compte ou groupe modifié' },
  { id: 'compte.motdepasse', niveau: 8, groupes: ['compte', 'integrite'], geste: 'compte.motdepasse', description: 'mot de passe changé' },
  { id: 'compte.motdepasse-admin', niveau: 10, groupes: ['compte', 'integrite', 'compte-admin'], si: 'compte.motdepasse', champs: { utilisateur: ROOT }, description: 'mot de passe d’administration changé' },
  { id: 'groupe.ajout', niveau: 6, groupes: ['compte', 'integrite'], geste: 'groupe.ajout', description: 'utilisateur ajouté à un groupe' },
  { id: 'groupe.ajout-admin', niveau: 12, groupes: ['compte', 'integrite', 'compte-admin', 'compromission'], si: 'groupe.ajout', champs: { groupe: /^(?:sudo|wheel|admin|root|docker|lxd|adm|shadow|disk)$/ }, description: 'utilisateur ajouté à un groupe qui donne les pleins pouvoirs' },
  { id: 'compte.cree-apres-intrusion', niveau: 13, groupes: ['compte', 'integrite', 'compromission'], si: 'compte.cree', apres: { groupe: 'compromission', fenetre: 3600, meme: ['hote'] }, description: 'compte créé sur un hôte où une compromission vient d’être signalée' },
  { id: 'compte.rafale', niveau: 12, groupes: ['compte', 'integrite', 'compromission'], si: 'compte.cree', frequence: 3, fenetre: 600, meme: ['hote'], description: 'plusieurs comptes créés d’affilée sur le même hôte' },

  // Services
  { id: 'service.echec', niveau: 5, groupes: ['service'], geste: 'service.echec', ignorer: 120, description: 'un service a échoué' },
  { id: 'service.echec.boucle', niveau: 7, groupes: ['service', 'instabilite'], si: 'service.echec', frequence: 5, fenetre: 300, meme: ['hote', 'unite'], ignorer: 600, description: 'un service échoue en boucle' },
  { id: 'service.arrete', niveau: 3, groupes: ['service'], geste: 'service.arrete', description: 'service arrêté' },
  { id: 'service.arrete.critique', niveau: 8, groupes: ['service', 'integrite', 'defense'], si: 'service.arrete', champs: { unite: SERVICE_CRITIQUE }, ignorer: 300, description: 'arrêt d’un service de sécurité ou d’infrastructure (pare-feu, journal, antivirus, SSH, gardien…)' },
  { id: 'service.demarre', niveau: 2, groupes: ['service'], geste: 'service.demarre', description: 'service démarré' },
  { id: 'service.grappe', niveau: 7, groupes: ['service', 'proxmox'], geste: 'service.grappe', message: /lost quorum|members: \d+/, ignorer: 300, description: 'changement de quorum ou de membres dans la grappe' },
  { id: 'action.tache', niveau: 2, groupes: ['proxmox'], geste: 'action.tache', description: 'tâche Proxmox' },
  { id: 'action.tache.sensible', niveau: 7, groupes: ['proxmox', 'integrite'], si: 'action.tache', champs: { tache: /:(?:qmdestroy|vzdestroy|qmrestore|vzrestore|qmclone|vzclone|aptupdate|srvreload|stopall|startall|qmsnapshot|vzsnapshot|imgdel|download|move_volume|qmigrate):/ }, description: 'tâche Proxmox sensible (destruction, restauration, migration, mise à jour)' },

  // Noyau
  { id: 'noyau.segfault', niveau: 6, groupes: ['noyau', 'instabilite'], geste: 'noyau.segfault', ignorer: 60, description: 'un processus a planté (segfault)' },
  { id: 'noyau.segfault.rafale', niveau: 9, groupes: ['noyau', 'instabilite', 'exploitation'], si: 'noyau.segfault', frequence: 5, fenetre: 120, meme: ['hote', 'processus'], ignorer: 300, description: 'le même programme plante en rafale : tentative d’exploitation probable' },
  { id: 'noyau.oom', niveau: 6, groupes: ['noyau', 'instabilite'], geste: 'noyau.oom', ignorer: 60, description: 'le noyau a tué un processus (mémoire épuisée)' },
  { id: 'noyau.syn', niveau: 10, groupes: ['noyau', 'reseau', 'deni-de-service'], geste: 'noyau.syn', ignorer: 300, description: 'inondation SYN détectée par le noyau (déni de service)' },
  { id: 'noyau.promiscuite', niveau: 8, groupes: ['noyau', 'reseau', 'integrite', 'ecoute'], geste: 'noyau.promiscuite', ignorer: 300, description: 'une interface passe en mode promiscuité : écoute du réseau' },
  { id: 'noyau.promiscuite-apres-intrusion', niveau: 13, groupes: ['noyau', 'reseau', 'compromission'], si: 'noyau.promiscuite', apres: { groupe: 'compromission', fenetre: 3600, meme: ['hote'] }, description: 'écoute du réseau sur un hôte déjà signalé compromis' },
  { id: 'noyau.usb', niveau: 4, groupes: ['noyau', 'materiel'], geste: 'noyau.usb', ignorer: 10, description: 'périphérique USB branché' },
  { id: 'noyau.module', niveau: 9, groupes: ['noyau', 'integrite'], geste: 'noyau.module', description: 'module noyau non signé ou hors arbre chargé' },
  { id: 'noyau.saturation', niveau: 7, groupes: ['noyau', 'reseau', 'deni-de-service'], geste: 'noyau.saturation', ignorer: 300, description: 'table de connexions pleine : saturation réseau' },
  { id: 'parefeu.paquet', niveau: 0, groupes: ['bruit', 'parefeu'], geste: 'parefeu.paquet', silence: true, description: 'paquet journalisé par le pare-feu de l’hôte' },
  { id: 'parefeu.balayage', niveau: 8, groupes: ['parefeu', 'reseau', 'balayage'], si: 'parefeu.paquet', frequence: 20, fenetre: 60, meme: ['hote', 'srcip'], ignorer: 300, description: 'balayage de ports sur l’hôte : vingt paquets journalisés de la même adresse en une minute' },

  // Web
  // Sous web.requete, les précisions atomiques s'excluent (la première qui
  // correspond gagne) ; les règles de répétition portent leurs propres champs
  // pour compter quelle que soit la précision retenue.
  { id: 'web.requete', niveau: 0, groupes: ['web'], geste: 'web.requete', silence: true, description: 'requête web' },
  { id: 'web.url-suspecte', niveau: 6, groupes: ['web', 'web-attaque', 'sonde'], si: 'web.requete', champs: { url: URL_SUSPECTE }, ignorer: 30, description: 'requête web au profil d’attaque (traversée, injection, fichiers sensibles, portes dérobées connues)' },
  { id: 'web.url-suspecte.servie', niveau: 12, groupes: ['web', 'web-attaque', 'compromission'], si: 'web.url-suspecte', champs: { statut: /^2\d\d$/, url: /(?:\.\.[\\/]|%2e%2e|\/etc\/(?:passwd|shadow)|\.(?:env|git\/|htpasswd|sql|bak)|\$\{jndi:|cmd=|\/shell)/i }, description: 'requête d’attaque servie avec succès : le serveur web a répondu 200 à une traversée, un fichier sensible ou une commande' },
  { id: 'web.outil', niveau: 6, groupes: ['web', 'web-attaque', 'sonde'], si: 'web.requete', message: UA_OUTIL, ignorer: 120, description: 'agent utilisateur d’un outil d’attaque ou de balayage' },
  { id: 'web.erreur-client', niveau: 3, groupes: ['web', 'web-erreur'], si: 'web.requete', champs: { statut: /^4\d\d$/ }, silence: true, description: 'requête web refusée ou introuvable' },
  { id: 'web.interdit', niveau: 5, groupes: ['web', 'web-erreur', 'auth-echec'], si: 'web.erreur-client', champs: { statut: /^40[13]$/ }, silence: true, description: 'requête web non autorisée' },
  { id: 'web.erreur-serveur', niveau: 4, groupes: ['web', 'web-erreur'], si: 'web.requete', champs: { statut: /^5\d\d$/ }, ignorer: 60, description: 'erreur interne du serveur web' },
  { id: 'web.balayage', niveau: 10, groupes: ['web', 'web-attaque', 'balayage'], si: 'web.requete', champs: { statut: /^4\d\d$/ }, frequence: 30, fenetre: 60, meme: ['srcip'], ignorer: 300, description: 'balayage web : trente erreurs 4xx de la même adresse en une minute' },
  { id: 'web.force-brute', niveau: 10, groupes: ['web', 'web-attaque', 'force-brute'], si: 'web.requete', champs: { statut: /^40[13]$/ }, frequence: 15, fenetre: 120, meme: ['srcip'], ignorer: 300, description: 'force brute web : quinze 401/403 de la même adresse' },
  { id: 'web.attaque.rafale', niveau: 10, groupes: ['web', 'web-attaque', 'balayage'], si: 'web.requete', champs: { url: URL_SUSPECTE }, frequence: 5, fenetre: 120, meme: ['srcip'], ignorer: 300, description: 'cinq requêtes d’attaque de la même adresse : outil de balayage de vulnérabilités' },
  { id: 'web.erreur', niveau: 4, groupes: ['web', 'web-erreur'], geste: 'web.erreur', ignorer: 60, description: 'erreur du serveur web' },
  { id: 'web.erreur.rafale', niveau: 8, groupes: ['web', 'web-attaque'], si: 'web.erreur', frequence: 20, fenetre: 60, meme: ['srcip'], ignorer: 300, description: 'rafale d’erreurs web de la même adresse' },

  // Conteneurs
  { id: 'conteneur.mort', niveau: 4, groupes: ['conteneur', 'service'], geste: 'conteneur.mort', ignorer: 30, description: 'un conteneur s’est arrêté anormalement' },
  { id: 'conteneur.mort.boucle', niveau: 7, groupes: ['conteneur', 'service', 'instabilite'], si: 'conteneur.mort', frequence: 5, fenetre: 600, meme: ['hote', 'id'], ignorer: 600, description: 'un conteneur meurt en boucle' },

  // Réseau local : DHCP, Wi-Fi, DNS
  { id: 'reseau.bail', niveau: 2, groupes: ['reseau', 'dhcp'], geste: 'reseau.bail', silence: true, description: 'bail DHCP' },
  { id: 'reseau.bail.nouveau', niveau: 7, groupes: ['reseau', 'dhcp', 'premiere-fois', 'nouvel-appareil'], si: 'reseau.bail', fts: ['mac'], description: 'adresse matérielle jamais vue : nouvel appareil sur le réseau' },
  { id: 'reseau.bail.rafale', niveau: 9, groupes: ['reseau', 'dhcp', 'deni-de-service'], si: 'reseau.bail', frequence: 30, fenetre: 60, meme: ['hote'], ignorer: 300, description: 'trente baux en une minute : épuisement DHCP ou tempête' },
  { id: 'wifi.assoc', niveau: 2, groupes: ['reseau', 'wifi'], geste: 'wifi.assoc', silence: true, description: 'appareil associé au Wi-Fi' },
  { id: 'wifi.assoc.nouveau', niveau: 7, groupes: ['reseau', 'wifi', 'premiere-fois', 'nouvel-appareil'], si: 'wifi.assoc', fts: ['mac'], description: 'adresse matérielle jamais vue sur le Wi-Fi' },
  { id: 'wifi.deauth', niveau: 2, groupes: ['reseau', 'wifi'], geste: 'wifi.deauth', silence: true, description: 'appareil désassocié du Wi-Fi' },
  { id: 'wifi.deauth.rafale', niveau: 9, groupes: ['reseau', 'wifi', 'deni-de-service'], si: 'wifi.deauth', frequence: 20, fenetre: 60, meme: ['hote'], ignorer: 300, description: 'vingt désassociations en une minute : attaque de désauthentification probable' },
  { id: 'wifi.echec', niveau: 5, groupes: ['reseau', 'wifi', 'auth-echec'], decodeur: 'wifi', geste: 'auth.echec', description: 'authentification Wi-Fi 802.1X refusée' },
  { id: 'dns.bloque', niveau: 5, groupes: ['dns', 'reseau'], geste: 'dns.bloque', ignorer: 60, description: 'domaine bloqué par le filtre DNS' },
  { id: 'dns.bloque.rafale', niveau: 9, groupes: ['dns', 'reseau', 'compromission'], si: 'dns.bloque', frequence: 20, fenetre: 300, meme: ['srcip'], ignorer: 600, description: 'un appareil insiste vers des domaines bloqués : logiciel indésirable probable' },
  { id: 'dns.suspect', niveau: 7, groupes: ['dns', 'reseau', 'sonde'], si: 'bruit.dns', champs: { domaine: /(?:\.(?:onion|tor2web|bit)$|\b(?:pastebin|ngrok|serveo|duckdns|no-ip|dyndns|hopto|zapto|ddns)\b|^(?:[a-z0-9]{20,}\.)|xmr|monero|minexmr|nanopool|c2\.|\bbeacon\b)/i }, ignorer: 120, description: 'résolution d’un domaine au profil suspect (réseau anonymisé, tunnel, mineur, DNS dynamique)' },
  { id: 'dns.rafale', niveau: 8, groupes: ['dns', 'reseau', 'exfiltration'], si: 'bruit.dns', frequence: 300, fenetre: 60, meme: ['srcip'], ignorer: 600, description: 'trois cents résolutions en une minute du même appareil : tunnel DNS ou logiciel emballé' },
  { id: 'dns.txt-rafale', niveau: 9, groupes: ['dns', 'reseau', 'exfiltration'], si: 'bruit.dns', champs: { type: /^(?:TXT|NULL|CNAME)$/ }, frequence: 40, fenetre: 60, meme: ['srcip'], ignorer: 600, description: 'rafale de requêtes TXT/NULL : tunnel DNS probable' },

  // Tâches planifiées
  { id: 'planif.commande', niveau: 2, groupes: ['planif'], geste: 'planif.commande', silence: true, description: 'tâche planifiée exécutée' },
  { id: 'planif.commande.suspecte', niveau: 11, groupes: ['planif', 'commande-suspecte', 'compromission'], si: 'planif.commande', champs: { commande: CMD_SUSPECTE }, ignorer: 300, description: 'tâche planifiée au profil d’un implant (téléchargement exécuté, coquille inversée, mineur)' },
  { id: 'planif.modifie', niveau: 7, groupes: ['planif', 'integrite'], geste: 'planif.modifie', description: 'table de tâches planifiées modifiée' },
  { id: 'planif.modifie-apres-intrusion', niveau: 13, groupes: ['planif', 'integrite', 'compromission', 'persistance'], si: 'planif.modifie', apres: { groupe: 'compromission', fenetre: 3600, meme: ['hote'] }, description: 'tâches planifiées modifiées sur un hôte signalé compromis : persistance' },

  // Gardiens
  { id: 'gardien.ban', niveau: 7, groupes: ['gardien', 'force-brute'], geste: 'bannissement', champs: { quoi: /^(?:Ban|ban|decision)$/ }, description: 'adresse bannie par un gardien (fail2ban, CrowdSec)' },
  { id: 'gardien.ban.recidive', niveau: 10, groupes: ['gardien', 'force-brute'], si: 'gardien.ban', frequence: 3, fenetre: 86400, meme: ['srcip'], description: 'adresse bannie trois fois en un jour : récidiviste' },
  { id: 'gardien.unban', niveau: 2, groupes: ['gardien'], geste: 'bannissement', champs: { quoi: /^Unban$/ }, description: 'bannissement levé' },

  // Repli : mots qui sentent mauvais, sans décodeur
  { id: 'texte.mauvais-mot', niveau: 2, groupes: ['texte'], geste: 'depot.texte', message: MOTS_MAUVAIS, ignorer: 60, description: 'ligne sans décodeur contenant un mot d’alerte' },
  { id: 'texte.intrusion', niveau: 9, groupes: ['texte', 'compromission'], si: 'texte.mauvais-mot', message: /\b(?:rootkit|backdoor|possible break-?in attempt|BREAK-IN|trojan|malware detected|virus found|exploit)\b/i, ignorer: 300, description: 'un programme signale lui-même une intrusion ou un code malveillant' },
  { id: 'texte.mauvais-mot.rafale', niveau: 7, groupes: ['texte'], si: 'texte.mauvais-mot', frequence: 30, fenetre: 60, meme: ['hote'], ignorer: 300, description: 'rafale de lignes d’erreur sur le même hôte' },
];

const PAR_ID = new Map(REGLES.map(r => [r.id, r]));
export const ENFANTS = new Map();
for (const r of REGLES) { if (r.si) { if (!PAR_ID.has(r.si)) throw new Error(`règle ${r.id} : parente inconnue ${r.si}`); const l = ENFANTS.get(r.si) || []; l.push(r); ENFANTS.set(r.si, l); } }
export const RACINES = REGLES.filter(r => !r.si);
export const regle = id => PAR_ID.get(id);

/** Gravité pour l'interface et le moteur d'alertes de VIGIE, d'après le niveau. */
export function gravite(niveau) {
  if (niveau >= 13) return 'critique';
  if (niveau >= 10) return 'eleve';
  if (niveau >= 7) return 'faible';
  return 'info';
}
