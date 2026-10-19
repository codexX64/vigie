// Décodeurs : une fois la ligne pré-décodée (predecodeur.js), on cherche quel
// programme parle et ce qu'il dit, et on extrait les champs qui comptent —
// adresse source, utilisateur, port, URL, statut… Les règles (regles.js) ne
// regardent ensuite que ces champs et le « geste » décodé, jamais le texte.
//
// Chaque décodeur : { nom, programme (regex sur le nom de programme, ou null
// pour « n'importe lequel »), prematch (regex rapide sur le message, facultatif),
// motifs: [{ regex à groupes nommés, geste }] }. Le premier motif qui
// correspond gagne ; les groupes nommés deviennent les champs. Gestes possibles :
//   auth.echec            un mot de passe refusé, un compte inconnu, une clé rejetée
//   auth.succes           une ouverture de session réussie
//   auth.invalide         tentative sur un compte qui n'existe pas
//   auth.limite           la cible elle-même a coupé (trop d'essais, blocage automatique)
//   session.ouverte / session.fermee
//   priv.commande         une commande exécutée avec élévation (sudo, su)
//   priv.echec            élévation refusée
//   compte.cree / compte.supprime / compte.modifie / compte.motdepasse / groupe.ajout
//   service.demarre / service.arrete / service.echec
//   noyau.segfault / noyau.oom / noyau.syn / noyau.promiscuite / noyau.usb / noyau.module
//   web.requete           une requête HTTP (statut, url, methode)
//   conteneur.mort / conteneur.demarre
//   reseau.bail           un bail DHCP accordé (nouvel appareil ?)
//   wifi.assoc / wifi.deauth
//   dns.requete           une résolution DNS (Pi-hole, dnsmasq, unbound)
//   planif.commande       une tâche cron exécutée
//   bannissement          une adresse bannie par un gardien (fail2ban, CrowdSec)
//   depot.texte           le reste : la ligne n'a pas de geste connu, seuls les
//                         « mauvais mots » (regles.js) la regardent

const ADRESSE = String.raw`(?:::[fF]{4}:)?(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{2,39}`;
const IP = String.raw`(?<srcip>${ADRESSE})`;
const IPD = String.raw`(?<dstip>${ADRESSE})`;
const UTIL = String.raw`(?<utilisateur>[^\s'"]{1,64})`;
const re = s => new RegExp(s);

export const DECODEURS = [
  // ---- SSH (OpenSSH) ----
  { nom: 'sshd', programme: /^sshd(?:-session)?$/, motifs: [
    { regex: re(String.raw`^Failed (?<methode>password|publickey|keyboard-interactive|none)(?:/\S+)? for invalid user ${UTIL} from ${IP} port (?<srcport>\d+)`), geste: 'auth.invalide' },
    { regex: re(String.raw`^Failed (?<methode>password|publickey|keyboard-interactive|none)(?:/\S+)? for ${UTIL} from ${IP} port (?<srcport>\d+)`), geste: 'auth.echec' },
    { regex: re(String.raw`^Invalid user ${UTIL} from ${IP}`), geste: 'auth.invalide' },
    { regex: re(String.raw`^Accepted (?<methode>password|publickey|keyboard-interactive|hostbased)(?:/\S+)? for ${UTIL} from ${IP} port (?<srcport>\d+)`), geste: 'auth.succes' },
    { regex: re(String.raw`^error: maximum authentication attempts exceeded for (?:invalid user )?${UTIL} from ${IP}`), geste: 'auth.limite' },
    { regex: re(String.raw`^(?:Did not receive identification string|Connection closed by(?: authenticating| invalid)? user \S+|Connection reset by|banner exchange: Connection) .*?${IP}`), geste: 'reseau.sonde' },
    { regex: re(String.raw`^(?:Disconnected from|Received disconnect from) (?:authenticating |invalid )?(?:user ${UTIL} )?${IP}`), geste: 'session.fermee' },
    { regex: re(String.raw`^(?:Unable to negotiate with|no matching \w+ found|fatal: Unable to negotiate) ${IP}`), geste: 'reseau.sonde' },
    { regex: re(String.raw`^Bad protocol version identification .* from ${IP}`), geste: 'reseau.sonde' },
    { regex: re(String.raw`^(?:reverse mapping checking|Address ${IP} maps to \S+, but this does not map back)`), geste: 'reseau.sonde' },
    { regex: re(String.raw`^User ${UTIL} from ${IP} not allowed because`), geste: 'auth.echec' },
    { regex: re(String.raw`^pam_unix\(sshd:auth\): authentication failure; .*?(?:ruser=\S* )?rhost=${IP}(?:\s+user=${UTIL})?`), geste: 'auth.echec' },
    { regex: re(String.raw`^pam_unix\(sshd:session\): session (?<etat>opened|closed) for user ${UTIL}`), geste: 'session.*' },
  ] },
  // ---- Dropbear (OpenWrt, UniFi, routeurs) ----
  { nom: 'dropbear', programme: /^dropbear$/, motifs: [
    { regex: re(String.raw`^Bad (?:password|PAM password) attempt for '${UTIL}' from ${IP}:(?<srcport>\d+)`), geste: 'auth.echec' },
    { regex: re(String.raw`^Login attempt for nonexistent user from ${IP}:(?<srcport>\d+)`), geste: 'auth.invalide' },
    { regex: re(String.raw`^(?:Password|Pubkey) auth succeeded for '${UTIL}' from ${IP}:(?<srcport>\d+)`), geste: 'auth.succes' },
    { regex: re(String.raw`^Exit before auth .*?: (?:Max auth tries reached|Exited normally|Error reading)`), geste: 'reseau.sonde' },
  ] },
  // ---- sudo ----
  { nom: 'sudo', programme: /^sudo$/, motifs: [
    { regex: re(String.raw`^\s*${UTIL} : (?<raison>\d+ incorrect password attempts?|incorrect password|user NOT in sudoers|command not allowed|a password is required|no tty present)\s*;.*?COMMAND=(?<commande>.*)$`), geste: 'priv.echec' },
    { regex: re(String.raw`^\s*${UTIL} : (?<raison>\d+ incorrect password attempts?|user NOT in sudoers|command not allowed)`), geste: 'priv.echec' },
    { regex: re(String.raw`^\s*${UTIL} : TTY=\S+ ; PWD=\S* ; USER=(?<cible>\S+) ; COMMAND=(?<commande>.*)$`), geste: 'priv.commande' },
    { regex: re(String.raw`^pam_unix\(sudo:auth\): authentication failure; .*?user=${UTIL}`), geste: 'priv.echec' },
  ] },
  // ---- su ----
  { nom: 'su', programme: /^su(?:-l)?$/, motifs: [
    { regex: re(String.raw`^(?:FAILED SU|FAILED su|pam_unix\(su(?:-l)?:auth\): authentication failure).*?(?:\(to (?<cible>\S+)\) ${UTIL}|user=${UTIL})`), geste: 'priv.echec' },
    { regex: re(String.raw`^\(to (?<cible>\S+)\) ${UTIL} on `), geste: 'priv.commande' },
    { regex: re(String.raw`^pam_unix\(su(?:-l)?:session\): session (?<etat>opened|closed) for user (?<cible>\S+?)(?:\(uid=\d+\))? by ${UTIL}`), geste: 'session.*' },
  ] },
  // ---- comptes (shadow-utils) ----
  { nom: 'comptes', programme: /^(?:useradd|adduser|userdel|deluser|usermod|groupadd|groupmod|gpasswd|passwd|chpasswd|chage)$/, motifs: [
    { regex: re(String.raw`^new user: name=${UTIL}, UID=(?<id>\d+)`), geste: 'compte.cree' },
    { regex: re(String.raw`^(?:delete user '${UTIL}'|removed user '${UTIL}'|Removing user .${UTIL}.)`), geste: 'compte.supprime' },
    { regex: re(String.raw`^add '${UTIL}' to (?:shadow )?group '(?<groupe>[^']+)'`), geste: 'groupe.ajout' },
    { regex: re(String.raw`^Adding user .${UTIL}. to group .(?<groupe>[^'\x60]+)`), geste: 'groupe.ajout' },
    { regex: re(String.raw`^user added to group: name=${UTIL}, group=(?<groupe>\S+)`), geste: 'groupe.ajout' },
    { regex: re(String.raw`^new group: name=(?<groupe>\S+), GID=(?<id>\d+)`), geste: 'compte.modifie' },
    { regex: re(String.raw`^change user '${UTIL}' (?<quoi>shell|password|UID|GID|home)`), geste: 'compte.modifie' },
    { regex: re(String.raw`^(?:password changed for|pam_unix\(passwd:chauthtok\): password changed for) ${UTIL}`), geste: 'compte.motdepasse' },
    { regex: re(String.raw`^changed password expiry for ${UTIL}`), geste: 'compte.modifie' },
  ] },
  // ---- connexion locale (login, getty) ----
  { nom: 'login', programme: /^login$/, motifs: [
    { regex: re(String.raw`^FAILED LOGIN (?:\(\d+\) )?(?:SESSION |on '[^']*' )?.*?(?:FOR|for) '?${UTIL}'?,? (?:Authentication failure|User not known)`), geste: 'auth.echec' },
    { regex: re(String.raw`^pam_unix\(login:session\): session (?<etat>opened|closed) for user ${UTIL}`), geste: 'session.*' },
    { regex: re(String.raw`^ROOT LOGIN\s+on`), geste: 'auth.succes', champs: { utilisateur: 'root' } },
  ] },
  // ---- PAM (toute application) ----
  { nom: 'pam', programme: null, prematch: /^pam_unix\(/, motifs: [
    { regex: re(String.raw`^pam_unix\((?<application>[\w-]+):auth\): authentication failure; .*?(?:rhost=${IP})?(?:\s+user=${UTIL})?`), geste: 'auth.echec' },
    { regex: re(String.raw`^pam_unix\((?<application>[\w-]+):session\): session (?<etat>opened|closed) for user ${UTIL}`), geste: 'session.*' },
    { regex: re(String.raw`^pam_unix\((?<application>[\w-]+):auth\): check pass; user unknown`), geste: 'auth.invalide' },
  ] },
  // ---- systemd ----
  { nom: 'systemd', programme: /^systemd(?:\[\d+\])?$/, motifs: [
    { regex: re(String.raw`^(?<unite>[\w@.:\\-]+\.service): (?:Main process exited, code=(?<code>\w+), status=(?<statut>[\w/]+)|Failed with result '(?<resultat>[^']+)')`), geste: 'service.echec' },
    { regex: re(String.raw`^Failed to start (?<unite>.+?)\.?$`), geste: 'service.echec' },
    { regex: re(String.raw`^Stopped (?<unite>.+?)\.?$`), geste: 'service.arrete' },
    { regex: re(String.raw`^Started (?<unite>.+?)\.?$`), geste: 'service.demarre' },
    { regex: re(String.raw`^(?<unite>[\w@.:\\-]+\.service): (?:Scheduled restart job|Start request repeated too quickly)`), geste: 'service.echec' },
  ] },
  // ---- cron ----
  { nom: 'cron', programme: /^(?:CRON|cron|crond|anacron|crontab)$/, motifs: [
    { regex: re(String.raw`^\(${UTIL}\) CMD \((?<commande>.*)\)$`), geste: 'planif.commande' },
    { regex: re(String.raw`^\(${UTIL}\) (?<quoi>BEGIN EDIT|END EDIT|REPLACE|DELETE) \(`), geste: 'planif.modifie' },
    { regex: re(String.raw`^pam_unix\(cron:session\): session (?<etat>opened|closed) for user ${UTIL}`), geste: 'session.*' },
  ] },
  // ---- noyau ----
  { nom: 'kernel', programme: /^kernel$/, motifs: [
    { regex: re(String.raw`^(?<processus>\S+)\[(?<id>\d+)\]: segfault at`), geste: 'noyau.segfault' },
    { regex: re(String.raw`^(?:Out of memory: Killed process (?<id>\d+) \((?<processus>[^)]+)\)|oom-kill|(?<processus2>\S+) invoked oom-killer)`), geste: 'noyau.oom' },
    { regex: re(String.raw`^(?:TCP: )?Possible SYN flooding on port (?<dstport>\d+)`), geste: 'noyau.syn' },
    { regex: re(String.raw`^(?:device (?<interface>\S+) entered promiscuous mode|(?<interface2>\S+): entered promiscuous mode)`), geste: 'noyau.promiscuite' },
    { regex: re(String.raw`^usb \S+: (?:New USB device found, idVendor=(?<fabricant>\w+), idProduct=(?<produit>\w+)|Product: (?<nom>.*))`), geste: 'noyau.usb' },
    { regex: re(String.raw`^(?<module>\S+): (?:loading out-of-tree module taints kernel|module verification failed|module license '\S+' taints kernel)`), geste: 'noyau.module' },
    { regex: re(String.raw`^(?:nf_conntrack: table full, dropping packet|net_ratelimit: \d+ callbacks suppressed)`), geste: 'noyau.saturation' },
    { regex: re(String.raw`^(?:\[\w+\] )?(?:\S+ )?IN=(?<interface>\S*) OUT=\S* .*?SRC=${IP} DST=${IPD} .*?PROTO=(?<protocole>\w+)(?: SPT=(?<srcport>\d+))?(?: DPT=(?<dstport>\d+))?`), geste: 'parefeu.paquet' },
  ] },
  // ---- Synology DSM ----
  { nom: 'synology', programme: /^(?:synoscgi|synoscgi_SYNO\S*|Connection|System|synology)$/i, prematch: /(?:failed to log in|logged in successfully|was blocked|blocked|logged out|Cleared)/i, motifs: [
    { regex: re(String.raw`User \[?${UTIL}\]? from \[?${IP}\]? failed to log in via \[?(?<application>[^\]]+)\]?`), geste: 'auth.echec' },
    { regex: re(String.raw`User \[?${UTIL}\]? from \[?${IP}\]? logged in successfully via \[?(?<application>[^\]]+)\]?`), geste: 'auth.succes' },
    { regex: re(String.raw`Host \[?${IP}\]? was blocked`), geste: 'auth.limite' },
    { regex: re(String.raw`User \[?${UTIL}\]? from \[?${IP}\]? logged out`), geste: 'session.fermee' },
  ] },
  // ---- Proxmox VE ----
  { nom: 'proxmox', programme: /^(?:pvedaemon|pveproxy|pmxcfs|pve-ha-crm|pve-ha-lrm|pvesh|pmgproxy|pmgdaemon)$/, motifs: [
    { regex: re(String.raw`^authentication failure; rhost=${IP} user=${UTIL} msg=(?<raison>.*)$`), geste: 'auth.echec' },
    { regex: re(String.raw`^successful auth for user '${UTIL}'`), geste: 'auth.succes' },
    { regex: re(String.raw`^<root@pam> (?:successful auth for user '${UTIL}'|update ticket for user '${UTIL}')`), geste: 'auth.succes' },
    { regex: re(String.raw`^<${UTIL}> (?:starting task (?<tache>\S+)|end task \S+ (?<resultat>OK|.*))`), geste: 'action.tache' },
    { regex: re(String.raw`^(?:members:|quorum|node lost quorum|node has quorum)`), geste: 'service.grappe' },
  ] },
  // ---- Serveurs web (access log en syslog : nginx, Apache, Caddy, Traefik) ----
  { nom: 'web', programme: /^(?:nginx|apache2?|httpd|caddy|traefik|lighttpd|haproxy)$/, motifs: [
    { regex: re(String.raw`^${IP} \S+ \S+ \[[^\]]*\] "(?<methode>[A-Z]{3,10}) (?<url>\S+)(?: HTTP/[\d.]+)?" (?<statut>\d{3}) `), geste: 'web.requete' },
    { regex: re(String.raw`^(?:\S+ )?${IP} - (?:\S+ )?\[[^\]]*\] "(?<methode>[A-Z]{3,10}) (?<url>\S+)(?: HTTP/[\d.]+)?" (?<statut>\d{3})`), geste: 'web.requete' },
    { regex: re(String.raw`client: ${IP}, server: \S+, request: "(?<methode>[A-Z]{3,10}) (?<url>\S+)`), geste: 'web.erreur' },
    { regex: re(String.raw`^\[(?:error|crit|alert)\] .*?client: ${IP}`), geste: 'web.erreur' },
  ] },
  // ---- Docker ----
  { nom: 'docker', programme: /^(?:dockerd|containerd|docker)$/, motifs: [
    { regex: re(String.raw`(?:msg="?container (?<id>[0-9a-f]{12,64})(?: .*?)? (?:exited|died)(?: with exit code (?<code>\d+))?|container exit .*?id=(?<id2>[0-9a-f]{12,64}))`), geste: 'conteneur.mort' },
    { regex: re(String.raw`(?:shim disconnected|OOM killed|error="?.*?(?:killed|OOM))`), geste: 'conteneur.mort' },
    { regex: re(String.raw`(?:msg="?)?(?:Loading containers|Daemon has completed initialization|API listen on)`), geste: 'service.demarre' },
  ] },
  // ---- Home Assistant ----
  { nom: 'homeassistant', programme: /^(?:homeassistant|hass|home-assistant)$/, motifs: [
    { regex: re(String.raw`Login attempt or request with invalid authentication from (?<hote2>\S+) \(${IP}\)`), geste: 'auth.echec' },
    { regex: re(String.raw`Login attempt or request with invalid authentication from ${IP}`), geste: 'auth.echec' },
    { regex: re(String.raw`Blocked IP ${IP}`), geste: 'auth.limite' },
  ] },
  // ---- Nextcloud ----
  { nom: 'nextcloud', programme: /^(?:nextcloud|owncloud)$/, motifs: [
    { regex: re(String.raw`Login failed: '?${UTIL}'? \(Remote IP: '?${IP}'?\)`), geste: 'auth.echec' },
    { regex: re(String.raw`Bruteforce attempt from "?${IP}"? detected`), geste: 'auth.limite' },
  ] },
  // ---- Vaultwarden ----
  { nom: 'vaultwarden', programme: /^(?:vaultwarden|bitwarden_rs)$/, motifs: [
    { regex: re(String.raw`Username or password is incorrect\. Try again\. IP: ${IP}\. Username: ${UTIL}\.`), geste: 'auth.echec' },
    { regex: re(String.raw`Invalid admin token\. IP: ${IP}`), geste: 'auth.echec', champs: { utilisateur: 'admin' } },
  ] },
  // ---- Jellyfin ----
  { nom: 'jellyfin', programme: /^(?:jellyfin|emby)$/, motifs: [
    { regex: re(String.raw`Authentication request for "${UTIL}" has been denied \(IP: ${IP}\)`), geste: 'auth.echec' },
    { regex: re(String.raw`Authentication request for "${UTIL}" has succeeded`), geste: 'auth.succes' },
  ] },
  // ---- Grafana ----
  { nom: 'grafana', programme: /^(?:grafana|grafana-server)$/, motifs: [
    { regex: re(String.raw`(?:Invalid username or password|invalid username or password).*?(?:uname=${UTIL})?.*?(?:remote_addr=${IP})`), geste: 'auth.echec' },
    { regex: re(String.raw`logger=context .*?remote_addr=${IP} .*?status=(?<statut>\d{3}) method=(?<methode>\w+) path=(?<url>\S+)`), geste: 'web.requete' },
  ] },
  // ---- Portainer, Gitea, Pi-hole, autres services courants ----
  { nom: 'gitea', programme: /^(?:gitea|forgejo)$/, motifs: [
    { regex: re(String.raw`Failed authentication attempt for ${UTIL} from ${IP}`), geste: 'auth.echec' },
  ] },
  { nom: 'portainer', programme: /^portainer$/, motifs: [
    { regex: re(String.raw`(?:Invalid credentials|invalid credentials|Authentication failed).*?(?:${IP})?`), geste: 'auth.echec' },
  ] },
  // ---- Courrier (postfix, dovecot) ----
  { nom: 'courrier', programme: /^(?:postfix\/\w+|dovecot|exim4?|opensmtpd)$/, motifs: [
    { regex: re(String.raw`(?:SASL (?:LOGIN|PLAIN|CRAM-MD5) authentication failed|auth failed, \d+ attempts|Aborted login \(auth failed, \d+ attempts(?: in \d+ secs)?\))(?:.*?user=<${UTIL}>)?.*?(?:rip=|\[|from \S+\[)${IP}`), geste: 'auth.echec' },
    { regex: re(String.raw`(?:imap|pop3)-login: Login: user=<${UTIL}>, .*?rip=${IP}`), geste: 'auth.succes' },
    { regex: re(String.raw`(?:NOQUEUE: reject|lost connection after \w+ from) \S*\[${IP}\]`), geste: 'reseau.sonde' },
  ] },
  // ---- FTP ----
  { nom: 'ftp', programme: /^(?:vsftpd|proftpd|pure-ftpd)$/, motifs: [
    { regex: re(String.raw`(?:FAIL LOGIN: Client "${IP}"|USER ${UTIL}: no such user found from \S+ \[${IP}\]|\(\S*@${IP}\) \[WARNING\] Authentication failed for user \[${UTIL}\])`), geste: 'auth.echec' },
    { regex: re(String.raw`(?:OK LOGIN: Client "${IP}"|USER ${UTIL}: Login successful|\[INFO\] ${UTIL} is now logged in)`), geste: 'auth.succes' },
  ] },
  // ---- Samba ----
  { nom: 'samba', programme: /^(?:smbd|samba|winbindd)$/, motifs: [
    { regex: re(String.raw`Auth: \[(?<application>[^,\]]+),[^\]]*\] user \[[^\]]*\]\\\[${UTIL}\] at \[[^\]]*\] with \[[^\]]*\] status \[(?<statut>NT_STATUS_\w+)\] .*?remote host \[ipv[46]:${IP}:`), geste: 'auth.*' },
  ] },
  // ---- Gardiens (fail2ban, CrowdSec) ----
  { nom: 'gardien', programme: /^(?:fail2ban\.actions|fail2ban|crowdsec)$/, motifs: [
    { regex: re(String.raw`\[(?<prison>[\w-]+)\] (?<quoi>Ban|Unban) ${IP}`), geste: 'bannissement' },
    { regex: re(String.raw`(?<quoi>Ban|ban|decision).*?${IP}.*?(?:scenario|reason)[:=]\s*"?(?<scenario>[\w/.-]+)`), geste: 'bannissement' },
  ] },
  // ---- Wi-Fi (hostapd, UniFi AP) ----
  { nom: 'wifi', programme: /^(?:hostapd|wpa_supplicant)$/, motifs: [
    { regex: re(String.raw`^(?<interface>[^\s:]{1,32}): STA (?<mac>(?:[0-9a-f]{2}:){5}[0-9a-f]{2}) IEEE 802\.1X: authentication failed`), geste: 'auth.echec' },
    { regex: re(String.raw`^(?<interface>[^\s:]{1,32}): (?:AP-STA-CONNECTED|STA|AP-STA-DISCONNECTED) (?<mac>(?:[0-9a-f]{2}:){5}[0-9a-f]{2})(?: IEEE 802\.11: (?<quoi>associated|disassociated|deauthenticated|authenticated))?`), geste: 'wifi.*' },
  ] },
  // ---- DHCP (ISC dhcpd, dnsmasq, Kea) ----
  { nom: 'dhcp', programme: /^(?:dhcpd|dnsmasq-dhcp|kea-dhcp4|udhcpd|isc-dhcp-server)$/, motifs: [
    { regex: re(String.raw`^DHCPACK (?:on|to) ${IP} (?:\(\S+\) )?(?:to|from) (?<mac>(?:[0-9a-f]{2}:){5}[0-9a-f]{2})(?: \((?<nom>[^)]+)\))?`), geste: 'reseau.bail' },
    { regex: re(String.raw`^DHCPACK\(\S+\) ${IP} (?<mac>(?:[0-9a-f]{2}:){5}[0-9a-f]{2})(?: (?<nom>\S+))?`), geste: 'reseau.bail' },
    { regex: re(String.raw`^DHCP4_LEASE_ALLOC .*?${IP}.*?(?<mac>(?:[0-9a-f]{2}:){5}[0-9a-f]{2})`), geste: 'reseau.bail' },
  ] },
  // ---- DNS (dnsmasq, Pi-hole, unbound, bind) ----
  { nom: 'dns', programme: /^(?:dnsmasq|pihole|pihole-FTL|unbound|named)$/, motifs: [
    { regex: re(String.raw`^query\[(?<type>\w+)\] (?<domaine>\S+) from ${IP}`), geste: 'dns.requete' },
    { regex: re(String.raw`^(?:gravity blocked|blocked|regex blocked|config blocked|blacklisted) (?<domaine>\S+) is .*?(?:from|for) ${IP}`), geste: 'dns.bloque' },
    { regex: re(String.raw`^client ${IP}#\d+(?: \([^)]+\))?: query: (?<domaine>\S+) IN (?<type>\w+)`), geste: 'dns.requete' },
    { regex: re(String.raw`^\[\d+:\d+\] info: ${IP} (?<domaine>\S+)\. (?<type>\w+) IN`), geste: 'dns.requete' },
  ] },
  // ---- WireGuard / OpenVPN ----
  { nom: 'vpn', programme: /^(?:openvpn|wireguard|wg-quick|tailscaled|zerotier-one)$/, motifs: [
    { regex: re(String.raw`${IP}:(?<srcport>\d+) (?:TLS Error|TLS handshake failed|VERIFY ERROR|AUTH_FAILED|Authenticate/Decrypt packet error)`), geste: 'auth.echec' },
    { regex: re(String.raw`${IP}:(?<srcport>\d+) \[${UTIL}\] Peer Connection Initiated`), geste: 'auth.succes' },
  ] },
  // ---- Serveurs de jeu / divers qui disent juste « connected / disconnected » ----
  { nom: 'wireguard-noyau', programme: /^kernel$/, prematch: /^wireguard: /, motifs: [
    { regex: re(String.raw`^wireguard: (?<interface>\S+): (?:Receiving handshake initiation from peer \d+ \(${IP}:(?<srcport>\d+)\)|Invalid handshake initiation from ${IP}:(?<srcport2>\d+)|Handshake for peer \d+ \(${IP}:(?<srcport3>\d+)\) did not complete)`), geste: 'vpn.poignee' },
  ] },
];

const CHAMPS = ['srcip', 'dstip', 'utilisateur', 'srcport', 'dstport', 'protocole', 'methode', 'url', 'statut', 'commande', 'cible', 'unite', 'application', 'groupe', 'id', 'raison', 'interface', 'mac', 'domaine', 'type', 'code', 'processus', 'module', 'nom', 'fabricant', 'produit', 'quoi', 'prison', 'scenario', 'tache', 'resultat', 'etat'];

/** Normalise les groupes nommés : alias (processus2 → processus), suppression des vides, IPv4 mappée. */
function champsDe(m, motif) {
  const c = { ...(motif.champs || {}) };
  for (const [k, v] of Object.entries(m.groups || {})) {
    if (v === undefined || v === '') continue;
    const cle = k.replace(/\d+$/, '');
    if (!c[cle]) c[cle] = v;
  }
  if (c.srcip) c.srcip = c.srcip.replace(/^::ffff:/i, '').toLowerCase();
  if (c.dstip) c.dstip = c.dstip.replace(/^::ffff:/i, '').toLowerCase();
  if (c.utilisateur) c.utilisateur = c.utilisateur.replace(/^['"[]|['"\]]$/g, '').replace(/\(uid=\d+\)$/, '').slice(0, 64);
  if (c.cible) c.cible = c.cible.replace(/\(uid=\d+\)$/, '');
  if (c.url) c.url = c.url.slice(0, 2048);
  if (c.commande) c.commande = c.commande.slice(0, 512);
  for (const k of Object.keys(c)) if (!CHAMPS.includes(k)) delete c[k];
  return c;
}

/** Le geste « étoile » (session.*, auth.*, wifi.*) se précise avec le champ etat/statut/quoi. */
function gesteDe(motif, c) {
  if (!motif.geste.endsWith('.*')) return motif.geste;
  const base = motif.geste.slice(0, -2);
  if (base === 'session') return c.etat === 'closed' ? 'session.fermee' : 'session.ouverte';
  if (base === 'auth') return /^NT_STATUS_OK$/.test(c.statut || '') ? 'auth.succes' : 'auth.echec';
  if (base === 'wifi') return /dis|deauth/.test(c.quoi || '') ? 'wifi.deauth' : 'wifi.assoc';
  return base;
}

/**
 * Décode une ligne pré-décodée → { decodeur, geste, champs }. Sans décodeur
 * connu : { decodeur: '', geste: 'depot.texte', champs: {} } — la ligne reste
 * exploitable par les règles de mots-clés et par le relevé des hôtes.
 */
export function decoder(pre) {
  const msg = pre.message;
  for (const d of DECODEURS) {
    if (d.programme ? !d.programme.test(pre.programme) : false) continue;
    if (d.prematch && !d.prematch.test(msg)) continue;
    for (const motif of d.motifs) {
      const m = motif.regex.exec(msg);
      if (!m) continue;
      const champs = champsDe(m, motif);
      return { decodeur: d.nom, geste: gesteDe(motif, champs), champs };
    }
  }
  // Repli : une adresse source et un utilisateur se devinent souvent même sans décodeur.
  const champs = {};
  const ip = /(?:\bfrom|\brhost|\bip|\bclient|\bsrc|\bremote(?:_addr| host)?)[\s:=]+\[?((?:\d{1,3}\.){3}\d{1,3}|[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,7})\]?/i.exec(msg);
  if (ip) champs.srcip = ip[1].toLowerCase();
  const u = /\b(?:user(?:name)?|login|account)[:= ]+['"[]?([A-Za-z0-9._@-]{1,64})['"\]]?/i.exec(msg);
  if (u) champs.utilisateur = u[1];
  return { decodeur: '', geste: 'depot.texte', champs };
}

export const NOMS_DECODEURS = DECODEURS.map(d => d.nom);
