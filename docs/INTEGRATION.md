# Intégration — VIGIE 1.1

## Jetons

| Appelant | Jeton | Ce qu'il ouvre |
|---|---|---|
| Hub | `VIGIE_HUB_TOKEN` (`HUB_TOKEN` du manifeste) | lecture, audits, passes de veille, actions (`/api/actions`, `/api/constats/:id/appliquer`, `/api/actions/:id/annuler`) — jamais `/api/reglages` |
| Service voisin | `cer_<nom>_<hmac-sha256(VIGIE_HUB_TOKEN, "cerveau:" + nom)>` | lecture (`/api/etat`, `/api/audits`, `/api/audits/:id`, `/api/audits/:id/pdf`, `/api/constats`, `/api/evenements`) et `POST /api/audits` |
| Session | cookie du socle | lecture ; membre : audits, passes, acquittements, balayages ; admin : isolement, réglages (secrets et réaction rapide sous renfort) |

Le Hub calcule le jeton dérivé d'un service qui accepte `security.audit` :
`{{provider.security.audit.jetonCerveau}}`. VIGIE le vérifie par le même
calcul, sans rien stocker ; changer le jeton du Hub les révoque tous.

Dans l'autre sens, VIGIE reçoit des jetons dérivés des sources :
`{{provider.network.inventory.jetonCerveau}}` (MapMyLAN, vérifié avec sa
semence `INTEGRATION_TOKEN_SEED`, rôle membre), `{{provider.fleet.inventory.jetonCerveau}}`
(NEXARC, lecture de `/api/state` et `/api/summary`) et
`{{provider.memory.learn.jetonCerveau}}` (SYNAPSE).

## Ce que VIGIE lit et fait chez MapMyLAN

Lecture : `GET /api/devices`, `/api/vlans`, `/api/stats`, `/api/alerts`,
`/api/devices/scan/ranges`, `/api/devices/scans/latest`, et à partir de
MapMyLAN 2.1 `/api/traffic/flows` et `/api/traffic/state`.

Actions : `POST /api/devices/:id/quarantine|ban|unban|deep-scan`,
`POST /api/devices/scan`. Avant chaque isolement, `GET /api/devices/:id`
(instantané) ; après, le même appel vérifie le statut, et un `unban` défait
l'action si elle n'a pas pris.

Périmètre : les plages déclarées dans MapMyLAN (sinon les plages privées),
moins les exclusions des réglages de VIGIE. Rien n'est sondé ni isolé hors de
ce périmètre.

## Formes

```
Audit    { id, debut, fin, statut: "en cours"|"termine"|"echec", declencheur, auteur,
           score|null, domaines: { <domaine>: { score|null, n, distribution } },
           distribution: { safe, info, faible, eleve, critique }, sources, ia, erreur }
Constat  { id, auditId, cle, regle, ref, domaine, gravite, titre, sujet, sujetId|null,
           preuve, correction, action: { type, appareil }|null, ia: { statut, note }|null }
Evenement { id, quand, gravite, type, titre, texte, sujet, acquitte|null, acquittePar|null }
Action   { id, quand, type, cible, cibleNom, auteur, motif, automatique, etat:
           "appliquee"|"restauree"|"echec"|"annulee", avant, resultat, annuleePar, annuleeLe }
```

`sujetId` est l'identifiant MapMyLAN de l'appareil : `GET /api/constats?appareil=<id>`
rend les constats du dernier audit pour un appareil (fiche d'appareil de MapMyLAN).

Types d'événements : `appareil.nouveau`, `port.nouveau`, `intrusion`,
`reaction`, `reaction.retenue`, `alerte.reseau`, `alerte.parc`,
`trafic.suspect`, `config.derive`, `source.panne`, `source.retour`,
`constat`, `audit.termine`.

## Bouclier

| Entrée | Qui | Ce qu'elle fait |
|---|---|---|
| syslog UDP/TCP 5514 | la passerelle (émetteurs déclarés) | CEF d'UniFi, lignes du pare-feu, EVE JSON |
| `GET /api/bouclier` | session, jeton du Hub, jeton dérivé | état : mode, menaces, blocages, alertes, passerelle, listes |
| `POST /api/bouclier/bloquer` `{ ip, minutes?, motif? }` | administrateur, jeton du Hub | bloque une adresse publique hors liste blanche |
| `POST /api/bouclier/blocages/:id/lever` | administrateur, jeton du Hub | lève un blocage |
| `GET /api/bouclier/liste.txt?jeton=vgl_…` | pare-feu qui lit une URL | adresses bloquées, une par ligne |
| `POST /api/sonde/eve` `{ evenements: [...] }` | sonde (jeton `vgs_…`) | EVE JSON de Suricata, 5 000 événements au plus |

Chez MapMyLAN (2.2 ou plus), avec le jeton dérivé de VIGIE, rôle membre :
`GET /api/passerelle` (le routeur principal, toutes les cinq minutes),
`GET /api/passerelle/ips?depuis=` (alertes de l'IPS, chaque minute, en pause
tant que la passerelle en envoie par syslog), `PUT /api/passerelle/bouclier`
`{ ips }` (les adresses bloquées, à chaque changement). Une clé d'API UniFi
posée dans VIGIE passe avant MapMyLAN.

| `POST /api/bouclier/cloudflare/sonde` `{ jeton? }` | administrateur | compte et zones lisibles avec le jeton (posé, ou nouveau) |
| `PUT /api/bouclier/cloudflare` `{ jeton?, zones?: [{id, nom}], retirer? }` | administrateur sous renfort | relier Cloudflare, choisir les zones, délier |
| `POST /api/bouclier/cloudflare/synchroniser` | administrateur | renvoyer la liste et reposer les règles |
| `POST /api/bouclier/cloudflare/attaque` `{ actif, minutes? }` | administrateur sous renfort | mode « Under Attack » sur les zones, pour un temps |

Réglages, passerelle, jetons de sonde et de liste : session d'administrateur
sous renfort, jamais un jeton. Chez Cloudflare (`api.cloudflare.com`) : liste
`vigie_bloquees` du compte, règle « ip.src in $vigie_bloquees » dans la phase
`http_request_firewall_custom` de chaque zone, réglage `security_level`.

Événements de veille : `bouclier.bloque` (faible), `bouclier.simule`,
`bouclier.menace` (mode observation), `bouclier.interne` (critique),
`bouclier.plafond`, `bouclier.passerelle` et `bouclier.cloudflare` (élevé),
`bouclier.tempete` (critique). Déclencheurs du Hub : « Adresse bloquée »,
« Machine du réseau suspecte », « Tempête (déni de service) » ; action « Mode
Under Attack Cloudflare ».

## Sentinelle

Les lignes reçues au syslog que le bouclier ne reconnaît pas (ni CEF, ni
pare-feu, ni EVE) sont des journaux d'hôtes : elles vont à la sentinelle,
sous le même filtre d'émetteurs.

| Entrée | Qui | Ce qu'elle fait |
|---|---|---|
| syslog UDP/TCP 5514 | les hôtes (émetteurs déclarés) | journaux RFC 3164/5424, journald, Docker syslog |
| `GET /api/sentinelle` | session, jeton du Hub, jeton dérivé | état : hôtes, alertes récentes, bilan 24 h, règles déclenchées |
| `GET /api/sentinelle/alertes?niveau=&hote=&regle=&srcip=&depuis=&limite=` | idem | les alertes gardées (30 jours) |
| `GET /api/sentinelle/regles` | idem | la table des règles (niveau, parente, répétition) |
| `GET /api/sentinelle/flux` | session (SSE) | le direct : `event: bouclier` (observations) et `event: sentinelle` (événements), `Last-Event-ID` honoré |
| `PUT /api/reglages/sentinelle` `{ actif, seuil, seuilEvenement, correler, retentionJours }` | administrateur | réglages |
| `POST /api/sentinelle/essai` `{ ligne }` | administrateur | ce que la sentinelle ferait d'une ligne, sans rien retenir |

Événement de veille : `sentinelle` (gravité faible 7-9, élevée 10-12,
critique 13-15), une fois par six heures et par règle, hôte et source.
Déclencheur du Hub : « Alerte d'hôte (sentinelle) » ; action « État de la
sentinelle » ; sonde « Alertes d'hôtes (24 h) ».
