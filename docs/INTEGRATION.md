# Intégration — VIGIE 1.0

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
