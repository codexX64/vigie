# VIGIE

Audit et veille de sécurité du réseau, sous le Hub. VIGIE lit ce que les
autres services savent déjà (MapMyLAN, NEXARC, docker-control), le confronte
à des règles fixes rattachées au référentiel Codex64, et donne un score par
domaine, du vert au rouge, avec la correction à côté de chaque écart. Une IA
— locale, en nuage, les deux, ou aucune — peut relire l'audit : elle confirme
ou écarte les constats et rédige la synthèse ; elle ne change ni les gravités
ni le score.

- **Moteur sans IA.** Règles déterministes : mêmes entrées, même résultat. Six
  domaines (surface réseau, segmentation, authentification, mises à jour,
  chiffrement, journaux), cinq gravités (conforme, info, faible, élevé,
  critique). Le conforme se compte aussi.
- **IA au choix.** Locale (l'Ollama du Hub : rien ne sort du réseau), en
  nuage (Anthropic, OpenAI ou Kimi avec ta clé), les deux (la locale relit,
  le nuage tranche), ou secours (la locale, le nuage si elle échoue). Plafond
  quotidien d'appels et de jetons, compté localement ; `max_tokens` borne
  chaque appel chez le fournisseur.
- **Veille continue.** Toutes les quinze minutes par défaut : nouveaux
  appareils, nouveaux ports, signes d'intrusion, trafic suspect, VLAN qui ne
  sont plus isolés, sources muettes. Un audit complet par jour.
- **Deux régimes de remédiation.** Par défaut VIGIE propose : rien ne
  s'exécute sans une personne. La réaction rapide (isoler seul un appareil
  sur un signe d'intrusion caractérisé) est coupée tant qu'un administrateur
  ne l'a pas allumée, sous renfort ; elle ne vise que les types d'appareils
  choisis, jamais l'infrastructure, et s'arrête au plafond horaire. Toute
  action passe par MapMyLAN, dans les plages qu'il déclare : instantané,
  vérification, retour arrière si elle n'a pas pris, annulation possible.
- **Rapport PDF** horodaté en un clic, écrit côté serveur sans dépendance.
- **Diffusion.** Déclencheurs pour les workflows du Hub, billetterie au
  format ticket/v1 (Aselia), Telegram, et SYNAPSE pour la mémoire des audits.
- **Page Vigie dans MapMyLAN** (2.1 et plus) : score, priorités, événements,
  et les constats de chaque appareil dans sa fiche.

## Installation

Depuis le Hub : Catalogue → VIGIE. MapMyLAN est requis ; NEXARC,
docker-control, Ollama et SYNAPSE sont pris s'ils sont installés. Le Hub
donne à VIGIE, pour chaque source, un jeton dérivé qui ne vaut que pour elle
(voir [docs/INTEGRATION.md](docs/INTEGRATION.md)). Le jeton de docker-control
se pose dans VIGIE → Réglages.

Seule, sans le Hub : `docker compose up -d --build` avec un `.env` (voir
`docker-compose.yml`).

## Règles

**Surface réseau**

| Règle | Contrôle | Ce qu’elle vérifie |
|---|---|---|
| `surface.intrusion` | SEC-LOG-004 | Signe d’intrusion sur un appareil |
| `surface.api-docker` | SEC-INFRA-004 | API Docker ouverte sans authentification |
| `surface.bdd` | SEC-INFRA-003 | Base de données joignable sur le réseau |
| `surface.partage` | SEC-INFRA-003 | Partage de fichiers exposé |
| `surface.upnp` | SEC-INFRA-003 | UPnP actif |
| `surface.ports` | SEC-INFRA-003 | Beaucoup de ports ouverts |
| `surface.pare-feu` | SEC-INFRA-003 | Pare-feu du poste inactif |
| `surface.antivirus` | SEC-INFRA-003 | Antivirus absent ou inactif |
| `surface.flux-suspect` | SEC-LOG-004 | Trafic sortant suspect |
| `surface.conteneur` | SEC-INFRA-004 | Conteneur trop privilégié |
| `surface.conteneur-bdd` | SEC-INFRA-003 | Base de données d’un conteneur publiée |
| `surface.ok` | SEC-INFRA-003 | Surface sans écart |

**Segmentation**

| Règle | Contrôle | Ce qu’elle vérifie |
|---|---|---|
| `segmentation.vlans` | SEC-INFRA-003 | Réseau découpé en VLAN |
| `segmentation.melange` | SEC-INFRA-003 | Objets connectés mêlés aux postes et serveurs |
| `segmentation.isolement` | SEC-INFRA-003 | VLAN d’objets ou d’invités non isolé |
| `segmentation.hors-vlan` | SEC-INFRA-003 | Appareils sans VLAN |
| `segmentation.inter-vlan` | SEC-INFRA-003 | Flux sortant d’un VLAN isolé |
| `segmentation.quarantaine` | SEC-INFRA-003 | Appareils isolés |

**Authentification**

| Règle | Contrôle | Ce qu’elle vérifie |
|---|---|---|
| `authentification.clair` | SEC-INFRA-003 | Protocole à mot de passe en clair |
| `authentification.vnc` | SEC-INFRA-003 | VNC ouvert |
| `authentification.rdp` | SEC-INFRA-003 | Bureau à distance ouvert |
| `authentification.ssh` | SEC-INFRA-003 | SSH ouvert |
| `authentification.snmp` | SEC-INFRA-003 | SNMP ouvert |
| `authentification.admin-http` | SEC-HDR-001 | Administration sans HTTPS |
| `authentification.tentatives` | SEC-LOG-004 | Tentatives de connexion répétées |
| `authentification.ok` | SEC-INFRA-003 | Accès sans écart |

**Mises à jour**

| Règle | Contrôle | Ce qu’elle vérifie |
|---|---|---|
| `maj.cve` | SEC-INFRA-003 | Vulnérabilités connues |
| `maj.obsolete` | SEC-INFRA-003 | Version en fin de vie |
| `maj.correctifs` | SEC-INFRA-003 | Correctifs en attente |
| `maj.image` | SEC-INFRA-004 | Image de conteneur non épinglée |
| `maj.ok` | SEC-INFRA-003 | À jour |

**Chiffrement**

| Règle | Contrôle | Ce qu’elle vérifie |
|---|---|---|
| `chiffrement.expire` | SEC-INFRA-001 | Certificat expiré ou proche de l’expiration |
| `chiffrement.ancien` | SEC-INFRA-001 | TLS 1.0 ou 1.1 accepté |
| `chiffrement.cle` | SEC-INFRA-001 | Clé de certificat trop courte |
| `chiffrement.autosigne` | SEC-INFRA-001 | Certificat auto-signé |
| `chiffrement.http` | SEC-HDR-001 | Service web sans HTTPS |
| `chiffrement.disque` | SEC-INFRA-003 | Disque non chiffré |
| `chiffrement.ok` | SEC-INFRA-001 | Chiffrement sans écart |

**Journaux & traçabilité**

| Règle | Contrôle | Ce qu’elle vérifie |
|---|---|---|
| `journaux.alertes` | SEC-LOG-004 | Alertes non traitées |
| `journaux.balayage` | SEC-LOG-005 | Inventaire du réseau à jour |
| `journaux.trafic` | SEC-LOG-001 | Collecte du trafic |
| `journaux.centralisation` | SEC-LOG-003 | Mémoire centrale des événements |
| `journaux.veille` | SEC-LOG-004 | Veille continue |
| `journaux.agents` | SEC-LOG-005 | Agent muet |
| `journaux.notifications` | SEC-LOG-004 | Alertes transmises |

Score d'un domaine : 100 moins les pénalités de ses écarts (faible 4, élevé
12, critique 30 ; une même règle pèse au plus trois fois son pire constat).
Un critique plafonne son domaine à 40 et le score global à 49. Un domaine sans
donnée est « non évalué » et ne compte pas.

## Développement

Node 24, aucune dépendance npm.

```
npm test
node outils/vitrine.mjs 8197          # une VIGIE de démonstration
node outils/parcours-navigateur.mjs http://localhost:8197 JETON   # parcours et mise en page (Playwright)
```

## Licence

MIT.
