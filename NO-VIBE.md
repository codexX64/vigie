# Code quality record — VIGIE

Method: Project Baseline Requirements & Security Manual, Part III (chapters 37-49)
Reviewed: 2026-10-19   ·   Owner: Codex64

## Behaviour freeze
Point de départ : `v1.2.6`. Ensemble de référence relevé avant toute modification : 41 essais du service (`test/vigie.test.js`, `test/bouclier.test.js`, `test/sentinelle.test.js`, contre de faux voisins en HTTP, un vrai récepteur syslog UDP et TCP, de vraies sessions) et 67 du socle embarqué, tous verts. Sur l’arbre final : 57 essais du service et 67 du socle, tous verts ; les 41 de départ y sont, certains complétés (émetteur déclaré avant de bloquer, passerelle nommée par son rôle).

Diff de l’API publique : les mêmes 47 routes, les mêmes schémas de corps et de requête, les mêmes codes, à quatre changements près, chacun le correctif d’un constat de SECURITY.md : réglages de la veille, de la sentinelle et de la conversation Telegram sous renfort (403 sans) ; journaux d’un émetteur non déclaré signalés au lieu d’agir ; adresses saisies interdites refusées (400) ; paramètre inconnu refusé même quand la route rend tôt (400). Ajouts : la ligne de commande (`src/cli.js`), l’export des données d’un compte.

Démarrage et parcours de bout en bout sur l’arbre final, le 2026-10-19 : `outils/exercice-incident.mjs` → 22 vérifications réussies ; `outils/parcours-navigateur.mjs` contre `outils/vitrine.mjs` → 91 écrans et largeurs contrôlés, aucun défaut de mise en page, aucune erreur en console.

## Layer status
| Chapter | Subject | Status | What changed |
|---|---|---|---|
| 39 | Comment layer | DONE | 102 marqueurs de section en tirets ou en égal ramenés à leur titre en une ligne (`b22116d`) : ils nomment les familles de décodeurs et de règles, les parties d’un module ou d’un essai ; les commentaires restants disent une raison (protocole, menace, choix de seuil), aucun ne raconte le code |
| 40 | Naming and vocabulary | DONE | vocabulaire du domaine en français (audit, constat, veille, bouclier, riposte, sentinelle, émetteur, sonde) ; `res`, `val` nommés par ce qu’ils portent (`a4cc99a`) ; noms des protocoles gardés là où ils traversent (CEF, EVE, `srcip`) |
| 41 | Formatting, layout and whitespace | DONE | aucun formateur dans le dépôt, aucun introduit ; 2 espaces, apostrophes simples, points-virgules, comme le socle ; `git diff --check` depuis l’arbre vide : propre ; aucun caractère invisible |
| 42 | Gratuitous abstraction | DONE | aucune interface à une seule implémentation ; deux aides nées de l’audit, chacune servie à plusieurs endroits : la lecture bornée d’une réponse (`src/lecture.js`, six appelants) et le contrôle d’une adresse saisie (`src/destination.js`, trois) |
| 43 | Defensive noise | DONE | 116 `catch` rangés ci-dessous selon ce que fait leur bloc, aucun hors classe ; aucun message vague, aucune journalisation d’entrée ou de sortie de fonction |
| 44 | Control flow and idiom | DONE | retours anticipés ; contrôle d’accès en tête de chaque route ; une route qui rend tôt fait valider ses paramètres avant de répondre (`1459001`) |
| 45 | Types, signatures and data shapes | DONE | JavaScript sans TypeScript ; contrats d’erreur : `ErreurHttp` du socle, `ErreurSource`, `ErreurAction`, `ErreurCloudflare`, `ErreurUnifi`, `ReponseTropGrande`, `DestinationInterdite`, chacun traduit une fois à la frontière de l’API |
| 46 | Dependencies, configuration, fitting the repository | DONE | aucune dépendance npm, contrôlé en CI ; `package-lock.json` sans contenu, né d’une installation locale, jamais commité ; décompression, flux bornés et résolution DNS par les modules de Node |
| 47 | Tests | DONE | 20 cassures volontaires, chacune détectée (ci-dessous) ; cinq passaient d’abord inaperçues et ont chacune donné un essai (`f4df560`) ; table des droits de chaque route (`98eef4d`) |
| 48 | Documentation, furniture and version control | DONE | README (installation seule, rotation, sauvegardes, incident, émetteurs), notice de confidentialité, Compose, Dependabot, vérification CI relus ; un sujet par commit, sans mention d’outil, en UTC |

`catch` restants, par raison (`rg -o 'catch\s*(\(\s*\w*\s*\))?\s*\{|\.catch\(' src web outils test`, 116) :

| Raison | Nombre | Où |
|---|---|---|
| relevée, traduite en erreur du domaine ou transmise | 30 | `src/api.js`, `src/sources.js`, `src/veille.js`, `src/ia.js`, `src/base.js`, `src/cli.js`, `src/main.js`, `src/diffusion.js`, `src/bouclier/` |
| montrée à l’écran, rendue au demandeur ou portée dans l’état du service, avec sa cause | 22 | `web/`, `src/main.js`, `src/diffusion.js`, `src/veille.js`, `src/sources.js`, `src/memoire.js`, `src/ia.js`, `src/bouclier/` |
| valeur de repli explicite (donnée externe illisible, source absente, nom qui ne se résout pas) | 22 | `src/lecture.js`, `src/base.js`, `src/destination.js`, `src/api.js`, `src/ia.js`, `src/veille.js`, `src/diffusion.js`, `src/memoire.js`, `src/bouclier/`, `web/`, `test/` |
| journalisée | 16 | `src/bouclier/`, `src/sentinelle/`, `src/veille.js` |
| tâche d’arrière-plan dont l’erreur est portée ailleurs (état de la passerelle, de Cloudflare, des listes) | 14 | `src/bouclier/`, `src/api.js`, `src/veille.js`, `src/diffusion.js`, `src/lecture.js` |
| sans effet voulu, la raison écrite dans le bloc | 10 | `outils/`, `src/base.js`, `src/sentinelle/`, `src/bouclier/`, `web/app.js` |
| connexion rompue : abonné du flux retiré | 2 | `src/sentinelle/index.js` |

## Tests
Cassures volontaires (REQ-CODE-005) : chacune posée seule, les trois suites du service lancées en entier, le fichier rétabli (`mutations.py`, hors dépôt), sur l’arbre final.

| Cassure | Fichier | Essais en échec | Premier essai qui échoue |
|---|---|---|---|
| un jeton dérivé passe sans le bon calcul | `src/api.js` | 2 | « jetons dérivés : seul le calcul exact avec le jeton de VIGIE passe » |
| une billetterie avec identifiants dans l’adresse est acceptée | `src/api.js` | 1 | « billetterie et essais de diffusion » |
| un jeton faux ne compte plus comme un échec | `src/api.js` | 1 | « jetons inventés en rafale : chacun compte, l’adresse est bloquée avant d’en deviner un » |
| un jeton dérivé agit au-delà de la lecture | `src/api.js` | 1 | « autorisations : anonyme, lecture, membre, Hub, jeton dérivé » |
| une isolation forcée sans renfort | `src/api.js` | 1 | « renfort : ce qui rend VIGIE sourde ou envoie ses alertes ailleurs le demande » |
| la sentinelle coupée sans renfort | `src/api.js` | 1 | « renfort : ce qui rend VIGIE sourde ou envoie ses alertes ailleurs le demande » |
| un identifiant hors format atteint le magasin | `src/api.js` | 1 | « renfort : ce qui rend VIGIE sourde ou envoie ses alertes ailleurs le demande » |
| les liens restent dans la sortie de l’IA | `src/ia.js` | 2 | « IA : la réponse est relue champ par champ, les liens et balises retirés » |
| l’IA écarte un constat critique | `src/ia.js` | 1 | « IA : un constat critique n’est jamais écarté, au plus nuancé » |
| une réponse démesurée est lue entière | `src/lecture.js` | 2 | « listes de menaces : formats, adresses non publiques écartées, cache sur disque, parents de domaine » |
| l’infrastructure est isolée seule | `src/veille.js` | 1 | « réaction rapide : renfort pour l’allumer, isolement vérifié, plafond, jamais l’infrastructure » |
| une isolation hors du périmètre | `src/veille.js` | 1 | « réaction rapide : jamais hors du périmètre balayé par MapMyLAN » |
| des journaux non déclarés font foi | `src/bouclier/correlation.js` | 2 | « bouclier : des journaux d’un émetteur non déclaré ne font rien bloquer ni isoler seul, une source authentifiée si » |
| un émetteur non déclaré est lu | `src/bouclier/recepteur.js` | 1 | « récepteur : UDP et TCP (lignes et cadrage par longueur), émetteurs filtrés » |
| une adresse privée est bloquée | `src/bouclier/riposte.js` | 2 | « riposte : jamais le privé ni la liste blanche, récidive qui allonge, levée, expiration » |
| la liste blanche est bloquée | `src/bouclier/riposte.js` | 1 | « riposte : jamais le privé ni la liste blanche, récidive qui allonge, levée, expiration » |
| le plafond horaire de blocages saute | `src/bouclier/riposte.js` | 1 | « riposte : observer, simulation, plafond horaire » |
| le décodeur Wi-Fi revient en arrière sur toute la ligne | `src/sentinelle/decodeurs.js` | 1 | « décodeurs : une ligne hostile de 16 Kio, quel que soit le programme annoncé, se lit vite » |
| les secrets de VIGIE ne sont plus rescellés | `src/main.js` | 1 | « rotation de SOCLE_CLE : les secrets de VIGIE sont rescellés, rien n’est perdu » |
| un compte supprimé reste nommé | `src/main.js` | 1 | « données d’un compte : ses gestes exportés, son identifiant effacé de VIGIE à sa suppression » |

Les faux voisins (MapMyLAN, NEXARC, docker-control, Ollama, SYNAPSE, une IA en nuage, Telegram, une billetterie) sont un vrai serveur HTTP ; les essais passent par les routes, avec de vraies sessions, de vrais renforts, le vrai jeton du Hub et des jetons dérivés calculés, un vrai récepteur syslog. Ils portent sur les frontières et les chemins d’erreur : chaque route contre la table des droits, les renforts, les jetons inventés en rafale, les journaux forgés, une ligne hostile de 16 Kio sur chaque décodeur, des réponses sans fin, des adresses qui mènent aux métadonnées, la rotation de la clé, la sauvegarde et sa restauration.

## Repository style profile
Node 24, modules ES, aucune dépendance npm. Serveur : `node:http` sous le portail du socle, `node:sqlite` avec requêtes préparées, `node:dgram` et `node:net` pour le récepteur syslog, `node:tls` pour la passerelle (empreinte épinglée), `fetch` borné pour les voisins. Interface : DOM construit par `h` du socle, gamme SOMA, aucun style en ligne. Erreurs : une classe par frontière, traduite une fois en `ErreurHttp`. Commentaires : en tête de module, ce que fait le module et pourquoi ; dans le code, une raison. Commits : une ligne, un sujet, en français, identité du dépôt, UTC.

## Detection sweep
Relancé à chaque génération de ce fichier (bash, LC_ALL=C.UTF-8) ; annexe B.5 et contrôles des chapitres 41 à 48, sur tout le dépôt hors des deux fichiers de conformité.

| # | Commande | Résultat | Justification |
|---|---|---|---|
| B.5.1 | `rg -n '^\s*(#\|//)\s*(Step \d\|Initialize\|Loop through\|Create (a\|an\|the)\|Return the\|Set the\|Get the\|Check if\|Now we\|First,\|Finally,)' . -g '!SECURITY.md' -g '!NO-VIBE.md'` | 0 ligne |  |
| B.5.2 | `rg -n '^\s*(//\|#\|\*)\s*(Étape \d\|Initialise\|On boucle\|Boucle sur\|Retourne (le\|la\|les\|l.)\|Crée (un\|une\|le\|la)\|Vérifie si\|Maintenant,\|D.abord,\|Enfin,)' . -g '!SECURITY.md' -g '!NO-VIBE.md'` | 0 ligne | la même recherche dans la langue du dépôt |
| B.5.3 | `rg -n '^\s*(#\|//)\s*[-=*_#─]{10,}' . -g '!SECURITY.md' -g '!NO-VIBE.md'` | 0 ligne | 37 avant la passe |
| B.5.4 | `rg -n '^\s*(#\|//)\s*(─{3,}\|-{4} )' src web outils test` | 0 ligne | les marqueurs « ---- titre ---- » : 52 avant la passe |
| B.5.5 | `rg -n -t js -t css -t html '^\s*[-=*_#─]{10,}\s*(\*/)?$' . -g '!SECURITY.md' -g '!NO-VIBE.md'` | 0 ligne |  |
| B.5.6 | `rg -n 'simplified (implementation\|version)\|in a (real\|production) (system\|app)\|for (demo\|illustration) purposes\|this is just an example' . -g '!SECURITY.md' -g '!NO-VIBE.md'` | 0 ligne |  |
| B.5.7 | `rg -n --pcre2 '[\x{1F300}-\x{1FAFF}\x{2600}-\x{27BF}\x{2B00}-\x{2BFF}]' . -g '!SECURITY.md' -g '!NO-VIBE.md' \| wc -l` | `2` | les pastilles de gravité des messages Telegram (contenu envoyé, pas du code) ; un mot de passe fait d’emoji dans un essai du socle |
| B.5.8 | `rg -n '\b(def\|function\|func\|fn)\s+\w*(process\|handle\|manage\|perform\|execute\|do)_?\w*\s*\(' . -g '!SECURITY.md' -g '!NO-VIBE.md'` | 0 ligne |  |
| B.5.9 | `rg -o '\b\w+(Manager\|Service\|Handler\|Provider\|Factory\|Helper\|Util\|Wrapper\|Processor\|Engine)\b' . -g '!SECURITY.md' -g '!NO-VIBE.md' \| cut -d: -f2- \| sort -u` | 0 ligne |  |
| B.5.10 | `find . -path ./node_modules -prune -o -type f -regextype posix-extended -regex '.*/(utils?\|helpers?\|common\|misc\|shared)\.(py\|ts\|js\|go\|rb\|java)' -print` | 0 ligne |  |
| B.5.11 | `rg -n '\b(data\|result\|output\|temp\|tmp\|res\|ret\|val\|obj\|item)\b\s*=' . -g '!SECURITY.md' -g '!NO-VIBE.md' \| wc -l` | `5` | dans les essais seulement : `tmp`, le dossier temporaire de chaque suite ; `res`, la réponse HTTP du flux en direct et la réponse simulée d’un essai du socle ; 19 avant la passe |
| B.5.12 | `rg -n 'catch\s*\(\s*(e\|err\|error)\s*\)\|catch\s*\{' . -g '!SECURITY.md' -g '!NO-VIBE.md' \| wc -l` | `112` | socle compris ; ceux de VIGIE relus un à un avec les `.catch(` : 116, par raison ci-dessus |
| B.5.13 | `rg -n 'An error occurred\|Something went wrong\|Unexpected error\|Une erreur est survenue\|Quelque chose s.est mal passé' . -g '!SECURITY.md' -g '!NO-VIBE.md'` | 0 ligne |  |
| B.5.14 | `rg -n 'except\s*:\|except Exception\s*:' . -g '!SECURITY.md' -g '!NO-VIBE.md'` | 0 ligne | aucun Python dans le dépôt |
| B.5.15 | `rg -n 'logger\.(info\|debug)\(f?["\x27](Starting\|Entering\|Finished\|Exiting\|Called)' . -g '!SECURITY.md' -g '!NO-VIBE.md'` | 0 ligne |  |
| 41.1.1 | `git diff --check $(git hash-object -t tree /dev/null) HEAD -- . ':!SECURITY.md' ':!NO-VIBE.md'` | 0 ligne | depuis l’arbre vide |
| 41.2.1 | `rg -n --pcre2 '[\x{200B}-\x{200D}\x{FEFF}\x{00A0}\x{2028}\x{2029}]' . -g '!SECURITY.md' -g '!NO-VIBE.md'` | 0 ligne | aucun caractère invisible ; la ponctuation typographique française est celle de tout le dépôt |
| 45.1.1 | `rg -n ':\s*any\b\|as unknown as' . -g '!SECURITY.md' -g '!NO-VIBE.md'` | 0 ligne | JavaScript sans TypeScript |
| 47.1.1 | `rg -n 'assert\.ok\(true\)\|toBeDefined\(\)\|assert\(true\)\|assertTrue\(True\)' . -g '!SECURITY.md' -g '!NO-VIBE.md'` | 0 ligne |  |
| 48.3.1 | `rg -n -i 'your-api-key-here\|TODO: implement\|FIXME: AI\|lorem ipsum\|example\.com/api' . -g '!SECURITY.md' -g '!NO-VIBE.md'` | 0 ligne |  |
| 48.3.2 | `rg -n -i 'placeholder' . -g '!SECURITY.md' -g '!NO-VIBE.md' \| wc -l` | `25` | attributs `placeholder` des champs de l’interface et du socle, leur style, et le champ `placeholder` du manifeste du Hub |
| 48.3.3 | `rg -n '\b(TODO\|FIXME\|XXX\|HACK)\b' . -g '!SECURITY.md' -g '!NO-VIBE.md'` | 0 ligne |  |
| 48.4.1 | `git log --all --format='%B' \| rg -i 'co-authored-by\|generated with'` | 0 ligne | tout l’historique |

## Report (chapter 49.6)
Comptes : 102 marqueurs de section ramenés à leur titre, 14 noms génériques renommés, 0 dépendance ajoutée, 2 aides nouvelles (chacune servie plusieurs fois), 16 essais ajoutés, 5 essais renforcés après des cassures passées inaperçues. Fichiers laissés tels quels : le socle embarqué (relu dans son propre dépôt, vérifié par ses empreintes), le manifeste du Hub, les règles et décodeurs hors des expressions corrigées.

Choix non faits, et pourquoi :
- Les champs des protocoles (`srcip`, `dstip`, `sid`, CEF, EVE) ne sont pas traduits : ce sont les noms que l’opérateur retrouve dans la passerelle et dans Suricata.
- Les décodeurs et les règles restent deux longues tables : leur ordre fait leur sens (le premier motif qui correspond gagne), un découpage en fichiers le cacherait.
- `web/app.js`, `web/bouclier.js` et `web/sentinelle.js` gardent leur forme : une page chacun, ses dialogues à côté d’elle.

## Verification (chapter 49)
- [x] Full suite passes and matches the baseline — les 41 essais de la référence, verts avant et après, dans les 57 de l’arbre final ; 67 du socle
- [x] Public API diff empty — mêmes routes et mêmes schémas ; les seuls changements de comportement sont les correctifs listés en tête
- [x] Characterisation tests deleted after use — aucun n’a été écrit
- [x] Read-aloud test passed — chaque fichier touché relu aux endroits touchés, autour de chaque fonction dont une instruction a changé
- [x] Blind-comparison test passed — les passages touchés ont la forme de ceux qui les entourent et du socle : même langue, phrases courtes, raisons plutôt que descriptions
- [x] Commit history: one concern per commit, repository style, no attribution trailers
- [x] REQ-CODE-001 to REQ-CODE-006 all PASS
