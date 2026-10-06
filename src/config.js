// Configuration de VIGIE, lue et validée une fois au démarrage. Les variables
// SOCLE_* (comptes, relais, clé maîtresse) sont lues par le socle. Une valeur
// invalide arrête le processus avec la liste complète des erreurs.
//
// Les adresses et jetons des sources viennent du Hub (capacités du manifeste) :
// chaque service donne à VIGIE un jeton dérivé pour lui seul — jamais le jeton
// qu'il partage avec le Hub.
import { lireConfig } from '../socle/src/index.js';

export const VERSION = '1.0.0';

const URL_OU_VIDE = { type: 'url', defaut: '' };
const DERIVE = /^cer_[a-z0-9][a-z0-9-]{1,30}_[0-9a-f]{64}$/;

export function lireConfigVigie(env = process.env) {
  return lireConfig({
    port: { env: 'PORT', type: 'entier', min: 0, max: 65535, defaut: 8170 },
    hote: { env: 'HOTE', type: 'chaine', defaut: '0.0.0.0' },
    donnees: { env: 'DATA_DIR', type: 'chaine', defaut: '/data' },
    // Jeton du Hub : actions, sondes et déclencheurs. Il sert aussi à vérifier
    // les jetons dérivés que le Hub donne aux services voisins (MapMyLAN).
    jetonHub: { env: 'VIGIE_HUB_TOKEN', type: 'secret', min: 24 },
    // Les sources. MapMyLAN est requis par le manifeste ; les autres, facultatives.
    mapmylanUrl: { env: 'MAPMYLAN_URL', ...URL_OU_VIDE },
    mapmylanJeton: { env: 'MAPMYLAN_JETON', type: 'chaine', motif: DERIVE, defaut: '' },
    nexarcUrl: { env: 'NEXARC_URL', ...URL_OU_VIDE },
    nexarcJeton: { env: 'NEXARC_JETON', type: 'chaine', motif: DERIVE, defaut: '' },
    dockerUrl: { env: 'DOCKER_CONTROL_URL', ...URL_OU_VIDE },
    // L'IA locale (Ollama du Hub) et son modèle par défaut.
    iaLocaleUrl: { env: 'IA_LOCALE_URL', ...URL_OU_VIDE },
    iaLocaleModele: { env: 'IA_LOCALE_MODELE', type: 'chaine', motif: /^[\w.:/-]{1,120}$/, defaut: '' },
    // Le moteur d'IA choisi depuis le Hub (installation) : appliqué au démarrage
    // quand il change ; les réglages de VIGIE le précisent ensuite.
    iaMode: { env: 'VIGIE_IA_MODE', type: 'choix', parmi: ['', 'aucune', 'locale', 'cloud', 'les-deux', 'secours'], defaut: '' },
    iaFournisseur: { env: 'VIGIE_IA_FOURNISSEUR', type: 'choix', parmi: ['anthropic', 'openai', 'kimi'], defaut: 'anthropic' },
    iaModeleCloud: { env: 'VIGIE_IA_MODELE', type: 'chaine', motif: /^[\w.:/-]{1,120}$/, defaut: '' },
    iaCle: { env: 'VIGIE_IA_CLE', type: 'secret', min: 20 },
    iaAppelsJour: { env: 'VIGIE_IA_APPELS_JOUR', type: 'entier', min: 0, max: 1000, defaut: 20 },
    // SYNAPSE : mémoire des audits et des interventions.
    synapseUrl: { env: 'SYNAPSE_URL', ...URL_OU_VIDE },
    synapseJeton: { env: 'SYNAPSE_JETON', type: 'chaine', motif: DERIVE, defaut: '' },
    // API des IA en nuage (remplacées dans les essais).
    anthropicApi: { env: 'VIGIE_ANTHROPIC_API', type: 'url', defaut: 'https://api.anthropic.com' },
    openaiApi: { env: 'VIGIE_OPENAI_API', type: 'url', defaut: 'https://api.openai.com' },
    kimiApi: { env: 'VIGIE_KIMI_API', type: 'url', defaut: 'https://api.moonshot.ai' },
    tgApi: { env: 'VIGIE_TELEGRAM_API', type: 'url', defaut: 'https://api.telegram.org' },
  }, env);
}
