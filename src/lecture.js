// Le corps d'une réponse HTTP, lu morceau par morceau jusqu'à une taille donnée :
// au-delà, la lecture s'arrête et la connexion est rendue. Un voisin en panne,
// une liste de menaces qui enfle ou un fournisseur d'IA bavard ne remplissent
// pas la mémoire de VIGIE.

export class ReponseTropGrande extends Error {
  constructor(max) { super(`réponse de plus de ${Math.round(max / 1024)} Kio`); }
}

export async function lireBorne(rep, max) {
  const annonce = Number(rep.headers?.get?.('content-length'));
  if (annonce > max) { await rep.body?.cancel?.().catch(() => {}); throw new ReponseTropGrande(max); }
  if (!rep.body) return Buffer.alloc(0);
  const morceaux = [];
  let total = 0;
  for await (const m of rep.body) {
    total += m.length;
    if (total > max) throw new ReponseTropGrande(max);
    morceaux.push(m);
  }
  return Buffer.concat(morceaux.map(m => Buffer.from(m)));
}

/** Le JSON d'une réponse, ou `repli` s'il est illisible ; trop grand, une erreur. */
export async function jsonBorne(rep, max, repli = null) {
  const brut = await lireBorne(rep, max);
  try { return JSON.parse(brut.toString('utf8')); } catch { return repli; }
}
