// Modelo simplificado baseado em frequência de uso e similaridade de perfis
export function suggestRoles(inputs: { userFeatures: string[]; knownBundles: Record<string,string[]>; topN?: number }) {
  const { userFeatures, knownBundles, topN = 5 } = inputs;
  const scored = Object.entries(knownBundles).map(([roleKey, feats]) => {
    const intersect = feats.filter(f => userFeatures.includes(f)).length;
    const score = intersect / Math.max(feats.length, 1);
    return { roleKey, score };
  }).sort((a,b)=>b.score - a.score);
  return scored.filter(s => s.score > 0).slice(0, topN);
}