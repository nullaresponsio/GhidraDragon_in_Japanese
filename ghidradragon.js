// ghdra_dragon.js
const seedrandom = require('seedrandom');
const random = seedrandom('20250525');
const ghidra_variants = ["ギドラ","ギイドラ","ぎどら","ＧＨＩＤＲＡ","ghidra"];
const engine_variants = ["エンジン","エンジンエンジン","機関","機構"];
const dragon_variants = ["ドラゴン","どらごん","竜","龍","ＤＲＡＧＯＮ"];
const connector_variants = ["・","－","／","："];
for (let i = 0; i < 10; i++) {
  const gh = ghidra_variants[Math.floor(random() * ghidra_variants.length)];
  const eng = engine_variants[Math.floor(random() * engine_variants.length)];
  const dr = dragon_variants[Math.floor(random() * dragon_variants.length)];
  const conn1 = connector_variants[Math.floor(random() * connector_variants.length)];
  const conn2 = connector_variants[Math.floor(random() * connector_variants.length)];
  console.log(`${gh}${conn1}${eng}${conn2}${dr}`);
}
