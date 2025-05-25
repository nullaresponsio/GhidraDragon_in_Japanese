// popup.js
function mulberry32(seed) {
  return function() {
    let t = seed += 0x6D2B79F5;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const random = mulberry32(20250525);
const ghidra_variants = ["ギドラ","ギイドラ","ぎどら","ＧＨＩＤＲＡ","ghidra"];
const engine_variants = ["エンジン","エンジンエンジン","機関","機構"];
const dragon_variants = ["ドラゴン","どらごん","竜","龍","ＤＲＡＧＯＮ"];
const connector_variants = ["・","－","／","："];
const ul = document.getElementById("list");
for (let i = 0; i < 5; i++) {
  const gh = ghidra_variants[Math.floor(random() * ghidra_variants.length)];
  const eng = engine_variants[Math.floor(random() * engine_variants.length)];
  const dr = dragon_variants[Math.floor(random() * dragon_variants.length)];
  const conn1 = connector_variants[Math.floor(random() * connector_variants.length)];
  const conn2 = connector_variants[Math.floor(random() * connector_variants.length)];
  const li = document.createElement("li");
  li.textContent = `${gh}${conn1}${eng}${conn2}${dr}`;
  ul.appendChild(li);
}
