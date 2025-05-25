// content.js
const britishWords = ["lift","lorry","boot","flat","biscuit","petrol","holiday","queue","crisps","jumper","rubbish","trousers","sweets","aubergine","courgette"];
const americanWords = ["elevator","truck","trunk","apartment","cookie","gasoline","vacation","line","chips","sweater","garbage","pants","candy","eggplant","zucchini"];
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === "analyze") {
    const text = document.body.innerText.toLowerCase();
    const result = { british: [], american: [] };
    britishWords.forEach(w => {
      const m = text.match(new RegExp(`\\b${w}\\b`, "g"));
      if (m) result.british.push({ word: w, count: m.length });
    });
    americanWords.forEach(w => {
      const m = text.match(new RegExp(`\\b${w}\\b`, "g"));
      if (m) result.american.push({ word: w, count: m.length });
    });
    sendResponse(result);
  }
  return true;
});
