// popup.js
document.addEventListener('DOMContentLoaded', () => {
  chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
    chrome.tabs.sendMessage(tabs[0].id, { action: "analyze" }, response => {
      const bList = document.querySelector('#british ul');
      const aList = document.querySelector('#american ul');
      if (!response) return;
      response.british.forEach(item => {
        const li = document.createElement('li');
        li.textContent = `${item.word}: ${item.count}`;
        bList.appendChild(li);
      });
      response.american.forEach(item => {
        const li = document.createElement('li');
        li.textContent = `${item.word}: ${item.count}`;
        aList.appendChild(li);
      });
    });
  });
});
