chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "FEATURE_DATA") {

    fetch("http://127.0.0.1:5000/predict", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        features: Object.values(message.payload)
      })
    })
    .then(res => res.json())
    .then(data => {
      chrome.runtime.lastResult = data;
      chrome.action.setBadgeText({ text: data.prediction ? "⚠️" : "✔️" });
      chrome.action.setBadgeBackgroundColor({
        color: data.prediction ? "red" : "green"
      });
    })
    .catch(err => console.error("Backend error:", err));
  }
});
