let features = {
  crypto_api: 0,
  file_access: 0,
  obfuscation: 0,
  eval_usage: 0,
  download: 0
};

// Detect crypto APIs
if (window.crypto && window.crypto.subtle) {
  features.crypto_api = 1;
}

// Detect suspicious JS usage
const scripts = document.getElementsByTagName("script");
for (let script of scripts) {
  const content = script.innerText || "";

  if (content.includes("eval(")) {
    features.eval_usage = 1;
  }
  if (content.includes("atob(")) {
    features.obfuscation = 1;
  }
}

// Detect download attempts
document.addEventListener("click", (e) => {
  if (e.target.tagName === "A" && e.target.download) {
    features.download = 1;
  }
});

// Send features to background
setTimeout(() => {
  chrome.runtime.sendMessage({
    type: "FEATURE_DATA",
    payload: features
  });
}, 3000);
