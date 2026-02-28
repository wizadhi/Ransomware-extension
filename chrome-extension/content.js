// ─── RANSOMWARE SHIELD — CONTENT SCRIPT ──────────────────────────
// Detects ransomware behavioral indicators on web pages

const features = {
  crypto_api: 0,
  file_access: 0,
  obfuscation: 0,
  eval_usage: 0,
  download: 0,
  suspicious_iframe: 0,
  base64_blob: 0
};

// 1. Detect crypto APIs (used by ransomware to encrypt files)
if (window.crypto && window.crypto.subtle) {
  features.crypto_api = 1;
}

// 2. Scan inline scripts for suspicious patterns
const scripts = document.getElementsByTagName("script");
for (const script of scripts) {
  const content = script.innerText || script.textContent || "";

  if (content.includes("eval(")) features.eval_usage = 1;
  if (content.includes("atob(") || content.includes("btoa(")) features.obfuscation = 1;
  if (content.includes("FileSystemWriter") || content.includes("showSaveFilePicker")) features.file_access = 1;
  if (/[A-Za-z0-9+/]{100,}={0,2}/.test(content)) features.base64_blob = 1; // large base64 blob
}

// 3. Detect download link clicks
document.addEventListener("click", (e) => {
  const el = e.target.closest("a");
  if (el && (el.download || /\.(exe|dll|bat|ps1|vbs|scr|zip|rar)$/i.test(el.href || ""))) {
    features.download = 1;
  }
}, true);

// 4. Detect hidden iframes (drive-by download technique)
const iframes = document.querySelectorAll("iframe");
for (const iframe of iframes) {
  const style = window.getComputedStyle(iframe);
  if (style.display === "none" || style.visibility === "hidden" ||
      parseInt(style.width) < 2 || parseInt(style.height) < 2) {
    features.suspicious_iframe = 1;
  }
}

// 5. Send features to background after page loads
setTimeout(() => {
  chrome.runtime.sendMessage(
    { type: "FEATURE_DATA", payload: features },
    (response) => {
      if (chrome.runtime.lastError) {
        // Extension context may be gone — silently ignore
        return;
      }
      if (response && response.threatScore >= 3) {
        console.warn("[Ransomware Shield] High threat score on this page:", response.threatScore);
      }
    }
  );
}, 2500);
