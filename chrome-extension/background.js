const BACKEND_URL = "http://localhost:8000/scan";

console.log("[Ransomware Shield] Background worker active");

// ─── AUTO DOWNLOAD SCAN ───────────────────────────────────────────
chrome.downloads.onDeterminingFilename.addListener((downloadItem, suggest) => {
  chrome.storage.local.get(["autoDetect"], async (result) => {
    if (!result.autoDetect) {
      suggest();
      return;
    }

    console.log("[Shield] Intercepting download:", downloadItem.filename);

    try {
      const response = await fetch(downloadItem.url);
      if (!response.ok) throw new Error(`Fetch failed: ${response.status}`);

      const blob = await response.blob();
      const formData = new FormData();
      formData.append("file", blob, downloadItem.filename);

      const scanResponse = await fetch(BACKEND_URL, {
        method: "POST",
        body: formData
      });

      if (!scanResponse.ok) throw new Error(`Scan server error: ${scanResponse.status}`);

      const scanResult = await scanResponse.json();
      console.log("[Shield] Scan result:", scanResult);

      // Save to history
      chrome.storage.local.get(["scanHistory"], (res) => {
        const history = res.scanHistory || [];
        history.unshift({
          name: downloadItem.filename,
          type: "file",
          ...scanResult,
          time: Date.now()
        });
        if (history.length > 50) history.pop();
        chrome.storage.local.set({ scanHistory: history });
      });

      if (scanResult.final_prediction === 1) {
        chrome.notifications.create({
          type: "basic",
          iconUrl: "icon.png",
          title: "🚨 Ransomware Blocked",
          message: `Malicious file blocked: ${downloadItem.filename} (Risk: ${(scanResult.ml_probability * 100).toFixed(1)}%)`
        });
        chrome.downloads.cancel(downloadItem.id);

      } else {
        chrome.notifications.create({
          type: "basic",
          iconUrl: "icon.png",
          title: "✅ File Safe",
          message: `${downloadItem.filename} passed scan. Safe to open.`
        });
        suggest();
      }

    } catch (err) {
      console.error("[Shield] Scan error:", err.message);
      // On error, allow download but notify user
      chrome.notifications.create({
        type: "basic",
        iconUrl: "icon.png",
        title: "⚠️ Scan Unavailable",
        message: "Could not scan file — backend offline. Download allowed, proceed with caution."
      });
      suggest();
    }
  });

  return true; // Required for async suggest
});

// ─── FIX: Listen for FEATURE_DATA from content.js ─────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "FEATURE_DATA") {
    const features = message.payload;
    const tabId = sender.tab?.id;

    console.log("[Shield] Feature data from tab", tabId, features);

    // Score the page based on detected features
    let threatScore = 0;
    if (features.crypto_api) threatScore += 1;
    if (features.eval_usage) threatScore += 2;
    if (features.obfuscation) threatScore += 2;
    if (features.download) threatScore += 1;

    if (threatScore >= 3) {
      chrome.notifications.create({
        type: "basic",
        iconUrl: "icon.png",
        title: "⚠️ Suspicious Page Detected",
        message: `This page shows ${threatScore} ransomware indicators (obfuscation, crypto API, eval). Be cautious.`
      });

      // Save page threat to history
      if (sender.tab?.url) {
        chrome.storage.local.get(["scanHistory"], (res) => {
          const history = res.scanHistory || [];
          history.unshift({
            name: sender.tab.url,
            type: "url",
            final_prediction: 1,
            ml_prediction: 1,
            ml_probability: Math.min(threatScore / 6, 1),
            signature_prediction: 1,
            signature_score: 2,
            flags: Object.entries(features).filter(([, v]) => v === 1).map(([k]) => k),
            time: Date.now()
          });
          if (history.length > 50) history.pop();
          chrome.storage.local.set({ scanHistory: history });
        });
      }
    }

    sendResponse({ status: "ok", threatScore });
  }
});
