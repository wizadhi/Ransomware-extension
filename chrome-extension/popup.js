const BACKEND_URL = "http://localhost:8000/scan";
const URL_SCAN_ENDPOINT = "http://localhost:8000/scan-url";

// ─── TAB SWITCHING ────────────────────────────────────────────────
document.querySelectorAll(".tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".panel").forEach(p => p.classList.remove("active"));
    tab.classList.add("active");
    document.getElementById(`panel-${tab.dataset.tab}`).classList.add("active");
    if (tab.dataset.tab === "history") renderHistory();
  });
});

// ─── AUTO PROTECT TOGGLE ─────────────────────────────────────────
const toggle = document.getElementById("toggleAuto");
const statusDot = document.getElementById("statusDot");

chrome.storage.local.get(["autoDetect"], res => {
  toggle.checked = res.autoDetect || false;
  statusDot.classList.toggle("active", toggle.checked);
});

toggle.addEventListener("change", () => {
  chrome.storage.local.set({ autoDetect: toggle.checked });
  statusDot.classList.toggle("active", toggle.checked);
});

// ─── FILE SELECTION ───────────────────────────────────────────────
const dropZone = document.getElementById("dropZone");
const fileInput = document.getElementById("fileInput");
const scanBtn = document.getElementById("scanBtn");
const selectedFile = document.getElementById("selectedFile");
const selectedFileName = document.getElementById("selectedFileName");

dropZone.addEventListener("click", () => fileInput.click());

dropZone.addEventListener("dragover", e => {
  e.preventDefault();
  dropZone.classList.add("dragover");
});
dropZone.addEventListener("dragleave", () => dropZone.classList.remove("dragover"));
dropZone.addEventListener("drop", e => {
  e.preventDefault();
  dropZone.classList.remove("dragover");
  if (e.dataTransfer.files.length) {
    fileInput.files = e.dataTransfer.files;
    onFileSelected(e.dataTransfer.files[0]);
  }
});

fileInput.addEventListener("change", () => {
  if (fileInput.files.length) onFileSelected(fileInput.files[0]);
});

function onFileSelected(file) {
  selectedFileName.textContent = file.name;
  selectedFile.style.display = "flex";
  scanBtn.disabled = false;
}

// ─── FILE SCAN ────────────────────────────────────────────────────
scanBtn.addEventListener("click", async () => {
  if (!fileInput.files.length) return;

  const file = fileInput.files[0];
  const scanBar = document.getElementById("scanBar");
  const resultDiv = document.getElementById("result");

  scanBtn.disabled = true;
  scanBtn.textContent = "SCANNING...";
  scanBar.classList.add("active");
  resultDiv.style.display = "none";

  try {
    const formData = new FormData();
    formData.append("file", file);

    const response = await fetch(BACKEND_URL, { method: "POST", body: formData });

    if (!response.ok) throw new Error(`Server error: ${response.status}`);

    const data = await response.json();
    showFileResult(resultDiv, file.name, data);
    saveToHistory({ name: file.name, type: "file", ...data, time: Date.now() });
    updateFooterStats();

  } catch (err) {
    showError(resultDiv, err.message);
  } finally {
    scanBtn.disabled = false;
    scanBtn.textContent = "RUN SCAN";
    scanBar.classList.remove("active");
  }
});

function showFileResult(container, filename, data) {
  const isSafe = data.final_prediction === 0;
  const prob = (data.ml_probability * 100).toFixed(1);
  const confidence = isSafe ? ((1 - data.ml_probability) * 100).toFixed(1) : prob;

  container.style.display = "block";
  container.className = `result ${isSafe ? "result-safe" : "result-danger"}`;
  container.innerHTML = `
    <div class="result-header">
      <div class="result-icon">${isSafe ? "✅" : "🚨"}</div>
      <div>
        <div class="result-title">${isSafe ? "FILE SAFE" : "THREAT DETECTED"}</div>
        <div class="result-sub">${filename}</div>
      </div>
    </div>
    <div class="result-body">
      <div class="result-row">
        <span class="result-key">ML_PREDICTION</span>
        <span class="result-val ${data.ml_prediction === 0 ? "val-green" : "val-red"}">${data.ml_prediction === 0 ? "CLEAN" : "MALICIOUS"}</span>
      </div>
      <div class="result-row">
        <span class="result-key">SIGNATURE_CHECK</span>
        <span class="result-val ${data.signature_prediction === 0 ? "val-green" : "val-red"}">${data.signature_prediction === 0 ? "CLEAN" : "FLAGGED"}</span>
      </div>
      <div class="result-row">
        <span class="result-key">RISK_PROBABILITY</span>
        <span class="result-val ${isSafe ? "val-green" : "val-red"}">${isSafe ? confidence + "% SAFE" : prob + "% RISK"}</span>
      </div>
      <div class="result-row">
        <span class="result-key">SIG_SCORE</span>
        <span class="result-val val-yellow">${data.signature_score}/2</span>
      </div>
    </div>
  `;
}

// ─── URL SCAN ─────────────────────────────────────────────────────
const urlInput = document.getElementById("urlInput");
const urlScanBtn = document.getElementById("urlScanBtn");
const urlResult = document.getElementById("urlResult");

urlScanBtn.addEventListener("click", async () => {
  const url = urlInput.value.trim();
  if (!url) { urlInput.focus(); return; }
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    showError(urlResult, "URL must start with http:// or https://");
    return;
  }

  const urlScanBar = document.getElementById("urlScanBar");
  urlScanBtn.disabled = true;
  urlScanBtn.textContent = "...";
  urlScanBar.classList.add("active");
  urlResult.innerHTML = "";

  try {
    // Heuristic URL analysis (no backend needed)
    const result = analyzeURL(url);
    showURLResult(urlResult, url, result);
    saveToHistory({ name: url, type: "url", ...result, time: Date.now() });
    updateFooterStats();
  } catch (err) {
    showError(urlResult, err.message);
  } finally {
    urlScanBtn.disabled = false;
    urlScanBtn.textContent = "SCAN";
    urlScanBar.classList.remove("active");
  }
});

function analyzeURL(url) {
  const suspiciousExtensions = [".exe", ".dll", ".bat", ".ps1", ".vbs", ".scr", ".zip", ".rar", ".7z"];
  const suspiciousTLDs = [".tk", ".ml", ".ga", ".cf", ".gq"];
  const suspiciousKeywords = ["ransomware", "decrypt", "bitcoin", "wallet", "crypt", "locky", "cerber", "keygen", "crack", "payload"];

  let score = 0;
  const flags = [];

  const urlLower = url.toLowerCase();

  if (suspiciousExtensions.some(ext => urlLower.endsWith(ext))) {
    score += 2; flags.push("Suspicious file extension");
  }
  if (suspiciousTLDs.some(tld => new URL(url).hostname.endsWith(tld))) {
    score += 2; flags.push("High-risk TLD");
  }
  if (suspiciousKeywords.some(kw => urlLower.includes(kw))) {
    score += 3; flags.push("Ransomware-related keyword");
  }
  try {
    const hostname = new URL(url).hostname;
    if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(hostname)) {
      score += 2; flags.push("IP address used as host");
    }
    if (hostname.split(".").length > 4) {
      score += 1; flags.push("Excessive subdomains");
    }
    if (url.length > 100) {
      score += 1; flags.push("Abnormally long URL");
    }
  } catch (e) {}

  const isSafe = score < 3;
  return {
    final_prediction: isSafe ? 0 : 1,
    ml_probability: Math.min(score / 10, 1),
    ml_prediction: isSafe ? 0 : 1,
    signature_prediction: score >= 3 ? 1 : 0,
    signature_score: Math.min(score, 2),
    flags
  };
}

function showURLResult(container, url, data) {
  const isSafe = data.final_prediction === 0;
  const shortUrl = url.length > 40 ? url.substring(0, 37) + "..." : url;

  container.style.display = "block";
  container.className = `result ${isSafe ? "result-safe" : "result-danger"}`;
  container.style.marginTop = "10px";
  container.innerHTML = `
    <div class="result-header">
      <div class="result-icon">${isSafe ? "✅" : "🚨"}</div>
      <div>
        <div class="result-title">${isSafe ? "URL SAFE" : "SUSPICIOUS URL"}</div>
        <div class="result-sub">${shortUrl}</div>
      </div>
    </div>
    <div class="result-body">
      <div class="result-row">
        <span class="result-key">THREAT_SCORE</span>
        <span class="result-val ${isSafe ? "val-green" : "val-red"}">${(data.ml_probability * 100).toFixed(0)}%</span>
      </div>
      ${data.flags && data.flags.length > 0 ? data.flags.map(f => `
        <div class="result-row">
          <span class="result-key">⚠ FLAG</span>
          <span class="result-val val-yellow">${f}</span>
        </div>
      `).join("") : `
        <div class="result-row">
          <span class="result-key">STATUS</span>
          <span class="result-val val-green">NO THREATS FOUND</span>
        </div>
      `}
    </div>
  `;
}

// ─── ERROR DISPLAY ────────────────────────────────────────────────
function showError(container, message) {
  container.style.display = "block";
  container.className = "result";
  container.innerHTML = `
    <div class="result-header" style="background: rgba(255,183,0,0.1);">
      <div class="result-icon">⚠️</div>
      <div>
        <div class="result-title" style="color: var(--warn);">SCAN ERROR</div>
        <div class="result-sub">${message.includes("fetch") || message.includes("Failed") ? "Backend offline — start server with: uvicorn app:main --reload" : message}</div>
      </div>
    </div>
  `;
}

// ─── HISTORY ─────────────────────────────────────────────────────
function saveToHistory(entry) {
  chrome.storage.local.get(["scanHistory"], res => {
    const history = res.scanHistory || [];
    history.unshift(entry);
    if (history.length > 50) history.pop(); // keep last 50
    chrome.storage.local.set({ scanHistory: history });
  });
}

function renderHistory() {
  const list = document.getElementById("historyList");
  chrome.storage.local.get(["scanHistory"], res => {
    const history = res.scanHistory || [];
    if (!history.length) {
      list.innerHTML = `<div class="empty-history"><div>📭</div>No scans yet</div>`;
      return;
    }
    list.innerHTML = history.map(item => {
      const isSafe = item.final_prediction === 0;
      const time = new Date(item.time).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      const date = new Date(item.time).toLocaleDateString([], { month: "short", day: "numeric" });
      const name = item.name.length > 35 ? item.name.substring(0, 32) + "..." : item.name;
      const prob = isSafe
        ? ((1 - item.ml_probability) * 100).toFixed(0) + "% safe"
        : (item.ml_probability * 100).toFixed(0) + "% risk";
      return `
        <div class="history-item">
          <div class="history-badge ${isSafe ? "badge-safe" : "badge-danger"}"></div>
          <div class="history-info">
            <div class="history-name">${name}</div>
            <div class="history-meta">${item.type === "url" ? "🔗 URL" : "📄 FILE"} · ${date} ${time}</div>
          </div>
          <div class="history-prob ${isSafe ? "val-green" : "val-red"}">${prob}</div>
        </div>
      `;
    }).join("");
  });
}

document.getElementById("clearHistory").addEventListener("click", () => {
  chrome.storage.local.set({ scanHistory: [] }, () => renderHistory());
  updateFooterStats();
});

// ─── FOOTER STATS ─────────────────────────────────────────────────
function updateFooterStats() {
  chrome.storage.local.get(["scanHistory"], res => {
    const history = res.scanHistory || [];
    const today = new Date().toDateString();
    const todayScans = history.filter(h => new Date(h.time).toDateString() === today);
    const threats = todayScans.filter(h => h.final_prediction === 1);
    document.getElementById("scanCount").textContent = todayScans.length;
    document.getElementById("threatCount").textContent = threats.length;
  });
}

updateFooterStats();
