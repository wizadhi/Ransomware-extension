chrome.runtime.getBackgroundPage?.(bg => {
  const resultDiv = document.getElementById("result");

  if (!bg || !bg.lastResult) {
    resultDiv.innerText = "No data yet";
    return;
  }

  if (bg.lastResult.prediction === 1) {
    resultDiv.innerHTML = `
      <p class="danger">
        ⚠️ Potential Ransomware Behavior Detected<br>
        Confidence: ${(bg.lastResult.probability * 100).toFixed(2)}%
      </p>
    `;
  } else {
    resultDiv.innerHTML = `
      <p class="safe">
        ✔️ No Ransomware Behavior Detected
      </p>
    `;
  }
});

document.getElementById("scanBtn").onclick = async () => {
  const fileInput = document.getElementById("fileInput");
  const result = document.getElementById("result");

  if (!fileInput.files.length) {
    result.innerText = "Please select a file";
    return;
  }

  const formData = new FormData();
  formData.append("file", fileInput.files[0]);

  result.innerText = "Scanning...";

  try {
    const res = await fetch("http://127.0.0.1:5000/scan-file", {
      method: "POST",
      body: formData
    });

    const data = await res.json();

    result.innerText =
      data.final_decision === 1
        ? "⚠️ RANSOMWARE DETECTED"
        : "✅ FILE IS SAFE";

  } catch (e) {
    console.error(e);
    result.innerText = "Scan failed";
  }
};

