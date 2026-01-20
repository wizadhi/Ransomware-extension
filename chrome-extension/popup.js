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
