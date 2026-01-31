const API_BASE = "http://127.0.0.1:8000";

const startBtn = document.getElementById("startScanBtn");
const input = document.getElementById("targetInput");
const resultBox = document.getElementById("resultBox");

// Store latest scan result for PDF generation
let latestScanResult = null;
let latestScanId = null;

startBtn.addEventListener("click", async () => {
  const targetId = input.value.trim();

  if (!targetId) {
    alert("Please enter a target ID");
    return;
  }

  resultBox.innerHTML = "🔍 Scanning...";

  // Show and reset timeline
  showTimeline();
  resetTimeline();

  // Connect to WebSocket for real-time progress
  const ws = new WebSocket(`ws://127.0.0.1:8000/ws/scan/${targetId}`);

  // Track completed agents for progress
  let completedCount = 0;
  const totalAgents = 4;

  ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    console.log("WebSocket message:", data);

    if (data.agent === "profile") {
      updateAgent("agent-profile", "RUNNING");
      updateProgress(25);
    }
    if (data.agent === "strategy") {
      updateAgent("agent-strategy", "RUNNING");
      updateProgress(50);
    }
    if (data.agent === "exec") {
      updateAgent("agent-exec", "RUNNING");
      updateProgress(75);
    }
    if (data.agent === "observer") {
      updateAgent("agent-observer", "RUNNING");
      updateProgress(90);
    }

    if (data.done) {
      completeAgent("agent-profile");
      completeAgent("agent-strategy");
      completeAgent("agent-exec");
      completeAgent("agent-observer");
      updateProgress(100);
      ws.close();
    }
  };

  ws.onerror = (error) => {
    console.error("WebSocket error:", error);
  };

  ws.onclose = () => {
    console.log("WebSocket connection closed");
  };

  try {
    const response = await fetch(
      `${API_BASE}/scan?target_id=${targetId}`,
      {
        method: "POST",
        headers: {
          "Accept": "application/json"
        }
      }
    );

    const data = await response.json();
    console.log("SCAN RESULT:", data);

    // Store for PDF download
    latestScanResult = data;
    latestScanId = targetId;

    renderResults(data);

  } catch (err) {
    console.error(err);
    resultBox.innerHTML = "❌ Scan failed. Check console.";
    hideTimeline();
  }
});

function renderResults(data) {
  if (!data.results || data.results.length === 0) {
    resultBox.innerHTML = `
      <div class="vuln-card medium">
        <h3>✅ No Vulnerabilities Found</h3>
        <p>No security issues were detected for this target.</p>
      </div>
    `;
    // Hide download button if no results
    document.getElementById("downloadPdfBtn").style.display = "none";
    return;
  }

  let html = "";
  data.results.forEach(vuln => {
    html += `
      <div class="vuln-card ${vuln.severity ? vuln.severity.toLowerCase() : 'medium'}">
        <h3>${vuln.attack}</h3>
        <p><b>Status:</b> ${vuln.status || 'Detected'}</p>
        <p><b>Severity:</b> ${vuln.severity || 'N/A'}</p>
        <p><b>Why:</b> ${vuln.why}</p>
        <p><b>Mitigation:</b> ${vuln.mitigation}</p>
        <p><b>OWASP:</b> ${vuln.owasp_reference || 'N/A'}</p>
      </div>
    `;
  });

  resultBox.innerHTML = html;
  
  // Show download PDF button
  document.getElementById("downloadPdfBtn").style.display = "inline-block";
}

// Allow Enter key to trigger scan
input.addEventListener("keypress", function(e) {
  if (e.key === "Enter") {
    startBtn.click();
  }
});

// Download PDF Report
function downloadReport(scanId) {
  const id = scanId || latestScanId;
  if (!id) {
    alert("No scan available. Please run a scan first.");
    return;
  }
  window.open(`${API_BASE}/report/${id}`);
}

// Progress Bar Functions
function initProgressBar() {
  const progressBar = document.getElementById("scanProgress");
  if (progressBar) {
    progressBar.value = 0;
    progressBar.style.display = "block";
  }
  const progressPercent = document.getElementById("progressPercent");
  if (progressPercent) {
    progressPercent.textContent = "0%";
    progressPercent.style.display = "inline";
  }
}

function updateProgress(percent) {
  const progressBar = document.getElementById("scanProgress");
  if (progressBar) {
    progressBar.value = percent;
  }
  const progressPercent = document.getElementById("progressPercent");
  if (progressPercent) {
    progressPercent.textContent = percent + "%";
  }
}

function hideProgressBar() {
  const progressBar = document.getElementById("scanProgress");
  if (progressBar) {
    progressBar.style.display = "none";
  }
  const progressPercent = document.getElementById("progressPercent");
  if (progressPercent) {
    progressPercent.style.display = "none";
  }
}

// Agent Timeline Functions
function showTimeline() {
  document.getElementById("agentTimeline").classList.remove("hidden");
  initProgressBar();
}

function hideTimeline() {
  document.getElementById("agentTimeline").classList.add("hidden");
  hideProgressBar();
}

function updateAgent(id, status) {
  const el = document.getElementById(id);
  if (el) {
    el.classList.add("active");
    el.querySelector(".status").innerText = status;
  }
}

function completeAgent(id) {
  const el = document.getElementById(id);
  if (el) {
    el.classList.remove("active");
    el.classList.add("done");
    el.querySelector(".status").innerText = "DONE";
  }
}

function resetTimeline() {
  const agents = ["agent-profile", "agent-strategy", "agent-exec", "agent-observer"];
  agents.forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      el.classList.remove("active", "done");
      el.querySelector(".status").innerText = "WAITING";
    }
  });
  updateProgress(0);
}

// Simulated timeline update for demo
function simulateTimeline() {
  showTimeline();
  resetTimeline();
  
  const agents = ["agent-profile", "agent-strategy", "agent-exec", "agent-observer"];
  let index = 0;
  
  const interval = setInterval(() => {
    if (index < agents.length) {
      updateAgent(agents[index], "RUNNING...");
      if (index > 0) {
        completeAgent(agents[index - 1]);
      }
      index++;
    } else {
      completeAgent(agents[agents.length - 1]);
      clearInterval(interval);
    }
  }, 1500);
}
