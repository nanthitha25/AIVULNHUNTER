const API_BASE = "http://127.0.0.1:8000";

// Store latest scan result for PDF generation
let latestScanResult = null;
let latestTarget = null;
let currentScanId = null;
let progressWebSocket = null;

// DOM Elements - support both old and new element IDs
const startBtn = document.getElementById("startScanBtn") || document.querySelector(".start-btn");
const input = document.getElementById("targetInput") || document.getElementById("targetId") || document.getElementById("scanTarget");
const resultBox = document.getElementById("resultBox") || document.getElementById("result");

// Check authentication and update UI
function checkAuth() {
  const token = localStorage.getItem("token");
  if (!token) {
    // Show login required message
    if (resultBox) {
      resultBox.innerHTML = `
        <div class="info-box">
          <h3>🔐 Login Required</h3>
          <p>Please login to start a vulnerability scan.</p>
          <button class="btn-primary" onclick="window.location.href='admin_login.html'">
            Go to Login
          </button>
        </div>
      `;
    }
    if (startBtn) {
      startBtn.disabled = true;
      startBtn.title = "Please login first";
    }
    return false;
  }
  return true;
}

// Initialize on page load
window.addEventListener('load', () => {
  checkAuth();
  
  // Add Enter key support for scan input
  if (input) {
    input.addEventListener("keypress", function(e) {
      if (e.key === "Enter") {
        startScan();
      }
    });
  }
});

// WebSocket Connection for Progress Updates
function connectProgressWebSocket(scanId) {
  // Close existing connection if any
  if (progressWebSocket) {
    progressWebSocket.close();
  }
  
  // Create new WebSocket connection
  const wsUrl = `ws://127.0.0.1:8000/ws/scan/${scanId}`;
  console.log(`[WS] Connecting to ${wsUrl}`);
  
  progressWebSocket = new WebSocket(wsUrl);
  
  progressWebSocket.onopen = () => {
    console.log(`[WS] Connected for scan ${scanId}`);
  };
  
  progressWebSocket.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      console.log(`[WS] Progress:`, data);
      
      // Handle progress updates
      if (data.progress !== undefined && data.agent) {
        updateProgressBar(data.progress, data.agent, data.details || "");
      }
      
      // Handle status messages
      if (data.status === "connected") {
        console.log("[WS] WebSocket handshake complete");
      }
    } catch (e) {
      console.error("[WS] Error parsing message:", e);
    }
  };
  
  progressWebSocket.onclose = (event) => {
    console.log(`[WS] Disconnected (code: ${event.code})`);
  };
  
  progressWebSocket.onerror = (error) => {
    console.error("[WS] Error:", error);
  };
  
  return progressWebSocket;
}

function disconnectProgressWebSocket() {
  if (progressWebSocket) {
    progressWebSocket.close();
    progressWebSocket = null;
  }
}

// Update Progress Bar with Agent Info
function updateProgressBar(progress, agent, details) {
  // Update progress bar
  const progressBar = document.getElementById("scanProgress");
  if (progressBar && progress >= 0) {
    progressBar.value = progress;
    progressBar.style.display = "block";
  }
  
  // Update percentage text
  const progressPercent = document.getElementById("progressPercent");
  if (progressPercent) {
    if (progress >= 0) {
      progressPercent.textContent = `${progress}%`;
      progressPercent.style.display = "inline";
    } else {
      progressPercent.textContent = agent;
    }
  }
  
  // Update agent status
  const agentStatus = document.getElementById("agentStatus");
  if (agentStatus) {
    if (details) {
      agentStatus.textContent = `${agent}: ${details}`;
    } else {
      agentStatus.textContent = agent;
    }
  }
  
  // Update timeline based on agent
  updateAgentStatus(agent);
}

function updateAgentStatus(agent) {
  // Map agent names to timeline element IDs
  const agentMapping = {
    "Target Profiling": "agent-profile",
    "Attack Strategy": "agent-strategy",
    "Attack Execution": "agent-exec",
    "Analysis & XAI": "agent-observer"
  };
  
  const elementId = agentMapping[agent];
  if (elementId) {
    updateAgent(elementId, "RUNNING");
  }
}

async function startScan() {
  const target = input ? input.value.trim() : "";
  
  if (!target) {
    alert("Please enter a target URL (e.g., https://api.example.com/llm)");
    return;
  }
  
  const token = localStorage.getItem("token");
  if (!token) {
    alert("Please login first");
    window.location.href = "admin_login.html";
    return;
  }
  
  // Show loading
  if (resultBox) {
    resultBox.innerHTML = `
      <div class="info-box">
        <h3>🔍 Starting Scan...</h3>
        <p>Target: ${target}</p>
        <p>Running multi-agent vulnerability assessment pipeline.</p>
      </div>
    `;
  }
  
  // Show and reset timeline
  showTimeline();
  resetTimeline();
  
  try {
    // Connect to WebSocket before starting scan
    // We'll use a temporary scan ID and reconnect after we get the actual one
    connectProgressWebSocket("connecting");
    
    // Start with profiling agent
    updateAgent("agent-profile", "RUNNING");
    updateProgress(25);
    
    // Call the scan API
    const response = await fetch(`${API_BASE}/scan`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        target_id: target,
        target_type: "llm"
      })
    });
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || "Scan failed");
    }
    
    const data = await response.json();
    console.log("SCAN RESULT:", data);
    
    // Store scan_id and reconnect WebSocket
    currentScanId = data.scan_id;
    disconnectProgressWebSocket();
    connectProgressWebSocket(currentScanId);
    
    // Mark strategy and exec as done
    completeAgent("agent-strategy");
    completeAgent("agent-exec");
    updateProgress(75);
    
    // Complete observer
    updateAgent("agent-observer", "RUNNING");
    updateProgress(90);
    
    // Store for PDF download
    latestScanResult = data;
    latestTarget = target;
    
    // Render results
    renderResults(data.results);
    
    // Complete observer and finish
    completeAgent("agent-observer");
    updateProgress(100);
    
    // Disconnect WebSocket after scan completes
    setTimeout(() => {
      disconnectProgressWebSocket();
    }, 1000);
    
  } catch (err) {
    console.error("Scan error:", err);
    disconnectProgressWebSocket();
    if (resultBox) {
      resultBox.innerHTML = `
        <div class="vuln-card error">
          <h3>❌ Scan Failed</h3>
          <p>${err.message}</p>
        </div>
      `;
    }
    hideTimeline();
  }
}

function renderResults(results) {
  if (!results || results.length === 0) {
    if (resultBox) {
      resultBox.innerHTML = `
        <div class="vuln-card low">
          <h3>✅ No Vulnerabilities Found</h3>
          <p>The security scan completed successfully with no issues detected.</p>
        </div>
      `;
    }
    // Hide download button if no results
    const downloadBtn = document.getElementById("downloadPdfBtn");
    if (downloadBtn) downloadBtn.style.display = "none";
    return;
  }
  
  let html = "";
  results.forEach(r => {
    const statusClass = r.status === "VULNERABLE" ? "critical" : "low";
    html += `
      <div class="vuln-card ${statusClass}">
        <h3>${r.attack || r.name || 'Vulnerability'} (${r.owasp_reference || r.owasp || 'N/A'})</h3>
        <p><b>Status:</b> ${r.status}</p>
        <p><b>Severity:</b> ${r.severity}</p>
        <p><b>Confidence:</b> ${((r.confidence || 0) * 100).toFixed(0)}%</p>
        <p><b>Why:</b> ${r.why || r.explanation}</p>
        <p><b>Mitigation:</b> ${r.mitigation}</p>
      </div>
    `;
  });
  
  if (resultBox) {
    resultBox.innerHTML = html;
  }
  
  // Show download PDF button
  const downloadBtn = document.getElementById("downloadPdfBtn");
  if (downloadBtn) downloadBtn.style.display = "inline-block";
}

// Download PDF Report
function downloadReport(target) {
  const id = target || latestTarget;
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
  const agentStatus = document.getElementById("agentStatus");
  if (agentStatus) {
    agentStatus.textContent = "";
  }
}

// Agent Timeline Functions
function showTimeline() {
  const timeline = document.getElementById("agentTimeline");
  if (timeline) {
    timeline.classList.remove("hidden");
  }
  initProgressBar();
}

function hideTimeline() {
  const timeline = document.getElementById("agentTimeline");
  if (timeline) {
    timeline.classList.add("hidden");
  }
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

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
  disconnectProgressWebSocket();
});

