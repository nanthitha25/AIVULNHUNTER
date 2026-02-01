const API_BASE = "http://127.0.0.1:8000";

// Store latest scan result for PDF generation
let latestScanResult = null;
let latestTarget = null;
let currentScanId = null;
let progressWebSocket = null;

// DOM Elements
const scanTargetInput = document.getElementById("scanTarget");
const scanTypeSelect = document.getElementById("scanType");
const datasetFileInput = document.getElementById("datasetFile");
const urlInputDiv = document.getElementById("urlInput");
const datasetInputDiv = document.getElementById("datasetInput");
const resultBox = document.getElementById("scanResults");
const downloadBtn = document.getElementById("downloadPdfBtn");

// Check authentication
function checkAuth() {
  const token = localStorage.getItem("token");
  if (!token) {
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
    return false;
  }
  return true;
}

// Toggle Input Fields
function toggleScanInput() {
  const type = document.getElementById("scanType").value;
  urlInputDiv.style.display = type === "DATASET" ? "none" : "block";
  datasetInputDiv.style.display = type === "DATASET" ? "block" : "none";
}

// Initialize on page load
window.addEventListener('load', () => {
  checkAuth();
  
  // Add Enter key support for URL input
  if (scanTargetInput) {
    scanTargetInput.addEventListener("keypress", function(e) {
      if (e.key === "Enter") {
        startUnifiedScan();
      }
    });
  }
});

// WebSocket Connection for Progress
function connectProgressWebSocket(scanId) {
  if (progressWebSocket) {
    progressWebSocket.close();
  }
  
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
      
      if (data.progress !== undefined && data.agent) {
        updateProgressBar(data.progress, data.agent, data.details || "");
        updateAgentStatus(data.agent);
      }
    } catch (e) {
      console.error("[WS] Error:", e);
    }
  };
  
  progressWebSocket.onclose = () => {
    console.log("[WS] Disconnected");
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

// Update Progress Bar
function updateProgressBar(progress, agent, details) {
  const progressBar = document.getElementById("scanProgress");
  if (progressBar && progress >= 0) {
    progressBar.value = progress;
    progressBar.style.display = "block";
  }
  
  const progressPercent = document.getElementById("progressPercent");
  if (progressPercent) {
    if (progress >= 0) {
      progressPercent.textContent = `${progress}%`;
      progressPercent.style.display = "inline";
    }
  }
  
  const agentStatus = document.getElementById("agentStatus");
  if (agentStatus) {
    agentStatus.textContent = details || agent;
  }
}

// Update Agent Timeline Status
function updateAgentStatus(agent) {
  const agentMapping = {
    "Target Profiling": "agent-profile",
    "Profiling": "agent-profile",
    "Attack Strategy": "agent-strategy",
    "Strategy": "agent-strategy",
    "Attack Execution": "agent-execute",
    "Execution": "agent-execute",
    "Analysis & XAI": "agent-observer",
    "Observer": "agent-observer"
  };
  
  const elementId = agentMapping[agent];
  if (elementId) {
    setAgentStatus(elementId, "active");
  }
}

function setAgentStatus(id, status) {
  const el = document.getElementById(id);
  if (el) {
    const statusEl = el.querySelector(".step-status");
    if (status === "active") {
      el.classList.add("active");
      el.classList.remove("done", "error");
      if (statusEl) statusEl.textContent = "RUNNING";
    } else if (status === "done") {
      el.classList.remove("active");
      el.classList.add("done");
      if (statusEl) statusEl.textContent = "DONE";
    } else if (status === "error") {
      el.classList.remove("active");
      el.classList.add("error");
      if (statusEl) statusEl.textContent = "ERROR";
    }
  }
}

function completeAllAgents() {
  ["agent-profile", "agent-strategy", "agent-execute", "agent-observer"].forEach(id => {
    setAgentStatus(id, "done");
  });
}

function resetTimeline() {
  const agents = ["agent-profile", "agent-strategy", "agent-execute", "agent-observer"];
  agents.forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      el.classList.remove("active", "done", "error");
      const statusEl = el.querySelector(".step-status");
      if (statusEl) statusEl.textContent = "WAITING";
    }
  });
  
  const progressBar = document.getElementById("scanProgress");
  if (progressBar) {
    progressBar.value = 0;
    progressBar.style.display = "none";
  }
  
  const progressPercent = document.getElementById("progressPercent");
  if (progressPercent) {
    progressPercent.style.display = "none";
  }
}

// Unified Scan Function
async function startUnifiedScan() {
  const type = document.getElementById("scanType").value;
  const token = localStorage.getItem("token");
  
  if (!token) {
    alert("Please login first");
    window.location.href = "admin_login.html";
    return;
  }
  
  if (type === "API") {
    const target = scanTargetInput ? scanTargetInput.value.trim() : "";
    
    if (!target) {
      alert("Please enter a target URL (e.g., https://api.example.com/llm)");
      return;
    }
    
    latestTarget = target;
    await runAPIScan(target, token);
  } else {
    const file = datasetFileInput ? datasetFileInput.files[0] : null;
    
    if (!file) {
      alert("Please select a dataset file to upload");
      return;
    }
    
    await runDatasetScan(file, token);
  }
}

// Run API/LLM Endpoint Scan
async function runAPIScan(target, token) {
  // Show loading
  resultBox.innerHTML = `
    <div class="info-box">
      <h3>🔍 Starting Scan...</h3>
      <p>Target: ${target}</p>
      <p>Running multi-agent vulnerability assessment pipeline.</p>
    </div>
  `;
  
  // Reset and show timeline
  resetTimeline();
  showTimeline();
  
  try {
    // Connect WebSocket
    connectProgressWebSocket("connecting");
    
    // Start profiling
    setAgentStatus("agent-profile", "active");
    updateProgressBar(25, "Profiling", "Analyzing target system...");
    
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
    
    // Update WebSocket with actual scan_id
    currentScanId = data.scan_id;
    disconnectProgressWebSocket();
    connectProgressWebSocket(currentScanId);
    
    // Complete agents
    setAgentStatus("agent-profile", "done");
    setAgentStatus("agent-strategy", "done");
    setAgentStatus("agent-execute", "done");
    updateProgressBar(90, "Observer", "Generating analysis...");
    
    // Store results
    latestScanResult = data;
    
    // Render results
    renderResults(data.results);
    
    // Complete observer
    setAgentStatus("agent-observer", "done");
    updateProgressBar(100, "Complete", "Scan finished!");
    
    // Disconnect WebSocket
    setTimeout(() => {
      disconnectProgressWebSocket();
    }, 1000);
    
    // Show download button
    if (downloadBtn) downloadBtn.style.display = "inline-block";
    
  } catch (err) {
    console.error("Scan error:", err);
    disconnectProgressWebSocket();
    
    // Mark failed agent
    setAgentStatus("agent-execute", "error");
    
    resultBox.innerHTML = `
      <div class="card ERROR">
        <h3>❌ Scan Failed</h3>
        <p>${err.message}</p>
      </div>
    `;
    hideTimeline();
  }
}

// Run Dataset Upload Scan
async function runDatasetScan(file, token) {
  resultBox.innerHTML = `
    <div class="info-box">
      <h3>📁 Processing Dataset...</h3>
      <p>File: ${file.name}</p>
    </div>
  `;
  
  resetTimeline();
  showTimeline();
  
  try {
    const formData = new FormData();
    formData.append("file", file);
    
    // For now, use the existing scan endpoint with the file content
    // In production, you'd have a dedicated /scan/upload endpoint
    const text = await file.text();
    const targets = JSON.parse(text);
    
    if (Array.isArray(targets) && targets.length > 0) {
      // Scan first target from dataset
      const firstTarget = targets[0];
      const targetUrl = firstTarget.url || firstTarget.id || JSON.stringify(firstTarget);
      
      latestTarget = targetUrl;
      
      const response = await fetch(`${API_BASE}/scan`, {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${token}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          target_id: targetUrl,
          target_type: "llm"
        })
      });
      
      if (!response.ok) {
        throw new Error("Scan failed");
      }
      
      const data = await response.json();
      latestScanResult = data;
      
      setAgentStatus("agent-profile", "done");
      setAgentStatus("agent-strategy", "done");
      setAgentStatus("agent-execute", "done");
      setAgentStatus("agent-observer", "done");
      
      renderResults(data.results);
      
      if (downloadBtn) downloadBtn.style.display = "inline-block";
    } else {
      throw new Error("Invalid dataset format");
    }
    
  } catch (err) {
    console.error("Dataset scan error:", err);
    setAgentStatus("agent-execute", "error");
    
    resultBox.innerHTML = `
      <div class="card ERROR">
        <h3>❌ Dataset Scan Failed</h3>
        <p>${err.message}</p>
      </div>
    `;
    hideTimeline();
  }
}

// Render Results
function renderResults(results) {
  if (!results || results.length === 0) {
    resultBox.innerHTML = `
      <div class="card SECURE">
        <h3>✅ No Vulnerabilities Found</h3>
        <p>The security scan completed successfully with no issues detected.</p>
      </div>
    `;
    if (downloadBtn) downloadBtn.style.display = "none";
    return;
  }
  
  let html = "";
  results.forEach(r => {
    const statusClass = r.status === "VULNERABLE" ? "VULNERABLE" : 
                        r.status === "SECURE" ? "SECURE" :
                        r.status === "PASSED" ? "PASSED" : "WARNING";
    
    const icon = r.status === "VULNERABLE" ? "⚠️" : "✅";
    
    html += `
      <div class="card ${statusClass}">
        <h4>${icon} ${r.attack || r.name || 'Vulnerability'} (${r.owasp_reference || r.owasp || 'N/A'})</h4>
        <p><b>Status:</b> ${r.status}</p>
        <p><b>Severity:</b> ${r.severity || 'N/A'}</p>
        <p><b>Confidence:</b> ${((r.confidence || 0) * 100).toFixed(0)}%</p>
        <p><b>Explanation:</b> ${r.why || r.explanation || 'No explanation available'}</p>
        <p><b>Mitigation:</b> ${r.mitigation || 'No mitigation available'}</p>
      </div>
    `;
  });
  
  resultBox.innerHTML = html;
}

// Download PDF Report
async function downloadPDF() {
  if (!latestScanResult) {
    alert("No scan available. Please run a scan first.");
    return;
  }
  
  const scanId = latestScanResult.scan_id;
  if (scanId) {
    // Open the PDF directly
    window.open(`${API_BASE}/scan/${scanId}/report`, "_blank");
  } else {
    alert("Scan ID not found. Please run a scan first.");
  }
}

// Progress Bar Functions
function showTimeline() {
  const progressBar = document.getElementById("scanProgress");
  if (progressBar) progressBar.style.display = "block";
  const progressPercent = document.getElementById("progressPercent");
  if (progressPercent) progressPercent.style.display = "inline";
}

function hideTimeline() {
  const progressBar = document.getElementById("scanProgress");
  if (progressBar) progressBar.style.display = "none";
  const progressPercent = document.getElementById("progressPercent");
  if (progressPercent) progressPercent.style.display = "none";
}

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
  disconnectProgressWebSocket();
});

