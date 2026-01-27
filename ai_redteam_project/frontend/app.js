/**
 * AI Redteam Project - Frontend Application
 */

// API Configuration
const API_BASE = "http://127.0.0.1:8000";

/**
 * Start a vulnerability scan on the target AI system
 */
async function startScan() {
  const apiUrl = document.getElementById("apiUrl").value;
  const appType = document.getElementById("appType").value;

  // Validate input
  if (!apiUrl) {
    alert("Please enter an API URL");
    return;
  }

  try {
    const response = await fetch(`${API_BASE}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        application_url: apiUrl,
        type: appType
      })
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const data = await response.json();
    document.getElementById("output").innerText = JSON.stringify(data, null, 2);
    
    // Update stats
    updateStats();
    
  } catch (error) {
    console.error("Scan failed:", error);
    document.getElementById("output").innerText = 
      `Error: ${error.message}\n\nMake sure the backend is running at ${API_BASE}`;
  }
}

function updateStats() {
  const scansEl = document.getElementById("scans");
  if (scansEl) {
    scansEl.textContent = parseInt(scansEl.textContent) + 1;
  }
}

// Initialize on page load
document.addEventListener("DOMContentLoaded", () => {
  console.log("RedTeam AI Vulnerability Scanner ready");
});

