/**
 * Rules API - Fetch and display security rules
 */

const API_BASE = "";

// Store for rules data
let rulesCache = [];

/**
 * Load rules from the backend API
 */
async function loadRules() {
  try {
    const token = localStorage.getItem("token");
    
    const res = await fetch("/rules/", {
      method: "GET",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json"
      }
    });

    if (!res.ok) {
      if (res.status === 401) {
        // Token expired, redirect to login
        localStorage.removeItem("token");
        localStorage.removeItem("role");
        window.location.href = "/admin_login.html";
        return;
      }
      throw new Error(`HTTP ${res.status}: ${res.statusText}`);
    }

    const rules = await res.json();
    rulesCache = rules;
    renderRules(rules);
  } catch (err) {
    console.error("Failed to load rules:", err);
    showError("Failed to load rules: " + err.message);
  }
}

/**
 * Render rules to the DOM
 * @param {Array} rules - Array of rule objects
 */
function renderRules(rules) {
  const container = document.getElementById("rulesContainer");
  if (!container) return;

  if (!rules || rules.length === 0) {
    container.innerHTML = `
      <div class="info-box">
        <h3>No Rules Found</h3>
        <p>No security rules are currently configured.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = rules.map(rule => `
    <div class="rule-card" data-id="${rule.id || rule.rule_id}">
      <div class="rule-header">
        <h4>${rule.name || rule.rule_name || "Unnamed Rule"}</h4>
        <span class="severity-badge ${(rule.severity || "UNKNOWN").toLowerCase()}">
          ${rule.severity || "UNKNOWN"}
        </span>
      </div>
      <div class="rule-body">
        <p><strong>OWASP:</strong> ${rule.owasp || "N/A"}</p>
        <p><strong>Priority:</strong> ${rule.priority || rule.rule_priority || "N/A"}</p>
        <p><strong>Description:</strong> ${rule.description || rule.explanation || "No description"}</p>
      </div>
  `).join("");
}

/**
 * Show error message in the rules container
 * @param {string} message - Error message to display
 */
function showError(message) {
  const container = document.getElementById("rulesContainer");
  if (container) {
    container.innerHTML = `
      <div class="card ERROR">
        <h3>❌ Error</h3>
        <p>${message}</p>
      </div>
    `;
  }
}

/**
 * Check if user is authenticated
 */
function isAuthenticated() {
  const token = localStorage.getItem("token");
  const role = localStorage.getItem("role");
  return token && role === "admin";
}

// Load rules on page load if authenticated
document.addEventListener("DOMContentLoaded", function() {
  if (isAuthenticated()) {
    loadRules();
  } else {
    // Redirect to login if not authenticated
    window.location.href = "/admin_login.html";
  }
});
