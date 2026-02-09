/**
 * Admin UI - Rule management functionality
 * NO DOMContentLoaded - called after admin.html is loaded
 */

const API_BASE = "http://127.0.0.1:8000";

/**
 * Initialize admin UI - called after admin.html content loads
 */
function initAdminUI() {
  console.log("Initializing admin UI...");
  loadRules();

  // Set up form submission
  const form = document.getElementById("ruleForm");
  if (form) {
    form.onsubmit = handleRuleSubmit;
  }
}

/**
 * Load and display all rules
 */
async function loadRules() {
  const token = localStorage.getItem("token");
  if (!token) {
    console.error("No auth token found");
    return;
  }

  try {
    const res = await fetch(`${API_BASE}/rules/`, {
      headers: { Authorization: `Bearer ${token}` }
    });

    if (!res.ok) {
      console.error("Failed to load rules:", res.status);
      return;
    }

    const rules = await res.json();
    const tbody = document.querySelector("#rulesTable tbody");
    if (!tbody) return;

    tbody.innerHTML = "";

    rules.forEach(rule => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${rule.name}</td>
        <td>${rule.owasp_id}</td>
        <td>${rule.severity}</td>
        <td><button class="delete-btn" onclick="deleteRule('${rule.id}')">Delete</button></td>
      `;
      tbody.appendChild(tr);
    });

    console.log(`Loaded ${rules.length} rules`);
  } catch (err) {
    console.error("Error loading rules:", err);
  }
}

/**
 * Handle rule form submission
 */
async function handleRuleSubmit(e) {
  e.preventDefault();

  const token = localStorage.getItem("token");
  const ruleName = document.getElementById("ruleName").value;
  const owaspId = document.getElementById("owaspId").value;
  const severity = document.getElementById("severity").value;

  const payload = {
    name: ruleName,
    owasp_id: owaspId,
    severity: severity
  };

  try {
    const res = await fetch(`${API_BASE}/rules/`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify(payload)
    });

    if (!res.ok) {
      console.error("Failed to create rule:", res.status);
      return;
    }

    // Clear form and reload rules
    e.target.reset();
    loadRules();
    console.log("Rule created successfully");

  } catch (err) {
    console.error("Error creating rule:", err);
  }
}

/**
 * Delete a rule
 */
async function deleteRule(id) {
  const token = localStorage.getItem("token");

  try {
    const res = await fetch(`${API_BASE}/rules/${id}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${token}` }
    });

    if (!res.ok) {
      console.error("Failed to delete rule:", res.status);
      return;
    }

    loadRules();
    console.log("Rule deleted successfully");

  } catch (err) {
    console.error("Error deleting rule:", err);
  }
}

// Export functions globally
window.initAdminUI = initAdminUI;
window.loadRules = loadRules;
window.deleteRule = deleteRule;

