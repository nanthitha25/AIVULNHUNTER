// Admin functionality for RedTeam AI

const API_URL = API; // Uses the API constant from api.js

// Get auth headers with Bearer token
function getAuthHeaders() {
  const token = localStorage.getItem("admin_token");
  return {
    "Content-Type": "application/json",
    ...(token && { "Authorization": `Bearer ${token}` })
  };
}

let currentRules = [];
let editingRuleId = null;

// Load rules on page load
document.addEventListener("DOMContentLoaded", loadRules);

async function loadRules() {
  try {
    const res = await fetch(`${API_URL}/admin/rules`, {
      headers: getAuthHeaders()
    });
    currentRules = await res.json();
    renderRulesTable();
  } catch (err) {
    console.error("Error loading rules:", err);
  }
}

function renderRulesTable() {
  const tbody = document.querySelector("#rulesTable tbody");
  tbody.innerHTML = "";

  currentRules.forEach(rule => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${rule.id || rule.name?.substring(0, 8)}</td>
      <td>${rule.name || "Unnamed"}</td>
      <td>${rule.owasp || rule.owasp_reference || "N/A"}</td>
      <td>${rule.severity || rule.risk || "MEDIUM"}</td>
      <td>${(rule.priority || rule.q_value || 0.5).toFixed(2)}</td>
      <td>
        <button onclick="editRule('${rule.id}')">Edit</button>
        <button onclick="deleteRule('${rule.id}')" class="danger">Delete</button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function openRuleModal(isEdit = false) {
  document.getElementById("ruleModal").style.display = "block";
  document.getElementById("modalTitle").innerText = isEdit ? "Edit Rule" : "Add Rule";
  editingRuleId = isEdit ? isEdit : null;
}

function closeModal() {
  document.getElementById("ruleModal").style.display = "none";
  clearModalForm();
}

function clearModalForm() {
  document.getElementById("ruleName").value = "";
  document.getElementById("ruleOWASP").value = "";
  document.getElementById("ruleSeverity").value = "MEDIUM";
}

function editRule(ruleId) {
  const rule = currentRules.find(r => r.id === ruleId);
  if (rule) {
    document.getElementById("ruleName").value = rule.name || "";
    document.getElementById("ruleOWASP").value = rule.owasp || rule.owasp_reference || "";
    document.getElementById("ruleSeverity").value = rule.severity || rule.risk || "MEDIUM";
    openRuleModal(ruleId);
  }
}

async function saveRule() {
  const ruleData = {
    name: document.getElementById("ruleName").value,
    owasp: document.getElementById("ruleOWASP").value,
    severity: document.getElementById("ruleSeverity").value,
    enabled: true
  };

  try {
    if (editingRuleId) {
      await fetch(`${API_URL}/admin/rules/${editingRuleId}`, {
        method: "PUT",
        headers: getAuthHeaders(),
        body: JSON.stringify(ruleData)
      });
    } else {
      await fetch(`${API_URL}/admin/rules`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify(ruleData)
      });
    }
    closeModal();
    loadRules();
  } catch (err) {
    console.error("Error saving rule:", err);
    alert("Error saving rule: " + err.message);
  }
}

async function deleteRule(ruleId) {
  if (!confirm("Are you sure you want to delete this rule?")) return;

  try {
    await fetch(`${API_URL}/admin/rules/${ruleId}`, {
      method: "DELETE",
      headers: getAuthHeaders()
    });
    loadRules();
  } catch (err) {
    console.error("Error deleting rule:", err);
    alert("Error deleting rule: " + err.message);
  }
}

// Close modal when clicking outside
window.onclick = function(event) {
  const modal = document.getElementById("ruleModal");
  if (event.target === modal) {
    closeModal();
  }
};
