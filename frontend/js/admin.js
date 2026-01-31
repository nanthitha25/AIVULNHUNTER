const API = "http://127.0.0.1:8000";
let editingRuleId = null;

/* 🔐 PROTECT PAGE */
const token = localStorage.getItem("admin_token");
if (!token) {
  window.location.href = "admin.html";
}

/* LOAD RULES */
async function loadRules() {
  const res = await fetch(API + "/admin/rules", {
    headers: {
      "Authorization": "Bearer " + token
    }
  });

  const rules = await res.json();
  const tbody = document.querySelector("#rulesTable tbody");
  tbody.innerHTML = "";

  rules.forEach(r => {
    tbody.innerHTML += `
      <tr>
        <td>${r.id}</td>
        <td>${r.name}</td>
        <td>${r.owasp}</td>
        <td>${r.severity}</td>
        <td>${r.priority}</td>
        <td>
          <button onclick='editRule(${JSON.stringify(r)})'>✏️</button>
          <button onclick='deleteRule("${r.id}")'>🗑️</button>
        </td>
      </tr>
    `;
  });
}

/* MODAL CONTROL */
function openModal() {
  editingRuleId = null;
  document.getElementById("ruleName").value = "";
  document.getElementById("ruleOWASP").value = "";
  document.getElementById("ruleSeverity").value = "LOW";
  document.getElementById("rulePriority").value = "";
  document.getElementById("ruleModal").style.display = "block";
}

function closeModal() {
  document.getElementById("ruleModal").style.display = "none";
}

function editRule(rule) {
  editingRuleId = rule.id;
  document.getElementById("ruleName").value = rule.name;
  document.getElementById("ruleOWASP").value = rule.owasp;
  document.getElementById("ruleSeverity").value = rule.severity;
  document.getElementById("rulePriority").value = rule.priority;
  document.getElementById("ruleModal").style.display = "block";
}

/* SAVE RULE */
async function saveRule() {
  const payload = {
    name: document.getElementById("ruleName").value,
    owasp: document.getElementById("ruleOWASP").value,
    severity: document.getElementById("ruleSeverity").value,
    priority: parseFloat(document.getElementById("rulePriority").value)
  };

  const url = editingRuleId
    ? `${API}/admin/rules/${editingRuleId}`
    : `${API}/admin/rules`;

  await fetch(url, {
    method: editingRuleId ? "PUT" : "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer " + token
    },
    body: JSON.stringify(payload)
  });

  closeModal();
  loadRules();
}

/* DELETE RULE */
async function deleteRule(id) {
  if (!confirm("Delete this rule?")) return;

  await fetch(`${API}/admin/rules/${id}`, {
    method: "DELETE",
    headers: {
      "Authorization": "Bearer " + token
    }
  });

  loadRules();
}

/* INIT */
loadRules();
