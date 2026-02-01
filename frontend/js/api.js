const API = "http://127.0.0.1:8000";

// Make API available globally for legacy scripts
if (typeof window !== 'undefined') {
  window.API = API;
}

// RL API Functions
async function getRLHeatmap() {
  const token = localStorage.getItem("token");
  const res = await fetch(`${API}/rl/heatmap`, {
    headers: {
      "Authorization": `Bearer ${token}`
    }
  });
  if (!res.ok) throw new Error("Failed to fetch RL heatmap");
  return res.json();
}

async function getRLMetrics() {
  const token = localStorage.getItem("token");
  const res = await fetch(`${API}/rl/metrics`, {
    headers: {
      "Authorization": `Bearer ${token}`
    }
  });
  if (!res.ok) throw new Error("Failed to fetch RL metrics");
  return res.json();
}

async function getRuleQScore(ruleId) {
  const token = localStorage.getItem("token");
  const res = await fetch(`${API}/rl/q_score/${ruleId}`, {
    headers: {
      "Authorization": `Bearer ${token}`
    }
  });
  if (!res.ok) throw new Error("Failed to fetch rule Q-score");
  return res.json();
}

async function resetRLMetrics() {
  const token = localStorage.getItem("token");
  const res = await fetch(`${API}/rl/reset`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${token}`
    }
  });
  if (!res.ok) throw new Error("Failed to reset RL metrics");
  return res.json();
}

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { API, getRLHeatmap, getRLMetrics, getRuleQScore, resetRLMetrics };
}
