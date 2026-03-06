const API = "";

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

// Load RL Heatmap using Chart.js
async function loadRLHeatmap() {
  const canvas = document.getElementById("rlHeatmap");
  if (!canvas) return;
  
  try {
    const data = await getRLHeatmap();
    
    new Chart(canvas, {
      type: "bar",
      data: {
        labels: data.map(r => r.rule),
        datasets: [{
          label: "Priority Score",
          data: data.map(r => r.weight),
          backgroundColor: [
            "rgba(239, 68, 68, 0.7)",
            "rgba(249, 115, 22, 0.7)",
            "rgba(234, 179, 8, 0.7)",
            "rgba(34, 197, 94, 0.7)",
            "rgba(59, 130, 246, 0.7)",
            "rgba(168, 85, 247, 0.7)",
            "rgba(236, 72, 153, 0.7)"
          ],
          borderColor: [
            "rgb(239, 68, 68)",
            "rgb(249, 115, 22)",
            "rgb(234, 179, 8)",
            "rgb(34, 197, 94)",
            "rgb(59, 130, 246)",
            "rgb(168, 85, 247)",
            "rgb(236, 72, 153)"
          ],
          borderWidth: 2,
          borderRadius: 8
        }]
      },
      options: {
        responsive: true,
        plugins: {
          legend: {
            display: false
          },
          title: {
            display: true,
            text: "RL-Optimized Rule Priority Weights",
            color: "#e5e7eb",
            font: { size: 16 }
          }
        },
        scales: {
          y: {
            beginAtZero: true,
            max: 1,
            grid: {
              color: "rgba(255,255,255,0.1)"
            },
            ticks: { color: "#9ca3af" }
          },
          x: {
            grid: {
              display: false
            },
            ticks: { color: "#9ca3af" }
          }
        }
      }
    });
  } catch (err) {
    console.error("Failed to load RL heatmap:", err);
  }
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
