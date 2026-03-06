const API_BASE = "";
const WS_BASE = "";

function goTo(page) {
  window.location.href = page;
}

async function startScan() {
  const targetId = document.getElementById("targetId").value;
  const output = document.getElementById("output");

  output.textContent = "Running scan...";

  // Connect to WebSocket for real-time progress
  const ws = new WebSocket(
    WS_BASE + "/ws/scan/" + targetId
  );

  ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    console.log("WebSocket message:", data);

    if (data.done) {
      ws.close();
    }
  };

  ws.onerror = (error) => {
    console.error("WebSocket error:", error);
  };

  try {
    const res = await fetch(
      `${API_BASE}/scan?target_id=${targetId}`,
      { method: "POST" }
    );

    if (!res.ok) throw new Error("Scan failed");

    const data = await res.json();
    output.textContent = JSON.stringify(data, null, 2);

  } catch (err) {
    output.textContent = "ERROR: " + err.message;
  }
}

async function loadRLGraph() {
  const res = await fetch(`${API_BASE}/rl/stats`);
  const data = await res.json();

  const ctx = document.getElementById("rlChart");
  new Chart(ctx, {
    type: "bar",
    data: {
      labels: Object.keys(data),
      datasets: [{
        label: "Rule Priority Score",
        data: Object.values(data),
        backgroundColor: "#5eead4"
      }]
    },
    options: {
      scales: {
        y: { min: 0, max: 1 }
      }
    }
  });
}

document.addEventListener("DOMContentLoaded", loadRLGraph);

