// Agent data and explanation functions
const agentsData = [
  {
    id: "target_profiling",
    name: "Target Profiling Agent",
    icon: "🎯",
    description: "Analyzes system type, architecture, APIs, and attack surface."
  },
  {
    id: "attack_strategy",
    name: "Attack Strategy Agent",
    icon: "♟️",
    description: "Chooses attack vectors based on rules and OWASP Top-11."
  },
  {
    id: "exploitation",
    name: "Exploitation Agent",
    icon: "⚡",
    description: "Executes controlled tests like prompt injection or SQL injection."
  },
  {
    id: "observer",
    name: "Observer Agent",
    icon: "📊",
    description: "Generates explainable AI reports and mitigation steps."
  }
];

function getAgentDescription(agentId) {
  const agent = agentsData.find(a => a.id === agentId);
  return agent ? agent.description : "Unknown agent";
}

function renderAgents(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;
  
  let html = "";
  agentsData.forEach(agent => {
    html += `
      <div class="agent">
        <h3>${agent.icon} ${agent.name}</h3>
        <p>${agent.description}</p>
      </div>
    `;
  });
  container.innerHTML = html;
}

