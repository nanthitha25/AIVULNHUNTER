function AgentCard({ agent }) {
  return (
    <div className="agent-card">
      <div className="agent-icon">{agent.icon}</div>
      <h3>{agent.name}</h3>
      <p className="agent-description">{agent.description}</p>
      <h4>Responsibilities:</h4>
      <ul className="agent-responsibilities">
        {agent.responsibilities.map((r, i) => (
          <li key={i}>{r}</li>
        ))}
      </ul>
    </div>
  );
}

export default AgentCard;

