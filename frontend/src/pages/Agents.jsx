import AgentCard from '../components/AgentCard';

const agents = [
  {
    id: 'target_profiling',
    name: 'Target Profiling Agent',
    icon: '🎯',
    description: 'Analyzes the target AI system to understand its architecture, capabilities, and potential vulnerabilities.',
    responsibilities: [
      'Identify system type (LLM, API, neural network)',
      'Map input/output patterns',
      'Detect defense mechanisms',
      'Profile attack surface'
    ]
  },
  {
    id: 'attack_strategy',
    name: 'Attack Strategy Agent',
    icon: '⚔️',
    description: 'Generates sophisticated attack vectors based on the target profile and known vulnerability patterns.',
    responsibilities: [
      'Generate prompt injection attacks',
      'Design jailbreak attempts',
      'Create edge case inputs',
      'Develop multi-step attack chains'
    ]
  },
  {
    id: 'executor',
    name: 'Executor Agent',
    icon: '🚀',
    description: 'Executes the generated attack strategies against the target system.',
    responsibilities: [
      'Send crafted inputs to target',
      'Handle rate limiting and retries',
      'Collect responses for analysis',
      'Manage attack persistence'
    ]
  },
  {
    id: 'observer',
    name: 'Observer Agent',
    icon: '👁️',
    description: 'Monitors and evaluates attack outcomes to identify successful exploits.',
    responsibilities: [
      'Analyze response patterns',
      'Detect successful exploits',
      'Measure attack effectiveness',
      'Flag potential vulnerabilities'
    ]
  }
];

function Agents() {
  return (
    <div className="container">
      <h1>AI Red Teaming Agents</h1>
      <p>Understanding the specialized agents that power AivulnHunter.</p>
      
      <div className="agents-grid">
        {agents.map(agent => (
          <AgentCard key={agent.id} agent={agent} />
        ))}
      </div>
    </div>
  );
}

export default Agents;

