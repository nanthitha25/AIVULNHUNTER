import { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import API, { getRules, addRule, updateRule, deleteRule } from '../services/api';
import RuleTable from '../components/RuleTable';
import Loader from '../components/Loader';

function Admin() {
  const { user, logout } = useAuth();
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(false);
  const [newRule, setNewRule] = useState({ name: '', severity: 'medium', strategy: '' });

  useEffect(() => {
    if (user) loadRules();
  }, [user]);

  const loadRules = async () => {
    setLoading(true);
    try {
      const res = await getRules();
      setRules(res.data);
    } catch (err) {
      console.error('Failed to load rules');
    } finally {
      setLoading(false);
    }
  };

  const handleAddRule = async () => {
    await addRule({
      name: newRule.name,
      severity: newRule.severity,
      strategy: newRule.strategy
    });
    setNewRule({ name: '', severity: 'medium', strategy: '' });
    loadRules();
  };

  const handleEditRule = async (rule) => {
    const updated = { ...rule, severity: prompt('New severity:', rule.severity) };
    try {
      await updateRule(rule.id, updated);
      loadRules();
    } catch (err) {
      console.error('Failed to update rule');
    }
  };

  const handleDeleteRule = async (id) => {
    if (confirm('Delete this rule?')) {
      await deleteRule(id);
      loadRules();
    }
  };

  if (!user) {
    return (
      <div className="container">
        <h1>Admin Login Required</h1>
        <p>Please log in to manage vulnerability rules.</p>
      </div>
    );
  }

  return (
    <div className="container">
      <div className="admin-header">
        <h1>Admin – Vulnerability Rules</h1>
        <button onClick={logout} className="secondary">Logout</button>
      </div>

      {loading ? (
        <Loader message="Loading rules..." />
      ) : (
        <>
          <RuleTable rules={rules} onEdit={handleEditRule} onDelete={handleDeleteRule} />
          
          <div className="add-rule-form">
            <h3>Add New Rule</h3>
            <input
              placeholder="Rule Name"
              value={newRule.name}
              onChange={(e) => setNewRule({ ...newRule, name: e.target.value })}
            />
            <select
              value={newRule.severity}
              onChange={(e) => setNewRule({ ...newRule, severity: e.target.value })}
            >
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            <input
              placeholder="Strategy"
              value={newRule.strategy}
              onChange={(e) => setNewRule({ ...newRule, strategy: e.target.value })}
            />
            <button onClick={handleAddRule}>Add Rule</button>
          </div>
        </>
      )}
    </div>
  );
}

export default Admin;

