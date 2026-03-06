import { useState, useEffect } from "react";
import API, { getRules, addRule, deleteRule } from "../services/api";
import AddRuleModal from "./AddRuleModal";

export default function AdminRules() {
  const [rules, setRules] = useState([]);
  const [showModal, setShowModal] = useState(false);

  const fetchRules = async () => {
    try {
      const res = await getRules();
      console.log("Rules API response:", res.data); // 🔥 DEBUG
      setRules(res.data); // 🔥 SET THE RULES STATE
    } catch (err) {
      console.error("Failed to load rules", err);
    }
  };

  useEffect(() => {
    fetchRules();
  }, []);

  return (
    <div className="admin-rules-container">
      <h2>Vulnerability Rules (Admin)</h2>

      <button className="btn-primary" onClick={() => setShowModal(true)}>
        + Add Rule
      </button>

      <table className="rules-table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Name</th>
            <th>OWASP</th>
            <th>Severity</th>
            <th>Priority</th>
          </tr>
        </thead>
        <tbody>
          {rules.map(rule => (
            <tr key={rule.id}>
              <td>{rule.id}</td>
              <td>{rule.name}</td>
              <td>{rule.owasp}</td>
              <td>
                <span className={`severity-badge severity-${rule.severity?.toLowerCase()}`}>
                  {rule.severity}
                </span>
              </td>
              <td>{rule.priority}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {showModal && (
        <AddRuleModal
          onClose={() => setShowModal(false)}
          onSuccess={fetchRules}
        />
      )}
    </div>
  );
}

