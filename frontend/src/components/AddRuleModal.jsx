import { useState } from "react";
import API, { addRule } from "../services/api";

export default function AddRuleModal({ onClose, onSuccess }) {
  const [name, setName] = useState("");
  const [owasp, setOwasp] = useState("");
  const [severity, setSeverity] = useState("HIGH");
  const [priority, setPriority] = useState(1);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async () => {
    setLoading(true);
    try {
      await addRule({
        name,
        owasp,
        severity,
        priority: Number(priority)
      });
      onSuccess();
      onClose();
    } catch (err) {
      console.error("Failed to add rule:", err);
      alert("Failed to add rule: " + (err.response?.data?.detail || err.message));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay">
      <div className="modal">
        <h3>Add Vulnerability Rule</h3>

        <input
          placeholder="Rule Name"
          value={name}
          onChange={e => setName(e.target.value)}
        />

        <input
          placeholder="OWASP ID (e.g. LLM01)"
          value={owasp}
          onChange={e => setOwasp(e.target.value)}
        />

        <select value={severity} onChange={e => setSeverity(e.target.value)}>
          <option>LOW</option>
          <option>MEDIUM</option>
          <option>HIGH</option>
          <option>CRITICAL</option>
        </select>

        <input
          type="number"
          placeholder="Priority"
          value={priority}
          onChange={e => setPriority(e.target.value)}
        />

        <div className="modal-actions">
          <button className="btn-primary" onClick={handleSubmit}>Save</button>
          <button className="btn-secondary" onClick={onClose}>Cancel</button>
        </div>
      </div>
    </div>
  );
}

