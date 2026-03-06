import { useState } from 'react';

function ScanForm({ onScan }) {
  const [targetId, setTargetId] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    onScan(targetId);
  };

  return (
    <form className="scan-form" onSubmit={handleSubmit}>
      <input
        type="text"
        value={targetId}
        onChange={(e) => setTargetId(e.target.value)}
        placeholder="Enter Target ID (llm_001)"
        required
      />
      <button type="submit">Start Scan</button>
    </form>
  );
}

export default ScanForm;

