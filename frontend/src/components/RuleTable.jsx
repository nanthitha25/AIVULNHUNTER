function RuleTable({ rules, onEdit, onDelete }) {
  return (
    <table className="rule-table">
      <thead>
        <tr>
          <th>ID</th>
          <th>Name</th>
          <th>Severity</th>
          <th>Strategy</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        {rules.map(rule => (
          <tr key={rule.id}>
            <td>{rule.id}</td>
            <td>{rule.name}</td>
            <td><span className={`severity-${rule.severity?.toLowerCase()}`}>{rule.severity}</span></td>
            <td>{rule.strategy}</td>
            <td>
              <button onClick={() => onEdit(rule)}>Edit</button>
              <button onClick={() => onDelete(rule.id)}>Delete</button>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default RuleTable;

