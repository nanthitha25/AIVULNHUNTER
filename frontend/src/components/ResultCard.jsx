function ResultCard({ vuln }) {
  return (
    <div className={`vuln-card ${vuln.severity?.toLowerCase() || 'medium'}`}>
      <h3>{vuln.attack}</h3>
      <p><b>Why:</b> {vuln.why}</p>
      <p><b>Mitigation:</b> {vuln.mitigation}</p>
      <p><b>OWASP:</b> {vuln.owasp_reference}</p>
    </div>
  );
}

export default ResultCard;

