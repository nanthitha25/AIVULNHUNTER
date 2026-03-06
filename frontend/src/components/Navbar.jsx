import { Link } from 'react-router-dom';

function Navbar() {
  return (
    <nav className="navbar">
      <div className="logo">
        <Link to="/">AivulnHunter</Link>
      </div>
      <div className="nav-links">
        <Link to="/">Dashboard</Link>
        <Link to="/scan">Scan</Link>
        <Link to="/agents">Agents</Link>
        <Link to="/admin">Admin</Link>
      </div>
    </nav>
  );
}

export default Navbar;

