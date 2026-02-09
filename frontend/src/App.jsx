import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import Navbar from './components/Navbar';
import Dashboard from './pages/Dashboard';
import Scan from './pages/Scan';
import Agents from './pages/Agents';
import Admin from './pages/Admin';
import AdminRules from './components/AdminRules';
import './style.css';

function App() {
  return (
    <AuthProvider>
      <Router>
        <Navbar />
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/scan" element={<Scan />} />
          <Route path="/agents" element={<Agents />} />
          <Route path="/admin" element={<Admin />} />
          <Route path="/admin/rules" element={<AdminRules />} />
        </Routes>
      </Router>
    </AuthProvider>
  );
}

export default App;

