import { createContext, useContext, useState, useEffect } from 'react';
import { login as loginApi, setToken, getToken, removeToken, isAuthenticated } from '../api/authApi';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const checkAuth = async () => {
      if (isAuthenticated()) {
        setUser({ authenticated: true });
      }
      setLoading(false);
    };
    checkAuth();
  }, []);

  const login = async (username, password) => {
    const data = await loginApi(username, password);
    if (data.token) {
      setToken(data.token);
      setUser({ authenticated: true, username });
      return true;
    }
    return false;
  };

  const logout = () => {
    removeToken();
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, login, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

