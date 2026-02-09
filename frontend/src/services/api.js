import axios from "axios";

const API = axios.create({
  baseURL: "",
});

// Request interceptor to add auth token
API.interceptors.request.use((config) => {
  const token = localStorage.getItem("token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Response interceptor for error handling
API.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem("token");
      // Optionally redirect to login
      window.location.href = "/admin/login";
    }
    return Promise.reject(error);
  }
);

export default API;

// Auth helpers
export const login = (username, password) => 
  API.post("/admin/login", { username, password });

export const getRules = () => 
  API.get("/rules/");

export const addRule = (rule) => 
  API.post("/rules/", rule);

export const deleteRule = (id) => 
  API.delete(`/rules/${id}`);

export const updateRule = (id, data) => 
  API.put(`/rules/${id}`, data);

// Scan API
export const startScan = (targetId, targetType = "llm") => 
  API.post("/scan", { target_id: targetId, target_type: targetType });

export const getScanResult = (scanId) => 
  API.get(`/scan/${scanId}`);

export const getScanReport = (scanId) => 
  API.get(`/scan/${scanId}/report`, { responseType: 'blob' });

// Dataset API
export const getTargets = () => 
  API.get("/targets");

