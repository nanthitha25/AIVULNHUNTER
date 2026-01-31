/**
 * Auth API
 * Handles authentication-related API calls
 */

import { API_BASE } from "../config.js";

export async function login(username, password) {
  const res = await fetch(`${API_BASE}/admin/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password })
  });
  return await res.json();
}

export function setToken(token) {
  localStorage.setItem("adminToken", token);
}

export function getToken() {
  return localStorage.getItem("adminToken");
}

export function removeToken() {
  localStorage.removeItem("adminToken");
}

export function isAuthenticated() {
  return !!getToken();
}
