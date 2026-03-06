/**
 * Rules API
 * Handles CRUD operations for vulnerability rules
 */

import { API_BASE } from "../config.js";
import { getToken } from "./authApi.js";

function getAuthHeaders() {
  const token = getToken();
  return {
    "Authorization": `Bearer ${token}`,
    "Content-Type": "application/json"
  };
}

export async function getRules() {
  const res = await fetch(`${API_BASE}/rules`, {
    headers: getAuthHeaders()
  });
  return await res.json();
}

export async function addRule(rule) {
  const res = await fetch(`${API_BASE}/rules`, {
    method: "POST",
    headers: getAuthHeaders(),
    body: JSON.stringify(rule)
  });
  return await res.json();
}

export async function updateRule(id, rule) {
  const res = await fetch(`${API_BASE}/rules/${id}`, {
    method: "PUT",
    headers: getAuthHeaders(),
    body: JSON.stringify(rule)
  });
  return await res.json();
}

export async function deleteRule(id) {
  const res = await fetch(`${API_BASE}/rules/${id}`, {
    method: "DELETE",
    headers: getAuthHeaders()
  });
  return await res.json();
}
