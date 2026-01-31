/**
 * Rules API
 * Handles CRUD operations for vulnerability rules
 */

import { API_BASE } from "../config.js";

export async function getRules() {
  const res = await fetch(`${API_BASE}/admin/rules`);
  return await res.json();
}

export async function addRule(rule) {
  const res = await fetch(`${API_BASE}/admin/rules`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(rule)
  });
  return await res.json();
}

export async function updateRule(id, rule) {
  const res = await fetch(`${API_BASE}/admin/rules/${id}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(rule)
  });
  return await res.json();
}

export async function deleteRule(id) {
  const res = await fetch(`${API_BASE}/admin/rules/${id}`, {
    method: "DELETE"
  });
  return await res.json();
}
