/**
 * Scan API
 * Handles scan-related API calls
 */

import { API_BASE } from "../config.js";

export async function startScan(targetId) {
  const res = await fetch(`${API_BASE}/scan?target_id=${targetId}`, {
    method: "POST"
  });
  return await res.json();
}

export async function getRLStats() {
  const res = await fetch(`${API_BASE}/rl/stats`);
  return await res.json();
}
