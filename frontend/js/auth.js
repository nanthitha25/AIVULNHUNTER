/**
 * Auth.js - JWT Authentication handling
 * Supports login (admin & user) and registration (user role)
 */

const API_BASE = window.API_BASE || "http://127.0.0.1:8000";

/**
 * Login - authenticate and store JWT + role in localStorage
 */
async function login() {
  const username = document.getElementById("user")?.value || document.getElementById("username")?.value;
  const password = document.getElementById("pass")?.value || document.getElementById("password")?.value;

  const res = await fetch(`${API_BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password })
  });

  if (!res.ok) {
    const err = await res.json();
    const errorBox = document.getElementById("login-error");
    if (errorBox) errorBox.textContent = err.detail || "Login failed";
    return;
  }

  const data = await res.json();
  localStorage.setItem("token",    data.access_token);
  localStorage.setItem("role",     data.role);
  localStorage.setItem("username", data.username);
  localStorage.setItem("scan_limit", data.scan_limit || "3");

  // Redirect based on role
  if (data.role === "admin") {
    window.location.href = "admin_rules.html";
  } else {
    window.location.href = "scan.html";
  }
}

/**
 * Register - create a new user account (role: user)
 */
async function register() {
  const username = document.getElementById("reg-user")?.value;
  const password = document.getElementById("reg-pass")?.value;
  const errorBox = document.getElementById("reg-error");

  if (!username || !password) {
    if (errorBox) errorBox.textContent = "Username and password are required.";
    return;
  }

  const res = await fetch(`${API_BASE}/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password })
  });

  const data = await res.json();
  if (!res.ok) {
    if (errorBox) errorBox.textContent = data.detail || "Registration failed";
    return;
  }

  alert(`✅ Registered successfully as '${data.username}'. You can now log in.`);
  window.location.href = "admin_login.html";
}

/**
 * Logout
 */
function logout() {
  localStorage.removeItem("token");
  localStorage.removeItem("role");
  localStorage.removeItem("username");
  window.location.href = "admin_login.html";
}

// Allow Enter key to submit login
document.addEventListener("keypress", function(e) {
  if (e.key === "Enter") login();
});

window.login    = login;
window.register = register;
window.logout   = logout;


