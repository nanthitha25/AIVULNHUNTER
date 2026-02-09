/**
 * Auth.js - Authentication handling
 */

const API_BASE = "http://127.0.0.1:8000";

/**
 * Login function - call this from admin_login.html
 */
async function login() {
  const username = document.getElementById("user").value;
  const password = document.getElementById("pass").value;

  const res = await fetch(`${API_BASE}/auth/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      username,
      password
    })
  });

  if (!res.ok) {
    const err = await res.json();
    const errorBox = document.getElementById("login-error");
    if (errorBox) {
      errorBox.textContent = err.detail || "Login failed";
    }
    return;
  }

  const data = await res.json();
  localStorage.setItem("token", data.access_token);
  localStorage.setItem("role", data.role);

  // Navigate to admin panel
  alert("Login successful! Redirecting to admin panel...");
  window.location.href = "admin_rules.html";
}

// Allow Enter key to submit
document.addEventListener("keypress", function(e) {
  if (e.key === "Enter") {
    login();
  }
});

// Export functions globally
window.login = login;

