/**
 * Admin Login - OAuth2 compatible FormData submission
 */

async function adminLogin() {
  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;

  if (!username || !password) {
    alert("Please enter both username and password");
    return;
  }

  const formData = new FormData();
  formData.append("username", username);
  formData.append("password", password);

  try {
    const res = await fetch("/auth/login", {
      method: "POST",
      body: formData
    });

    if (!res.ok) {
      const error = await res.json();
      alert(error.detail || "Login failed");
      return;
    }

    const data = await res.json();
    localStorage.setItem("token", data.access_token);
    localStorage.setItem("role", "admin");

    // Redirect to main dashboard
    window.location.href = "/";
  } catch (err) {
    console.error("Login error:", err);
    alert("Login failed: " + err.message);
  }
}

// Handle Enter key on login form
document.addEventListener("DOMContentLoaded", function() {
  const passwordInput = document.getElementById("password");
  if (passwordInput) {
    passwordInput.addEventListener("keypress", function(e) {
      if (e.key === "Enter") {
        adminLogin();
      }
    });
  }
});
