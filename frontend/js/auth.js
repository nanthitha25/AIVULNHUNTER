async function login() {
  const user = document.getElementById("user").value;
  const pass = document.getElementById("pass").value;
  const message = document.getElementById("message");

  if (!user || !pass) {
    message.textContent = "Please enter username and password";
    return;
  }

  try {
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({
        username: user,
        password: pass
      })
    });

    if (res.ok) {
      const data = await res.json();
      localStorage.setItem("admin_token", data.access_token || data.token || "true");
      window.location = "admin_rules.html";
    } else {
      message.textContent = "Invalid login credentials";
    }
  } catch (err) {
    message.textContent = "Login failed: " + err.message;
  }
}

// Allow Enter key to submit
document.addEventListener("keypress", function(e) {
  if (e.key === "Enter") {
    login();
  }
});

