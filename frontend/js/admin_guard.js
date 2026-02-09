// Admin Guard - Protect Admin Dashboard
// Include this script in admin_dashboard.html BEFORE other scripts

(function() {
  const token = localStorage.getItem("token");
  const role = localStorage.getItem("role");

  console.log("DEBUG admin_guard.js: token:", !!token, "role:", role);

  // Redirect to login if not authenticated or not admin
  if (!token || role !== "admin") {
    console.log("DEBUG admin_guard.js: Redirecting to login - missing or invalid credentials");
    window.location.href = "admin_login.html";
    return;
  }

  console.log("DEBUG admin_guard.js: ✅ Admin access granted");
})();

