/**
 * Router.js - SPA Page Routing
 * Handles dynamic loading of pages into index.html#main-content
 */

// Store current page for navigation
let currentPage = 'home';

/**
 * Load scan page into main-content container
 */
async function loadScanPage() {
  const mainContent = document.getElementById("main-content");
  if (!mainContent) {
    console.error("main-content container not found in index.html");
    return;
  }
  
  console.log("Loading scan page...");
  
  try {
    const res = await fetch("scan.html");
    if (!res.ok) {
      throw new Error("Failed to load scan page");
    }
    const html = await res.text();
    
    // Insert HTML into main-content
    mainContent.innerHTML = html;
    
    // Initialize scan UI after content loads
    if (typeof initScanUI === 'function') {
      initScanUI();
    } else {
      console.error("initScanUI function not found - make sure scan.js is loaded");
    }
    
    currentPage = 'scan';
    console.log("Scan page loaded successfully");
    
  } catch (err) {
    console.error("Error loading scan page:", err);
    alert("Failed to load scan page");
  }
}

/**
 * Load admin page into main-content container
 * Includes role verification
 */
async function loadAdminPage() {
  const mainContent = document.getElementById("main-content");
  if (!mainContent) {
    console.error("main-content container not found in index.html");
    return;
  }
  
  // 🔐 Verify admin role
  const role = localStorage.getItem("role");
  if (role !== "admin") {
    alert("Admin access only. Redirecting to login...");
    window.location.href = "admin_login.html";
    return;
  }
  
  console.log("Loading admin page...");
  
  try {
    const res = await fetch("admin.html");
    if (!res.ok) {
      throw new Error("Failed to load admin page");
    }
    const html = await res.text();
    
    // Insert HTML into main-content
    mainContent.innerHTML = html;
    
    // 🔥 Initialize admin UI after content loads
    if (typeof initAdminUI === 'function') {
      initAdminUI();
    } else {
      console.error("initAdminUI function not found - make sure admin.js is loaded");
    }
    
    currentPage = 'admin';
    console.log("Admin page loaded successfully");
    
  } catch (err) {
    console.error("Error loading admin page:", err);
    alert("Failed to load admin page");
  }
}

/**
 * Load home page content (clear dynamic content)
 */
function loadHomePage() {
  const mainContent = document.getElementById("main-content");
  if (!mainContent) return;
  
  // Home content is already in index.html, just clear dynamic content
  mainContent.innerHTML = '';
  currentPage = 'home';
}

/**
 * Navigate to a page
 */
function navigateTo(page) {
  switch(page) {
    case 'admin':
      loadAdminPage();
      break;
    case 'home':
    default:
      loadHomePage();
      break;
  }
}

// Export functions globally
window.loadAdminPage = loadAdminPage;
window.loadScanPage = loadScanPage;
window.loadHomePage = loadHomePage;
window.navigateTo = navigateTo;

