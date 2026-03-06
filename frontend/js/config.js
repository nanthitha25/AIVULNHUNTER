// Use absolute URL for backend when frontend is served from different port
const API_BASE = "http://127.0.0.1:8000";

// Make API_BASE globally available for all scripts
if (typeof window !== 'undefined') {
  window.API_BASE = API_BASE;
}

