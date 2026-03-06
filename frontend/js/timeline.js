// timeline.js - Manages the UI timeline updates
function updateTimeline(stepId, status) {
    const step = document.getElementById(stepId);
    if (!step) return;

    const statusEl = step.querySelector(".step-status");
    statusEl.textContent = status;

    if (status === "RUNNING") {
        step.className = "timeline-step active";
    } else if (status === "COMPLETED") {
        step.className = "timeline-step done";
    } else if (status === "ERROR") {
        step.className = "timeline-step error";
    }
}
