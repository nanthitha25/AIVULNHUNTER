"""
AI Redteam Project - FastAPI Backend Entry Point

Main application with CORS support and REST endpoints.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from orchestrator import run_pipeline
from reports.pdf_generator import generate_pdf

app = FastAPI()

# Allow frontend to talk to backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

latest_report = {}


@app.post("/scan")
def scan(data: dict):
    """Run vulnerability assessment scan."""
    global latest_report
    latest_report = run_pipeline(data)
    return latest_report


@app.get("/download-report")
def download():
    """Generate and download PDF report."""
    generate_pdf(latest_report)
    return {"message": "PDF generated as final_report.pdf"}


@app.get("/health")
def health():
    """Health check endpoint."""
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

