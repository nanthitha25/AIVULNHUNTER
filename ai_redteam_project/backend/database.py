"""
AI Redteam Project - Database Module

Handles all database operations for the vulnerability assessment system.
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum


class StorageType(Enum):
    """Supported storage types."""
    MEMORY = "memory"
    JSON = "json"
    SQLITE = "sqlite"


class Database:
    """
    Database handler for storing scan results, vulnerabilities, and configurations.
    """
    
    def __init__(self, storage_type: StorageType = StorageType.MEMORY, db_path: str = "./data"):
        """
        Initialize the database.
        
        Args:
            storage_type: Type of storage to use
            db_path: Path to database files
        """
        self.storage_type = storage_type
        self.db_path = db_path
        self.scans: Dict[str, dict] = {}
        self.vulnerabilities: List[dict] = []
        self.targets: Dict[str, dict] = {}
        
        self._ensure_storage_dir()
    
    def _ensure_storage_dir(self):
        """Ensure the storage directory exists."""
        if self.storage_type != StorageType.MEMORY:
            os.makedirs(self.db_path, exist_ok=True)
    
    def init_db(self):
        """Initialize the database and create necessary structures."""
        print(f"Initializing database with {self.storage_type.value} storage...")
        
        if self.storage_type == StorageType.JSON:
            self._load_from_json()
        
        print("Database initialized successfully")
    
    def _load_from_json(self):
        """Load data from JSON files."""
        scans_file = os.path.join(self.db_path, "scans.json")
        vulnerabilities_file = os.path.join(self.db_path, "vulnerabilities.json")
        
        if os.path.exists(scans_file):
            with open(scans_file, 'r') as f:
                self.scans = json.load(f)
        
        if os.path.exists(vulnerabilities_file):
            with open(vulnerabilities_file, 'r') as f:
                self.vulnerabilities = json.load(f)
    
    def _save_to_json(self):
        """Save data to JSON files."""
        if self.storage_type != StorageType.JSON:
            return
        
        scans_file = os.path.join(self.db_path, "scans.json")
        vulnerabilities_file = os.path.join(self.db_path, "vulnerabilities.json")
        
        with open(scans_file, 'w') as f:
            json.dump(self.scans, f, indent=2, default=str)
        
        with open(vulnerabilities_file, 'w') as f:
            json.dump(self.vulnerabilities, f, indent=2, default=str)
    
    # Scan Operations
    def create_scan(self, target: dict) -> str:
        """
        Create a new scan record.
        
        Args:
            target: Target configuration
            
        Returns:
            Scan ID
        """
        scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        self.scans[scan_id] = {
            "id": scan_id,
            "target": target,
            "status": "pending",
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "results": None,
            "vulnerabilities": []
        }
        
        self._save_to_json()
        return scan_id
    
    def get_scan(self, scan_id: str) -> Optional[dict]:
        """
        Get a scan by ID.
        
        Args:
            scan_id: Scan ID
            
        Returns:
            Scan record or None
        """
        return self.scans.get(scan_id)
    
    def update_scan(self, scan_id: str, updates: dict) -> bool:
        """
        Update a scan record.
        
        Args:
            scan_id: Scan ID
            updates: Fields to update
            
        Returns:
            True if updated successfully
        """
        if scan_id not in self.scans:
            return False
        
        self.scans[scan_id].update(updates)
        self.scans[scan_id]["updated_at"] = datetime.now().isoformat()
        self._save_to_json()
        return True
    
    def delete_scan(self, scan_id: str) -> bool:
        """
        Delete a scan record.
        
        Args:
            scan_id: Scan ID
            
        Returns:
            True if deleted successfully
        """
        if scan_id not in self.scans:
            return False
        
        del self.scans[scan_id]
        self._save_to_json()
        return True
    
    def list_scans(self, status: Optional[str] = None) -> List[dict]:
        """
        List all scans, optionally filtered by status.
        
        Args:
            status: Optional status filter
            
        Returns:
            List of scan records
        """
        scans = list(self.scans.values())
        
        if status:
            scans = [s for s in scans if s["status"] == status]
        
        return sorted(scans, key=lambda x: x["created_at"], reverse=True)
    
    # Vulnerability Operations
    def add_vulnerability(self, scan_id: str, vulnerability: dict) -> str:
        """
        Add a vulnerability to a scan.
        
        Args:
            scan_id: Scan ID
            vulnerability: Vulnerability details
            
        Returns:
            Vulnerability ID
        """
        vuln_id = f"vuln_{len(self.vulnerabilities) + 1}"
        
        vulnerability["id"] = vuln_id
        vulnerability["scan_id"] = scan_id
        vulnerability["created_at"] = datetime.now().isoformat()
        
        self.vulnerabilities.append(vulnerability)
        
        if scan_id in self.scans:
            self.scans[scan_id]["vulnerabilities"].append(vuln_id)
        
        self._save_to_json()
        return vuln_id
    
    def get_vulnerabilities(self, scan_id: Optional[str] = None) -> List[dict]:
        """
        Get vulnerabilities, optionally filtered by scan ID.
        
        Args:
            scan_id: Optional scan ID filter
            
        Returns:
            List of vulnerabilities
        """
        if scan_id:
            return [v for v in self.vulnerabilities if v["scan_id"] == scan_id]
        return self.vulnerabilities
    
    # Target Operations
    def save_target(self, target: dict) -> str:
        """
        Save a target configuration.
        
        Args:
            target: Target configuration
            
        Returns:
            Target ID
        """
        target_id = target.get("id", f"target_{len(self.targets) + 1}")
        target["saved_at"] = datetime.now().isoformat()
        
        self.targets[target_id] = target
        self._save_to_json()
        return target_id
    
    def get_target(self, target_id: str) -> Optional[dict]:
        """
        Get a target by ID.
        
        Args:
            target_id: Target ID
            
        Returns:
            Target configuration or None
        """
        return self.targets.get(target_id)
    
    def list_targets(self) -> List[dict]:
        """
        List all saved targets.
        
        Returns:
            List of target configurations
        """
        return list(self.targets.values())
    
    # Statistics
    def get_statistics(self) -> dict:
        """
        Get database statistics.
        
        Returns:
            Statistics dictionary
        """
        total_scans = len(self.scans)
        completed_scans = len([s for s in self.scans.values() if s["status"] == "completed"])
        total_vulnerabilities = len(self.vulnerabilities)
        
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }
        
        for vuln in self.vulnerabilities:
            severity = vuln.get("severity", "low")
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return {
            "total_scans": total_scans,
            "completed_scans": completed_scans,
            "pending_scans": total_scans - completed_scans,
            "total_vulnerabilities": total_vulnerabilities,
            "vulnerabilities_by_severity": severity_counts
        }


# Global database instance
db = Database()


def init_db():
    """Initialize the global database instance."""
    db.init_db()


def get_db() -> Database:
    """Get the global database instance."""
    return db

