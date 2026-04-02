import sys
import os

# Ensure backend can be imported
sys.path.append(os.getcwd())

from backend.agents.registry import registry
from backend.services.pipeline_service import PipelineService

def check_registry():
    # PipelineService initializes the registry on first run or we can trigger it
    pipeline = PipelineService()
    
    # Get unique scanner instances
    scanners = list(set(registry._scanners.values()))
    count = len(scanners)
    print(f"Total Unique Scanners Registered: {count}")
    
    # List all scanner names to check for duplicates or missing ones
    scanner_names = [s.__class__.__name__ for s in scanners]
    
    # Advanced Scanners we just added:
    advanced_scanners = [
        "AdvancedBOLAScanner", 
        "ParameterTamperingScanner", 
        "MassAssignmentScanner", 
        "InjectionFuzzScanner", 
        "AdvancedRateLimitScanner",
        "ToolArgumentInjectionScanner", 
        "MemoryPoisoningScanner", 
        "AutonomousEscalationScanner", 
        "AdvancedPromptExtractionScanner", 
        "ToolChainingExfiltrationScanner"
    ]
    
    print("\nAdvanced Scanners Status:")
    for adv in advanced_scanners:
        present = adv in scanner_names
        print(f" - {adv}: {'✅ Found' if present else '❌ Missing'}")
        
    # Check for duplicates
    from collections import Counter
    duplicates = [name for name, count in Counter(scanner_names).items() if count > 1]
    if duplicates:
        print(f"\n❌ DUPLICATES FOUND: {duplicates}")
    else:
        print("\n✅ No duplicates found.")

if __name__ == "__main__":
    check_registry()
