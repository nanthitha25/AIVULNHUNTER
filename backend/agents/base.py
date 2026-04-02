from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger(__name__)

class BaseAgent(ABC):
    """
    Abstract base class for all agents in the system.
    """
    def __init__(self, agent_id: str, config: Dict[str, Any] = None):
        self.agent_id = agent_id
        self.config = config or {}
        self.logger = logging.getLogger(f"agent.{agent_id}")

    @abstractmethod
    async def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process input data and return results.
        
        Args:
            input_data: Dictionary containing input parameters
            
        Returns:
            Dictionary containing processing results
        """
        pass

    async def health_check(self) -> bool:
        """
        Verify if the agent is operational.
        
        Returns:
            True if healthy, False otherwise
        """
        return True


class ScannerPlugin(BaseAgent):
    """
    Abstract base class for scanner plugins (e.g., specific OWASP checks).
    """
    @property
    @abstractmethod
    def rules(self) -> List[str]:
        """
        List of OWASP codes this scanner handles (e.g., ['LLM01', 'LLM02']).
        """
        pass

    @abstractmethod
    async def scan(self, target: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Execute the scan against the target.
        
        Args:
            target: Target URL or identifier
            context: Additional context (e.g., auth headers, profile)
            
        Returns:
            Dictionary containing scan results (status, evidence, etc.)
        """
        pass

    async def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Standard process implementation for scanners.
        Expects 'target' and optional 'context' in input_data.
        """
        target = input_data.get("target")
        if not target:
            raise ValueError("Target is required for ScannerPlugin")
            
        context = input_data.get("context", {})
        return await self.scan(target, context)
