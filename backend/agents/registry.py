from typing import Dict, Type, Any, List, Optional
import importlib
import pkgutil
import inspect
import logging
from backend.agents.base import BaseAgent, ScannerPlugin

logger = logging.getLogger(__name__)

class AgentRegistry:
    """
    Registry for managing and loading agents and plugins.
    """
    def __init__(self):
        self._agents: Dict[str, BaseAgent] = {}
        self._scanners: Dict[str, ScannerPlugin] = {}
        self._scanner_classes: Dict[str, Type[ScannerPlugin]] = {}

    def register_agent(self, agent_id: str, agent_instance: BaseAgent):
        """Register an instantiated agent."""
        self._agents[agent_id] = agent_instance
        logger.info(f"Registered agent: {agent_id}")

    def get_agent(self, agent_id: str) -> Optional[BaseAgent]:
        """Get an agent by ID."""
        return self._agents.get(agent_id)

    def register_scanner(self, scanner_class: Type[ScannerPlugin]):
        """Register a scanner class."""
        # Create a temporary instance to get rules, or verify rules property is static-friendly if changed
        # For now, we instantiate on registration or on demand. 
        # Making it simple: Instantiate on registration for this version.
        try:
            instance = scanner_class(agent_id=scanner_class.__name__, config={})
            for rule in instance.rules:
                self._scanners[rule] = instance
                logger.info(f"Registered scanner for rule {rule}: {scanner_class.__name__}")
        except Exception as e:
            logger.error(f"Failed to register scanner {scanner_class.__name__}: {e}")

    def get_scanner_for_rule(self, rule_code: str) -> Optional[ScannerPlugin]:
        """Get the scanner instance responsible for a specific rule."""
        return self._scanners.get(rule_code)

    def load_plugins(self, package_path: str):
        """
        Dynamically load scanner plugins from a package path.
        
        Args:
            package_path: Dot-notation package path (e.g., 'backend.agents.plugins')
        """
        try:
            module = importlib.import_module(package_path)
            path = module.__path__
            
            for _, name, _ in pkgutil.iter_modules(path):
                full_name = f"{package_path}.{name}"
                try:
                    plugin_module = importlib.import_module(full_name)
                    
                    for _, obj in inspect.getmembers(plugin_module):
                        if (inspect.isclass(obj) and 
                            issubclass(obj, ScannerPlugin) and 
                            obj is not ScannerPlugin):
                            self.register_scanner(obj)
                            
                except Exception as e:
                    logger.error(f"Error loading plugin module {full_name}: {e}")
                    
        except ImportError as e:
            logger.error(f"Could not import plugin package {package_path}: {e}")

# Global registry instance
registry = AgentRegistry()
