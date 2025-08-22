"""
Risk Assessor Factory

This module provides a factory pattern for managing and loading risk assessment modules
at runtime. It supports dynamic registration, priority-based execution, and plugin loading.
"""

import importlib
import inspect
import os
from typing import Dict, List, Type, Optional, Any
from pathlib import Path

from .base import BaseRiskAssessor, RiskAssessment, RiskCategory


class RiskAssessorFactory:
    """
    Factory class for managing risk assessment modules.
    
    Supports:
    - Dynamic registration of risk assessors
    - Priority-based execution order
    - Runtime loading from configuration
    - Plugin discovery and loading
    """
    
    def __init__(self):
        self._assessors: Dict[str, BaseRiskAssessor] = {}
        self._assessor_classes: Dict[str, Type[BaseRiskAssessor]] = {}
        self._execution_order: List[str] = []
    
    def register_assessor(self, assessor: BaseRiskAssessor) -> None:
        """
        Register a risk assessor instance.
        
        Args:
            assessor: Risk assessor instance to register
        """
        if not isinstance(assessor, BaseRiskAssessor):
            raise ValueError(f"Assessor must inherit from BaseRiskAssessor, got {type(assessor)}")
        
        self._assessors[assessor.name] = assessor
        self._update_execution_order()
        
    def register_assessor_class(self, name: str, assessor_class: Type[BaseRiskAssessor], 
                              **kwargs) -> None:
        """
        Register a risk assessor class for lazy instantiation.
        
        Args:
            name: Unique name for the assessor
            assessor_class: Risk assessor class to register
            **kwargs: Arguments to pass to the assessor constructor
        """
        if not issubclass(assessor_class, BaseRiskAssessor):
            raise ValueError(f"Assessor class must inherit from BaseRiskAssessor, got {assessor_class}")
        
        self._assessor_classes[name] = assessor_class
        # Create instance with kwargs
        instance = assessor_class(**kwargs)
        self.register_assessor(instance)
    
    def unregister_assessor(self, name: str) -> None:
        """
        Unregister a risk assessor.
        
        Args:
            name: Name of the assessor to unregister
        """
        if name in self._assessors:
            del self._assessors[name]
            self._update_execution_order()
    
    def get_assessor(self, name: str) -> Optional[BaseRiskAssessor]:
        """
        Get a registered risk assessor by name.
        
        Args:
            name: Name of the assessor
            
        Returns:
            Risk assessor instance or None if not found
        """
        return self._assessors.get(name)
    
    def list_assessors(self) -> List[Dict[str, Any]]:
        """
        List all registered risk assessors with metadata.
        
        Returns:
            List of assessor metadata dictionaries
        """
        return [assessor.get_metadata() for assessor in self._assessors.values()]
    
    def get_enabled_assessors(self) -> List[BaseRiskAssessor]:
        """
        Get list of enabled risk assessors in execution order.
        
        Returns:
            List of enabled assessors ordered by priority
        """
        return [self._assessors[name] for name in self._execution_order 
                if self._assessors[name].is_enabled()]
    
    def assess_endpoint_risk(self, endpoint_path: str, http_methods: List[str],
                           parameters: Dict[str, Any], headers: List[str],
                           response_info: Optional[Dict[str, Any]] = None) -> List[RiskAssessment]:
        """
        Assess endpoint risk using all enabled assessors.
        
        Args:
            endpoint_path: The API endpoint path
            http_methods: List of supported HTTP methods
            parameters: Dictionary of endpoint parameters
            headers: List of required headers
            response_info: Optional response information for analysis
            
        Returns:
            List of risk assessments from all assessors
        """
        assessments = []
        enabled_assessors = self.get_enabled_assessors()
        
        for assessor in enabled_assessors:
            try:
                # Check if assessor supports this endpoint pattern
                if self._assessor_supports_endpoint(assessor, endpoint_path):
                    assessment = assessor.assess_risk(
                        endpoint_path, http_methods, parameters, headers, response_info
                    )
                    assessments.append(assessment)
            except Exception as e:
                # Log error but continue with other assessors
                print(f"Error in risk assessor {assessor.name}: {e}")
                continue
        
        return assessments
    
    def _assessor_supports_endpoint(self, assessor: BaseRiskAssessor, endpoint_path: str) -> bool:
        """
        Check if an assessor supports analyzing a specific endpoint.
        
        Args:
            assessor: Risk assessor to check
            endpoint_path: Endpoint path to check
            
        Returns:
            True if assessor supports this endpoint pattern
        """
        supported_patterns = assessor.get_supported_patterns()
        endpoint_lower = endpoint_path.lower()
        
        for pattern in supported_patterns:
            if pattern.lower() in endpoint_lower:
                return True
        
        return False
    
    def _update_execution_order(self) -> None:
        """Update the execution order based on assessor priorities."""
        # Sort by priority (higher first), then by registration order
        sorted_assessors = sorted(
            self._assessors.items(),
            key=lambda x: (x[1].priority, list(self._assessors.keys()).index(x[0])),
            reverse=True
        )
        self._execution_order = [name for name, _ in sorted_assessors]
    
    def load_from_config(self, config: Dict[str, Any]) -> None:
        """
        Load risk assessors from configuration.
        
        Args:
            config: Configuration dictionary with assessor settings
        """
        assessors_config = config.get('risk_assessors', {})
        
        for name, assessor_config in assessors_config.items():
            try:
                # Get assessor class
                class_path = assessor_config.get('class')
                if not class_path:
                    continue
                
                # Import the class
                module_path, class_name = class_path.rsplit('.', 1)
                module = importlib.import_module(module_path)
                assessor_class = getattr(module, class_name)
                
                # Create instance with configuration
                kwargs = assessor_config.get('config', {})
                instance = assessor_class(**kwargs)
                
                # Set properties
                if 'enabled' in assessor_config:
                    if assessor_config['enabled']:
                        instance.enable()
                    else:
                        instance.disable()
                
                if 'priority' in assessor_config:
                    instance.set_priority(assessor_config['priority'])
                
                # Register the assessor
                self.register_assessor(instance)
                
            except Exception as e:
                print(f"Failed to load risk assessor {name}: {e}")
                continue
    
    def discover_plugins(self, plugin_dir: str) -> None:
        """
        Discover and load risk assessor plugins from a directory.
        
        Args:
            plugin_dir: Directory path to search for plugins
        """
        plugin_path = Path(plugin_dir)
        if not plugin_path.exists() or not plugin_path.is_dir():
            return
        
        # Look for Python files in the plugin directory
        for py_file in plugin_path.glob("*.py"):
            if py_file.name.startswith("_"):
                continue  # Skip private modules
            
            try:
                # Import the module
                module_name = py_file.stem
                spec = importlib.util.spec_from_file_location(module_name, py_file)
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    
                    # Look for classes that inherit from BaseRiskAssessor
                    for name, obj in inspect.getmembers(module):
                        if (inspect.isclass(obj) and 
                            issubclass(obj, BaseRiskAssessor) and 
                            obj != BaseRiskAssessor):
                            
                            # Auto-register the assessor
                            instance = obj()
                            self.register_assessor(instance)
                            print(f"Auto-discovered risk assessor: {instance.name}")
                            
            except Exception as e:
                print(f"Failed to load plugin {py_file}: {e}")
                continue
    
    def reset(self) -> None:
        """Reset the factory to initial state."""
        self._assessors.clear()
        self._assessor_classes.clear()
        self._execution_order.clear()
    
    def __len__(self) -> int:
        """Return number of registered assessors."""
        return len(self._assessors)
    
    def __contains__(self, name: str) -> bool:
        """Check if assessor is registered."""
        return name in self._assessors 