"""
Base Risk Assessor Interface

This module defines the abstract base class that all risk assessment modules must implement.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from enum import Enum
from dataclasses import dataclass


class RiskCategory(Enum):
    """Risk categories for classification."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class RiskAssessment:
    """Result of a risk assessment."""
    category: RiskCategory
    score: float  # 0.0 to 10.0
    factors: List[str]
    description: str
    recommendations: List[str]
    confidence: float  # 0.0 to 1.0


class BaseRiskAssessor(ABC):
    """
    Abstract base class for all risk assessment modules.
    
    Each risk assessor must implement the assess_risk method and provide
    metadata about its capabilities and supported patterns.
    """
    
    def __init__(self, name: str, description: str, version: str = "1.0.0"):
        self.name = name
        self.description = description
        self.version = version
        self.enabled = True
        self.priority = 1  # Higher priority assessors run first
    
    @abstractmethod
    def assess_risk(self, endpoint_path: str, http_methods: List[str], 
                   parameters: Dict[str, Any], headers: List[str], 
                   response_info: Optional[Dict[str, Any]] = None) -> RiskAssessment:
        """
        Assess the risk level of an endpoint.
        
        Args:
            endpoint_path: The API endpoint path
            http_methods: List of supported HTTP methods
            parameters: Dictionary of endpoint parameters
            headers: List of required headers
            response_info: Optional response information for analysis
            
        Returns:
            RiskAssessment object with risk details
        """
        pass
    
    @abstractmethod
    def get_supported_patterns(self) -> List[str]:
        """Return list of patterns this assessor can analyze."""
        pass
    
    @abstractmethod
    def get_risk_categories(self) -> List[RiskCategory]:
        """Return list of risk categories this assessor can identify."""
        pass
    
    def is_enabled(self) -> bool:
        """Check if this assessor is enabled."""
        return self.enabled
    
    def enable(self):
        """Enable this risk assessor."""
        self.enabled = True
    
    def disable(self):
        """Disable this risk assessor."""
        self.enabled = False
    
    def set_priority(self, priority: int):
        """Set the priority of this assessor (higher = runs first)."""
        self.priority = priority
    
    def get_metadata(self) -> Dict[str, Any]:
        """Get metadata about this risk assessor."""
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "enabled": self.enabled,
            "priority": self.priority,
            "supported_patterns": self.get_supported_patterns(),
            "risk_categories": [cat.value for cat in self.get_risk_categories()]
        }
    
    def __str__(self) -> str:
        return f"{self.name} v{self.version} ({self.description})"
    
    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}: {self.name}>" 