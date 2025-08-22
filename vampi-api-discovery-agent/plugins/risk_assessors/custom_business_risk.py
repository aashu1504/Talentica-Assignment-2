"""
Custom Business Risk Assessor Plugin

This is an example custom risk assessor that demonstrates how to create
custom risk assessment plugins that can be loaded at runtime.
"""

from typing import Dict, List, Any, Optional
import sys
import os

# Add the src directory to the path to import the base classes
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from risk_assessment.base import BaseRiskAssessor, RiskAssessment, RiskCategory


class CustomBusinessRiskAssessor(BaseRiskAssessor):
    """
    Custom risk assessor for business-specific endpoints.
    
    This plugin demonstrates how to create custom risk assessment logic
    that can be loaded and used by the main discovery engine.
    """
    
    def __init__(self):
        super().__init__(
            name="Custom Business Risk Assessor",
            description="Custom risk assessment for business-specific endpoints and logic",
            version="1.0.0"
        )
        self.set_priority(3)  # Lower priority than built-in assessors
        
        # Custom configuration
        self.business_patterns = [
            "/business/",
            "/custom/",
            "/enterprise/",
            "/corporate/",
            "/internal/"
        ]
        
        self.sensitive_business_terms = [
            "revenue",
            "profit",
            "customer",
            "financial",
            "confidential",
            "proprietary"
        ]
    
    def assess_risk(self, endpoint_path: str, http_methods: List[str],
                   parameters: Dict[str, Any], headers: List[str],
                   response_info: Optional[Dict[str, Any]] = None) -> RiskAssessment:
        """Assess business-specific risks."""
        path_lower = endpoint_path.lower()
        risk_factors = []
        score = 0.0
        
        # Check for business patterns
        if any(pattern in path_lower for pattern in self.business_patterns):
            risk_factors.append("Business-specific endpoint")
            score += 2.0
        
        # Check for sensitive business terms in path
        for term in self.sensitive_business_terms:
            if term in path_lower:
                risk_factors.append(f"Sensitive business term: {term}")
                score += 1.5
        
        # Check for business operations
        if "POST" in http_methods and any(pattern in path_lower for pattern in self.business_patterns):
            risk_factors.append("Business data modification endpoint")
            score += 2.5
        
        if "DELETE" in http_methods and any(pattern in path_lower for pattern in self.business_patterns):
            risk_factors.append("Business data deletion endpoint")
            score += 3.0
        
        # Check for authentication requirements
        if "Authorization" not in headers and any(pattern in path_lower for pattern in self.business_patterns):
            risk_factors.append("No authentication for business endpoint")
            score += 3.0
        
        # Check for parameter validation
        if parameters.get("path_params") and not parameters.get("validation_rules"):
            risk_factors.append("No parameter validation for business endpoint")
            score += 1.0
        
        # Determine risk category
        if score >= 7.0:
            category = RiskCategory.HIGH
        elif score >= 5.0:
            category = RiskCategory.MEDIUM
        elif score >= 3.0:
            category = RiskCategory.LOW
        else:
            category = RiskCategory.INFO
        
        recommendations = [
            "Implement strong authentication for business endpoints",
            "Add input validation and sanitization",
            "Use HTTPS for all business operations",
            "Implement audit logging for business modifications",
            "Add business logic validation",
            "Consider implementing role-based access control"
        ]
        
        return RiskAssessment(
            category=category,
            score=min(score, 10.0),
            factors=risk_factors,
            description=f"Business endpoint with {len(risk_factors)} risk factors",
            recommendations=recommendations,
            confidence=0.85
        )
    
    def get_supported_patterns(self) -> List[str]:
        """Return patterns this assessor can analyze."""
        return self.business_patterns + self.sensitive_business_terms
    
    def get_risk_categories(self) -> List[RiskCategory]:
        """Return risk categories this assessor can identify."""
        return [RiskCategory.HIGH, RiskCategory.MEDIUM, RiskCategory.LOW, RiskCategory.INFO]


class FinancialDataRiskAssessor(BaseRiskAssessor):
    """
    Custom risk assessor for financial data endpoints.
    
    This plugin demonstrates another type of custom risk assessment
    focused on financial data security.
    """
    
    def __init__(self):
        super().__init__(
            name="Financial Data Risk Assessor",
            description="Risk assessment for financial data and payment endpoints",
            version="1.0.0"
        )
        self.set_priority(4)
        
        self.financial_patterns = [
            "/payment/",
            "/financial/",
            "/billing/",
            "/invoice/",
            "/transaction/",
            "/accounting/"
        ]
    
    def assess_risk(self, endpoint_path: str, http_methods: List[str],
                   parameters: Dict[str, Any], headers: List[str],
                   response_info: Optional[Dict[str, Any]] = None) -> RiskAssessment:
        """Assess financial data risks."""
        path_lower = endpoint_path.lower()
        risk_factors = []
        score = 0.0
        
        # Check for financial patterns
        if any(pattern in path_lower for pattern in self.financial_patterns):
            risk_factors.append("Financial data endpoint")
            score += 3.0
        
        # Check for payment operations
        if "POST" in http_methods and "payment" in path_lower:
            risk_factors.append("Payment processing endpoint")
            score += 4.0
        
        # Check for authentication
        if "Authorization" not in headers and any(pattern in path_lower for pattern in self.financial_patterns):
            risk_factors.append("No authentication for financial endpoint")
            score += 4.0
        
        # Check for HTTPS
        if response_info and not response_info.get("https", False):
            risk_factors.append("HTTPS not enforced for financial data")
            score += 3.0
        
        # Determine risk category
        if score >= 8.0:
            category = RiskCategory.CRITICAL
        elif score >= 6.0:
            category = RiskCategory.HIGH
        elif score >= 4.0:
            category = RiskCategory.MEDIUM
        else:
            category = RiskCategory.LOW
        
        recommendations = [
            "Enforce HTTPS for all financial endpoints",
            "Implement strong authentication and authorization",
            "Add PCI DSS compliance measures",
            "Implement encryption for sensitive data",
            "Add comprehensive audit logging",
            "Use secure payment gateways"
        ]
        
        return RiskAssessment(
            category=category,
            score=min(score, 10.0),
            factors=risk_factors,
            description=f"Financial endpoint with {len(risk_factors)} risk factors",
            recommendations=recommendations,
            confidence=0.9
        )
    
    def get_supported_patterns(self) -> List[str]:
        """Return patterns this assessor can analyze."""
        return self.financial_patterns
    
    def get_risk_categories(self) -> List[RiskCategory]:
        """Return risk categories this assessor can identify."""
        return [RiskCategory.CRITICAL, RiskCategory.HIGH, RiskCategory.MEDIUM, RiskCategory.LOW] 