"""
Risk Assessment Modules

This module contains concrete implementations of risk assessment strategies
for different types of API security concerns.
"""

from typing import Dict, List, Any, Optional
from .base import BaseRiskAssessor, RiskAssessment, RiskCategory


class UserManagementRiskAssessor(BaseRiskAssessor):
    """Assesses risks related to user management endpoints."""
    
    def __init__(self):
        super().__init__(
            name="User Management Risk Assessor",
            description="Identifies security risks in user management operations",
            version="1.0.0"
        )
        self.set_priority(10)  # High priority for user management
    
    def assess_risk(self, endpoint_path: str, http_methods: List[str],
                   parameters: Dict[str, Any], headers: List[str],
                   response_info: Optional[Dict[str, Any]] = None) -> RiskAssessment:
        """Assess user management endpoint risks."""
        path_lower = endpoint_path.lower()
        risk_factors = []
        score = 0.0
        
        # High-risk patterns
        if "/users" in path_lower and "DELETE" in http_methods:
            risk_factors.append("User deletion endpoint")
            score += 3.0
        
        if "/users" in path_lower and "POST" in http_methods:
            risk_factors.append("User creation endpoint")
            score += 2.0
        
        if "/password" in path_lower:
            risk_factors.append("Password modification endpoint")
            score += 3.0
        
        if "/email" in path_lower:
            risk_factors.append("Email modification endpoint")
            score += 2.0
        
        # Authentication requirements
        if "Authorization" not in headers and "/users" in path_lower:
            risk_factors.append("No authentication required for user operations")
            score += 4.0
        
        # Parameter validation
        if parameters.get("path_params") and not parameters.get("validation_rules"):
            risk_factors.append("No parameter validation rules")
            score += 1.0
        
        # Determine risk category
        if score >= 7.0:
            category = RiskCategory.CRITICAL
        elif score >= 5.0:
            category = RiskCategory.HIGH
        elif score >= 3.0:
            category = RiskCategory.MEDIUM
        else:
            category = RiskCategory.LOW
        
        recommendations = [
            "Implement strong authentication for all user management endpoints",
            "Add input validation and sanitization",
            "Use HTTPS for all user operations",
            "Implement rate limiting",
            "Add audit logging for user modifications"
        ]
        
        return RiskAssessment(
            category=category,
            score=min(score, 10.0),
            factors=risk_factors,
            description=f"User management endpoint with {len(risk_factors)} risk factors",
            recommendations=recommendations,
            confidence=0.9
        )
    
    def get_supported_patterns(self) -> List[str]:
        return ["/users", "/user", "/password", "/email", "/profile", "/account"]
    
    def get_risk_categories(self) -> List[RiskCategory]:
        return [RiskCategory.CRITICAL, RiskCategory.HIGH, RiskCategory.MEDIUM, RiskCategory.LOW]


class DataExposureRiskAssessor(BaseRiskAssessor):
    """Assesses risks related to data exposure endpoints."""
    
    def __init__(self):
        super().__init__(
            name="Data Exposure Risk Assessor",
            description="Identifies risks of sensitive data exposure",
            version="1.0.0"
        )
        self.set_priority(9)
    
    def assess_risk(self, endpoint_path: str, http_methods: List[str],
                   parameters: Dict[str, Any], headers: List[str],
                   response_info: Optional[Dict[str, Any]] = None) -> RiskAssessment:
        """Assess data exposure risks."""
        path_lower = endpoint_path.lower()
        risk_factors = []
        score = 0.0
        
        # Sensitive data patterns
        if "/admin" in path_lower:
            risk_factors.append("Administrative endpoint")
            score += 3.0
        
        if "/books" in path_lower and "GET" in http_methods:
            risk_factors.append("Data retrieval endpoint")
            score += 1.0
        
        if "/users" in path_lower and "GET" in http_methods:
            risk_factors.append("User data retrieval")
            score += 2.0
        
        # Pagination and filtering
        if "limit" in str(parameters) and "offset" not in str(parameters):
            risk_factors.append("Incomplete pagination controls")
            score += 1.0
        
        # Response size controls
        if response_info and response_info.get("size", 0) > 1000:
            risk_factors.append("Large response size without limits")
            score += 1.0
        
        # Determine risk category
        if score >= 6.0:
            category = RiskCategory.HIGH
        elif score >= 3.0:
            category = RiskCategory.MEDIUM
        else:
            category = RiskCategory.LOW
        
        recommendations = [
            "Implement proper pagination controls",
            "Add response size limits",
            "Filter sensitive data in responses",
            "Implement rate limiting",
            "Add access logging"
        ]
        
        return RiskAssessment(
            category=category,
            score=min(score, 10.0),
            factors=risk_factors,
            description=f"Data exposure endpoint with {len(risk_factors)} risk factors",
            recommendations=recommendations,
            confidence=0.8
        )
    
    def get_supported_patterns(self) -> List[str]:
        return ["/books", "/users", "/admin", "/data", "/export", "/query"]
    
    def get_risk_categories(self) -> List[RiskCategory]:
        return [RiskCategory.HIGH, RiskCategory.MEDIUM, RiskCategory.LOW]


class AuthenticationRiskAssessor(BaseRiskAssessor):
    """Assesses risks related to authentication endpoints."""
    
    def __init__(self):
        super().__init__(
            name="Authentication Risk Assessor",
            description="Identifies authentication and authorization risks",
            version="1.0.0"
        )
        self.set_priority(8)
    
    def assess_risk(self, endpoint_path: str, http_methods: List[str],
                   parameters: Dict[str, Any], headers: List[str],
                   response_info: Optional[Dict[str, Any]] = None) -> RiskAssessment:
        """Assess authentication risks."""
        path_lower = endpoint_path.lower()
        risk_factors = []
        score = 0.0
        
        # Authentication endpoints
        if "/login" in path_lower or "/auth" in path_lower:
            risk_factors.append("Authentication endpoint")
            score += 2.0
        
        if "/register" in path_lower:
            risk_factors.append("User registration endpoint")
            score += 2.0
        
        # Security headers
        if "Authorization" not in headers and ("/login" in path_lower or "/auth" in path_lower):
            risk_factors.append("No authorization header required")
            score += 3.0
        
        # HTTPS enforcement
        if response_info and not response_info.get("https", False):
            risk_factors.append("HTTPS not enforced")
            score += 2.0
        
        # Brute force protection
        if "/login" in path_lower and "POST" in http_methods:
            risk_factors.append("Login endpoint without rate limiting")
            score += 2.0
        
        # Determine risk category
        if score >= 7.0:
            category = RiskCategory.CRITICAL
        elif score >= 5.0:
            category = RiskCategory.HIGH
        elif score >= 3.0:
            category = RiskCategory.MEDIUM
        else:
            category = RiskCategory.LOW
        
        recommendations = [
            "Enforce HTTPS for all authentication endpoints",
            "Implement rate limiting and brute force protection",
            "Use secure session management",
            "Add security headers (HSTS, CSP)",
            "Implement multi-factor authentication"
        ]
        
        return RiskAssessment(
            category=category,
            score=min(score, 10.0),
            factors=risk_factors,
            description=f"Authentication endpoint with {len(risk_factors)} risk factors",
            recommendations=recommendations,
            confidence=0.9
        )
    
    def get_supported_patterns(self) -> List[str]:
        return ["/login", "/auth", "/register", "/signup", "/password", "/reset"]
    
    def get_risk_categories(self) -> List[RiskCategory]:
        return [RiskCategory.CRITICAL, RiskCategory.HIGH, RiskCategory.MEDIUM, RiskCategory.LOW]


class AdminAccessRiskAssessor(BaseRiskAssessor):
    """Assesses risks related to administrative access."""
    
    def __init__(self):
        super().__init__(
            name="Admin Access Risk Assessor",
            description="Identifies administrative access risks",
            version="1.0.0"
        )
        self.set_priority(7)
    
    def assess_risk(self, endpoint_path: str, http_methods: List[str],
                   parameters: Dict[str, Any], headers: List[str],
                   response_info: Optional[Dict[str, Any]] = None) -> RiskAssessment:
        """Assess admin access risks."""
        path_lower = endpoint_path.lower()
        risk_factors = []
        score = 0.0
        
        # Admin patterns
        if "/admin" in path_lower:
            risk_factors.append("Administrative endpoint")
            score += 4.0
        
        if "/system" in path_lower:
            risk_factors.append("System management endpoint")
            score += 3.0
        
        if "/config" in path_lower or "/settings" in path_lower:
            risk_factors.append("Configuration endpoint")
            score += 3.0
        
        # Authentication requirements
        if "Authorization" not in headers and "/admin" in path_lower:
            risk_factors.append("No authentication for admin endpoint")
            score += 5.0
        
        # HTTP methods
        if "DELETE" in http_methods and "/admin" in path_lower:
            risk_factors.append("Admin deletion capability")
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
            "Require strong authentication for all admin endpoints",
            "Implement role-based access control",
            "Add audit logging for all admin operations",
            "Use HTTPS for admin access",
            "Implement IP whitelisting for admin endpoints"
        ]
        
        return RiskAssessment(
            category=category,
            score=min(score, 10.0),
            factors=risk_factors,
            description=f"Admin access endpoint with {len(risk_factors)} risk factors",
            recommendations=recommendations,
            confidence=0.95
        )
    
    def get_supported_patterns(self) -> List[str]:
        return ["/admin", "/system", "/config", "/settings", "/management", "/control"]
    
    def get_risk_categories(self) -> List[RiskCategory]:
        return [RiskCategory.CRITICAL, RiskCategory.HIGH, RiskCategory.MEDIUM, RiskCategory.LOW]


class FileOperationsRiskAssessor(BaseRiskAssessor):
    """Assesses risks related to file operations."""
    
    def __init__(self):
        super().__init__(
            name="File Operations Risk Assessor",
            description="Identifies file operation security risks",
            version="1.0.0"
        )
        self.set_priority(6)
    
    def assess_risk(self, endpoint_path: str, http_methods: List[str],
                   parameters: Dict[str, Any], headers: List[str],
                   response_info: Optional[Dict[str, Any]] = None) -> RiskAssessment:
        """Assess file operation risks."""
        path_lower = endpoint_path.lower()
        risk_factors = []
        score = 0.0
        
        # File operation patterns
        if "/upload" in path_lower:
            risk_factors.append("File upload endpoint")
            score += 3.0
        
        if "/download" in path_lower:
            risk_factors.append("File download endpoint")
            score += 2.0
        
        if "/files" in path_lower:
            risk_factors.append("File management endpoint")
            score += 2.0
        
        # File type validation
        if parameters.get("file_types") and len(parameters["file_types"]) > 10:
            risk_factors.append("Too many allowed file types")
            score += 1.0
        
        # File size limits
        if parameters.get("max_size") and parameters["max_size"] > 10000000:  # 10MB
            risk_factors.append("Large file size limit")
            score += 1.0
        
        # Determine risk category
        if score >= 6.0:
            category = RiskCategory.HIGH
        elif score >= 4.0:
            category = RiskCategory.MEDIUM
        else:
            category = RiskCategory.LOW
        
        recommendations = [
            "Implement file type validation",
            "Set reasonable file size limits",
            "Scan uploaded files for malware",
            "Store files outside web root",
            "Implement access controls"
        ]
        
        return RiskAssessment(
            category=category,
            score=min(score, 10.0),
            factors=risk_factors,
            description=f"File operation endpoint with {len(risk_factors)} risk factors",
            recommendations=recommendations,
            confidence=0.8
        )
    
    def get_supported_patterns(self) -> List[str]:
        return ["/upload", "/download", "/files", "/file", "/media", "/static"]
    
    def get_risk_categories(self) -> List[RiskCategory]:
        return [RiskCategory.HIGH, RiskCategory.MEDIUM, RiskCategory.LOW]


class DatabaseOperationsRiskAssessor(BaseRiskAssessor):
    """Assesses risks related to database operations."""
    
    def __init__(self):
        super().__init__(
            name="Database Operations Risk Assessor",
            description="Identifies database operation security risks",
            version="1.0.0"
        )
        self.set_priority(5)
    
    def assess_risk(self, endpoint_path: str, http_methods: List[str],
                   parameters: Dict[str, Any], headers: List[str],
                   response_info: Optional[Dict[str, Any]] = None) -> RiskAssessment:
        """Assess database operation risks."""
        path_lower = endpoint_path.lower()
        risk_factors = []
        score = 0.0
        
        # Database operation patterns
        if "/query" in path_lower:
            risk_factors.append("Direct query endpoint")
            score += 4.0
        
        if "/sql" in path_lower:
            risk_factors.append("SQL operation endpoint")
            score += 4.0
        
        if "/db" in path_lower:
            risk_factors.append("Database management endpoint")
            score += 3.0
        
        # Parameter injection risks
        if parameters.get("query") or parameters.get("sql"):
            risk_factors.append("Raw query parameters")
            score += 3.0
        
        # Authentication requirements
        if "Authorization" not in headers and ("/query" in path_lower or "/sql" in path_lower):
            risk_factors.append("No authentication for database operations")
            score += 4.0
        
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
            "Use parameterized queries",
            "Implement strong authentication",
            "Add input validation",
            "Use database connection pooling",
            "Implement query logging"
        ]
        
        return RiskAssessment(
            category=category,
            score=min(score, 10.0),
            factors=risk_factors,
            description=f"Database operation endpoint with {len(risk_factors)} risk factors",
            recommendations=recommendations,
            confidence=0.9
        )
    
    def get_supported_patterns(self) -> List[str]:
        return ["/query", "/sql", "/db", "/database", "/execute", "/run"]
    
    def get_risk_categories(self) -> List[RiskCategory]:
        return [RiskCategory.CRITICAL, RiskCategory.HIGH, RiskCategory.MEDIUM, RiskCategory.LOW] 