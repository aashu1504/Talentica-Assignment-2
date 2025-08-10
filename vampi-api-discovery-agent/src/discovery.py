"""
VAmPI API Discovery Engine.

This module implements the core discovery logic for finding and analyzing
VAmPI API endpoints with comprehensive metadata extraction.
"""

import asyncio
import logging
import time
from datetime import datetime
from typing import List, Dict, Optional, Set, Tuple, Any
from urllib.parse import urljoin, urlparse
import re

import httpx

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Import models and utils
from models import (
    APIDiscoveryResult, DiscoverySummary, EndpointMetadata, EndpointParameters,
    AuthenticationMechanism, APIStructure, RiskLevel, AuthenticationType,
    DiscoveryMethod, DiscoveryConfig
)
from utils import (
    normalize_url, extract_path_parameters, rate_limit_delay, 
    calculate_success_rate, is_valid_url
)


class VAmPIDiscoveryEngine:
    """
    Engine for discovering and analyzing VAmPI API endpoints.
    
    This class implements various discovery techniques including:
    - Active endpoint scanning
    - Response analysis
    - Authentication detection
    - Risk assessment
    """
    
    def __init__(self, config: DiscoveryConfig):
        """
        Initialize the discovery engine.
        
        Args:
            config: Discovery configuration
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.session = None
        self.discovered_endpoints: Set[str] = set()
        self.auth_mechanisms: List[AuthenticationMechanism] = []
        
        # VAmPI-specific API paths to scan
        self.common_paths = [
            "/users/v1",
            "/users/v1/register", 
            "/users/v1/login",
            "/books/v1",
            "/",
            "/createdb"
        ]
        
        # HTTP methods to test (focused on VAmPI supported methods)
        self.http_methods = ["GET", "POST", "PUT", "DELETE"]
        
        # Risk assessment patterns
        self.risk_patterns = {
            "user_management": ["/users", "/auth", "/register", "/login"],
            "data_exposure": ["/users", "/books", "/admin"],
            "authentication_bypass": ["/auth", "/login", "/register"],
            "admin_access": ["/admin"],
            "file_operations": ["/upload", "/download", "/files"],
            "database_operations": ["/query", "/sql", "/db"]
        }
    
    async def __aenter__(self):
        """Async context manager entry."""
        self.session = httpx.AsyncClient(
            timeout=self.config.timeout,
            headers={"User-Agent": self.config.user_agent},
            follow_redirects=True
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.aclose()
    
    def _assess_risk_level(self, path: str, method: str, auth_required: bool) -> Tuple[RiskLevel, List[str]]:
        """
        Assess the security risk level of an endpoint.
        
        Args:
            path: Endpoint path
            method: HTTP method
            auth_required: Whether authentication is required
            
        Returns:
            Tuple of (risk_level, risk_factors)
        """
        risk_factors = []
        base_risk = RiskLevel.LOW
        
        # Check for high-risk patterns
        path_lower = path.lower()
        
        # User management endpoints
        if any(pattern in path_lower for pattern in self.risk_patterns["user_management"]):
            risk_factors.append("user_management")
            base_risk = RiskLevel.MEDIUM
        
        # Data exposure endpoints
        if any(pattern in path_lower for pattern in self.risk_patterns["data_exposure"]):
            risk_factors.append("data_exposure")
            base_risk = RiskLevel.HIGH
        
        # Admin access endpoints
        if any(pattern in path_lower for pattern in self.risk_patterns["admin_access"]):
            risk_factors.append("admin_access")
            base_risk = RiskLevel.HIGH
        
        # Authentication bypass potential
        if any(pattern in path_lower for pattern in self.risk_patterns["authentication_bypass"]):
            risk_factors.append("authentication_bypass")
            base_risk = RiskLevel.HIGH
        
        # Method-based risk assessment
        if method in ["DELETE", "PUT", "PATCH"]:
            risk_factors.append("modification_operations")
            if base_risk == RiskLevel.LOW:
                base_risk = RiskLevel.MEDIUM
        
        # Authentication requirement impact
        if not auth_required and base_risk in [RiskLevel.MEDIUM, RiskLevel.HIGH]:
            risk_factors.append("no_authentication")
            if base_risk == RiskLevel.MEDIUM:
                base_risk = RiskLevel.HIGH
            elif base_risk == RiskLevel.HIGH:
                base_risk = RiskLevel.CRITICAL
        
        return base_risk, risk_factors
    
    def _detect_authentication_type(self, response: httpx.Response, path: str) -> Tuple[AuthenticationType, bool]:
        """
        Detect authentication type from response.
        
        Args:
            response: HTTP response
            path: Endpoint path
            
        Returns:
            Tuple of (auth_type, auth_required)
        """
        auth_required = False
        auth_type = AuthenticationType.NONE
        
        # Check response status codes
        if response.status_code in [401, 403]:
            auth_required = True
        
        # Check for JWT patterns in response
        if "jwt" in response.text.lower() or "bearer" in response.text.lower():
            auth_type = AuthenticationType.JWT
            auth_required = True
        
        # Check for session patterns
        if "session" in response.text.lower() or "cookie" in response.text.lower():
            auth_type = AuthenticationType.SESSION
            auth_required = True
        
        # Check for API key patterns
        if "api_key" in response.text.lower() or "x-api-key" in response.text.lower():
            auth_type = AuthenticationType.API_KEY
            auth_required = True
        
        # Check for basic auth patterns
        if "basic" in response.text.lower() or "www-authenticate" in response.headers:
            auth_type = AuthenticationType.BASIC
            auth_required = True
        
        # Path-based authentication detection
        if path in ["/users/v1/login", "/auth/login", "/login"]:
            auth_type = AuthenticationType.JWT
            auth_required = False  # Login endpoints don't require auth
        
        return auth_type, auth_required
    
    def _extract_parameters(self, path: str, response: httpx.Response) -> EndpointParameters:
        """
        Extract parameters from endpoint path and response.
        
        Args:
            path: Endpoint path
            response: HTTP response
            
        Returns:
            EndpointParameters instance
        """
        # Extract path parameters
        path_params = extract_path_parameters(path)
        
        # Extract query parameters from URL
        query_params = []
        if "?" in str(response.url):
            query_string = str(response.url).split("?")[1]
            query_params = [param.split("=")[0] for param in query_string.split("&")]
        
        # Extract headers from response
        headers = []
        if "content-type" in response.headers:
            headers.append("Content-Type")
        if "authorization" in response.headers:
            headers.append("Authorization")
        if "x-api-key" in response.headers:
            headers.append("X-API-Key")
        
        # Try to extract body parameters from response
        body_params = []
        try:
            if response.headers.get("content-type", "").startswith("application/json"):
                data = response.json()
                if isinstance(data, dict):
                    body_params = list(data.keys())
        except Exception:
            pass
        
        return EndpointParameters(
            query_params=query_params,
            path_params=path_params,
            body_params=body_params,
            headers=headers
        )
    
    async def _test_endpoint(self, url: str, method: str) -> Optional[EndpointMetadata]:
        """
        Test a specific endpoint with a given HTTP method.
        
        Args:
            url: Full URL to test
            method: HTTP method to test
            
        Returns:
            EndpointMetadata if successful, None otherwise
        """
        try:
            start_time = time.time()
            
            # Make the request
            response = await self.session.request(method, url)
            response_time = time.time() - start_time
            
            # Extract path from URL
            path = urlparse(str(url)).path
            
            # Detect authentication
            auth_type, auth_required = self._detect_authentication_type(response, path)
            
            # Assess risk
            risk_level, risk_factors = self._assess_risk_level(path, method, auth_required)
            
            # Extract parameters
            parameters = self._extract_parameters(path, response)
            
            # Determine response types
            response_types = []
            content_type = response.headers.get("content-type", "")
            if "application/json" in content_type:
                response_types.append("application/json")
            if "text/html" in content_type:
                response_types.append("text/html")
            if "text/plain" in content_type:
                response_types.append("text/plain")
            
            # Generate endpoint ID
            endpoint_id = f"EP{len(self.discovered_endpoints):03d}"
            
            # Create endpoint metadata
            endpoint = EndpointMetadata(
                id=endpoint_id,
                path=path,
                methods=[method],
                description=self._generate_description(path, method, response),
                parameters=parameters,
                authentication_required=auth_required,
                authentication_type=auth_type,
                risk_level=risk_level,
                risk_factors=risk_factors,
                response_types=response_types,
                discovered_via=DiscoveryMethod.ENDPOINT_SCANNING,
                status_code=response.status_code,
                response_time=response_time
            )
            
            self.discovered_endpoints.add(path)
            return endpoint
            
        except Exception as e:
            self.logger.warning(f"Failed to test {method} {url}: {e}")
            # Log more details for debugging
            if hasattr(e, '__class__'):
                self.logger.debug(f"Error type: {e.__class__.__name__}")
            return None
    
    def _generate_description(self, path: str, method: str, response: httpx.Response) -> str:
        """
        Generate a description for an endpoint based on path and response.
        
        Args:
            path: Endpoint path
            method: HTTP method
            response: HTTP response
            
        Returns:
            Generated description
        """
        path_lower = path.lower()
        
        # VAmPI User management endpoints
        if "/users/v1" in path_lower:
            if "login" in path_lower:
                return "VAmPI user authentication endpoint"
            elif "register" in path_lower:
                return "VAmPI user registration endpoint"
            elif path_lower.endswith("/users/v1") or path_lower.endswith("/users/v1/"):
                return "VAmPI user management endpoint - list all users"
            elif "{username}" in path_lower:
                if "email" in path_lower:
                    return "VAmPI update user email endpoint"
                elif "password" in path_lower:
                    return "VAmPI update user password endpoint"
                else:
                    return "VAmPI individual user operation endpoint"
            else:
                return "VAmPI user operation endpoint"
        
        # VAmPI Book management endpoints
        elif "/books/v1" in path_lower:
            if path_lower.endswith("/books/v1") or path_lower.endswith("/books/v1/"):
                return "VAmPI book management endpoint - list all books or add new book"
            elif "{book_title}" in path_lower:
                return "VAmPI get book by title endpoint"
            else:
                return "VAmPI book operation endpoint"
        
        # VAmPI root and database endpoints
        elif path_lower == "/":
            return "VAmPI home endpoint - API information and help"
        elif path_lower == "/createdb":
            return "VAmPI database initialization endpoint"
        
        # VAmPI other endpoints
        elif "/auth" in path_lower:
            if "login" in path_lower:
                return "VAmPI authentication endpoint"
            elif "register" in path_lower:
                return "VAmPI user registration endpoint"
            else:
                return "VAmPI authentication endpoint"
        
        # Admin endpoints
        elif "/admin" in path_lower:
            return "VAmPI administrative endpoint"
        
        # Health and status endpoints
        elif path in ["/health", "/status", "/info"]:
            return "VAmPI health and status endpoint"
        
        # Documentation endpoints
        elif path in ["/docs", "/swagger", "/openapi"]:
            return "VAmPI documentation endpoint"
        
        # Generic description based on method
        else:
            method_descriptions = {
                "GET": "VAmPI retrieve data endpoint",
                "POST": "VAmPI create data endpoint",
                "PUT": "VAmPI update data endpoint",
                "DELETE": "VAmPI delete data endpoint",
                "PATCH": "VAmPI partial update endpoint",
                "HEAD": "VAmPI header information endpoint",
                "OPTIONS": "VAmPI options endpoint"
            }
            return method_descriptions.get(method, "VAmPI API endpoint")
    
    async def discover_endpoints(self) -> APIDiscoveryResult:
        """
        Discover all VAmPI endpoints using various techniques.
        
        Returns:
            APIDiscoveryResult with discovered endpoints
        """
        self.logger.info("Starting VAmPI endpoint discovery...")
        self.logger.info(f"Target VAmPI endpoints to discover:")
        self.logger.info("User Management: GET /users/v1, POST /users/v1/register, POST /users/v1/login, GET /users/v1/{username}, DELETE /users/v1/{username}, PUT /users/v1/{username}/email, PUT /users/v1/{username}/password")
        self.logger.info("Book Management: GET /books/v1, POST /books/v1, GET /books/v1/{book_title}")
        self.logger.info("Other: GET /, GET /createdb")
        start_time = time.time()
        
        # Reset state
        self.discovered_endpoints.clear()
        self.auth_mechanisms.clear()
        
        # Discover endpoints using VAmPI-specific endpoint testing
        endpoints = await self._test_vampi_specific_endpoints()
        
        # Also try common paths as fallback
        common_endpoints = await self._scan_common_paths()
        endpoints.extend(common_endpoints)
        
        # Discover endpoints using pattern-based scanning as additional fallback
        pattern_endpoints = await self._pattern_based_discovery()
        endpoints.extend(pattern_endpoints)
        
        # Remove duplicates and merge methods
        unique_endpoints = self._merge_endpoint_methods(endpoints)
        
        # Analyze API structure
        api_structure = self._analyze_api_structure(unique_endpoints)
        
        # Detect authentication mechanisms
        auth_mechanisms = self._detect_auth_mechanisms(unique_endpoints)
        
        # Calculate scan duration
        scan_duration = time.time() - start_time
        
        # Calculate authentication counts
        authenticated_count = len([ep for ep in unique_endpoints if ep.authentication_required])
        public_count = len([ep for ep in unique_endpoints if not ep.authentication_required])
        
        # Calculate risk distribution
        high_risk_count = len([ep for ep in unique_endpoints if ep.risk_level == RiskLevel.HIGH])
        medium_risk_count = len([ep for ep in unique_endpoints if ep.risk_level == RiskLevel.MEDIUM])
        low_risk_count = len([ep for ep in unique_endpoints if ep.risk_level == RiskLevel.LOW])
        
        # Calculate coverage (simple percentage of discovered vs expected endpoints)
        expected_endpoints = 10  # VAmPI has about 10 main endpoints
        discovery_coverage = min(100.0, (len(unique_endpoints) / expected_endpoints) * 100)
        
        # Create discovery summary
        summary = DiscoverySummary(
            total_endpoints=len(unique_endpoints),
            authenticated_endpoints=authenticated_count,
            public_endpoints=public_count,
            high_risk_endpoints=high_risk_count,
            medium_risk_endpoints=medium_risk_count,
            low_risk_endpoints=low_risk_count,
            discovery_coverage=discovery_coverage,
            discovery_start_time=datetime.now(),
            discovery_duration=scan_duration
        )
        
        # Create result
        result = APIDiscoveryResult(
            discovery_summary=summary,
            endpoints=unique_endpoints,
            authentication_mechanisms=auth_mechanisms,
            api_structure=api_structure
        )
        
        self.logger.info(f"Discovery completed. Found {len(unique_endpoints)} endpoints in {scan_duration:.2f}s")
        
        # Log discovered endpoints summary
        if unique_endpoints:
            self.logger.info("Discovered endpoints:")
            for endpoint in unique_endpoints:
                self.logger.info(f"  {', '.join(endpoint.methods)} {endpoint.path} - {endpoint.description}")
        else:
            self.logger.warning("No endpoints discovered!")
        
        return result
    
    async def _scan_common_paths(self) -> List[EndpointMetadata]:
        """
        Scan common API paths for endpoints.
        
        Returns:
            List of discovered endpoints
        """
        endpoints = []
        
        for path in self.common_paths:
            full_url = normalize_url(self.config.base_url, path)
            
            for method in self.http_methods:
                if self.config.respect_rate_limits:
                    rate_limit_delay()
                
                endpoint = await self._test_endpoint(full_url, method)
                if endpoint:
                    endpoints.append(endpoint)
                    self.logger.debug(f"Discovered {method} {path}")
        
        return endpoints
    
    async def _test_vampi_specific_endpoints(self) -> List[EndpointMetadata]:
        """
        Test the specific VAmPI endpoints that should be discovered.
        
        Returns:
            List of discovered VAmPI endpoints
        """
        endpoints = []
        
        # Define the exact VAmPI endpoints to test
        vampi_endpoints = [
            # User Management APIs
            {"path": "/users/v1", "methods": ["GET"], "description": "List all users"},
            {"path": "/users/v1/register", "methods": ["POST"], "description": "User registration"},
            {"path": "/users/v1/login", "methods": ["POST"], "description": "User authentication"},
            {"path": "/users/v1/{username}", "methods": ["GET", "DELETE"], "description": "Get/Delete specific user"},
            {"path": "/users/v1/{username}/email", "methods": ["PUT"], "description": "Update user email"},
            {"path": "/users/v1/{username}/password", "methods": ["PUT"], "description": "Update user password"},
            
            # Book Management APIs
            {"path": "/books/v1", "methods": ["GET", "POST"], "description": "List all books or add new book"},
            {"path": "/books/v1/{book_title}", "methods": ["GET"], "description": "Get book by title"},
            
            # Other VAmPI endpoints
            {"path": "/", "methods": ["GET"], "description": "VAmPI home and help"},
            {"path": "/createdb", "methods": ["GET"], "description": "Database initialization"}
        ]
        
        for endpoint_info in vampi_endpoints:
            path = endpoint_info["path"]
            methods = endpoint_info["methods"]
            description = endpoint_info["description"]
            
            # Test with sample values for parameterized paths
            test_path = path
            if "{username}" in path:
                test_path = path.replace("{username}", "name1")
            elif "{book_title}" in path:
                test_path = path.replace("{book_title}", "bookTitle77")
            
            full_url = normalize_url(self.config.base_url, test_path)
            
            for method in methods:
                if self.config.respect_rate_limits:
                    rate_limit_delay()
                
                endpoint = await self._test_endpoint(full_url, method)
                if endpoint:
                    # Update path to show parameterized version if it was parameterized
                    if "{username}" in path or "{book_title}" in path:
                        endpoint.path = path
                    endpoint.description = description
                    endpoints.append(endpoint)
                    self.logger.debug(f"Discovered VAmPI endpoint {method} {path}")
        
        return endpoints
    
    async def _pattern_based_discovery(self) -> List[EndpointMetadata]:
        """
        Discover endpoints using pattern-based scanning.
        
        Returns:
            List of discovered endpoints
        """
        endpoints = []
        
        # VAmPI-specific patterns with correct parameter names
        vampi_patterns = [
            "/users/v1/{username}",
            "/users/v1/{username}/email",
            "/users/v1/{username}/password",
            "/books/v1/{book_title}"
        ]
        
        for pattern in vampi_patterns:
            # Test with sample values based on VAmPI examples
            sample_values = {
                "username": "name1",
                "book_title": "bookTitle77"
            }
            
            # Replace placeholders with sample values
            test_path = pattern
            for placeholder, value in sample_values.items():
                if placeholder in test_path:
                    test_path = test_path.replace(f"{{{placeholder}}}", value)
            
            full_url = normalize_url(self.config.base_url, test_path)
            
            # Test appropriate methods for each pattern
            if "users" in pattern:
                methods = ["GET", "DELETE", "PUT"]
            else:  # books
                methods = ["GET"]
                
            for method in methods:
                if self.config.respect_rate_limits:
                    rate_limit_delay()
                
                endpoint = await self._test_endpoint(full_url, method)
                if endpoint:
                    # Update path to show parameterized version
                    endpoint.path = pattern
                    endpoints.append(endpoint)
                    self.logger.debug(f"Discovered pattern {method} {pattern}")
        
        return endpoints
    
    def _merge_endpoint_methods(self, endpoints: List[EndpointMetadata]) -> List[EndpointMetadata]:
        """
        Merge endpoints with the same path but different methods.
        
        Args:
            endpoints: List of endpoints to merge
            
        Returns:
            List of merged endpoints
        """
        path_map = {}
        
        for endpoint in endpoints:
            if endpoint.path in path_map:
                # Merge methods
                existing = path_map[endpoint.path]
                if endpoint.methods[0] not in existing.methods:
                    existing.methods.extend(endpoint.methods)
                
                # Update other fields if this endpoint has more information
                if not existing.description and endpoint.description:
                    existing.description = endpoint.description
                if not existing.parameters and endpoint.parameters:
                    existing.parameters = endpoint.parameters
            else:
                path_map[endpoint.path] = endpoint
        
        return list(path_map.values())
    
    def _analyze_api_structure(self, endpoints: List[EndpointMetadata]) -> APIStructure:
        """
        Analyze the overall API structure.
        
        Args:
            endpoints: List of discovered endpoints
            
        Returns:
            APIStructure instance
        """
        base_paths = set()
        versions = set()
        patterns = set()
        
        for endpoint in endpoints:
            path = endpoint.path
            
            # Extract base paths
            parts = path.strip("/").split("/")
            if len(parts) >= 2:
                base_paths.add(f"/{parts[0]}")
                if len(parts) >= 3:
                    base_paths.add(f"/{parts[0]}/{parts[1]}")
            
            # Extract versions
            version_match = re.search(r'/v(\d+)/', path)
            if version_match:
                versions.add(f"v{version_match.group(1)}")
            
            # Detect patterns
            if "/{id}" in path or "/{user_id}" in path or "/{book_title}" in path:
                patterns.add("REST")
            
            if endpoint.response_types and "application/json" in endpoint.response_types:
                patterns.add("JSON_responses")
        
        return APIStructure(
            base_url=self.config.base_url,
            discovery_method="endpoint_scanning",
            title="VAmPI API",
            description="VAmPI API discovered through endpoint scanning"
        )
    
    def _detect_auth_mechanisms(self, endpoints: List[EndpointMetadata]) -> List[AuthenticationMechanism]:
        """
        Detect and categorize authentication mechanisms.
        
        Args:
            endpoints: List of discovered endpoints
            
        Returns:
            List of authentication mechanisms
        """
        auth_map = {}
        
        for endpoint in endpoints:
            if endpoint.authentication_required and endpoint.authentication_type != AuthenticationType.NONE:
                auth_type = endpoint.authentication_type
                
                if auth_type not in auth_map:
                    auth_map[auth_type] = AuthenticationMechanism(
                        type=auth_type,
                        name=f"{auth_type.value}_auth",
                        description=f"{auth_type.value} authentication mechanism",
                        endpoints_using=[]
                    )
                
                auth_map[auth_type].endpoints_using.append(endpoint.path)
        
        return list(auth_map.values())
    
    def get_discovery_stats(self) -> Dict[str, Any]:
        """
        Get statistics about the discovery process.
        
        Returns:
            Dictionary with discovery statistics
        """
        return {
            "total_endpoints": len(self.discovered_endpoints),
            "unique_paths": len(set(ep.path for ep in self.discovered_endpoints)),
            "auth_mechanisms": len(self.auth_mechanisms),
            "risk_distribution": {
                "low": len([ep for ep in self.discovered_endpoints if ep.risk_level == RiskLevel.LOW]),
                "medium": len([ep for ep in self.discovered_endpoints if ep.risk_level == RiskLevel.MEDIUM]),
                "high": len([ep for ep in self.discovered_endpoints if ep.risk_level == RiskLevel.HIGH]),
                "critical": len([ep for ep in self.discovered_endpoints if ep.risk_level == RiskLevel.CRITICAL])
            }
        } 