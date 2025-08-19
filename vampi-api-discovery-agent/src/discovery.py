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
        
        # Enhanced security headers detection
        security_headers = self._detect_security_headers(response.headers)
        headers.extend(security_headers)
        
        # Try to extract body parameters from response with type inference
        body_params = []
        param_types = {}
        try:
            if response.headers.get("content-type", "").startswith("application/json"):
                data = response.json()
                if isinstance(data, dict):
                    body_params = list(data.keys())
                    # Infer parameter types
                    for key, value in data.items():
                        if isinstance(value, str):
                            param_types[key] = "string"
                        elif isinstance(value, int):
                            param_types[key] = "integer"
                        elif isinstance(value, float):
                            param_types[key] = "float"
                        elif isinstance(value, bool):
                            param_types[key] = "boolean"
                        elif isinstance(value, list):
                            param_types[key] = "array"
                        elif isinstance(value, dict):
                            param_types[key] = "object"
                        else:
                            param_types[key] = "unknown"
        except Exception:
            pass
        
        return EndpointParameters(
            query_params=query_params,
            path_params=path_params,
            body_params=body_params,
            headers=headers,
            param_types=param_types
        )
    
    def _detect_security_headers(self, headers: Dict[str, str]) -> List[str]:
        """
        Detect security-related headers in the response.
        
        Args:
            headers: Response headers dictionary
            
        Returns:
            List of security header names
        """
        security_headers = []
        
        # Common security headers
        security_header_patterns = {
            "x-frame-options": "X-Frame-Options",
            "x-content-type-options": "X-Content-Type-Options", 
            "strict-transport-security": "HSTS",
            "x-xss-protection": "XSS-Protection",
            "content-security-policy": "CSP",
            "referrer-policy": "Referrer-Policy",
            "permissions-policy": "Permissions-Policy",
            "x-permitted-cross-domain-policies": "X-Permitted-Cross-Domain-Policies"
        }
        
        for header_name, header_display in security_header_patterns.items():
            if header_name in headers:
                security_headers.append(header_display)
        
        return security_headers
    
    def _detect_deprecated_endpoint(self, response: httpx.Response) -> bool:
        """
        Detect if endpoint is deprecated.
        
        Args:
            response: HTTP response
            
        Returns:
            True if endpoint is deprecated, False otherwise
        """
        # Check for deprecation headers
        if "deprecation" in response.headers:
            return True
        
        # Check response body for deprecation warnings
        try:
            if response.headers.get("content-type", "").startswith("application/json"):
                data = response.json()
                if isinstance(data, dict):
                    # Look for deprecation indicators in response
                    if any("deprecated" in str(value).lower() for value in data.values()):
                        return True
                    # Check for deprecation in error messages
                    if "message" in data and "deprecated" in str(data["message"]).lower():
                        return True
        except Exception:
            pass
        
        # Check for deprecation in HTML responses
        try:
            if response.headers.get("content-type", "").startswith("text/html"):
                content = response.text.lower()
                if "deprecated" in content or "deprecation" in content:
                    return True
        except Exception:
            pass
        
        return False
    
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
            
            # Detect deprecated endpoints
            deprecated = self._detect_deprecated_endpoint(response)
            
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
                response_time=response_time,
                deprecated=deprecated
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
        
        # Analyze endpoint relationships and dependencies
        endpoint_relationships = self._analyze_endpoint_relationships(unique_endpoints)
        
        # Analyze API compliance with security standards
        api_compliance = self._analyze_api_compliance(unique_endpoints)
        
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
        
        # Enhanced versioning analysis
        versioning_info = self._detect_api_versioning(endpoints)
        latest_version = versioning_info.get("latest_version", "v1")
        
        return APIStructure(
            base_url=self.config.base_url,
            version=latest_version,
            discovery_method="endpoint_scanning",
            title="VAmPI API",
            description="VAmPI API discovered through endpoint scanning",
            base_path="/",
            schemes=["http", "https"],
            host=urlparse(self.config.base_url).hostname,
            port=urlparse(self.config.base_url).port or 80,
            endpoint_groups=self._group_endpoints_by_functionality(endpoints),
            endpoint_relationships=self._analyze_endpoint_relationships(endpoints),
            api_compliance=self._analyze_api_compliance(endpoints),
            contact_info=None,
            license_info=None,
            external_docs=None,
            discovered_at=datetime.now()
        )
    
    def _detect_api_versioning(self, endpoints: List[EndpointMetadata]) -> Dict[str, Any]:
        """
        Detect API versioning patterns and deprecated endpoints.
        
        Args:
            endpoints: List of discovered endpoints
            
        Returns:
            Dictionary with versioning information
        """
        version_patterns = {}
        deprecated_endpoints = []
        latest_version = "v1"  # Default
        
        for endpoint in endpoints:
            # Extract version from path
            if '/v' in endpoint.path:
                version_match = re.search(r'/v(\d+)', endpoint.path)
                if version_match:
                    version_num = version_match.group(1)
                    if version_num not in version_patterns:
                        version_patterns[version_num] = []
                    version_patterns[version_num].append(endpoint)
                    
                    # Track latest version
                    if version_num > latest_version.lstrip('v'):
                        latest_version = f"v{version_num}"
        
        # Check for deprecated endpoints
        for endpoint in endpoints:
            if hasattr(endpoint, 'deprecated') and endpoint.deprecated:
                deprecated_endpoints.append(endpoint)
        
        return {
            "versions": version_patterns,
            "deprecated": deprecated_endpoints,
            "latest_version": latest_version,
            "total_versions": len(version_patterns)
        }
    
    def _group_endpoints_by_functionality(self, endpoints: List[EndpointMetadata]) -> Dict[str, List[EndpointMetadata]]:
        """
        Group endpoints by functionality for better organization.
        
        Args:
            endpoints: List of discovered endpoints
            
        Returns:
            Dictionary with grouped endpoints
        """
        endpoint_groups = {}
        
        for endpoint in endpoints:
            # Extract main resource from path
            path_parts = endpoint.path.strip('/').split('/')
            if len(path_parts) > 0:
                main_resource = path_parts[0]
                if main_resource not in endpoint_groups:
                    endpoint_groups[main_resource] = []
                endpoint_groups[main_resource].append(endpoint)
        
        return endpoint_groups
    
    def _analyze_endpoint_relationships(self, endpoints: List[EndpointMetadata]) -> Dict[str, Any]:
        """
        Analyze relationships and dependencies between endpoints.
        
        Args:
            endpoints: List of discovered endpoints
            
        Returns:
            Dictionary with relationship analysis
        """
        relationships = {
            "resource_hierarchy": {},
            "dependencies": {},
            "data_flow": {},
            "authentication_flow": {},
            "risk_correlation": {}
        }
        
        # Analyze resource hierarchy
        for endpoint in endpoints:
            path_parts = endpoint.path.strip('/').split('/')
            if len(path_parts) >= 2:
                resource = path_parts[0]
                sub_resource = path_parts[1] if len(path_parts) > 1 else None
                
                if resource not in relationships["resource_hierarchy"]:
                    relationships["resource_hierarchy"][resource] = {
                        "endpoints": [],
                        "sub_resources": set(),
                        "methods": set(),
                        "risk_levels": set()
                    }
                
                relationships["resource_hierarchy"][resource]["endpoints"].append(endpoint)
                relationships["resource_hierarchy"][resource]["methods"].update(endpoint.methods)
                relationships["resource_hierarchy"][resource]["risk_levels"].add(endpoint.risk_level)
                
                if sub_resource:
                    relationships["resource_hierarchy"][resource]["sub_resources"].add(sub_resource)
        
        # Analyze dependencies between endpoints
        for endpoint in endpoints:
            dependencies = []
            
            # Check for parameter dependencies
            if endpoint.parameters.path_params:
                for param in endpoint.parameters.path_params:
                    # Look for endpoints that might provide this parameter
                    for other_endpoint in endpoints:
                        if other_endpoint != endpoint:
                            # Check if other endpoint returns data that could be used as parameter
                            if any(param.lower() in method.lower() for method in other_endpoint.methods):
                                dependencies.append({
                                    "endpoint": other_endpoint.path,
                                    "type": "parameter_dependency",
                                    "parameter": param
                                })
            
            # Check for authentication dependencies
            if endpoint.authentication_required:
                auth_endpoints = [ep for ep in endpoints if "auth" in ep.path.lower() or "login" in ep.path.lower()]
                for auth_ep in auth_endpoints:
                    dependencies.append({
                        "endpoint": auth_ep.path,
                        "type": "authentication_dependency",
                        "description": "Required for access"
                    })
            
            if dependencies:
                relationships["dependencies"][endpoint.path] = dependencies
        
        # Analyze data flow patterns
        for endpoint in endpoints:
            if "GET" in endpoint.methods:
                # Read operations
                relationships["data_flow"][endpoint.path] = {
                    "type": "read",
                    "targets": self._identify_data_targets(endpoint)
                }
            elif "POST" in endpoint.methods:
                # Create operations
                relationships["data_flow"][endpoint.path] = {
                    "type": "create",
                    "dependencies": self._identify_creation_dependencies(endpoint)
                }
            elif "PUT" in endpoint.methods:
                # Update operations
                relationships["data_flow"][endpoint.path] = {
                    "type": "update",
                    "prerequisites": self._identify_update_prerequisites(endpoint)
                }
            elif "DELETE" in endpoint.methods:
                # Delete operations
                relationships["data_flow"][endpoint.path] = {
                    "type": "delete",
                    "cascade_effects": self._identify_delete_cascade_effects(endpoint)
                }
        
        # Analyze authentication flow
        auth_endpoints = [ep for ep in endpoints if "auth" in ep.path.lower() or "login" in ep.path.lower()]
        if auth_endpoints:
            relationships["authentication_flow"] = {
                "entry_points": [ep.path for ep in auth_endpoints if "POST" in ep.methods],
                "protected_resources": [ep.path for ep in endpoints if ep.authentication_required],
                "public_resources": [ep.path for ep in endpoints if not ep.authentication_required]
            }
        
        # Analyze risk correlation
        high_risk_endpoints = [ep for ep in endpoints if ep.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]]
        if high_risk_endpoints:
            relationships["risk_correlation"] = {
                "high_risk_clusters": self._identify_risk_clusters(high_risk_endpoints),
                "risk_propagation": self._analyze_risk_propagation(high_risk_endpoints, endpoints)
            }
        
        return relationships
    
    def _identify_data_targets(self, endpoint: EndpointMetadata) -> List[str]:
        """Identify what data this endpoint reads."""
        targets = []
        if "users" in endpoint.path:
            targets.append("user_data")
        if "books" in endpoint.path:
            targets.append("book_data")
        if "auth" in endpoint.path:
            targets.append("authentication_data")
        return targets
    
    def _identify_creation_dependencies(self, endpoint: EndpointMetadata) -> List[str]:
        """Identify dependencies for creation operations."""
        dependencies = []
        if "users" in endpoint.path:
            dependencies.append("user_validation")
        if "books" in endpoint.path:
            dependencies.append("user_authentication")
        return dependencies
    
    def _identify_update_prerequisites(self, endpoint: EndpointMetadata) -> List[str]:
        """Identify prerequisites for update operations."""
        prerequisites = []
        if "users" in endpoint.path:
            prerequisites.append("user_exists")
            prerequisites.append("user_authentication")
        if "books" in endpoint.path:
            prerequisites.append("book_exists")
            prerequisites.append("user_authentication")
        return prerequisites
    
    def _identify_delete_cascade_effects(self, endpoint: EndpointMetadata) -> List[str]:
        """Identify cascade effects of delete operations."""
        effects = []
        if "users" in endpoint.path:
            effects.append("user_data_removal")
            effects.append("associated_books_cleanup")
        if "books" in endpoint.path:
            effects.append("book_data_removal")
        return effects
    
    def _identify_risk_clusters(self, high_risk_endpoints: List[EndpointMetadata]) -> Dict[str, List[str]]:
        """Identify clusters of related high-risk endpoints."""
        clusters = {}
        
        for endpoint in high_risk_endpoints:
            if "users" in endpoint.path:
                if "user_management" not in clusters:
                    clusters["user_management"] = []
                clusters["user_management"].append(endpoint.path)
            elif "books" in endpoint.path:
                if "book_management" not in clusters:
                    clusters["book_management"] = []
                clusters["book_management"].append(endpoint.path)
            elif "auth" in endpoint.path:
                if "authentication" not in clusters:
                    clusters["authentication"] = []
                clusters["authentication"].append(endpoint.path)
        
        return clusters
    
    def _analyze_risk_propagation(self, high_risk_endpoints: List[EndpointMetadata], all_endpoints: List[EndpointMetadata]) -> Dict[str, List[str]]:
        """Analyze how risks propagate across related endpoints."""
        propagation = {}
        
        for high_risk_ep in high_risk_endpoints:
            if "users" in high_risk_ep.path:
                # Find related user endpoints
                related_endpoints = [ep for ep in all_endpoints if "users" in ep.path and ep != high_risk_ep]
                if related_endpoints:
                    propagation[high_risk_ep.path] = [ep.path for ep in related_endpoints]
        
        return propagation
    
    def _analyze_api_compliance(self, endpoints: List[EndpointMetadata]) -> Dict[str, Any]:
        """
        Analyze API compliance with security standards and best practices.
        
        Args:
            endpoints: List of discovered endpoints
            
        Returns:
            Dictionary with compliance analysis
        """
        compliance = {
            "owasp_api_top_10": {},
            "security_headers": {},
            "authentication_standards": {},
            "data_protection": {},
            "overall_score": 0
        }
        
        # OWASP API Security Top 10 Analysis
        owasp_checks = {
            "broken_object_level_authorization": False,
            "broken_authentication": False,
            "broken_user_authentication": False,
            "excessive_data_exposure": False,
            "lack_of_resources_rate_limiting": False,
            "broken_function_level_authorization": False,
            "mass_assignment": False,
            "security_misconfiguration": False,
            "improper_assets_management": False,
            "insufficient_logging_monitoring": False
        }
        
        # Check for BOLA vulnerabilities
        for endpoint in endpoints:
            if endpoint.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                if "users" in endpoint.path and any(method in endpoint.methods for method in ["GET", "PUT", "DELETE"]):
                    owasp_checks["broken_object_level_authorization"] = True
                
                if "auth" in endpoint.path and not endpoint.authentication_required:
                    owasp_checks["broken_authentication"] = True
                
                if not endpoint.authentication_required and "users" in endpoint.path:
                    owasp_checks["broken_user_authentication"] = True
        
        # Check for rate limiting
        auth_endpoints = [ep for ep in endpoints if "auth" in ep.path.lower() or "login" in ep.path.lower()]
        if auth_endpoints:
            owasp_checks["lack_of_resources_rate_limiting"] = True
        
        # Check for security headers
        security_headers_found = 0
        total_security_headers = 8  # X-Frame-Options, HSTS, CSP, etc.
        
        for endpoint in endpoints:
            if hasattr(endpoint.parameters, 'headers'):
                security_headers_found += len([h for h in endpoint.parameters.headers if h in [
                    "X-Frame-Options", "HSTS", "XSS-Protection", "CSP"
                ]])
        
        security_headers_score = min(100, (security_headers_found / total_security_headers) * 100)
        
        # Calculate overall compliance score
        passed_checks = sum(1 for check in owasp_checks.values() if not check)
        total_checks = len(owasp_checks)
        owasp_score = (passed_checks / total_checks) * 100
        
        # Authentication standards compliance
        auth_compliance = {
            "jwt_usage": any("bearer" in str(ep.authentication_type).lower() for ep in endpoints if ep.authentication_required),
            "secure_headers": security_headers_score > 50,
            "rate_limiting": not owasp_checks["lack_of_resources_rate_limiting"]
        }
        
        # Data protection compliance
        data_protection = {
            "sensitive_data_exposure": not any(ep.risk_level == RiskLevel.CRITICAL for ep in endpoints),
            "input_validation": True,  # Assume basic validation exists
            "output_encoding": True    # Assume basic encoding exists
        }
        
        # Calculate overall score
        overall_score = (owasp_score * 0.4 + security_headers_score * 0.3 + 
                        (sum(auth_compliance.values()) / len(auth_compliance)) * 100 * 0.2 +
                        (sum(data_protection.values()) / len(data_protection)) * 100 * 0.1)
        
        compliance.update({
            "owasp_api_top_10": owasp_checks,
            "security_headers": {"score": security_headers_score, "found": security_headers_found},
            "authentication_standards": auth_compliance,
            "data_protection": data_protection,
            "overall_score": round(overall_score, 2)
        })
        
        return compliance
    
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