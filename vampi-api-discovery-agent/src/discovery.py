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
import requests
from bs4 import BeautifulSoup

# Handle both direct execution and module import
try:
    from .models import (
        APIDiscoveryResult, DiscoverySummary, EndpointMetadata, EndpointParameters,
        AuthenticationMechanism, APIStructure, RiskLevel, AuthenticationType,
        DiscoveryMethod, DiscoveryConfig
    )
    from .utils import (
        normalize_url, extract_path_parameters, rate_limit_delay, 
        calculate_success_rate, is_valid_url
    )
except ImportError:
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
        
        # Common API paths to scan
        self.common_paths = [
            "/users", "/users/v1", "/users/v1/", "/users/v1/register", "/users/v1/login",
            "/books", "/books/v1", "/books/v1/",
            "/api", "/api/v1", "/api/v1/", "/api/v1/users", "/api/v1/books",
            "/auth", "/auth/login", "/auth/register",
            "/admin", "/admin/users", "/admin/books",
            "/health", "/status", "/info", "/docs", "/swagger", "/openapi"
        ]
        
        # HTTP methods to test
        self.http_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
        
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
        if "?" in response.url:
            query_string = response.url.split("?")[1]
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
            path = urlparse(url).path
            
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
        
        # User management endpoints
        if "/users" in path_lower:
            if "login" in path_lower:
                return "User authentication endpoint"
            elif "register" in path_lower:
                return "User registration endpoint"
            elif path_lower.endswith("/users") or path_lower.endswith("/users/"):
                return "User management endpoint"
            else:
                return "Individual user operation endpoint"
        
        # Book management endpoints
        elif "/books" in path_lower:
            if path_lower.endswith("/books") or path_lower.endswith("/books/"):
                return "Book management endpoint"
            else:
                return "Individual book operation endpoint"
        
        # Authentication endpoints
        elif "/auth" in path_lower:
            if "login" in path_lower:
                return "Authentication login endpoint"
            elif "register" in path_lower:
                return "Authentication registration endpoint"
            else:
                return "Authentication endpoint"
        
        # Admin endpoints
        elif "/admin" in path_lower:
            return "Administrative endpoint"
        
        # Health and status endpoints
        elif path in ["/health", "/status", "/info"]:
            return "Application health and status endpoint"
        
        # Documentation endpoints
        elif path in ["/docs", "/swagger", "/openapi"]:
            return "API documentation endpoint"
        
        # Generic description based on method
        else:
            method_descriptions = {
                "GET": "Retrieve data endpoint",
                "POST": "Create data endpoint",
                "PUT": "Update data endpoint",
                "DELETE": "Delete data endpoint",
                "PATCH": "Partial update endpoint",
                "HEAD": "Header information endpoint",
                "OPTIONS": "Options endpoint"
            }
            return method_descriptions.get(method, "API endpoint")
    
    async def discover_endpoints(self) -> APIDiscoveryResult:
        """
        Discover all VAmPI endpoints using various techniques.
        
        Returns:
            APIDiscoveryResult with discovered endpoints
        """
        self.logger.info("Starting VAmPI endpoint discovery...")
        start_time = time.time()
        
        # Reset state
        self.discovered_endpoints.clear()
        self.auth_mechanisms.clear()
        
        # Discover endpoints using common paths
        endpoints = await self._scan_common_paths()
        
        # Discover endpoints using pattern-based scanning
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
        
        # Create discovery summary
        summary = DiscoverySummary(
            total_endpoints=len(unique_endpoints),
            discovery_timestamp=datetime.utcnow(),
            target_application="VAmPI",
            base_url=self.config.base_url,
            scan_duration=scan_duration,
            success_rate=calculate_success_rate(len(endpoints), len(unique_endpoints))
        )
        
        # Create result
        result = APIDiscoveryResult(
            discovery_summary=summary,
            endpoints=unique_endpoints,
            authentication_mechanisms=auth_mechanisms,
            api_structure=api_structure
        )
        
        self.logger.info(f"Discovery completed. Found {len(unique_endpoints)} endpoints in {scan_duration:.2f}s")
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
    
    async def _pattern_based_discovery(self) -> List[EndpointMetadata]:
        """
        Discover endpoints using pattern-based scanning.
        
        Returns:
            List of discovered endpoints
        """
        endpoints = []
        
        # VAmPI-specific patterns
        vampi_patterns = [
            "/users/v1/{user_id}",
            "/users/v1/{user_id}/email",
            "/users/v1/{user_id}/password",
            "/books/v1/{book_title}"
        ]
        
        for pattern in vampi_patterns:
            # Test with sample values
            sample_values = {
                "user_id": "123",
                "book_title": "sample_book"
            }
            
            # Replace placeholders with sample values
            test_path = pattern
            for placeholder, value in sample_values.items():
                if placeholder in test_path:
                    test_path = test_path.replace(f"{{{placeholder}}}", value)
            
            full_url = normalize_url(self.config.base_url, test_path)
            
            for method in ["GET", "PUT", "DELETE"]:
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
            base_paths=list(base_paths),
            versions=list(versions),
            common_patterns=list(patterns)
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
                        endpoints=[],
                        token_location="header",
                        header_name="Authorization"
                    )
                
                auth_map[auth_type].endpoints.append(endpoint.path)
        
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