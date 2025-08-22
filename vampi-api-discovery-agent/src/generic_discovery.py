"""
Generic API Discovery Engine.

This module implements a framework-agnostic API discovery engine that can
work with any REST API, regardless of the underlying framework or technology.
"""

import asyncio
import logging
import time
import json
import yaml
import sys
import os
from datetime import datetime
from typing import List, Dict, Optional, Set, Tuple, Any
from urllib.parse import urljoin, urlparse
from pathlib import Path
import re

# Add src directory to Python path for imports
sys.path.append(os.path.dirname(__file__))

import httpx
import urllib3
from urllib3.util.retry import Retry
from urllib3.poolmanager import PoolManager

# Import models and utils
from models import (
    APIDiscoveryResult, DiscoverySummary, EndpointMetadata, EndpointParameters,
    AuthenticationMechanism, APIStructure, RiskLevel, AuthenticationType,
    DiscoveryMethod, DiscoveryConfig
)
from utils import (
    normalize_url, extract_path_parameters, rate_limit_delay, 
    calculate_success_rate, is_valid_url, normalize_parameter_format
)
from config_loader import ConfigLoader, DEFAULT_CONFIG


class GenericAPIDiscoveryEngine:
    """
    Generic engine for discovering and analyzing any REST API endpoints.
    
    This class implements framework-agnostic discovery techniques including:
    - Universal endpoint scanning
    - Framework-agnostic response analysis
    - Generic authentication detection
    - Universal risk assessment
    """
    
    def __init__(self, config: DiscoveryConfig, config_file_path: Optional[str] = None):
        """
        Initialize the generic discovery engine.
        
        Args:
            config: Discovery configuration
            config_file_path: Optional path to custom configuration file
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.session = None
        self.discovered_endpoints: Set[str] = set()
        self.auth_mechanisms: List[AuthenticationMechanism] = []
        
        # Configure urllib3 for connection pooling and retries
        self.urllib3_pool = PoolManager(
            maxsize=10,
            retries=Retry(
                total=3,
                backoff_factor=0.1,
                status_forcelist=[500, 502, 503, 504]
            )
        )
        
        # Load configuration from file or use defaults
        try:
            self.config_loader = ConfigLoader(config_file_path)
            self.discovery_config = self.config_loader.get_config()
            self.logger.info(f"Loaded configuration from: {self.config_loader.config_path}")
        except Exception as e:
            self.logger.warning(f"Failed to load configuration file, using defaults: {e}")
            self.discovery_config = DEFAULT_CONFIG
        
        # Load configurable settings
        self.common_paths = self.discovery_config.common_paths
        self.http_methods = self.discovery_config.http_methods
        self.risk_patterns = self.discovery_config.risk_patterns
        
        # Framework-agnostic discovery patterns
        self.universal_patterns = self._generate_universal_patterns()
        self.framework_indicators = self._initialize_framework_indicators()
    
    def _generate_universal_patterns(self) -> Dict[str, List[str]]:
        """
        Generate universal API patterns that work across different frameworks.
        
        Returns:
            Dictionary of universal pattern categories
        """
        return {
            "common_resources": [
                "/users", "/user", "/accounts", "/account",
                "/products", "/product", "/items", "/item",
                "/orders", "/order", "/bookings", "/booking",
                "/payments", "/payment", "/invoices", "/invoice",
                "/files", "/file", "/documents", "/document",
                "/images", "/image", "/media", "/uploads"
            ],
            "authentication": [
                "/auth", "/login", "/logout", "/register", "/signup",
                "/signin", "/signout", "/password", "/reset", "/verify",
                "/token", "/refresh", "/session", "/oauth", "/sso"
            ],
            "administration": [
                "/admin", "/administrator", "/management", "/manage",
                "/settings", "/config", "/configuration", "/system",
                "/dashboard", "/control", "/superuser", "/root"
            ],
            "documentation": [
                "/docs", "/documentation", "/api", "/swagger",
                "/openapi", "/redoc", "/help", "/guide", "/reference",
                "/schema", "/spec", "/specification"
            ],
            "system": [
                "/health", "/status", "/ping", "/ready", "/live",
                "/metrics", "/monitoring", "/logs", "/debug", "/info",
                "/version", "/about", "/contact", "/support"
            ],
            "data_operations": [
                "/search", "/query", "/filter", "/sort", "/page",
                "/export", "/import", "/sync", "/backup", "/restore",
                "/archive", "/trash", "/deleted", "/history"
            ]
        }
    
    def _initialize_framework_indicators(self) -> Dict[str, Dict[str, Any]]:
        """
        Initialize indicators for detecting different API frameworks.
        
        Returns:
            Dictionary of framework detection indicators
        """
        return {
            "flask": {
                "headers": ["X-Powered-By: Flask"],
                "patterns": ["/static/", "/templates/"],
                "responses": ["werkzeug", "flask"]
            },
            "django": {
                "headers": ["X-Powered-By: Django", "X-Frame-Options"],
                "patterns": ["/admin/", "/static/", "/media/"],
                "responses": ["django", "csrf", "sessionid"]
            },
            "fastapi": {
                "headers": ["X-Powered-By: FastAPI"],
                "patterns": ["/docs", "/redoc", "/openapi.json"],
                "responses": ["fastapi", "pydantic"]
            },
            "express": {
                "headers": ["X-Powered-By: Express"],
                "patterns": ["/public/", "/views/"],
                "responses": ["express", "node", "npm"]
            },
            "spring": {
                "headers": ["X-Powered-By: Spring"],
                "patterns": ["/actuator/", "/h2-console/"],
                "responses": ["spring", "java", "tomcat"]
            },
            "aspnet": {
                "headers": ["X-Powered-By: ASP.NET", "X-AspNet-Version"],
                "patterns": ["/Content/", "/Scripts/"],
                "responses": ["asp.net", "microsoft", "iis"]
            }
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
    
    async def discover_endpoints(self) -> APIDiscoveryResult:
        """
        Discover endpoints using universal, framework-agnostic patterns.
        
        Returns:
            APIDiscoveryResult with discovered endpoints and metadata
        """
        start_time = time.time()
        self.logger.info("Starting universal API endpoint discovery...")
        
        # Initialize results
        endpoints = []
        discovered_paths = set()
        
        # Phase 1: Universal pattern-based discovery
        self.logger.info("Phase 1: Universal pattern-based discovery")
        universal_endpoints = await self._universal_pattern_discovery()
        endpoints.extend(universal_endpoints)
        discovered_paths.update([ep.path for ep in universal_endpoints])
        
        # Phase 2: Framework-specific discovery
        self.logger.info("Phase 2: Framework-specific discovery")
        framework_endpoints = await self._framework_specific_discovery()
        endpoints.extend(framework_endpoints)
        discovered_paths.update([ep.path for ep in framework_endpoints])
        
        # Phase 3: Intelligent path generation
        self.logger.info("Phase 3: Intelligent path generation")
        intelligent_endpoints = await self._intelligent_path_generation(discovered_paths)
        endpoints.extend(intelligent_endpoints)
        
        # Phase 4: Response analysis and enhancement
        self.logger.info("Phase 4: Response analysis and enhancement")
        enhanced_endpoints = await self._enhance_endpoints_with_responses(endpoints)
        
        # Phase 5: Framework detection and categorization
        self.logger.info("Phase 5: Framework detection and categorization")
        framework_info = await self._detect_api_framework()
        
        # Create discovery summary
        summary = self._create_discovery_summary(enhanced_endpoints, framework_info)
        
        # Create API structure
        api_structure = self._analyze_api_structure(enhanced_endpoints)
        
        # Create authentication mechanisms
        auth_mechanisms = self._create_authentication_mechanisms(enhanced_endpoints)
        
        # Create result
        result = APIDiscoveryResult(
            endpoints=enhanced_endpoints,
            discovery_summary=summary,
            api_structure=api_structure,
            authentication_mechanisms=auth_mechanisms,
            framework_info=framework_info
        )
        
        duration = time.time() - start_time
        self.logger.info(f"Universal discovery completed in {duration:.2f}s. Found {len(enhanced_endpoints)} endpoints.")
        
        return result
    
    async def _universal_pattern_discovery(self) -> List[EndpointMetadata]:
        """
        Discover endpoints using universal patterns that work across frameworks.
        
        Returns:
            List of discovered endpoints
        """
        endpoints = []
        
        # Test common resource patterns
        for resource in self.universal_patterns["common_resources"]:
            for method in self.http_methods:
                endpoint = await self._test_universal_endpoint(resource, method)
                if endpoint:
                    endpoints.append(endpoint)
        
        # Test authentication patterns
        for auth_path in self.universal_patterns["authentication"]:
            for method in self.http_methods:
                endpoint = await self._test_universal_endpoint(auth_path, method)
                if endpoint:
                    endpoints.append(endpoint)
        
        # Test system patterns
        for system_path in self.universal_patterns["system"]:
            for method in self.http_methods:
                endpoint = await self._test_universal_endpoint(system_path, method)
                if endpoint:
                    endpoints.append(endpoint)
        
        return endpoints
    
    async def _test_universal_endpoint(self, path: str, method: str) -> Optional[EndpointMetadata]:
        """
        Test a universal endpoint pattern.
        
        Args:
            path: Endpoint path to test
            method: HTTP method to test
            
        Returns:
            EndpointMetadata if endpoint exists, None otherwise
        """
        try:
            url = urljoin(self.config.base_url, path)
            
            # Test with httpx first
            try:
                response = await self.session.request(method, url, timeout=10)
                if response.status_code < 500:  # Accept any non-server-error response
                    return self._create_endpoint_from_response(path, method, response)
            except Exception as e:
                self.logger.debug(f"httpx failed for {method} {path}: {e}")
            
            # Fallback to urllib3
            try:
                urllib3_response = self.urllib3_pool.request(method, url, timeout=10)
                if urllib3_response.status < 500:
                    return self._create_endpoint_from_urllib3_response(path, method, urllib3_response)
            except Exception as e:
                self.logger.debug(f"urllib3 failed for {method} {path}: {e}")
            
        except Exception as e:
            self.logger.debug(f"Error testing {method} {path}: {e}")
        
        return None
    
    def _create_endpoint_from_response(self, path: str, method: str, response) -> EndpointMetadata:
        """Create EndpointMetadata from httpx response."""
        try:
            # Extract authentication information
            auth_type, auth_required = self._detect_authentication_generic(response, path)
            
            # Assess risk level
            risk_level, risk_factors = self._assess_risk_generic(path, method, auth_required)
            
            # Extract parameters
            parameters = self._extract_parameters_generic(path, response)
            
            # Create endpoint
            endpoint = EndpointMetadata(
                id=f"GEN_{len(self.discovered_endpoints) + 1:03d}",
                path=path,
                methods=[method],
                description=self._generate_description_generic(path, method),
                parameters=parameters,
                authentication_required=auth_required,
                authentication_type=auth_type,
                risk_level=risk_level,
                risk_factors=risk_factors,
                response_types=self._extract_response_types(response),
                discovered_via=DiscoveryMethod.ENDPOINT_SCANNING,
                status_code=response.status_code,
                response_time=None,  # Could be added if timing is needed
                error_messages=[],
                deprecated=False
            )
            
            self.discovered_endpoints.add(path)
            return endpoint
            
        except Exception as e:
            self.logger.error(f"Error creating endpoint from response: {e}")
            return None
    
    def _create_endpoint_from_urllib3_response(self, path: str, method: str, response) -> EndpointMetadata:
        """Create EndpointMetadata from urllib3 response."""
        try:
            # Extract authentication information
            auth_type, auth_required = self._detect_authentication_generic(response, path)
            
            # Assess risk level
            risk_level, risk_factors = self._assess_risk_generic(path, method, auth_required)
            
            # Extract parameters
            parameters = self._extract_parameters_generic(path, response)
            
            # Create endpoint
            endpoint = EndpointMetadata(
                id=f"GEN_{len(self.discovered_endpoints) + 1:03d}",
                path=path,
                methods=[method],
                description=self._generate_description_generic(path, method),
                parameters=parameters,
                authentication_required=auth_required,
                authentication_type=auth_type,
                risk_level=risk_level,
                risk_factors=risk_factors,
                response_types=self._extract_response_types_urllib3(response),
                discovered_via=DiscoveryMethod.ENDPOINT_SCANNING,
                status_code=response.status,
                response_time=None,
                error_messages=[],
                deprecated=False
            )
            
            self.discovered_endpoints.add(path)
            return endpoint
            
        except Exception as e:
            self.logger.error(f"Error creating endpoint from urllib3 response: {e}")
            return None
    
    def _detect_authentication_generic(self, response, path: str) -> Tuple[AuthenticationType, bool]:
        """
        Generic authentication detection that works across frameworks.
        
        Args:
            response: HTTP response object (httpx.Response or urllib3 response)
            path: Endpoint path
            
        Returns:
            Tuple of (authentication_type, authentication_required)
        """
        auth_required = False
        auth_type = AuthenticationType.NONE
        
        # Check for authentication headers
        if hasattr(response, 'headers'):
            headers = response.headers
        else:
            headers = getattr(response, 'headers', {})
        
        # Check for authentication headers
        auth_header = headers.get("www-authenticate", "").lower()
        if "bearer" in auth_header:
            return AuthenticationType.BEARER, True
        elif "basic" in auth_header:
            return AuthenticationType.BASIC, True
        
        # Check for JWT tokens in response
        if "jwt" in headers.get("authorization", "").lower():
            return AuthenticationType.JWT, True
        
        # Check for common authentication patterns in path
        auth_patterns = ["/login", "/register", "/auth", "/signin", "/signup"]
        if any(pattern in path.lower() for pattern in auth_patterns):
            return AuthenticationType.NONE, False  # These are auth endpoints
        
        # Check response status codes for authentication requirements
        status_code = getattr(response, 'status_code', getattr(response, 'status', 200))
        if status_code == 401:  # Unauthorized
            return AuthenticationType.UNKNOWN, True
        elif status_code == 403:  # Forbidden
            return AuthenticationType.UNKNOWN, True
        
        # Default to no authentication for public endpoints
        return AuthenticationType.NONE, False
    
    def _assess_risk_generic(self, path: str, method: str, auth_required: bool) -> Tuple[RiskLevel, List[str]]:
        """
        Generic risk assessment that works across different APIs.
        
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
        if any(pattern in path_lower for pattern in ["/users", "/user", "/accounts", "/account"]):
            risk_factors.append("user_management")
            base_risk = RiskLevel.MEDIUM
        
        # Data exposure endpoints
        if any(pattern in path_lower for pattern in ["/admin", "/config", "/settings", "/system"]):
            risk_factors.append("data_exposure")
            base_risk = RiskLevel.HIGH
        
        # Authentication bypass potential
        if any(pattern in path_lower for pattern in ["/auth", "/login", "/register", "/password"]):
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
        
        # Add context for low-risk endpoints
        if base_risk == RiskLevel.LOW:
            if not auth_required:
                risk_factors.append("public_endpoint")
            if method == "GET":
                risk_factors.append("read_only_operation")
            if "health" in path_lower or "status" in path_lower:
                risk_factors.append("system_monitoring")
            elif "docs" in path_lower or "swagger" in path_lower:
                risk_factors.append("documentation_access")
            else:
                risk_factors.append("standard_api_operation")
        
        return base_risk, risk_factors
    
    def _extract_parameters_generic(self, path: str, response) -> EndpointParameters:
        """
        Generic parameter extraction that works across frameworks.
        
        Args:
            path: Endpoint path
            response: HTTP response object
            
        Returns:
            EndpointParameters object
        """
        # Extract path parameters
        path_params = []
        if "{" in path or ":" in path:
            # Extract template parameters
            param_matches = re.findall(r'\{([^}]+)\}|:([^/]+)', path)
            path_params = [match[0] if match[0] else match[1] for match in param_matches]
        
        # Extract headers
        headers = []
        if hasattr(response, 'headers'):
            response_headers = response.headers
        else:
            response_headers = getattr(response, 'headers', {})
        
        # Common headers that might be required
        common_headers = ["Content-Type", "Accept", "Authorization", "X-API-Key"]
        for header in common_headers:
            if header.lower() in [h.lower() for h in response_headers.keys()]:
                headers.append(header)
        
        # Create parameters object
        parameters = EndpointParameters(
            path_params=path_params,
            query_params=[],  # Could be enhanced with response analysis
            body_params=[],   # Could be enhanced with response analysis
            headers=headers,
            param_types={},
            validation_rules={}
        )
        
        return parameters
    
    def _generate_description_generic(self, path: str, method: str) -> str:
        """Generate generic description for endpoint."""
        path_lower = path.lower()
        
        if "users" in path_lower or "user" in path_lower:
            resource = "user"
        elif "books" in path_lower or "book" in path_lower:
            resource = "book"
        elif "products" in path_lower or "product" in path_lower:
            resource = "product"
        elif "orders" in path_lower or "order" in path_lower:
            resource = "order"
        elif "auth" in path_lower or "login" in path_lower:
            resource = "authentication"
        elif "admin" in path_lower:
            resource = "administration"
        elif "health" in path_lower or "status" in path_lower:
            resource = "system"
        else:
            resource = "resource"
        
        if method == "GET":
            action = "retrieve"
        elif method == "POST":
            action = "create"
        elif method == "PUT":
            action = "update"
        elif method == "DELETE":
            action = "delete"
        else:
            action = "access"
        
        return f"{action.capitalize()} {resource} information"
    
    def _extract_response_types(self, response) -> List[str]:
        """Extract response content types from httpx response."""
        try:
            content_type = response.headers.get("content-type", "")
            if content_type:
                return [content_type.split(";")[0].strip()]
            return ["application/json"]  # Default assumption
        except:
            return ["application/json"]
    
    def _extract_response_types_urllib3(self, response) -> List[str]:
        """Extract response content types from urllib3 response."""
        try:
            content_type = response.headers.get("content-type", "")
            if content_type:
                return [content_type.split(";")[0].strip()]
            return ["application/json"]  # Default assumption
        except:
            return ["application/json"]
    
    async def _framework_specific_discovery(self) -> List[EndpointMetadata]:
        """Discover endpoints specific to detected frameworks."""
        endpoints = []
        
        # Test framework-specific patterns
        for framework, indicators in self.framework_indicators.items():
            for pattern in indicators["patterns"]:
                for method in self.http_methods:
                    endpoint = await self._test_universal_endpoint(pattern, method)
                    if endpoint:
                        endpoints.append(endpoint)
        
        return endpoints
    
    async def _intelligent_path_generation(self, discovered_paths: Set[str]) -> List[EndpointMetadata]:
        """Generate intelligent paths based on discovered patterns."""
        endpoints = []
        
        # Analyze discovered paths for patterns
        resource_patterns = set()
        version_patterns = set()
        
        for path in discovered_paths:
            # Extract resource patterns
            if "/" in path:
                parts = path.split("/")
                if len(parts) > 1:
                    resource_patterns.add(parts[1])
                if len(parts) > 2 and parts[2].startswith("v"):
                    version_patterns.add(parts[2])
        
        # Generate variations based on discovered patterns
        for resource in resource_patterns:
            for version in version_patterns:
                # Test common CRUD patterns
                crud_patterns = [
                    f"/{resource}/{version}",
                    f"/{resource}/{version}/{{id}}",
                    f"/{resource}/{version}/{{id}}/details",
                    f"/{resource}/{version}/search",
                    f"/{resource}/{version}/export"
                ]
                
                for pattern in crud_patterns:
                    for method in self.http_methods:
                        endpoint = await self._test_universal_endpoint(pattern, method)
                        if endpoint:
                            endpoints.append(endpoint)
        
        return endpoints
    
    async def _enhance_endpoints_with_responses(self, endpoints: List[EndpointMetadata]) -> List[EndpointMetadata]:
        """Enhance endpoints with response analysis."""
        enhanced_endpoints = []
        
        for endpoint in endpoints:
            try:
                # Test the endpoint to get response details
                url = urljoin(self.config.base_url, endpoint.path)
                method = endpoint.methods[0] if endpoint.methods else "GET"
                
                try:
                    response = await self.session.request(method, url, timeout=5)
                    # Enhance with response analysis
                    enhanced_endpoint = self._enhance_endpoint_with_response(endpoint, response)
                    enhanced_endpoints.append(enhanced_endpoint)
                except:
                    enhanced_endpoints.append(endpoint)
                    
            except Exception as e:
                self.logger.debug(f"Error enhancing endpoint {endpoint.path}: {e}")
                enhanced_endpoints.append(endpoint)
        
        return enhanced_endpoints
    
    def _enhance_endpoint_with_response(self, endpoint: EndpointMetadata, response) -> EndpointMetadata:
        """Enhance endpoint with response analysis."""
        try:
            # Extract additional response information
            if hasattr(response, 'headers'):
                headers = response.headers
            else:
                headers = getattr(response, 'headers', {})
            
            # Update response types if not already set
            if not endpoint.response_types:
                content_type = headers.get("content-type", "")
                if content_type:
                    endpoint.response_types = [content_type.split(";")[0].strip()]
            
            # Add any error messages
            if hasattr(response, 'status_code'):
                status_code = response.status_code
            else:
                status_code = getattr(response, 'status', 200)
            
            if status_code >= 400:
                endpoint.error_messages.append(f"HTTP {status_code}")
            
        except Exception as e:
            self.logger.debug(f"Error enhancing endpoint: {e}")
        
        return endpoint
    
    async def _detect_api_framework(self) -> Dict[str, Any]:
        """Detect the API framework and technology stack."""
        framework_info = {
            "detected_framework": "Unknown",
            "confidence": 0.0,
            "indicators": [],
            "technology_stack": [],
            "server_info": {}
        }
        
        try:
            # Test root endpoint to get server information
            url = urljoin(self.config.base_url, "/")
            response = await self.session.get(url, timeout=5)
            
            # Analyze headers for framework indicators
            headers = response.headers
            framework_info["server_info"] = {
                "server": headers.get("server", "Unknown"),
                "x_powered_by": headers.get("x-powered-by", "Unknown"),
                "content_type": headers.get("content-type", "Unknown")
            }
            
            # Check for framework indicators
            for framework, indicators in self.framework_indicators.items():
                score = 0
                found_indicators = []
                
                # Check headers
                for header in indicators["headers"]:
                    if header.lower() in str(headers).lower():
                        score += 0.4
                        found_indicators.append(f"header: {header}")
                
                # Check patterns
                for pattern in indicators["patterns"]:
                    if pattern in str(response.text).lower():
                        score += 0.3
                        found_indicators.append(f"pattern: {pattern}")
                
                # Check response content
                for response_indicator in indicators["responses"]:
                    if response_indicator.lower() in response.text.lower():
                        score += 0.3
                        found_indicators.append(f"response: {response_indicator}")
                
                if score > framework_info["confidence"]:
                    framework_info["detected_framework"] = framework
                    framework_info["confidence"] = score
                    framework_info["indicators"] = found_indicators
            
            # Add technology stack information
            if framework_info["detected_framework"] != "Unknown":
                framework_info["technology_stack"] = [
                    framework_info["detected_framework"],
                    "REST API",
                    "HTTP/1.1"
                ]
            
        except Exception as e:
            self.logger.debug(f"Error detecting framework: {e}")
        
        return framework_info
    
    def _create_discovery_summary(self, endpoints: List[EndpointMetadata], framework_info: Dict[str, Any]) -> DiscoverySummary:
        """Create discovery summary with framework information."""
        # Calculate statistics
        total_endpoints = len(endpoints)
        authenticated_endpoints = len([ep for ep in endpoints if ep.authentication_required])
        public_endpoints = total_endpoints - authenticated_endpoints
        
        # Risk level distribution
        high_risk = len([ep for ep in endpoints if ep.risk_level == RiskLevel.HIGH])
        medium_risk = len([ep for ep in endpoints if ep.risk_level == RiskLevel.MEDIUM])
        low_risk = len([ep for ep in endpoints if ep.risk_level == RiskLevel.LOW])
        
        # Authentication types
        auth_types = set()
        for ep in endpoints:
            if ep.authentication_type:
                auth_types.add(ep.authentication_type)
        
        # Calculate coverage (generic approach)
        discovery_coverage = min(95.0, max(0.0, (total_endpoints / 50.0) * 100))  # Normalize to 0-100
        
        summary = DiscoverySummary(
            discovery_timestamp=datetime.now(),
            target_application=framework_info.get("detected_framework", "Unknown API"),
            base_url=self.config.base_url,
            total_endpoints=total_endpoints,
            authenticated_endpoints=authenticated_endpoints,
            public_endpoints=public_endpoints,
            high_risk_endpoints=high_risk,
            medium_risk_endpoints=medium_risk,
            low_risk_endpoints=low_risk,
            authentication_types=list(auth_types),
            discovery_coverage=discovery_coverage,
            parameter_coverage=75.0,  # Generic default
            discovery_start_time=datetime.now(),
            discovery_end_time=datetime.now(),
            discovery_duration=0.0,
            total_parameters=0,
            unique_parameters=0
        )
        
        return summary
    
    def _analyze_api_structure(self, endpoints: List[EndpointMetadata]) -> APIStructure:
        """Analyze API structure generically."""
        # Extract base paths
        base_paths = set()
        versions = set()
        
        for endpoint in endpoints:
            path = endpoint.path
            if "/" in path:
                parts = path.split("/")
                if len(parts) > 1:
                    base_paths.add(f"/{parts[1]}")
                if len(parts) > 2 and parts[2].startswith("v"):
                    versions.add(parts[2])
        
        # Determine common patterns
        common_patterns = ["REST", "JSON_responses"]
        
        # Check if GraphQL or SOAP patterns exist
        if any("/graphql" in ep.path for ep in endpoints):
            common_patterns.append("GraphQL")
        if any("/soap" in ep.path for ep in endpoints):
            common_patterns.append("SOAP")
        
        # Group endpoints by functionality
        endpoint_groups = {}
        for endpoint in endpoints:
            path = endpoint.path
            if "/users" in path or "/user" in path:
                if "user_management" not in endpoint_groups:
                    endpoint_groups["user_management"] = []
                endpoint_groups["user_management"].append(endpoint.path)
            elif "/admin" in path:
                if "administration" not in endpoint_groups:
                    endpoint_groups["administration"] = []
                endpoint_groups["administration"].append(endpoint.path)
            elif "/auth" in path or "/login" in path:
                if "authentication" not in endpoint_groups:
                    endpoint_groups["authentication"] = []
                endpoint_groups["authentication"].append(endpoint.path)
            else:
                if "general" not in endpoint_groups:
                    endpoint_groups["general"] = []
                endpoint_groups["general"].append(endpoint.path)
        
        # Create API structure
        api_structure = APIStructure(
            base_url=self.config.base_url,
            discovery_method="generic_universal_discovery",
            base_paths=list(base_paths),
            versions=list(versions),
            common_patterns=common_patterns,
            endpoint_groups=endpoint_groups
        )
        
        return api_structure
    
    def _create_authentication_mechanisms(self, endpoints: List[EndpointMetadata]) -> List[AuthenticationMechanism]:
        """Create authentication mechanisms from discovered endpoints."""
        auth_mechanisms = []
        
        # Group endpoints by authentication type
        auth_groups = {}
        for endpoint in endpoints:
            auth_type = endpoint.authentication_type
            if auth_type not in auth_groups:
                auth_groups[auth_type] = []
            auth_groups[auth_type].append(endpoint.path)
        
        # Create AuthenticationMechanism objects
        for auth_type, paths in auth_groups.items():
            if auth_type == AuthenticationType.NONE:
                continue  # Skip endpoints with no authentication
                
            # Determine security strength
            if auth_type in [AuthenticationType.JWT, AuthenticationType.BEARER]:
                security_strength = "High"
            elif auth_type in [AuthenticationType.BASIC, AuthenticationType.API_KEY]:
                security_strength = "Medium"
            else:
                security_strength = "Low"
            
            # Determine vulnerabilities
            vulnerabilities = []
            if auth_type == AuthenticationType.BASIC:
                vulnerabilities.append("Credentials in headers")
            elif auth_type == AuthenticationType.JWT:
                vulnerabilities.append("Token expiration")
                vulnerabilities.append("Algorithm validation")
            
            # Create mechanism
            mechanism = AuthenticationMechanism(
                name=f"{auth_type.value}_auth",
                type=auth_type,
                description=f"Authentication using {auth_type.value}",
                security_strength=security_strength,
                vulnerabilities=vulnerabilities,
                endpoints_using=paths,
                token_location="header" if auth_type in [AuthenticationType.BEARER, AuthenticationType.JWT] else "query",
                header_name="Authorization" if auth_type in [AuthenticationType.BEARER, AuthenticationType.JWT] else "X-API-Key"
            )
            auth_mechanisms.append(mechanism)
        
        return auth_mechanisms 