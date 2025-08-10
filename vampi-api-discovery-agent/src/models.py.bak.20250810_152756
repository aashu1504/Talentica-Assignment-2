"""
Data models for VAmPI API Discovery Agent.

This module defines the Pydantic models used throughout the application
for structured data handling and validation.
"""

from datetime import datetime
from enum import Enum
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field, HttpUrl


class RiskLevel(str, Enum):
    """Risk level enumeration for API endpoints."""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class AuthenticationType(str, Enum):
    """Authentication type enumeration."""
    NONE = "None"
    JWT = "JWT"
    SESSION = "Session"
    API_KEY = "API_Key"
    BASIC = "Basic"
    OAUTH = "OAuth"


class DiscoveryMethod(str, Enum):
    """Method used to discover the endpoint."""
    ENDPOINT_SCANNING = "endpoint_scanning"
    DOCUMENTATION_PARSING = "documentation_parsing"
    ERROR_ANALYSIS = "error_analysis"
    RESPONSE_ANALYSIS = "response_analysis"
    PATTERN_RECOGNITION = "pattern_recognition"


class EndpointParameters(BaseModel):
    """Model for endpoint parameters."""
    query_params: List[str] = Field(default_factory=list, description="Query parameters")
    path_params: List[str] = Field(default_factory=list, description="Path parameters")
    body_params: List[str] = Field(default_factory=list, description="Body parameters")
    headers: List[str] = Field(default_factory=list, description="Required headers")


class EndpointMetadata(BaseModel):
    """Model for individual endpoint metadata."""
    id: str = Field(..., description="Unique endpoint identifier")
    path: str = Field(..., description="API endpoint path")
    methods: List[str] = Field(..., description="Supported HTTP methods")
    description: str = Field(..., description="Endpoint description")
    parameters: EndpointParameters = Field(..., description="Endpoint parameters")
    authentication_required: bool = Field(..., description="Whether authentication is required")
    authentication_type: AuthenticationType = Field(default=AuthenticationType.NONE, description="Type of authentication")
    risk_level: RiskLevel = Field(..., description="Security risk level")
    risk_factors: List[str] = Field(default_factory=list, description="Factors contributing to risk level")
    response_types: List[str] = Field(default_factory=list, description="Supported response content types")
    discovered_via: DiscoveryMethod = Field(..., description="Method used to discover this endpoint")
    status_code: Optional[int] = Field(None, description="HTTP status code from discovery")
    response_time: Optional[float] = Field(None, description="Response time in seconds")
    error_messages: List[str] = Field(default_factory=list, description="Error messages encountered during discovery")


class AuthenticationMechanism(BaseModel):
    """Model for authentication mechanisms."""
    type: AuthenticationType = Field(..., description="Authentication type")
    endpoints: List[str] = Field(..., description="Endpoints using this authentication")
    token_location: Optional[str] = Field(None, description="Where the token is located")
    header_name: Optional[str] = Field(None, description="Header name for authentication")
    cookie_name: Optional[str] = Field(None, description="Cookie name for authentication")
    parameter_name: Optional[str] = Field(None, description="Parameter name for authentication")


class APIStructure(BaseModel):
    """Model for API structure analysis."""
    base_paths: List[str] = Field(default_factory=list, description="Base API paths")
    versions: List[str] = Field(default_factory=list, description="API versions discovered")
    common_patterns: List[str] = Field(default_factory=list, description="Common API patterns")
    rate_limiting: Optional[Dict[str, Any]] = Field(None, description="Rate limiting information")
    cors_policy: Optional[Dict[str, Any]] = Field(None, description="CORS policy information")


class DiscoverySummary(BaseModel):
    """Model for discovery summary."""
    total_endpoints: int = Field(..., description="Total number of endpoints discovered")
    discovery_timestamp: datetime = Field(..., description="When the discovery was performed")
    target_application: str = Field(..., description="Target application name")
    base_url: HttpUrl = Field(..., description="Base URL of the target application")
    scan_duration: Optional[float] = Field(None, description="Total scan duration in seconds")
    success_rate: Optional[float] = Field(None, description="Percentage of successful endpoint discoveries")
    errors_encountered: List[str] = Field(default_factory=list, description="Errors encountered during discovery")


class APIDiscoveryResult(BaseModel):
    """Main model for API discovery results."""
    discovery_summary: DiscoverySummary = Field(..., description="Discovery summary information")
    endpoints: List[EndpointMetadata] = Field(..., description="List of discovered endpoints")
    authentication_mechanisms: List[AuthenticationMechanism] = Field(..., description="Authentication mechanisms")
    api_structure: APIStructure = Field(..., description="API structure analysis")
    security_insights: Optional[Dict[str, Any]] = Field(None, description="Additional security insights")
    recommendations: Optional[List[str]] = Field(None, description="Security recommendations")


class DiscoveryConfig(BaseModel):
    """Configuration for the discovery process."""
    base_url: str = Field(..., description="Base URL to scan")
    timeout: int = Field(default=30, description="Request timeout in seconds")
    max_retries: int = Field(default=3, description="Maximum retry attempts")
    rate_limit_delay: float = Field(default=1.0, description="Delay between requests in seconds")
    user_agent: str = Field(default="VAmPI-Discovery-Agent/1.0", description="User agent string")
    scan_paths: List[str] = Field(default_factory=list, description="Specific paths to scan")
    exclude_paths: List[str] = Field(default_factory=list, description="Paths to exclude from scanning")
    respect_rate_limits: bool = Field(default=True, description="Whether to respect rate limits")


class DiscoveryTask(BaseModel):
    """Model for discovery tasks."""
    task_id: str = Field(..., description="Unique task identifier")
    description: str = Field(..., description="Task description")
    status: str = Field(default="pending", description="Task status")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Task creation timestamp")
    completed_at: Optional[datetime] = Field(None, description="Task completion timestamp")
    result: Optional[APIDiscoveryResult] = Field(None, description="Task result")
    error: Optional[str] = Field(None, description="Error message if task failed") 