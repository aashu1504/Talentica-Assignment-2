#!/usr/bin/env python3
"""
Pydantic models for VAmPI API Discovery Agent
Defines the data structures for API discovery results and reports
"""

from typing import List, Dict, Optional, Any, Union
from enum import Enum
from datetime import datetime
from pydantic import BaseModel, Field, validator
import json


class RiskLevel(str, Enum):
    """Risk level enumeration for API endpoints"""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class HTTPMethod(str, Enum):
    """HTTP methods enumeration"""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class AuthenticationType(str, Enum):
    """Authentication type enumeration"""
    NONE = "None"
    BASIC = "Basic"
    BEARER = "Bearer"
    API_KEY = "API_Key"
    OAUTH2 = "OAuth2"
    JWT = "JWT"
    SESSION = "Session"
    CUSTOM = "Custom"


class ParameterType(str, Enum):
    """Parameter type enumeration"""
    STRING = "string"
    INTEGER = "integer"
    NUMBER = "number"
    BOOLEAN = "boolean"
    ARRAY = "array"
    OBJECT = "object"


class ParameterLocation(str, Enum):
    """Parameter location enumeration"""
    PATH = "path"
    QUERY = "query"
    BODY = "body"
    HEADERS = "headers"


class Parameter(BaseModel):
    """Parameter model for API endpoints"""
    name: str = Field(..., description="Parameter name")
    type: ParameterType = Field(..., description="Parameter data type")
    required: bool = Field(default=False, description="Whether parameter is required")
    description: Optional[str] = Field(None, description="Parameter description")
    example: Optional[Any] = Field(None, description="Example value")
    default: Optional[Any] = Field(None, description="Default value")
    enum: Optional[List[Any]] = Field(None, description="Allowed values")
    min_length: Optional[int] = Field(None, description="Minimum length for strings")
    max_length: Optional[int] = Field(None, description="Maximum length for strings")
    min_value: Optional[Union[int, float]] = Field(None, description="Minimum value for numbers")
    max_value: Optional[Union[int, float]] = Field(None, description="Maximum value for numbers")
    pattern: Optional[str] = Field(None, description="Regex pattern for validation")
    format: Optional[str] = Field(None, description="Data format (e.g., date, email)")


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
    methods: List[HTTPMethod] = Field(..., description="Supported HTTP methods")
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
    
    @validator('path')
    def validate_path(cls, v):
        """Ensure path starts with /"""
        if not v.startswith('/'):
            v = '/' + v
        return v
    
    def get_parameter_count(self) -> int:
        """Get total number of parameters across all locations"""
        return sum(len(params) for params in self.parameters.values())
    
    def get_required_parameters(self) -> List[Parameter]:
        """Get all required parameters"""
        required = []
        for params in self.parameters.values():
            required.extend([p for p in params if p.required])
        return required


class AuthenticationMechanism(BaseModel):
    """Authentication mechanism details"""
    type: AuthenticationType = Field(..., description="Type of authentication")
    name: str = Field(..., description="Name/identifier for the authentication mechanism")
    description: Optional[str] = Field(None, description="Description of the authentication method")
    
    # Configuration details
    config: Dict[str, Any] = Field(
        default_factory=dict,
        description="Configuration parameters for the authentication mechanism"
    )
    
    # Security assessment
    security_strength: str = Field(default="medium", description="Security strength rating")
    vulnerabilities: List[str] = Field(
        default_factory=list,
        description="Known vulnerabilities or weaknesses"
    )
    
    # Implementation details
    implementation_details: Optional[str] = Field(None, description="Implementation details")
    documentation_url: Optional[str] = Field(None, description="URL to documentation")
    
    # Metadata
    discovered_at: datetime = Field(default_factory=datetime.now, description="When authentication was discovered")
    endpoints_using: List[str] = Field(
        default_factory=list,
        description="List of endpoint IDs using this authentication"
    )


class APIStructure(BaseModel):
    """Overall API structure and organization"""
    base_url: str = Field(..., description="Base URL of the API")
    version: Optional[str] = Field(None, description="API version")
    title: Optional[str] = Field(None, description="API title/name")
    description: Optional[str] = Field(None, description="API description")
    
    # Organization
    base_path: Optional[str] = Field(None, description="Base path for all endpoints")
    schemes: List[str] = Field(default_factory=list, description="Supported schemes (http, https)")
    host: Optional[str] = Field(None, description="API host")
    port: Optional[int] = Field(None, description="API port")
    
    # Endpoint organization
    endpoint_groups: Dict[str, List[str]] = Field(
        default_factory=dict,
        description="Grouped endpoints by category or functionality"
    )
    
    # API metadata
    contact_info: Optional[Dict[str, str]] = Field(None, description="Contact information")
    license_info: Optional[Dict[str, str]] = Field(None, description="License information")
    external_docs: Optional[Dict[str, str]] = Field(None, description="External documentation links")
    
    # Discovery metadata
    discovered_at: datetime = Field(default_factory=datetime.now, description="When API structure was discovered")
    discovery_method: str = Field(..., description="Method used to discover API structure")


class DiscoverySummary(BaseModel):
    """Summary of API discovery results"""
    total_endpoints: int = Field(..., description="Total number of discovered endpoints")
    authenticated_endpoints: int = Field(..., description="Number of endpoints requiring authentication")
    public_endpoints: int = Field(..., description="Number of public endpoints")
    
    # Risk assessment summary
    high_risk_endpoints: int = Field(default=0, description="Number of high-risk endpoints")
    medium_risk_endpoints: int = Field(default=0, description="Number of medium-risk endpoints")
    low_risk_endpoints: int = Field(default=0, description="Number of low-risk endpoints")
    
    # Authentication summary
    authentication_types: List[AuthenticationType] = Field(
        default_factory=list,
        description="Types of authentication mechanisms found"
    )
    
    # Coverage metrics
    discovery_coverage: float = Field(..., description="Percentage of API surface discovered")
    parameter_coverage: float = Field(default=0.0, description="Percentage of parameters documented")
    
    # Discovery metadata
    discovery_start_time: datetime = Field(..., description="When discovery process started")
    discovery_end_time: Optional[datetime] = Field(None, description="When discovery process completed")
    discovery_duration: Optional[float] = Field(None, description="Discovery duration in seconds")
    
    # Statistics
    total_parameters: int = Field(default=0, description="Total number of parameters across all endpoints")
    unique_parameters: int = Field(default=0, description="Number of unique parameter names")
    
    @validator('discovery_coverage')
    def validate_coverage(cls, v):
        """Ensure coverage is between 0 and 100"""
        if not 0 <= v <= 100:
            raise ValueError('Coverage must be between 0 and 100')
        return v
    
    def calculate_risk_distribution(self) -> Dict[str, int]:
        """Calculate distribution of endpoints by risk level"""
        return {
            "critical": self.high_risk_endpoints,
            "high": self.high_risk_endpoints,
            "medium": self.medium_risk_endpoints,
            "low": self.low_risk_endpoints
        }


class DiscoveryReport(BaseModel):
    """Root model containing complete API discovery report"""
    # Core components
    discovery_summary: DiscoverySummary = Field(..., description="Summary of discovery results")
    endpoints: List[EndpointMetadata] = Field(..., description="List of discovered endpoints")
    authentication_mechanisms: List[AuthenticationMechanism] = Field(
        default_factory=list,
        description="List of authentication mechanisms"
    )
    api_structure: APIStructure = Field(..., description="Overall API structure")
    
    # Report metadata
    report_id: str = Field(..., description="Unique identifier for this report")
    generated_at: datetime = Field(default_factory=datetime.now, description="When report was generated")
    generator_version: str = Field(default="1.0.0", description="Version of the discovery agent")
    
    # Configuration
    discovery_config: Dict[str, Any] = Field(
        default_factory=dict,
        description="Configuration used for discovery"
    )
    
    # Additional metadata
    tags: List[str] = Field(default_factory=list, description="Tags for report categorization")
    notes: Optional[str] = Field(None, description="Additional notes about the discovery")
    
    class Config:
        """Pydantic configuration"""
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
        use_enum_values = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert model to dictionary"""
        return self.model_dump()
    
    def to_json(self, **kwargs) -> str:
        """Convert model to JSON string"""
        return self.model_dump_json(**kwargs)
    
    def save_to_file(self, filepath: str, **kwargs) -> None:
        """Save report to JSON file"""
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.model_dump(mode='json'), f, indent=2, ensure_ascii=False, **kwargs)
    
    @classmethod
    def load_from_file(cls, filepath: str) -> 'DiscoveryReport':
        """Load report from JSON file"""
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return cls(**data)
    
    def get_endpoint_by_id(self, endpoint_id: str) -> Optional[EndpointMetadata]:
        """Get endpoint by ID"""
        for endpoint in self.endpoints:
            if endpoint.id == endpoint_id:
                return endpoint
        return None
    
    def get_endpoints_by_risk_level(self, risk_level: RiskLevel) -> List[EndpointMetadata]:
        """Get all endpoints with specified risk level"""
        return [ep for ep in self.endpoints if ep.risk_level == risk_level]
    
    def get_endpoints_by_authentication(self, auth_required: bool = True) -> List[EndpointMetadata]:
        """Get endpoints by authentication requirement"""
        return [ep for ep in self.endpoints if ep.authentication_required == auth_required]
    
    def get_authentication_mechanism(self, auth_type: AuthenticationType) -> Optional[AuthenticationMechanism]:
        """Get authentication mechanism by type"""
        for auth in self.authentication_mechanisms:
            if auth.type == auth_type:
                return auth
        return None
    
    def update_summary_statistics(self) -> None:
        """Update summary statistics based on current data"""
        summary = self.discovery_summary
        
        # Update endpoint counts
        summary.total_endpoints = len(self.endpoints)
        summary.authenticated_endpoints = len([ep for ep in self.endpoints if ep.authentication_required])
        summary.public_endpoints = summary.total_endpoints - summary.authenticated_endpoints
        
        # Update risk level counts
        summary.high_risk_endpoints = len(self.get_endpoints_by_risk_level(RiskLevel.HIGH))
        summary.medium_risk_endpoints = len(self.get_endpoints_by_risk_level(RiskLevel.MEDIUM))
        summary.low_risk_endpoints = len(self.get_endpoints_by_risk_level(RiskLevel.LOW))
        
        # Update authentication types
        auth_types = set()
        for ep in self.endpoints:
            if ep.authentication_type:
                auth_types.add(ep.authentication_type)
        summary.authentication_types = list(auth_types)
        
        # Update parameter counts
        total_params = sum(ep.get_parameter_count() for ep in self.endpoints)
        summary.total_parameters = total_params
        
        # Calculate unique parameters
        unique_params = set()
        for ep in self.endpoints:
            for params in ep.parameters.values():
                unique_params.update(p.name for p in params)
        summary.unique_parameters = len(unique_params)


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
    timeout: float = Field(default=30.0, description="Request timeout in seconds")
    max_concurrent_requests: int = Field(default=5, description="Maximum concurrent requests")
    max_retries: int = Field(default=3, description="Maximum retry attempts")
    rate_limit_delay: float = Field(default=1.0, description="Delay between requests in seconds")
    user_agent: str = Field(default="VAmPI-Discovery-Agent/1.0", description="User agent string")
    scan_paths: List[str] = Field(default_factory=list, description="Specific paths to scan")
    exclude_paths: List[str] = Field(default_factory=list, description="Paths to exclude from scanning")
    respect_rate_limits: bool = Field(default=True, description="Whether to respect rate limits")


# Utility functions for working with models
def create_sample_discovery_report() -> DiscoveryReport:
    """Create a sample discovery report for testing"""
    # Create sample endpoint
    sample_endpoint = EndpointMetadata(
        id="sample-endpoint-1",
        path="/api/users",
        methods=[HTTPMethod.GET, HTTPMethod.POST],
        description="User management endpoint",
        parameters=EndpointParameters(
            query_params=["limit"],
            path_params=["user_id"],
            body_params=["user_data"],
            headers=["Authorization"]
        ),
        authentication_required=True,
        authentication_type=AuthenticationType.BEARER,
        risk_level=RiskLevel.MEDIUM,
        risk_factors=["User data exposure", "Authentication bypass"],
        response_types=["application/json"],
        discovered_via=DiscoveryMethod.DOCUMENTATION_PARSING,
        status_code=200,
        response_time=0.123,
        error_messages=[]
    )
    
    # Create sample authentication mechanism
    sample_auth = AuthenticationMechanism(
        type=AuthenticationType.BEARER,
        name="JWT Bearer Token",
        description="JWT-based authentication using Bearer tokens",
        security_strength="high",
        endpoints_using=["sample-endpoint-1"]
    )
    
    # Create sample API structure
    sample_structure = APIStructure(
        base_url="http://localhost:5000",
        title="Sample API",
        description="A sample API for demonstration",
        schemes=["http"],
        host="localhost",
        port=5000,
        discovery_method="Manual inspection"
    )
    
    # Create discovery summary
    summary = DiscoverySummary(
        total_endpoints=1,
        authenticated_endpoints=1,
        public_endpoints=0,
        discovery_coverage=25.0,
        discovery_start_time=datetime.now()
    )
    
    # Create and return the report
    report = DiscoveryReport(
        report_id="sample-report-001",
        discovery_summary=summary,
        endpoints=[sample_endpoint],
        authentication_mechanisms=[sample_auth],
        api_structure=sample_structure
    )
    
    # Update statistics
    report.update_summary_statistics()
    
    return report


if __name__ == "__main__":
    # Test the models by creating a sample report
    sample_report = create_sample_discovery_report()
    print("✅ Sample discovery report created successfully!")
    print(f"📊 Report ID: {sample_report.report_id}")
    print(f"🔍 Endpoints: {sample_report.discovery_summary.total_endpoints}")
    print(f"🔐 Authentication mechanisms: {len(sample_report.authentication_mechanisms)}")
    
    # Test JSON serialization
    json_output = sample_report.to_json(indent=2)
    print(f"\n📄 JSON output length: {len(json_output)} characters")
    
    # Test file operations
    test_file = "sample_report.json"
    sample_report.save_to_file(test_file)
    print(f"💾 Report saved to: {test_file}")
    
    # Test loading from file
    loaded_report = DiscoveryReport.load_from_file(test_file)
    print(f"📂 Report loaded from: {test_file}")
    print(f"🔄 Loaded report ID: {loaded_report.report_id}")
    
    # Clean up test file
    import os
    os.remove(test_file)
    print(f"🧹 Test file cleaned up: {test_file}") 