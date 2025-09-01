#!/usr/bin/env python3
"""
Security Testing Models for OWASP API Security Testing Agent

This module defines the data structures for API security testing results,
CVSS scoring, and vulnerability assessment reports.
"""

from typing import List, Dict, Optional, Any, Union
from enum import Enum
from datetime import datetime
from pydantic import BaseModel, Field, validator
import json


class OWASPCategory(str, Enum):
    """OWASP API Top 10 Security Categories"""
    BROKEN_OBJECT_LEVEL_AUTHORIZATION = "Broken Object Level Authorization"
    BROKEN_USER_AUTHENTICATION = "Broken User Authentication"
    BROKEN_FUNCTION_LEVEL_AUTHORIZATION = "Broken Function Level Authorization"
    MASS_ASSIGNMENT = "Mass Assignment"
    SECURITY_MISCONFIGURATION = "Security Misconfiguration"
    EXCESSIVE_DATA_EXPOSURE = "Excessive Data Exposure"
    INSUFFICIENT_LOGGING_MONITORING = "Insufficient Logging & Monitoring"
    INJECTION = "Injection"
    IMPROPER_ASSET_MANAGEMENT = "Improper Asset Management"
    BROKEN_RATE_LIMITING = "Broken Rate Limiting"
    BROKEN_CRYPTOGRAPHY = "Broken Cryptography"


class VulnerabilitySeverity(str, Enum):
    """Vulnerability severity levels based on CVSS"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class AttackVector(str, Enum):
    """CVSS Attack Vector types"""
    NETWORK = "Network"
    ADJACENT_NETWORK = "Adjacent Network"
    LOCAL = "Local"
    PHYSICAL = "Physical"


class AttackComplexity(str, Enum):
    """CVSS Attack Complexity levels"""
    LOW = "Low"
    HIGH = "High"


class PrivilegesRequired(str, Enum):
    """CVSS Privileges Required levels"""
    NONE = "None"
    LOW = "Low"
    HIGH = "High"


class UserInteraction(str, Enum):
    """CVSS User Interaction requirements"""
    NONE = "None"
    REQUIRED = "Required"


class Scope(str, Enum):
    """CVSS Scope impact"""
    UNCHANGED = "Unchanged"
    CHANGED = "Changed"


class Impact(str, Enum):
    """CVSS Impact levels"""
    NONE = "None"
    LOW = "Low"
    HIGH = "High"


class CVSSMetrics(BaseModel):
    """CVSS v3.1 Base Score Metrics"""
    attack_vector: AttackVector = Field(..., description="Attack Vector")
    attack_complexity: AttackComplexity = Field(..., description="Attack Complexity")
    privileges_required: PrivilegesRequired = Field(..., description="Privileges Required")
    user_interaction: UserInteraction = Field(..., description="User Interaction")
    scope: Scope = Field(..., description="Scope")
    confidentiality_impact: Impact = Field(..., description="Confidentiality Impact")
    integrity_impact: Impact = Field(..., description="Integrity Impact")
    availability_impact: Impact = Field(..., description="Availability Impact")
    
    @property
    def base_score(self) -> float:
        """Calculate CVSS Base Score (0.0 to 10.0)"""
        # Simplified CVSS calculation - in production, use proper CVSS library
        impact_score = 0
        if self.confidentiality_impact == Impact.HIGH:
            impact_score += 0.56
        elif self.confidentiality_impact == Impact.LOW:
            impact_score += 0.22
            
        if self.integrity_impact == Impact.HIGH:
            impact_score += 0.56
        elif self.integrity_impact == Impact.LOW:
            impact_score += 0.22
            
        if self.availability_impact == Impact.HIGH:
            impact_score += 0.56
        elif self.availability_impact == Impact.LOW:
            impact_score += 0.22
        
        if impact_score == 0:
            return 0.0
        
        exploitability = 8.22
        if self.attack_vector == AttackVector.NETWORK:
            exploitability *= 0.85
        elif self.attack_vector == AttackVector.ADJACENT_NETWORK:
            exploitability *= 0.62
        elif self.attack_vector == AttackVector.LOCAL:
            exploitability *= 0.55
        elif self.attack_vector == AttackVector.PHYSICAL:
            exploitability *= 0.2
            
        if self.attack_complexity == AttackComplexity.HIGH:
            exploitability *= 0.45
            
        if self.privileges_required == PrivilegesRequired.NONE:
            exploitability *= 0.85
        elif self.privileges_required == PrivilegesRequired.LOW:
            exploitability *= 0.62
        elif self.privileges_required == PrivilegesRequired.HIGH:
            exploitability *= 0.27
            
        if self.user_interaction == UserInteraction.NONE:
            exploitability *= 0.85
        elif self.user_interaction == UserInteraction.REQUIRED:
            exploitability *= 0.62
            
        if self.scope == Scope.UNCHANGED:
            exploitability *= 6.42
        elif self.scope == Scope.CHANGED:
            exploitability *= 7.52
        
        base_score = min(10.0, max(0.0, impact_score + exploitability))
        
        if base_score >= 9.0:
            return 9.0
        elif base_score >= 7.0:
            return 7.0
        elif base_score >= 4.0:
            return 4.0
        else:
            return 0.0


class SecurityTest(BaseModel):
    """Individual security test result"""
    test_name: str = Field(..., description="Name of the security test")
    test_category: OWASPCategory = Field(..., description="OWASP category")
    test_description: str = Field(..., description="Description of what was tested")
    test_method: str = Field(..., description="Method used for testing")
    payload_used: Optional[str] = Field(None, description="Payload used in testing")
    request_details: Optional[Dict[str, Any]] = Field(None, description="Request details")
    response_details: Optional[Dict[str, Any]] = Field(None, description="Response details")
    vulnerability_found: bool = Field(..., description="Whether vulnerability was found")
    vulnerability_details: Optional[str] = Field(None, description="Details about the vulnerability")
    cvss_metrics: Optional[CVSSMetrics] = Field(None, description="CVSS metrics if vulnerability found")
    severity: VulnerabilitySeverity = Field(..., description="Vulnerability severity")
    risk_score: float = Field(..., description="Risk score (0.0 to 10.0)")
    recommendations: List[str] = Field(default_factory=list, description="Security recommendations")
    proof_of_concept: Optional[str] = Field(None, description="Proof of concept exploit")
    test_timestamp: datetime = Field(default_factory=datetime.now, description="When test was performed")
    test_duration: Optional[float] = Field(None, description="Test duration in seconds")


class EndpointSecurityReport(BaseModel):
    """Security testing report for a single endpoint"""
    endpoint_path: str = Field(..., description="API endpoint path")
    http_methods: List[str] = Field(..., description="HTTP methods tested")
    total_tests: int = Field(..., description="Total number of security tests performed")
    tests_passed: int = Field(..., description="Number of tests that passed")
    tests_failed: int = Field(..., description="Number of tests that failed")
    vulnerabilities_found: int = Field(..., description="Number of vulnerabilities found")
    critical_vulnerabilities: int = Field(..., description="Number of critical vulnerabilities")
    high_vulnerabilities: int = Field(..., description="Number of high severity vulnerabilities")
    medium_vulnerabilities: int = Field(..., description="Number of medium severity vulnerabilities")
    low_vulnerabilities: int = Field(..., description="Number of low severity vulnerabilities")
    overall_risk_score: float = Field(..., description="Overall risk score for endpoint")
    security_tests: List[SecurityTest] = Field(default_factory=list, description="Individual test results")
    summary: str = Field(..., description="Summary of security assessment")
    recommendations: List[str] = Field(default_factory=list, description="Overall security recommendations")
    test_timestamp: datetime = Field(default_factory=datetime.now, description="When testing was performed")


class SecurityTestSuite(BaseModel):
    """Complete security testing suite configuration"""
    suite_name: str = Field(..., description="Name of the test suite")
    suite_version: str = Field(..., description="Version of the test suite")
    owasp_categories: List[OWASPCategory] = Field(..., description="OWASP categories to test")
    injection_payloads: List[str] = Field(default_factory=list, description="Injection attack payloads")
    authentication_tests: List[str] = Field(default_factory=list, description="Authentication test types")
    authorization_tests: List[str] = Field(default_factory=list, description="Authorization test types")
    rate_limiting_tests: List[str] = Field(default_factory=list, description="Rate limiting test types")
    cryptography_tests: List[str] = Field(default_factory=list, description="Cryptography test types")
    custom_tests: List[str] = Field(default_factory=list, description="Custom test types")
    enabled: bool = Field(default=True, description="Whether test suite is enabled")


class ComplianceStatus(BaseModel):
    """Compliance status for various regulatory frameworks"""
    gdpr_compliance: Dict[str, Any] = Field(default_factory=dict, description="GDPR compliance status")
    hipaa_compliance: Dict[str, Any] = Field(default_factory=dict, description="HIPAA compliance status")
    sox_compliance: Dict[str, Any] = Field(default_factory=dict, description="SOX compliance status")
    pci_dss_compliance: Dict[str, Any] = Field(default_factory=dict, description="PCI-DSS compliance status")
    iso_27001_compliance: Dict[str, Any] = Field(default_factory=dict, description="ISO 27001 compliance status")
    industry_standards: List[str] = Field(default_factory=list, description="Industry-specific compliance standards")
    audit_requirements: Dict[str, Any] = Field(default_factory=dict, description="Audit and compliance requirements")
    compliance_score: float = Field(default=0.0, description="Overall compliance score (0-100)")
    compliance_status: str = Field(default="NON_COMPLIANT", description="Overall compliance status")


class BusinessRiskImplications(BaseModel):
    """Enhanced business risk implications analysis"""
    financial_impact: Dict[str, Any] = Field(default_factory=dict, description="Financial risk assessment")
    reputation_risk: Dict[str, Any] = Field(default_factory=dict, description="Reputation and brand risk")
    operational_risk: Dict[str, Any] = Field(default_factory=dict, description="Operational continuity risk")
    competitive_risk: Dict[str, Any] = Field(default_factory=dict, description="Competitive advantage risk")
    legal_risk: Dict[str, Any] = Field(default_factory=dict, description="Legal and regulatory risk")
    customer_trust_risk: Dict[str, Any] = Field(default_factory=dict, description="Customer trust and retention risk")
    overall_business_risk_score: float = Field(default=0.0, description="Overall business risk score (0-100)")
    business_risk_level: str = Field(default="HIGH", description="Overall business risk level")


class ExecutiveDashboard(BaseModel):
    """Executive dashboard with key metrics and visualizations"""
    security_scorecard: Dict[str, Any] = Field(default_factory=dict, description="Security metrics scorecard")
    risk_heatmap: Dict[str, Any] = Field(default_factory=dict, description="Risk heatmap data")
    compliance_matrix: Dict[str, Any] = Field(default_factory=dict, description="Compliance matrix")
    trend_analysis: Dict[str, Any] = Field(default_factory=dict, description="Security trend analysis")
    kpi_metrics: Dict[str, Any] = Field(default_factory=dict, description="Key Performance Indicators")


class StakeholderSummary(BaseModel):
    """Stakeholder-specific summaries"""
    executive_summary: str = Field(default="", description="C-level executive summary")
    technical_summary: str = Field(default="", description="Technical team summary")
    compliance_summary: str = Field(default="", description="Compliance team summary")
    business_summary: str = Field(default="", description="Business stakeholders summary")
    board_summary: str = Field(default="", description="Board of directors summary")


class SecurityAssessmentReport(BaseModel):
    """Enhanced comprehensive security assessment report"""
    # Basic report information
    report_id: str = Field(..., description="Unique report identifier")
    target_application: str = Field(..., description="Target application name")
    base_url: str = Field(..., description="Base URL of the target application")
    
    # Assessment metadata
    assessment_start_time: datetime = Field(..., description="Assessment start timestamp")
    assessment_end_time: datetime = Field(..., description="Assessment end timestamp")
    assessment_duration: float = Field(..., description="Assessment duration in seconds")
    
    # Security metrics
    total_endpoints_tested: int = Field(..., description="Total number of endpoints tested")
    endpoints_with_vulnerabilities: int = Field(..., description="Number of endpoints with vulnerabilities")
    total_vulnerabilities: int = Field(..., description="Total number of vulnerabilities found")
    critical_vulnerabilities: int = Field(..., description="Number of critical vulnerabilities")
    high_vulnerabilities: int = Field(..., description="Number of high vulnerabilities")
    medium_vulnerabilities: int = Field(..., description="Number of medium vulnerabilities")
    low_vulnerabilities: int = Field(..., description="Number of low vulnerabilities")
    overall_risk_score: float = Field(..., description="Overall security risk score (0-10)")
    
    # Enhanced professional report sections
    executive_summary: str = Field(..., description="Executive summary for business stakeholders")
    compliance_status: ComplianceStatus = Field(default_factory=ComplianceStatus, description="Compliance status overview")
    business_risk_implications: BusinessRiskImplications = Field(default_factory=BusinessRiskImplications, description="Enhanced business risk analysis")
    executive_dashboard: ExecutiveDashboard = Field(default_factory=ExecutiveDashboard, description="Executive dashboard with key metrics")
    stakeholder_summaries: StakeholderSummary = Field(default_factory=StakeholderSummary, description="Stakeholder-specific summaries")
    
    # Technical details
    endpoint_reports: List[EndpointSecurityReport] = Field(..., description="Detailed endpoint security reports")
    test_suite_used: SecurityTestSuite = Field(..., description="Security test suite information")
    risk_analysis: str = Field(..., description="Detailed risk analysis")
    recommendations: List[str] = Field(..., description="Security recommendations")
    remediation_priority: List[str] = Field(..., description="Prioritized remediation actions")
    
    # Report metadata
    generated_by: str = Field(..., description="Tool/agent that generated the report")
    generated_at: datetime = Field(..., description="Report generation timestamp")
    version: str = Field(..., description="Report version")
    
    # Additional professional features
    executive_dashboard_data: Dict[str, Any] = Field(default_factory=dict, description="Executive dashboard data for visualizations")
    compliance_matrix_data: Dict[str, Any] = Field(default_factory=dict, description="Compliance matrix data")
    risk_heatmap_data: Dict[str, Any] = Field(default_factory=dict, description="Risk heatmap data")
    trend_analysis_data: Dict[str, Any] = Field(default_factory=dict, description="Security trend analysis data")


class SecurityTestResult(BaseModel):
    """Result of a security test execution"""
    success: bool = Field(..., description="Whether test executed successfully")
    test_name: str = Field(..., description="Name of the test")
    endpoint_path: str = Field(..., description="Endpoint being tested")
    http_method: str = Field(..., description="HTTP method used")
    payload: Optional[str] = Field(None, description="Payload used in test")
    request_headers: Optional[Dict[str, str]] = Field(None, description="Request headers")
    request_body: Optional[Dict[str, Any]] = Field(None, description="Request body")
    response_status: Optional[int] = Field(None, description="Response status code")
    response_headers: Optional[Dict[str, str]] = Field(None, description="Response headers")
    response_body: Optional[str] = Field(None, description="Response body")
    vulnerability_detected: bool = Field(..., description="Whether vulnerability was detected")
    vulnerability_type: Optional[str] = Field(None, description="Type of vulnerability")
    vulnerability_description: Optional[str] = Field(None, description="Vulnerability description")
    cvss_score: Optional[float] = Field(None, description="CVSS score if vulnerability found")
    risk_level: Optional[VulnerabilitySeverity] = Field(None, description="Risk level")
    recommendations: List[str] = Field(default_factory=list, description="Security recommendations")
    error_message: Optional[str] = Field(None, description="Error message if test failed")
    execution_time: float = Field(..., description="Test execution time in seconds")
    timestamp: datetime = Field(default_factory=datetime.now, description="When test was executed") 