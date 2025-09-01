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
    """CVSS v3.1 Base Score Metrics with Full Scoring and Justification"""
    attack_vector: AttackVector = Field(..., description="Attack Vector")
    attack_complexity: AttackComplexity = Field(..., description="Attack Complexity")
    privileges_required: PrivilegesRequired = Field(..., description="Priviles Required")
    user_interaction: UserInteraction = Field(..., description="User Interaction")
    scope: Scope = Field(..., description="Scope")
    confidentiality_impact: Impact = Field(..., description="Confidentiality Impact")
    integrity_impact: Impact = Field(..., description="Integrity Impact")
    availability_impact: Impact = Field(..., description="Availability Impact")
    
    # Enhanced CVSS v3.1 scoring fields
    base_score: Optional[float] = Field(None, description="Calculated CVSS Base Score (0.0 to 10.0)")
    base_severity: Optional[str] = Field(None, description="Base severity rating (None, Low, Medium, High, Critical)")
    temporal_score: Optional[float] = Field(None, description="Temporal score if applicable")
    environmental_score: Optional[float] = Field(None, description="Environmental score if applicable")
    overall_score: Optional[float] = Field(None, description="Overall CVSS score")
    overall_severity: Optional[str] = Field(None, description="Overall severity rating")
    
    # Justification fields for each metric
    attack_vector_justification: Optional[str] = Field(None, description="Justification for attack vector selection")
    attack_complexity_justification: Optional[str] = Field(None, description="Justification for attack complexity")
    privileges_justification: Optional[str] = Field(None, description="Justification for privileges required")
    user_interaction_justification: Optional[str] = Field(None, description="Justification for user interaction")
    scope_justification: Optional[str] = Field(None, description="Justification for scope selection")
    impact_justification: Optional[str] = Field(None, description="Justification for impact assessments")
    
    # CVSS v3.1 specific fields
    exploitability_score: Optional[float] = Field(None, description="Exploitability subscore")
    impact_score: Optional[float] = Field(None, description="Impact subscore")
    
    @property
    def calculated_base_score(self) -> float:
        """Calculate CVSS v3.1 Base Score according to official specification"""
        # Calculate Impact Subscore
        impact_score = 0.0
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
        
        # If no impact, return 0
        if impact_score == 0.0:
            return 0.0
        
        # Calculate Exploitability Subscore
        exploitability_score = 8.22
        
        # Attack Vector multiplier
        if self.attack_vector == AttackVector.NETWORK:
            exploitability_score *= 0.85
        elif self.attack_vector == AttackVector.ADJACENT_NETWORK:
            exploitability_score *= 0.62
        elif self.attack_vector == AttackVector.LOCAL:
            exploitability_score *= 0.55
        elif self.attack_vector == AttackVector.PHYSICAL:
            exploitability_score *= 0.2
        
        # Attack Complexity multiplier
        if self.attack_complexity == AttackComplexity.HIGH:
            exploitability_score *= 0.45
        
        # Privileges Required multiplier (depends on scope)
        if self.scope == Scope.UNCHANGED:
            if self.privileges_required == PrivilegesRequired.NONE:
                exploitability_score *= 0.85
            elif self.privileges_required == PrivilegesRequired.LOW:
                exploitability_score *= 0.62
            elif self.privileges_required == PrivilegesRequired.HIGH:
                exploitability_score *= 0.27
        else:  # Scope Changed
            if self.privileges_required == PrivilegesRequired.NONE:
                exploitability_score *= 0.85
            elif self.privileges_required == PrivilegesRequired.LOW:
                exploitability_score *= 0.68
            elif self.privileges_required == PrivilegesRequired.HIGH:
                exploitability_score *= 0.50
        
        # User Interaction multiplier
        if self.user_interaction == UserInteraction.NONE:
            exploitability_score *= 0.85
        elif self.user_interaction == UserInteraction.REQUIRED:
            exploitability_score *= 0.62
        
        # Scope multiplier
        if self.scope == Scope.UNCHANGED:
            exploitability_score *= 6.42
        elif self.scope == Scope.CHANGED:
            exploitability_score *= 7.52
        
        # Calculate final base score
        base_score = min(10.0, max(0.0, impact_score + exploitability_score))
        
        # Round to 1 decimal place as per CVSS specification
        return round(base_score, 1)
    
    @property
    def calculated_severity(self) -> str:
        """Determine severity based on CVSS base score"""
        score = self.calculated_base_score
        if score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        elif score >= 0.1:
            return "Low"
        else:
            return "None"
    
    def calculate_scores(self):
        """Calculate all CVSS scores and update fields"""
        self.base_score = self.calculated_base_score
        self.base_severity = self.calculated_severity
        self.exploitability_score = self._calculate_exploitability_subscore()
        self.impact_score = self._calculate_impact_subscore()
        
        # For now, set overall scores same as base scores
        # In production, these would include temporal and environmental factors
        self.overall_score = self.base_score
        self.overall_severity = self.base_severity
    
    def _calculate_exploitability_subscore(self) -> float:
        """Calculate exploitability subscore component"""
        score = 8.22
        
        # Apply multipliers (same logic as in calculated_base_score)
        if self.attack_vector == AttackVector.NETWORK:
            score *= 0.85
        elif self.attack_vector == AttackVector.ADJACENT_NETWORK:
            score *= 0.62
        elif self.attack_vector == AttackVector.LOCAL:
            score *= 0.55
        elif self.attack_vector == AttackVector.PHYSICAL:
            score *= 0.2
        
        if self.attack_complexity == AttackComplexity.HIGH:
            score *= 0.45
        
        if self.scope == Scope.UNCHANGED:
            if self.privileges_required == PrivilegesRequired.NONE:
                score *= 0.85
            elif self.privileges_required == PrivilegesRequired.LOW:
                score *= 0.62
            elif self.privileges_required == PrivilegesRequired.HIGH:
                score *= 0.27
        else:
            if self.privileges_required == PrivilegesRequired.NONE:
                score *= 0.85
            elif self.privileges_required == PrivilegesRequired.LOW:
                score *= 0.68
            elif self.privileges_required == PrivilegesRequired.HIGH:
                score *= 0.50
        
        if self.user_interaction == UserInteraction.NONE:
            score *= 0.85
        elif self.user_interaction == UserInteraction.REQUIRED:
            score *= 0.62
        
        return round(score, 1)
    
    def _calculate_impact_subscore(self) -> float:
        """Calculate impact subscore component"""
        score = 0.0
        
        if self.confidentiality_impact == Impact.HIGH:
            score += 0.56
        elif self.confidentiality_impact == Impact.LOW:
            score += 0.22
            
        if self.integrity_impact == Impact.HIGH:
            score += 0.56
        elif self.integrity_impact == Impact.LOW:
            score += 0.22
            
        if self.availability_impact == Impact.HIGH:
            score += 0.56
        elif self.availability_impact == Impact.LOW:
            score += 0.22
        
        return round(score, 1)


class VulnerabilityDescription(BaseModel):
    """Detailed vulnerability description with technical analysis"""
    vulnerability_type: str = Field(..., description="Type of vulnerability")
    vulnerability_name: str = Field(..., description="Specific vulnerability name")
    description: str = Field(..., description="Detailed description of the vulnerability")
    technical_details: str = Field(..., description="Technical explanation of how the vulnerability works")
    root_cause: str = Field(..., description="Root cause analysis")
    attack_vectors: List[str] = Field(..., description="Possible attack vectors")
    prerequisites: List[str] = Field(..., description="Prerequisites for exploitation")
    exploitation_conditions: str = Field(..., description="Conditions required for successful exploitation")
    vulnerability_classification: str = Field(..., description="OWASP classification")
    cwe_id: Optional[str] = Field(None, description="Common Weakness Enumeration ID")
    cve_references: List[str] = Field(default_factory=list, description="Related CVE references")
    affected_components: List[str] = Field(..., description="System components affected")
    data_flow_analysis: str = Field(..., description="Data flow analysis for the vulnerability")
    architecture_impact: str = Field(..., description="Impact on system architecture")


class TechnicalImpactAnalysis(BaseModel):
    """Comprehensive technical impact analysis"""
    system_level_impact: str = Field(..., description="System-level technical impact")
    data_impact: str = Field(..., description="Impact on data integrity, confidentiality, and availability")
    network_impact: str = Field(..., description="Impact on network security and communication")
    application_impact: str = Field(..., description="Impact on application functionality and security")
    infrastructure_impact: str = Field(..., description="Impact on underlying infrastructure")
    integration_impact: str = Field(..., description="Impact on system integrations and APIs")
    performance_impact: str = Field(..., description="Performance and availability impact")
    scalability_impact: str = Field(..., description="Impact on system scalability")
    maintenance_impact: str = Field(..., description="Impact on system maintenance and operations")
    technical_risk_propagation: str = Field(..., description="How technical risks propagate through the system")
    cascading_effects: List[str] = Field(..., description="Cascading technical effects")
    recovery_complexity: str = Field(..., description="Complexity of technical recovery")
    technical_debt_implications: str = Field(..., description="Implications for technical debt")


class ProofOfConcept(BaseModel):
    """Enhanced proof-of-concept with detailed technical information"""
    poc_title: str = Field(..., description="Title of the proof-of-concept")
    poc_description: str = Field(..., description="Description of what the PoC demonstrates")
    target_environment: str = Field(..., description="Target environment for the PoC")
    prerequisites: List[str] = Field(..., description="Prerequisites for running the PoC")
    attack_scenario: str = Field(..., description="Detailed attack scenario")
    step_by_step_exploitation: List[str] = Field(..., description="Step-by-step exploitation process")
    code_implementation: str = Field(..., description="Complete code implementation")
    payload_details: Dict[str, Any] = Field(..., description="Detailed payload information")
    expected_results: str = Field(..., description="Expected results when PoC is successful")
    success_indicators: List[str] = Field(..., description="Indicators of successful exploitation")
    failure_indicators: List[str] = Field(..., description="Indicators of failed exploitation")
    safety_notes: str = Field(..., description="Safety notes and warnings")
    testing_environment: str = Field(..., description="Recommended testing environment")
    mitigation_during_testing: str = Field(..., description="Mitigation measures during testing")


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


class EnhancedSecurityTest(BaseModel):
    """Enhanced security test with comprehensive technical findings"""
    # Inherit from SecurityTest
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
    
    # Enhanced Technical Findings fields
    detailed_vulnerability_description: Optional[VulnerabilityDescription] = Field(None, description="Detailed vulnerability description")
    technical_impact_analysis: Optional[TechnicalImpactAnalysis] = Field(None, description="Technical impact analysis")
    enhanced_proof_of_concept: Optional[ProofOfConcept] = Field(None, description="Enhanced proof-of-concept")
    cvss_justification: Optional[str] = Field(None, description="Detailed CVSS scoring justification")
    technical_risk_assessment: Optional[str] = Field(None, description="Technical risk assessment")
    remediation_complexity: Optional[str] = Field(None, description="Complexity of remediation")
    testing_methodology: Optional[str] = Field(None, description="Testing methodology used")
    false_positive_analysis: Optional[str] = Field(None, description="False positive analysis")
    validation_methods: List[str] = Field(default_factory=list, description="Methods used to validate the vulnerability")


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
    recommendations: List[str] = Field(default_factory=list, description="Security recommendations")
    remediation_priority: List[str] = Field(default_factory=list, description="Prioritized remediation actions")
    
    # Report metadata
    generated_by: str = Field(..., description="Tool/agent that generated the report")
    generated_at: datetime = Field(default_factory=datetime.now, description="Report generation timestamp")
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