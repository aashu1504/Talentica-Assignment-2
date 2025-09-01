#!/usr/bin/env python3
"""
Technical Findings Generator for Enhanced Security Reports

This module generates comprehensive technical findings including:
- Detailed vulnerability descriptions
- Accurate CVSS v3.1 scoring with justification
- Technical impact analysis
- Enhanced proof-of-concept demonstrations
"""

import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

from .models import (
    CVSSMetrics, VulnerabilityDescription, TechnicalImpactAnalysis,
    ProofOfConcept, AttackVector, AttackComplexity, PrivilegesRequired,
    UserInteraction, Scope, Impact, VulnerabilitySeverity
)


class TechnicalFindingsGenerator:
    """Generator for comprehensive technical findings"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Vulnerability type definitions and CWE mappings
        self.vulnerability_definitions = {
            "SQL_INJECTION": {
                "name": "SQL Injection",
                "cwe_id": "CWE-89",
                "description": "SQL injection vulnerability allows attackers to manipulate database queries through user input",
                "technical_details": "The application fails to properly validate and sanitize user input before using it in SQL queries, allowing malicious SQL code to be executed in the database context.",
                "root_cause": "Lack of input validation, use of string concatenation for SQL queries instead of parameterized queries, missing input sanitization",
                "attack_vectors": ["URL parameters", "Form inputs", "HTTP headers", "JSON payloads", "XML payloads"],
                "prerequisites": ["Direct database access", "User input used in SQL queries", "Lack of input validation"],
                "exploitation_conditions": "User input is directly concatenated into SQL queries without proper sanitization or parameterization",
                "vulnerability_classification": "OWASP Top 10 - A03:2021 - Injection",
                "affected_components": ["Database layer", "Application logic", "Data access layer", "API endpoints"],
                "data_flow_analysis": "User input flows from HTTP request → Application logic → Database query without validation",
                "architecture_impact": "Compromises the entire database layer and potentially the underlying infrastructure"
            },
            "XSS": {
                "name": "Cross-Site Scripting (XSS)",
                "cwe_id": "CWE-79",
                "description": "XSS allows attackers to inject malicious scripts into web pages viewed by other users",
                "technical_details": "The application fails to properly encode or validate user input before rendering it in HTML output, allowing execution of arbitrary JavaScript code.",
                "root_cause": "Lack of output encoding, insufficient input validation, missing Content Security Policy",
                "attack_vectors": ["URL parameters", "Form inputs", "HTTP headers", "JSON responses", "Error messages"],
                "prerequisites": ["User input rendered in HTML output", "Lack of output encoding", "Missing CSP headers"],
                "exploitation_conditions": "User input is rendered in HTML context without proper encoding or sanitization",
                "vulnerability_classification": "OWASP Top 10 - A03:2021 - Injection",
                "affected_components": ["Frontend rendering", "API responses", "Error handling", "User interface"],
                "data_flow_analysis": "User input flows from HTTP request → Application logic → HTML output without encoding",
                "architecture_impact": "Compromises client-side security and user session integrity"
            }
        }
        
        # Technical impact templates
        self.impact_templates = {
            "SQL_INJECTION": {
                "system_level_impact": "Complete database compromise leading to data exfiltration, data manipulation, and potential system takeover",
                "data_impact": "High risk of data breach, unauthorized data access, data corruption, and loss of data integrity",
                "network_impact": "Potential network access through database server, lateral movement within infrastructure",
                "application_impact": "Application functionality compromise, unauthorized data access, potential application takeover",
                "infrastructure_impact": "Database server compromise, potential access to underlying operating system and infrastructure",
                "integration_impact": "Compromise of integrated systems, API access through database connections, data flow disruption",
                "performance_impact": "Database performance degradation, potential denial of service through malicious queries",
                "scalability_impact": "Reduced system reliability, compromised scaling capabilities, increased maintenance overhead",
                "maintenance_impact": "Complex incident response, potential data recovery requirements, system rebuild considerations",
                "technical_risk_propagation": "Risk propagates from application layer through database to infrastructure and integrated systems",
                "cascading_effects": ["Data breach", "Regulatory non-compliance", "Customer trust loss", "Legal consequences", "Financial losses"],
                "recovery_complexity": "High - requires incident response, data assessment, system hardening, and potential rebuild",
                "technical_debt_implications": "Significant technical debt in security architecture, requires comprehensive security review and redesign"
            },
            "XSS": {
                "system_level_impact": "Client-side security compromise, potential session hijacking, and user account takeover",
                "data_impact": "User session data compromise, potential access to sensitive user information, data exfiltration",
                "network_impact": "Client-side network requests manipulation, potential internal network access through user browsers",
                "application_impact": "User interface compromise, potential application logic manipulation, client-side security bypass",
                "infrastructure_impact": "Limited direct infrastructure impact, but can lead to secondary attacks and data compromise",
                "integration_impact": "Potential compromise of integrated third-party services, API abuse through user sessions",
                "performance_impact": "Client-side performance degradation, potential browser-based denial of service",
                "scalability_impact": "Reduced user trust, potential user abandonment, reputation damage affecting scalability",
                "maintenance_impact": "Client-side security monitoring, incident response for affected users, trust rebuilding",
                "technical_risk_propagation": "Risk propagates from application to client browsers, potentially affecting multiple users",
                "cascading_effects": ["Session hijacking", "User account compromise", "Data theft", "Reputation damage", "Regulatory issues"],
                "recovery_complexity": "Medium - requires client-side security fixes, user notification, and trust rebuilding",
                "technical_debt_implications": "Technical debt in client-side security, requires frontend security review and CSP implementation"
            }
        }
    
    def generate_detailed_vulnerability_description(self, vulnerability_type: str, 
                                                 endpoint: str, method: str, 
                                                 parameter: str, payload: str) -> VulnerabilityDescription:
        """Generate detailed vulnerability description"""
        
        # Get base definition
        base_def = self.vulnerability_definitions.get(vulnerability_type, {})
        
        # Customize description based on specific context
        custom_description = f"{base_def.get('description', '')} in the {endpoint} endpoint using {method} method with parameter '{parameter}'."
        
        custom_technical_details = f"{base_def.get('technical_details', '')} Specifically, the '{parameter}' parameter accepts the payload '{payload}' which demonstrates the vulnerability."
        
        custom_root_cause = f"{base_def.get('root_cause', '')} In this case, the application fails to properly validate the '{parameter}' parameter before processing."
        
        custom_exploitation_conditions = f"{base_def.get('exploitation_conditions', '')} The payload '{payload}' can be sent to {endpoint} via {method} request to exploit this vulnerability."
        
        return VulnerabilityDescription(
            vulnerability_type=vulnerability_type,
            vulnerability_name=base_def.get('name', vulnerability_type),
            description=custom_description,
            technical_details=custom_technical_details,
            root_cause=custom_root_cause,
            attack_vectors=base_def.get('attack_vectors', []),
            prerequisites=base_def.get('prerequisites', []),
            exploitation_conditions=custom_exploitation_conditions,
            vulnerability_classification=base_def.get('vulnerability_classification', ''),
            cwe_id=base_def.get('cwe_id', ''),
            cve_references=base_def.get('cve_references', []),
            affected_components=base_def.get('affected_components', []),
            data_flow_analysis=base_def.get('data_flow_analysis', ''),
            architecture_impact=base_def.get('architecture_impact', '')
        )
    
    def generate_technical_impact_analysis(self, vulnerability_type: str, 
                                         severity: str, endpoint: str) -> TechnicalImpactAnalysis:
        """Generate comprehensive technical impact analysis"""
        
        # Get base impact template
        base_impact = self.impact_templates.get(vulnerability_type, {})
        
        # Customize based on severity and context
        custom_system_impact = f"{base_impact.get('system_level_impact', '')} This {severity.lower()} severity vulnerability affects the {endpoint} endpoint."
        
        # Customize recovery complexity based on severity
        recovery_complexity_map = {
            "Critical": "Very High - requires immediate incident response and potential system rebuild",
            "High": "High - requires comprehensive incident response and system hardening",
            "Medium": "Medium - requires security fixes and monitoring implementation",
            "Low": "Low - requires security patches and basic monitoring",
            "Info": "Minimal - requires basic security review"
        }
        
        return TechnicalImpactAnalysis(
            system_level_impact=custom_system_impact,
            data_impact=base_impact.get('data_impact', ''),
            network_impact=base_impact.get('network_impact', ''),
            application_impact=base_impact.get('application_impact', ''),
            infrastructure_impact=base_impact.get('infrastructure_impact', ''),
            integration_impact=base_impact.get('integration_impact', ''),
            performance_impact=base_impact.get('performance_impact', ''),
            scalability_impact=base_impact.get('scalability_impact', ''),
            maintenance_impact=base_impact.get('maintenance_impact', ''),
            technical_risk_propagation=base_impact.get('technical_risk_propagation', ''),
            cascading_effects=base_impact.get('cascading_effects', []),
            recovery_complexity=recovery_complexity_map.get(severity, 'Unknown'),
            technical_debt_implications=base_impact.get('technical_debt_implications', '')
        )
    
    def generate_cvss_justification(self, cvss_metrics: CVSSMetrics, 
                                   vulnerability_type: str, endpoint: str) -> str:
        """Generate detailed CVSS scoring justification"""
        
        justification = f"CVSS v3.1 Scoring Justification for {vulnerability_type} vulnerability in {endpoint}:\n\n"
        
        # Attack Vector justification
        justification += f"**Attack Vector (AV): {cvss_metrics.attack_vector.value}**\n"
        justification += f"Justification: {cvss_metrics.attack_vector_justification or 'The vulnerability can be exploited remotely over the network without requiring physical or local access to the target system.'}\n\n"
        
        # Attack Complexity justification
        justification += f"**Attack Complexity (AC): {cvss_metrics.attack_complexity.value}**\n"
        justification += f"Justification: {cvss_metrics.attack_complexity_justification or 'The attack requires no special conditions or extenuating circumstances to be exploited.'}\n\n"
        
        # Privileges Required justification
        justification += f"**Attack Complexity (AC): {cvss_metrics.attack_complexity.value}**\n"
        justification += f"Justification: {cvss_metrics.attack_complexity_justification or 'The attack requires no special conditions or extenuating circumstances to be exploited.'}\n\n"
        
        # User Interaction justification
        justification += f"**User Interaction (UI): {cvss_metrics.user_interaction.value}**\n"
        justification += f"Justification: {cvss_metrics.user_interaction_justification or 'The vulnerability can be exploited without any user interaction beyond the attacker.'}\n\n"
        
        # Scope justification
        justification += f"**Scope (S): {cvss_metrics.scope.value}**\n"
        justification += f"Justification: {cvss_metrics.scope_justification or 'The vulnerable component affects resources beyond its own security scope.'}\n\n"
        
        # Impact justifications
        justification += f"**Confidentiality Impact (C): {cvss_metrics.confidentiality_impact.value}**\n"
        justification += f"Justification: {cvss_metrics.impact_justification or 'There is a total loss of confidentiality, resulting in all resources within the impacted component being divulged to the attacker.'}\n\n"
        
        justification += f"**Integrity Impact (I): {cvss_metrics.integrity_impact.value}**\n"
        justification += f"Justification: {cvss_metrics.impact_justification or 'There is a total loss of integrity, resulting in the attacker being able to modify any/all data within the impacted component.'}\n\n"
        
        justification += f"**Availability Impact (A): {cvss_metrics.availability_impact.value}**\n"
        justification += f"Justification: {cvss_metrics.impact_justification or 'There is a total loss of availability, resulting in the attacker being able to deny access to resources within the impacted component.'}\n\n"
        
        # Score calculation explanation
        justification += f"**Score Calculation:**\n"
        justification += f"Base Score: {cvss_metrics.base_score}\n"
        justification += f"Exploitability Subscore: {cvss_metrics.exploitability_score}\n"
        justification += f"Impact Subscore: {cvss_metrics.impact_score}\n"
        justification += f"Overall Severity: {cvss_metrics.base_severity}\n\n"
        
        justification += f"This scoring follows the official CVSS v3.1 specification and represents the intrinsic characteristics of the vulnerability that are constant over time and across user environments."
        
        return justification
    
    def enhance_cvss_metrics(self, cvss_metrics: CVSSMetrics, 
                            vulnerability_type: str, endpoint: str) -> CVSSMetrics:
        """Enhance CVSS metrics with justification and calculated scores"""
        
        # Add justifications based on vulnerability type and context
        if vulnerability_type == "SQL_INJECTION":
            cvss_metrics.attack_vector_justification = "SQL injection can be exploited remotely over the network without requiring physical or local access to the target system."
            cvss_metrics.attack_complexity_justification = "The attack requires no special conditions or extenuating circumstances to be exploited. Standard SQL injection techniques are well-documented and easily accessible."
            cvss_metrics.privileges_justification = "The attacker requires no privileges to exploit the vulnerability. Any unauthenticated user can potentially exploit this vulnerability."
            cvss_metrics.user_interaction_justification = "The vulnerability can be exploited without any user interaction beyond the attacker. No user cooperation is required."
            cvss_metrics.scope_justification = "The vulnerable component affects resources beyond its own security scope. Database access can lead to compromise of other system components."
            cvss_metrics.impact_justification = "SQL injection can lead to complete data compromise, unauthorized access to sensitive information, and potential system takeover."
        
        elif vulnerability_type == "XSS":
            cvss_metrics.attack_vector_justification = "XSS can be exploited remotely over the network through web requests without requiring physical or local access."
            cvss_metrics.attack_complexity_justification = "The attack requires no special conditions. Standard XSS payloads are well-documented and easily accessible."
            cvss_metrics.privileges_justification = "The attacker requires no privileges to exploit the vulnerability. Any user can potentially exploit this vulnerability."
            cvss_metrics.user_interaction_justification = "The vulnerability can be exploited without any user interaction beyond the attacker. No user cooperation is required."
            cvss_metrics.scope_justification = "The vulnerable component affects resources beyond its own security scope. Client-side execution can affect user sessions and data."
            cvss_metrics.impact_justification = "XSS can lead to session hijacking, user account compromise, and unauthorized access to sensitive user information."
        
        # Calculate all scores
        cvss_metrics.calculate_scores()
        
        return cvss_metrics
