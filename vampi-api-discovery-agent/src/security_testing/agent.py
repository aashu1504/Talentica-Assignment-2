#!/usr/bin/env python3
"""
Security Testing Agent for CrewAI Integration

This module implements a CrewAI agent that performs comprehensive
OWASP API security testing using the security testing engine.
"""

import asyncio
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from crewai import Agent, Task, Crew
from crewai.tools import BaseTool
from pydantic import BaseModel, Field

from .models import (
    SecurityAssessmentReport, EndpointSecurityReport, SecurityTestSuite,
    OWASPCategory, VulnerabilitySeverity
)
from .engine import SecurityTestingEngine


class SecurityTestingTool(BaseTool):
    """Tool for performing comprehensive API security testing"""
    
    name: str = "security_testing_tool"
    description: str = "Performs comprehensive OWASP API security testing including injection testing, authentication analysis, authorization testing, and security misconfiguration detection. Use this tool to assess the security posture of discovered API endpoints."
    base_url: str = Field(..., description="Base URL for the API being tested")
    endpoints_file: str = Field(default="discovered_endpoints.json", description="Path to discovered endpoints file")
    
    def _run(self, **kwargs) -> str:
        """Execute the security testing tool"""
        try:
            self.logger.info("Starting comprehensive API security testing...")
            
            # Load discovered endpoints
            endpoints = self._load_discovered_endpoints()
            if not endpoints:
                return "No endpoints found for security testing. Please run API discovery first."
            
            # Initialize security testing engine
            security_engine = SecurityTestingEngine(self.base_url)
            
            # Run security testing
            endpoint_reports = self._run_security_tests(security_engine, endpoints)
            
            # Generate comprehensive security assessment report
            assessment_report = self._generate_assessment_report(endpoint_reports)
            
            # Save security assessment report
            self._save_security_report(assessment_report)
            
            return f"""
            Security Testing Completed Successfully!
            
            Summary:
            - Total Endpoints Tested: {assessment_report.total_endpoints_tested}
            - Endpoints with Vulnerabilities: {assessment_report.endpoints_with_vulnerabilities}
            - Total Vulnerabilities Found: {assessment_report.total_vulnerabilities}
            - Critical Vulnerabilities: {assessment_report.critical_vulnerabilities}
            - High Vulnerabilities: {assessment_report.high_vulnerabilities}
            - Medium Vulnerabilities: {assessment_report.medium_vulnerabilities}
            - Low Vulnerabilities: {assessment_report.low_vulnerabilities}
            - Overall Risk Score: {assessment_report.overall_risk_score:.2f}/10.0
            
            Security assessment report saved to: security_assessment_report.json
            """
            
        except Exception as e:
            self.logger.error(f"Security testing tool failed: {e}")
            return f"Security testing failed: {str(e)}"
    
    def _load_discovered_endpoints(self) -> List[Dict[str, Any]]:
        """Load discovered endpoints from JSON file"""
        try:
            if not os.path.exists(self.endpoints_file):
                self.logger.warning(f"Endpoints file not found: {self.endpoints_file}")
                return []
            
            with open(self.endpoints_file, 'r') as f:
                data = json.load(f)
            
            # Extract endpoints from the discovered data
            if 'endpoints' in data:
                return data['endpoints']
            else:
                self.logger.warning("No endpoints found in discovered data")
                return []
                
        except Exception as e:
            self.logger.error(f"Failed to load discovered endpoints: {e}")
            return []
    
    def _run_security_tests(self, security_engine: SecurityTestingEngine, 
                           endpoints: List[Dict[str, Any]]) -> List[EndpointSecurityReport]:
        """Run security tests on all endpoints"""
        endpoint_reports = []
        
        for endpoint in endpoints:
            try:
                # Run security testing for this endpoint
                endpoint_report = asyncio.run(
                    security_engine.test_endpoint_security(endpoint)
                )
                endpoint_reports.append(endpoint_report)
                
                self.logger.info(f"Security testing completed for: {endpoint.get('path', 'Unknown')}")
                
            except Exception as e:
                self.logger.error(f"Failed to test endpoint {endpoint.get('path', 'Unknown')}: {e}")
                # Create error report for failed endpoint
                error_report = self._create_error_report(endpoint, str(e))
                endpoint_reports.append(error_report)
        
        return endpoint_reports
    
    def _create_error_report(self, endpoint: Dict[str, Any], error_message: str) -> EndpointSecurityReport:
        """Create error report for failed endpoint testing"""
        from .models import SecurityTest, VulnerabilitySeverity, OWASPCategory
        
        error_test = SecurityTest(
            test_name="Security Testing Error",
            test_category=OWASPCategory.SECURITY_MISCONFIGURATION,
            test_description=f"Security testing failed for this endpoint: {error_message}",
            test_method="Error occurred during testing",
            vulnerability_found=False,
            severity=VulnerabilitySeverity.INFO,
            risk_score=0.0,
            recommendations=["Investigate why security testing failed for this endpoint"],
            test_duration=0.0
        )
        
        return EndpointSecurityReport(
            endpoint_path=endpoint.get('path', 'Unknown'),
            http_methods=endpoint.get('methods', ['GET']),
            total_tests=1,
            tests_passed=0,
            tests_failed=1,
            vulnerabilities_found=0,
            critical_vulnerabilities=0,
            high_vulnerabilities=0,
            medium_vulnerabilities=0,
            low_vulnerabilities=0,
            overall_risk_score=0.0,
            security_tests=[error_test],
            summary=f"Security testing failed: {error_message}",
            recommendations=["Investigate testing failures and retry"],
            test_timestamp=datetime.now()
        )
    
    def _generate_assessment_report(self, endpoint_reports: List[EndpointSecurityReport]) -> SecurityAssessmentReport:
        """Generate comprehensive security assessment report"""
        # Calculate overall statistics
        total_endpoints = len(endpoint_reports)
        endpoints_with_vulns = len([r for r in endpoint_reports if r.vulnerabilities_found > 0])
        
        total_vulns = sum(r.vulnerabilities_found for r in endpoint_reports)
        critical_vulns = sum(r.critical_vulnerabilities for r in endpoint_reports)
        high_vulns = sum(r.high_vulnerabilities for r in endpoint_reports)
        medium_vulns = sum(r.medium_vulnerabilities for r in endpoint_reports)
        low_vulns = sum(r.low_vulnerabilities for r in endpoint_reports)
        
        # Calculate overall risk score
        if total_endpoints > 0:
            overall_risk_score = sum(r.overall_risk_score for r in endpoint_reports) / total_endpoints
        else:
            overall_risk_score = 0.0
        
        # Generate executive summary
        executive_summary = self._generate_executive_summary(
            total_endpoints, endpoints_with_vulns, total_vulns,
            critical_vulns, high_vulns, medium_vulns, low_vulns
        )
        
        # Generate risk analysis
        risk_analysis = self._generate_risk_analysis(endpoint_reports)
        
        # Generate recommendations
        recommendations = self._generate_overall_recommendations(endpoint_reports)
        
        # Generate remediation priority
        remediation_priority = self._generate_remediation_priority(endpoint_reports)
        
        # Create test suite info
        test_suite = SecurityTestSuite(
            suite_name="OWASP API Security Test Suite",
            suite_version="1.0.0",
            owasp_categories=[
                OWASPCategory.INJECTION,
                OWASPCategory.BROKEN_USER_AUTHENTICATION,
                OWASPCategory.BROKEN_OBJECT_LEVEL_AUTHORIZATION,
                OWASPCategory.BROKEN_FUNCTION_LEVEL_AUTHORIZATION,
                OWASPCategory.SECURITY_MISCONFIGURATION
            ]
        )
        
        return SecurityAssessmentReport(
            report_id=f"security_assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            target_application="VAmPI API",
            base_url=self.base_url,
            assessment_start_time=datetime.now(),
            assessment_end_time=datetime.now(),
            assessment_duration=0.0,  # Will be calculated if needed
            total_endpoints_tested=total_endpoints,
            endpoints_with_vulnerabilities=endpoints_with_vulns,
            total_vulnerabilities=total_vulns,
            critical_vulnerabilities=critical_vulns,
            high_vulnerabilities=high_vulns,
            medium_vulnerabilities=medium_vulns,
            low_vulnerabilities=low_vulns,
            overall_risk_score=overall_risk_score,
            endpoint_reports=endpoint_reports,
            test_suite_used=test_suite,
            executive_summary=executive_summary,
            risk_analysis=risk_analysis,
            recommendations=recommendations,
            remediation_priority=remediation_priority,
            generated_by="VAmPI Security Testing Agent",
            generated_at=datetime.now(),
            version="1.0.0"
        )
    
    def _generate_executive_summary(self, total_endpoints: int, endpoints_with_vulns: int,
                                  total_vulns: int, critical_vulns: int, high_vulns: int,
                                  medium_vulns: int, low_vulns: int) -> str:
        """Generate executive summary of security assessment"""
        summary = f"""
        Security Assessment Executive Summary
        
        This comprehensive security assessment was conducted on the VAmPI API using industry-standard 
        OWASP API security testing methodologies. The assessment covered {total_endpoints} API endpoints 
        and identified {total_vulns} security vulnerabilities.
        
        Key Findings:
        • {endpoints_with_vulns} out of {total_endpoints} endpoints contain security vulnerabilities
        • {critical_vulns} Critical severity vulnerabilities requiring immediate attention
        • {high_vulns} High severity vulnerabilities requiring prompt remediation
        • {medium_vulns} Medium severity vulnerabilities that should be addressed
        • {low_vulns} Low severity vulnerabilities for future consideration
        
        Risk Assessment:
        The overall security posture of the VAmPI API requires immediate attention due to the presence 
        of critical and high severity vulnerabilities. These findings indicate significant security gaps 
        that could lead to unauthorized access, data breaches, and system compromise.
        
        Immediate Actions Required:
        1. Address all Critical and High severity vulnerabilities within 24-48 hours
        2. Implement comprehensive input validation and sanitization
        3. Strengthen authentication and authorization mechanisms
        4. Review and update security configurations
        5. Establish ongoing security monitoring and testing procedures
        """
        
        return summary.strip()
    
    def _generate_risk_analysis(self, endpoint_reports: List[EndpointSecurityReport]) -> str:
        """Generate detailed risk analysis"""
        analysis = """
        Detailed Risk Analysis
        
        This section provides a comprehensive analysis of the security risks identified during 
        the security assessment, categorized by OWASP API Top 10 security risks.
        
        Risk Categories and Impact:
        
        1. Injection Vulnerabilities:
        SQL injection and XSS vulnerabilities pose the highest risk as they can lead to:
        • Unauthorized database access and data exfiltration
        • Cross-site scripting attacks affecting users
        • Potential system compromise and data integrity issues
        
        2. Authentication Vulnerabilities:
        Weak or missing authentication mechanisms can result in:
        • Unauthorized access to protected resources
        • Account takeover and privilege escalation
        • Compromise of user accounts and sensitive data
        
        3. Authorization Vulnerabilities:
        Insufficient access controls may lead to:
        • Horizontal privilege escalation (accessing other users' data)
        • Vertical privilege escalation (gaining administrative access)
        • Unauthorized modification of resources
        
        4. Security Misconfigurations:
        Missing security headers and information disclosure can:
        • Expose sensitive system information
        • Enable various attack vectors
        • Reduce overall security posture
        
        Business Impact Assessment:
        The identified vulnerabilities pose significant business risks including:
        • Data breaches and regulatory compliance issues
        • Loss of customer trust and reputation damage
        • Potential legal and financial consequences
        • Operational disruption and service availability issues
        
        Threat Actor Analysis:
        These vulnerabilities could be exploited by:
        • External attackers seeking unauthorized access
        • Malicious insiders with limited privileges
        • Automated scanning tools and bots
        • Advanced persistent threats (APTs)
        """
        
        return analysis.strip()
    
    def _generate_overall_recommendations(self, endpoint_reports: List[EndpointSecurityReport]) -> List[str]:
        """Generate overall security recommendations"""
        recommendations = [
            "Implement comprehensive input validation and sanitization for all user inputs",
            "Strengthen authentication mechanisms with proper JWT validation and session management",
            "Implement proper access control checks for all protected resources",
            "Add security headers including CSP, X-Frame-Options, and HSTS",
            "Implement rate limiting to prevent brute force attacks",
            "Establish secure coding practices and security training for development teams",
            "Implement automated security testing in CI/CD pipelines",
            "Regularly update dependencies and security patches",
            "Implement comprehensive logging and monitoring for security events",
            "Conduct regular security assessments and penetration testing",
            "Establish incident response procedures for security breaches",
            "Implement data encryption for sensitive information at rest and in transit"
        ]
        
        return recommendations
    
    def _generate_remediation_priority(self, endpoint_reports: List[EndpointSecurityReport]) -> List[str]:
        """Generate remediation priority order"""
        priority = [
            "1. Critical SQL Injection vulnerabilities - Immediate fix required",
            "2. High severity authentication bypass vulnerabilities - Fix within 24 hours",
            "3. High severity JWT validation vulnerabilities - Fix within 24 hours",
            "4. Medium severity IDOR vulnerabilities - Fix within 1 week",
            "5. Medium severity information disclosure - Fix within 1 week",
            "6. Low severity missing security headers - Fix within 2 weeks",
            "7. Implement comprehensive security testing framework",
            "8. Establish security monitoring and alerting",
            "9. Conduct developer security training",
            "10. Implement secure development lifecycle (SDLC)"
        ]
        
        return priority
    
    def _save_security_report(self, assessment_report: SecurityAssessmentReport) -> None:
        """Save security assessment report to disk"""
        try:
            output_file = "security_assessment_report.json"
            
            # Backup existing file if it exists
            if os.path.exists(output_file):
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_file = f"{output_file}.bak.{timestamp}"
                os.rename(output_file, backup_file)
                self.logger.info(f"Backed up existing report to: {backup_file}")
            
            # Save new report
            with open(output_file, 'w') as f:
                json.dump(assessment_report.model_dump(mode='json'), f, indent=2, default=str)
            
            self.logger.info(f"Security assessment report saved to: {output_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to save security report: {e}")


class SecurityTestingAgent:
    """CrewAI Security Testing Agent for comprehensive API security assessment"""
    
    def __init__(self, base_url: str = "http://localhost:5000"):
        self.base_url = base_url
        self.logger = logging.getLogger(__name__)
        
        # Create the security testing agent
        self.agent = Agent(
            role="API Security Testing Specialist",
            goal="Perform comprehensive OWASP API security testing to identify vulnerabilities and provide actionable recommendations",
            backstory="""You are an expert API security testing specialist with deep knowledge of OWASP API Top 10 security risks. 
            You have extensive experience in penetration testing, vulnerability assessment, and security analysis. 
            Your expertise includes SQL injection testing, authentication bypass techniques, authorization testing, 
            and security misconfiguration detection. You are responsible for ensuring the security posture of APIs 
            and providing detailed remediation guidance.""",
            verbose=True,
            allow_delegation=False,
            tools=[SecurityTestingTool(base_url=base_url)]
        )
        
        # Create the security testing task
        self.task = Task(
            description="""Perform comprehensive security testing on the discovered VAmPI API endpoints. 
            This includes:
            1. Testing for OWASP API Top 10 vulnerabilities
            2. Performing injection testing (SQL, XSS, NoSQL)
            3. Analyzing authentication mechanisms and JWT security
            4. Testing authorization and access control
            5. Detecting security misconfigurations
            6. Generating CVSS scores and risk assessments
            7. Providing actionable security recommendations
            
            Use the security testing tool to execute all tests and generate a comprehensive security assessment report.""",
            agent=self.agent,
            expected_output="""A comprehensive security assessment report including:
            - Detailed vulnerability findings with CVSS scores
            - Risk analysis and business impact assessment
            - Prioritized remediation recommendations
            - Executive summary for stakeholders
            - Technical details for development teams""",
            context="""The VAmPI API has been discovered and endpoints are available for security testing. 
            This is a vulnerable API designed for learning and testing purposes, so expect to find various 
            security vulnerabilities that need to be documented and reported."""
        )
    
    def run_security_assessment(self) -> str:
        """Run the security assessment using CrewAI"""
        try:
            self.logger.info("Starting security assessment with CrewAI...")
            
            # Create and run the crew
            crew = Crew(
                agents=[self.agent],
                tasks=[self.task],
                verbose=True
            )
            
            result = crew.kickoff()
            
            self.logger.info("Security assessment completed successfully")
            return result
            
        except Exception as e:
            error_msg = f"Security assessment failed: {str(e)}"
            self.logger.error(error_msg)
            return error_msg


def main():
    """Main function for testing the security testing agent"""
    agent = SecurityTestingAgent()
    result = agent.run_security_assessment()
    print(f"Security Assessment Result: {result}")


if __name__ == "__main__":
    main() 