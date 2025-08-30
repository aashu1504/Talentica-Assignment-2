#!/usr/bin/env python3
"""
Integrated Security Assessment Demo for VAmPI API Discovery Agent

This script demonstrates the complete end-to-end security assessment capabilities:
1. API Discovery
2. Comprehensive Security Testing (OWASP Top 10)
3. NoSQL Injection Testing
4. Exploit Generation
5. CVSS Scoring
6. Professional Reporting

Run this script to see all security testing capabilities in action.
"""

import asyncio
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

# Add src directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from security_testing.engine import SecurityTestingEngine
from security_testing.models import SecurityTestSuite, OWASPCategory
from discovery import VAmPIDiscoveryEngine, DiscoveryConfig


class IntegratedSecurityDemo:
    """Demo class for integrated security assessment"""
    
    def __init__(self, base_url: str = "http://localhost:5000"):
        self.base_url = base_url
        self.security_engine = None
        self.discovery_engine = None
        
    def print_header(self, title: str):
        """Print a formatted header"""
        print("\n" + "="*60)
        print(f"🔒 {title}")
        print("="*60)
    
    def print_section(self, title: str):
        """Print a formatted section header"""
        print(f"\n📋 {title}")
        print("-" * 40)
    
    def print_success(self, message: str):
        """Print a success message"""
        print(f"✅ {message}")
    
    def print_info(self, message: str):
        """Print an info message"""
        print(f"ℹ️  {message}")
    
    def print_warning(self, message: str):
        """Print a warning message"""
        print(f"⚠️  {message}")
    
    def print_error(self, message: str):
        """Print an error message"""
        print(f"❌ {message}")
    
    async def check_vampi_status(self) -> bool:
        """Check if VAmPI API is running"""
        self.print_section("Checking VAmPI API Status")
        
        try:
            import requests
            response = requests.head(self.base_url, timeout=5)
            if response.status_code == 200:
                self.print_success(f"VAmPI API is running at {self.base_url}")
                return True
            else:
                self.print_warning(f"VAmPI API responded with status {response.status_code}")
                return False
        except Exception as e:
            self.print_error(f"VAmPI API is not accessible: {e}")
            self.print_info("Please start VAmPI API first:")
            self.print_info("  cd vampi-local && npm start")
            return False
    
    async def demonstrate_discovery(self):
        """Demonstrate API discovery capabilities"""
        self.print_section("API Discovery Demonstration")
        
        try:
            # Initialize discovery engine
            config = DiscoveryConfig(
                base_url=self.base_url,
                timeout=30,
                rate_limit_delay=1.0,
                max_retries=3,
                user_agent="VAmPI-Discovery-Agent/1.0"
            )
            
            self.discovery_engine = VAmPIDiscoveryEngine(config)
            self.print_success("Discovery engine initialized")
            
            # Run discovery
            self.print_info("Running API endpoint discovery...")
            result = await self.discovery_engine.discover_endpoints()
            
            if result and result.endpoints:
                self.print_success(f"Discovered {len(result.endpoints)} endpoints")
                
                # Save discovery results
                discovery_data = {
                    "discovery_summary": {
                        "target_application": "VAmPI",
                        "base_url": self.base_url,
                        "total_endpoints": len(result.endpoints),
                        "discovery_timestamp": datetime.now().isoformat()
                    },
                    "endpoints": [endpoint.dict() for endpoint in result.endpoints]
                }
                
                with open("discovered_endpoints.json", "w") as f:
                    json.dump(discovery_data, f, indent=2, default=str)
                
                self.print_success("Discovery results saved to discovered_endpoints.json")
                return discovery_data
            else:
                self.print_warning("No endpoints discovered")
                return None
                
        except Exception as e:
            self.print_error(f"Discovery failed: {e}")
            return None
    
    async def demonstrate_security_testing(self, discovery_data):
        """Demonstrate security testing capabilities"""
        self.print_section("Security Testing Demonstration")
        
        try:
            # Initialize security testing engine
            self.security_engine = SecurityTestingEngine(self.base_url)
            self.print_success("Security testing engine initialized")
            
            # Configure comprehensive test suite
            test_suite = SecurityTestSuite(
                suite_name="Comprehensive OWASP API Security Test Suite",
                suite_version="2.0.0",
                owasp_categories=[
                    OWASPCategory.INJECTION,
                    OWASPCategory.BROKEN_USER_AUTHENTICATION,
                    OWASPCategory.BROKEN_OBJECT_LEVEL_AUTHORIZATION,
                    OWASPCategory.BROKEN_FUNCTION_LEVEL_AUTHORIZATION,
                    OWASPCategory.SECURITY_MISCONFIGURATION
                ],
                injection_payloads=[
                    "' OR '1'='1",
                    "'; DROP TABLE users; --",
                    "<script>alert('XSS')</script>",
                    "admin'--",
                    "1' UNION SELECT * FROM users--",
                    "'; EXEC xp_cmdshell('dir');--"
                ],
                authentication_tests=[
                    "jwt_token_manipulation",
                    "missing_authentication",
                    "weak_authentication",
                    "session_fixation"
                ],
                authorization_tests=[
                    "horizontal_privilege_escalation",
                    "vertical_privilege_escalation",
                    "idor_vulnerability",
                    "function_level_access_control"
                ]
            )
            
            self.security_engine.test_suite = test_suite
            self.print_success("Comprehensive test suite configured")
            
            # Test a few endpoints for demonstration
            if discovery_data and discovery_data.get('endpoints'):
                endpoints_to_test = discovery_data['endpoints'][:3]  # Test first 3 endpoints
                
                self.print_info(f"Testing {len(endpoints_to_test)} endpoints for security vulnerabilities...")
                
                security_reports = []
                for endpoint in endpoints_to_test:
                    self.print_info(f"Testing endpoint: {endpoint.get('path', 'Unknown')}")
                    
                    # Prepare endpoint data for security testing
                    endpoint_data = {
                        'path': endpoint.get('path', ''),
                        'methods': endpoint.get('methods', ['GET']),
                        'parameters': endpoint.get('parameters', {})
                    }
                    
                    # Run security tests
                    report = await self.security_engine.test_endpoint_security(endpoint_data)
                    security_reports.append(report)
                    
                    # Show results
                    if report.vulnerabilities_found > 0:
                        self.print_warning(f"Found {report.vulnerabilities_found} vulnerabilities")
                        for test in report.security_tests:
                            if test.vulnerability_found:
                                self.print_warning(f"  - {test.test_name}: {test.severity} (Score: {test.risk_score:.1f})")
                                if test.proof_of_concept:
                                    self.print_success(f"    Proof of concept exploit generated")
                    else:
                        self.print_success("No vulnerabilities found")
                
                # Generate comprehensive security assessment report
                await self.generate_security_report(security_reports)
                
                return security_reports
            else:
                self.print_warning("No endpoints available for security testing")
                return None
                
        except Exception as e:
            self.print_error(f"Security testing failed: {e}")
            return None
    
    async def generate_security_report(self, security_reports):
        """Generate comprehensive security assessment report"""
        self.print_section("Generating Security Assessment Report")
        
        try:
            # Calculate overall statistics
            total_vulnerabilities = sum(r.vulnerabilities_found for r in security_reports)
            critical_vulns = sum(r.critical_vulnerabilities for r in security_reports)
            high_vulns = sum(r.high_vulnerabilities for r in security_reports)
            medium_vulns = sum(r.medium_vulnerabilities for r in security_reports)
            low_vulns = sum(r.low_vulnerabilities for r in security_reports)
            
            # Create comprehensive report
            assessment_report = {
                "report_id": f"SEC-{int(time.time())}",
                "target_application": "VAmPI",
                "base_url": self.base_url,
                "assessment_start_time": datetime.now().isoformat(),
                "assessment_end_time": datetime.now().isoformat(),
                "total_endpoints_tested": len(security_reports),
                "endpoints_with_vulnerabilities": len([r for r in security_reports if r.vulnerabilities_found > 0]),
                "total_vulnerabilities": total_vulnerabilities,
                "critical_vulnerabilities": critical_vulns,
                "high_vulnerabilities": high_vulns,
                "medium_vulnerabilities": medium_vulns,
                "low_vulnerabilities": low_vulns,
                "overall_risk_score": sum(r.overall_risk_score for r in security_reports) / len(security_reports) if security_reports else 0,
                "endpoint_reports": [r.dict() for r in security_reports],
                "test_suite_used": {
                    "suite_name": "Comprehensive OWASP API Security Test Suite",
                    "suite_version": "2.0.0",
                    "owasp_categories": ["Injection", "Broken Authentication", "Broken Authorization", "Security Misconfiguration"]
                },
                "executive_summary": f"Security assessment completed with {total_vulnerabilities} vulnerabilities found across {len(security_reports)} endpoints.",
                "risk_analysis": f"Critical: {critical_vulns}, High: {high_vulns}, Medium: {medium_vulns}, Low: {low_vulns}",
                "recommendations": [
                    "Immediate remediation required for critical and high severity vulnerabilities",
                    "Implement proper input validation and sanitization",
                    "Enforce authentication and authorization controls",
                    "Configure security headers and error handling"
                ],
                "remediation_priority": [
                    "Critical SQL/NoSQL injection vulnerabilities",
                    "Authentication bypass issues",
                    "Authorization flaws",
                    "Security misconfigurations"
                ],
                "generated_by": "VAmPI API Discovery Agent - Integrated Security Demo",
                "generated_at": datetime.now().isoformat(),
                "version": "2.0.0"
            }
            
            # Save report
            with open("security_assessment_report.json", "w") as f:
                json.dump(assessment_report, f, indent=2, default=str)
            
            self.print_success("Security assessment report generated: security_assessment_report.json")
            
            # Show summary
            self.print_section("Security Assessment Summary")
            self.print_info(f"Total Endpoints Tested: {len(security_reports)}")
            self.print_info(f"Endpoints with Vulnerabilities: {len([r for r in security_reports if r.vulnerabilities_found > 0])}")
            self.print_info(f"Total Vulnerabilities: {total_vulnerabilities}")
            self.print_info(f"Critical: {critical_vulns}, High: {high_vulns}, Medium: {medium_vulns}, Low: {low_vulns}")
            
        except Exception as e:
            self.print_error(f"Failed to generate security report: {e}")
    
    async def demonstrate_exploit_generation(self):
        """Demonstrate exploit generation capabilities"""
        self.print_section("Exploit Generation Demonstration")
        
        try:
            if not self.security_engine:
                self.print_warning("Security engine not initialized")
                return
            
            # Demonstrate exploit generation for different vulnerability types
            vulnerability_types = [
                ("SQL Injection", "' OR '1'='1", "/test", "GET", "id"),
                ("NoSQL Injection", '{"$gt": ""}', "/test", "POST", "query"),
                ("XSS", "<script>alert('XSS')</script>", "/test", "POST", "content"),
                ("Authentication Bypass", "", "/admin", "GET", None),
                ("JWT Vulnerability", "fake_token", "/api", "GET", None)
            ]
            
            for vuln_type, payload, endpoint, method, param in vulnerability_types:
                self.print_info(f"Generating exploit for {vuln_type}...")
                
                exploit_code = self.security_engine._generate_proof_of_concept(
                    vuln_type, payload, endpoint, method, param
                )
                
                if exploit_code:
                    self.print_success(f"✅ {vuln_type} exploit generated")
                    
                    # Save individual exploit
                    filename = f"exploit_{vuln_type.lower().replace(' ', '_')}.py"
                    with open(filename, "w") as f:
                        f.write(exploit_code)
                    
                    self.print_info(f"Exploit saved to: {filename}")
                else:
                    self.print_warning(f"❌ Failed to generate {vuln_type} exploit")
            
            self.print_success("Exploit generation demonstration completed")
            
        except Exception as e:
            self.print_error(f"Exploit generation failed: {e}")
    
    async def run_complete_demo(self):
        """Run the complete integrated security assessment demo"""
        self.print_header("VAmPI API Discovery Agent - Integrated Security Assessment Demo")
        
        # Check VAmPI status
        if not await self.check_vampi_status():
            self.print_error("Cannot proceed without VAmPI API running")
            return False
        
        # Step 1: API Discovery
        discovery_data = await self.demonstrate_discovery()
        if not discovery_data:
            self.print_error("Discovery failed, cannot proceed with security testing")
            return False
        
        # Step 2: Security Testing
        security_reports = await self.demonstrate_security_testing(discovery_data)
        if not security_reports:
            self.print_error("Security testing failed")
            return False
        
        # Step 3: Exploit Generation
        await self.demonstrate_exploit_generation()
        
        # Final summary
        self.print_header("Demo Completed Successfully!")
        self.print_success("All security testing capabilities demonstrated")
        self.print_success("Generated files:")
        self.print_info("  - discovered_endpoints.json (API discovery results)")
        self.print_info("  - security_assessment_report.json (Security assessment)")
        self.print_info("  - exploit_*.py files (Proof of concept exploits)")
        
        return True


async def main():
    """Main function to run the demo"""
    demo = IntegratedSecurityDemo()
    
    try:
        success = await demo.run_complete_demo()
        if success:
            print("\n🎉 Demo completed successfully!")
            print("Check the generated files to see the results.")
        else:
            print("\n💥 Demo failed. Check the error messages above.")
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n⏹️  Demo interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n💥 Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    # Run the demo
    asyncio.run(main()) 