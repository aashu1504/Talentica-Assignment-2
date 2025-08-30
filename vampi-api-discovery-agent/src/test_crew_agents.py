#!/usr/bin/env python3
"""
VAmPI API Discovery & Security Testing Agent - CrewAI Orchestration Test

This script uses CrewAI to orchestrate four specialized agents in a sequential workflow:
1. API Discovery Specialist - Discovers and analyzes API endpoints
2. QA Testing Engineer - Tests discovered endpoints for basic vulnerabilities
3. Security Testing Specialist - Performs comprehensive OWASP API security testing with CVSS scoring
4. Technical Writer & Security Analyst - Generates comprehensive reports combining all findings

The workflow creates a complete end-to-end security assessment:
- API Discovery → QA Testing → Security Testing → Report Generation
- Each phase builds upon the previous phase's results
- Security testing includes OWASP API Top 10 vulnerability assessment
- Final reports combine discovery, QA, and security testing findings

Each agent uses Google Gemini 2.5 Flash for intelligent execution.
"""

import os
import sys
from pathlib import Path
import asyncio
from typing import List, Dict, Any

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent))

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

# CrewAI imports
from crewai import Agent, Task, Crew, Process, LLM
from crewai.tools.base_tool import BaseTool

# Import our custom tools
from tools import APIDiscoveryTool, QATestingTool, TechnicalWriterTool

# Import security testing components
from security_testing import SecurityTestingEngine
from security_testing.models import SecurityAssessmentReport, EndpointSecurityReport
from datetime import datetime
import json
import os

# Create security testing tool
class SecurityTestingTool(BaseTool):
    """Tool for performing comprehensive OWASP API security testing"""
    
    name: str = "security_testing_tool"
    description: str = "Performs comprehensive OWASP API security testing including injection testing, authentication analysis, authorization testing, and security misconfiguration detection. Use this tool to assess the security posture of discovered API endpoints."
    base_url: str = None
    api_key: str = None
    
    def __init__(self, base_url: str, api_key: str):
        super().__init__()
        self.base_url = base_url
        self.api_key = api_key
    
    def _run(self, **kwargs) -> str:
        """Execute the security testing tool"""
        try:
            print("🔒 Starting comprehensive API security testing...")
            
            # Check if discovery results exist
            if not os.path.exists("temp_discovery_results.json"):
                return "No discovery results found. Please run API discovery first."
            
            # Load discovered endpoints
            with open("temp_discovery_results.json", 'r') as f:
                discovery_data = json.load(f)
            
            # Extract endpoints from the nested structure
            endpoints = discovery_data.get('discovery_data', {}).get('endpoints', [])
            if not endpoints:
                return "No endpoints found for security testing. Please run API discovery first."
            
            print(f"📊 Found {len(endpoints)} endpoints for security testing")
            
            # Initialize security testing engine
            security_engine = SecurityTestingEngine(self.base_url)
            
            # Run security testing on all endpoints
            endpoint_reports = []
            for i, endpoint in enumerate(endpoints):
                try:
                    print(f"🔍 Testing endpoint {i+1}/{len(endpoints)}: {endpoint.get('path', 'Unknown')}")
                    
                    # Convert discovery format to security testing format
                    endpoint_data = {
                        'path': endpoint.get('path', ''),
                        'methods': endpoint.get('methods', ['GET']),  # Use 'methods' field (array)
                        'parameters': endpoint.get('parameters', {}),
                        'description': endpoint.get('description', ''),
                        'risk_level': endpoint.get('risk_level', 'Medium'),
                        'auth_required': endpoint.get('authentication_required', False)  # Use 'authentication_required' field
                    }
                    
                    # Run security testing for this endpoint
                    endpoint_report = asyncio.run(
                        security_engine.test_endpoint_security(endpoint_data)
                    )
                    endpoint_reports.append(endpoint_report)
                    
                except Exception as e:
                    print(f"❌ Failed to test endpoint {endpoint.get('path', 'Unknown')}: {e}")
                    # Create error report for failed endpoint
                    from security_testing.models import SecurityTest, VulnerabilitySeverity, OWASPCategory
                    
                    error_test = SecurityTest(
                        test_name="Security Testing Error",
                        test_category=OWASPCategory.SECURITY_MISCONFIGURATION,
                        test_description=f"Security testing failed: {str(e)}",
                        test_method="Error occurred during testing",
                        vulnerability_found=False,
                        severity=VulnerabilitySeverity.INFO,
                        risk_score=0.0,
                        recommendations=["Investigate why security testing failed for this endpoint"],
                        test_duration=0.0
                    )
                    
                    error_report = EndpointSecurityReport(
                        endpoint_path=endpoint.get('path', 'Unknown'),
                        http_methods=endpoint.get('methods', ['GET']),  # Use 'methods' field (array)
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
                        summary=f"Security testing failed: {str(e)}",
                        recommendations=["Investigate testing failures and retry"],
                        test_timestamp=datetime.now()
                    )
                    endpoint_reports.append(error_report)
            
            # Generate comprehensive security assessment report
            security_report = self._generate_security_assessment_report(endpoint_reports)
            
            # Save security assessment report
            self._save_security_report(security_report)
            
            # Save endpoint reports for technical writer
            with open("temp_security_results.json", "w") as f:
                json.dump([report.model_dump(mode='json') for report in endpoint_reports], f, indent=2, default=str)
            
            print(f"✅ Security testing completed for {len(endpoints)} endpoints")
            print(f"📊 Total vulnerabilities found: {security_report.total_vulnerabilities}")
            print(f"🔴 Critical: {security_report.critical_vulnerabilities}")
            print(f"🟠 High: {security_report.high_vulnerabilities}")
            print(f"🟡 Medium: {security_report.medium_vulnerabilities}")
            print(f"🟢 Low: {security_report.low_vulnerabilities}")
            
            return f"""
            Security Testing Completed Successfully!
            
            Summary:
            - Total Endpoints Tested: {security_report.total_endpoints_tested}
            - Endpoints with Vulnerabilities: {security_report.endpoints_with_vulnerabilities}
            - Total Vulnerabilities Found: {security_report.total_vulnerabilities}
            - Critical Vulnerabilities: {security_report.critical_vulnerabilities}
            - High Vulnerabilities: {security_report.high_vulnerabilities}
            - Medium Vulnerabilities: {security_report.medium_vulnerabilities}
            - Low Vulnerabilities: {security_report.low_vulnerabilities}
            - Overall Risk Score: {security_report.overall_risk_score:.2f}/10.0
            
            Security assessment report saved to: security_assessment_report.json
            Endpoint security results saved to: temp_security_results.json
            """
            
        except Exception as e:
            return f"Security testing failed: {str(e)}"
    
    def _generate_security_assessment_report(self, endpoint_reports) -> SecurityAssessmentReport:
        """Generate comprehensive security assessment report"""
        from security_testing.models import SecurityTestSuite, OWASPCategory
        
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
            assessment_duration=0.0,
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
    
    def _save_security_report(self, security_report: SecurityAssessmentReport) -> None:
        """Save security assessment report to disk"""
        try:
            output_file = "security_assessment_report.json"
            
            # Backup existing file if it exists
            if os.path.exists(output_file):
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_file = f"{output_file}.bak.{timestamp}"
                os.rename(output_file, backup_file)
                print(f"📁 Backed up existing security report to: {backup_file}")
            
            # Save new report
            with open(output_file, 'w') as f:
                json.dump(security_report.model_dump(mode='json'), f, indent=2, default=str)
            
            print(f"💾 Security assessment report saved to: {output_file}")
            
        except Exception as e:
            print(f"❌ Failed to save security report: {e}")
    
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
    
    def _generate_risk_analysis(self, endpoint_reports) -> str:
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
        """
        
        return analysis.strip()
    
    def _generate_overall_recommendations(self, endpoint_reports) -> list:
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
            "Conduct regular security assessments and penetration testing"
        ]
        
        return recommendations
    
    def _generate_remediation_priority(self, endpoint_reports) -> list:
        """Generate remediation priority order"""
        priority = [
            "1. Critical SQL Injection vulnerabilities - Immediate fix required (0-24 hours)",
            "2. High severity authentication bypass vulnerabilities - Fix within 24 hours",
            "3. High severity JWT validation vulnerabilities - Fix within 24 hours",
            "4. Medium severity IDOR vulnerabilities - Fix within 1 week",
            "5. Medium severity information disclosure - Fix within 1 week",
            "6. Low severity missing security headers - Fix within 2 weeks",
            "7. Implement comprehensive security testing framework - Within 2 weeks",
            "8. Establish security monitoring and alerting - Within 2 weeks",
            "9. Conduct developer security training - Within 1 month",
            "10. Implement secure development lifecycle (SDLC) - Ongoing process"
        ]
        
        return priority

# Import models for data validation
from models import DiscoveryReport, EndpointMetadata

# Configure logging - Cleaner output
import logging
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s: %(message)s',
    datefmt='%H:%M:%S'
)

# Reduce noise from external libraries
logging.getLogger('crewai').setLevel(logging.WARNING)
logging.getLogger('httpx').setLevel(logging.WARNING)
logging.getLogger('LiteLLM').setLevel(logging.WARNING)

class CrewAITestOrchestrator:
    """Orchestrates the VAmPI API discovery and security testing workflow using CrewAI."""
    
    def __init__(self):
        """Initialize the orchestrator with environment variables."""
        self.api_key = os.getenv('GEMINI_API_KEY')
        self.base_url = os.getenv('API_BASE_URL', 'http://localhost:5000')
        
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY not found in environment")
        
        # Configure Gemini LLM using CrewAI's native integration
        self.llm = LLM(
            model='gemini/gemini-2.5-flash',
            api_key=self.api_key
        )
        
        print(f"🔑 Using Gemini API Key: {self.api_key[:10]}...")
        print(f"🌐 Target VAmPI URL: {self.base_url}")
        print(f"🤖 LLM Model: gemini/gemini-2.5-flash")
        print()
    
    def create_agents(self) -> List[Agent]:
        """Create the four specialized agents."""
        print("🤖 Creating CrewAI agents...")
        
        # 1. API Discovery Specialist
        api_discovery_agent = Agent(
            role="API Discovery Specialist",
            goal="Discover and analyze all API endpoints of the VAmPI application",
            backstory="""You are an expert API security researcher with deep knowledge of 
            REST APIs, authentication mechanisms, and security vulnerabilities. Your expertise 
            lies in systematically discovering API endpoints and analyzing their security posture.""",
            verbose=False,  # Reduced verbosity
            allow_delegation=False,
            llm=self.llm,
            tools=[
                APIDiscoveryTool(base_url=self.base_url, api_key=self.api_key)
            ]
        )
        
        # 2. QA Testing Engineer
        qa_testing_agent = Agent(
            role="QA Testing Engineer",
            goal="Test discovered endpoints for vulnerabilities and validate their functionality",
            backstory="""You are a senior QA engineer specializing in security testing and 
            API validation. You have extensive experience in penetration testing, vulnerability 
            assessment, and quality assurance for web applications.""",
            verbose=False,  # Reduced verbosity
            allow_delegation=False,
            llm=self.llm,
            tools=[
                QATestingTool(base_url=self.base_url, api_key=self.api_key)
            ]
        )
        
        # 3. Security Testing Specialist (NEW)
        security_testing_agent = Agent(
            role="Security Testing Specialist",
            goal="Perform comprehensive OWASP API security testing to identify vulnerabilities and provide actionable recommendations",
            backstory="""You are an expert API security testing specialist with deep knowledge of OWASP API Top 10 security risks. 
            You have extensive experience in penetration testing, vulnerability assessment, and security analysis. 
            Your expertise includes SQL injection testing, authentication bypass techniques, authorization testing, 
            and security misconfiguration detection. You are responsible for ensuring the security posture of APIs 
            and providing detailed remediation guidance.""",
            verbose=False,  # Reduced verbosity
            allow_delegation=False,
            llm=self.llm,
            tools=[
                SecurityTestingTool(base_url=self.base_url, api_key=self.api_key)
            ]
        )
        
        # 4. Technical Writer & Security Analyst
        technical_writer_agent = Agent(
            role="Technical Writer & Security Analyst",
            goal="Generate comprehensive security reports and technical documentation",
            backstory="""You are an expert technical writer and security analyst with expertise in 
            creating detailed security reports, risk assessments, and technical documentation. 
            You excel at translating complex security findings into actionable insights.""",
            verbose=False,  # Reduced verbosity
            allow_delegation=False,
            llm=self.llm,
            tools=[
                TechnicalWriterTool(base_url=self.base_url, api_key=self.api_key)
            ]
        )
        
        print("✅ Agents created successfully")
        return [api_discovery_agent, qa_testing_agent, security_testing_agent, technical_writer_agent]
    
    def create_tasks(self, agents: List[Task]) -> List[Task]:
        """Create tasks for each agent."""
        print("📋 Creating CrewAI tasks...")
        
        api_discovery_agent, qa_testing_agent, security_testing_agent, technical_writer_agent = agents
        
        # Task 1: API Discovery - This task MUST call the discovery agent
        discovery_task = Task(
            description=f"""CRITICAL: You MUST execute the api_discovery_tool to complete this task.
            
            You are the API Discovery Specialist agent. Your primary responsibility is to discover 
            all API endpoints of the VAmPI application at {self.base_url}.
            
            REQUIRED ACTIONS:
            1. Execute the api_discovery_tool with the base_url parameter set to {self.base_url}
            2. Wait for the tool to complete the API scanning process
            3. The tool will automatically call the VAmPIDiscoveryEngine from discovery.py
            4. Report the number of endpoints discovered and any security findings
            
            The discovery tool will:
            - Scan common VAmPI API paths (/users/v1, /books/v1, etc.)
            - Test different HTTP methods (GET, POST, PUT, DELETE)
            - Analyze authentication requirements
            - Assess security risk levels
            - Generate comprehensive endpoint metadata
            
            EXPECTED OUTPUT:
            - Total number of endpoints discovered
            - Authentication requirements for each endpoint
            - Security risk levels identified
            - Endpoint metadata and parameters
            - Discovery results saved to temp_discovery_results.json
            
            DO NOT just describe what you would do - ACTUALLY RUN THE api_discovery_tool.
            The tool will handle all the complex discovery logic internally.""",
            agent=api_discovery_agent,
            expected_output="""A comprehensive API discovery report including:
            - Total number of endpoints discovered
            - Authentication requirements for each endpoint
            - Security risk levels identified
            - Endpoint metadata and parameters
            - Discovery results saved to temp_discovery_results.json"""
        )
        
        # Task 2: QA Testing
        qa_task = Task(
            description=f"""CRITICAL: You MUST execute the qa_testing_tool to complete this task.
            
            Using the discovery results from the previous task, perform comprehensive QA testing
            on the discovered VAmPI API endpoints. Test for common vulnerabilities, validate
            authentication mechanisms, and assess the overall security posture.
            
            REQUIRED ACTIONS:
            1. Read the discovery results from temp_discovery_results.json
            2. Execute the qa_testing_tool to test each endpoint
            3. Identify and document any security vulnerabilities
            4. Generate test results and recommendations
            
            DO NOT just describe what you would do - ACTUALLY RUN THE TOOL.""",
            agent=qa_testing_agent,
            expected_output="""A comprehensive QA testing report including:
            - Test results for each endpoint
            - Identified vulnerabilities and their severity
            - Authentication bypass attempts and results
            - Security recommendations and best practices
            - QA results saved to temp_qa_results.json"""
        )
        
        # Task 3: Security Testing (NEW)
        security_task = Task(
            description=f"""CRITICAL: You MUST execute the security_testing_tool to complete this task.
            
            Using the discovery results from the previous task, perform comprehensive OWASP API 
            security testing on the discovered VAmPI API endpoints. This is a specialized security 
            testing phase that goes beyond basic QA testing to identify deep security vulnerabilities.
            
            REQUIRED ACTIONS:
            1. Read the discovery results from temp_discovery_results.json
            2. Execute the security_testing_tool to perform comprehensive security testing
            3. Test for OWASP API Top 10 vulnerabilities including:
               - SQL Injection and XSS vulnerabilities
               - Authentication bypass and JWT validation issues
               - Authorization and access control weaknesses
               - Security misconfigurations and information disclosure
            4. Generate CVSS scores and risk assessments
            5. Provide actionable security recommendations
            
            DO NOT just describe what you would do - ACTUALLY RUN THE TOOL.""",
            agent=security_testing_agent,
            expected_output="""A comprehensive security testing report including:
            - OWASP API Top 10 vulnerability findings
            - CVSS scores and risk assessments for each vulnerability
            - Detailed security test results for each endpoint
            - Prioritized remediation recommendations
            - Security assessment report saved to security_assessment_report.json
            - Endpoint security results saved to temp_security_results.json"""
        )
        
        # Task 4: Technical Report Generation
        report_task = Task(
            description=f"""CRITICAL: You MUST execute the technical_writer_tool to complete this task.
            
            Using the discovery, QA testing, and security testing results, generate a comprehensive 
            technical report that includes security analysis, risk assessment, and actionable recommendations.
            
            REQUIRED ACTIONS:
            1. Read discovery results from temp_discovery_results.json
            2. Read QA results from temp_qa_results.json
            3. Read security testing results from temp_security_results.json
            4. Execute the technical_writer_tool to generate the final report
            5. Create a comprehensive security analysis document that combines all findings
            6. Generate both JSON and Markdown formatted reports
            
            DO NOT just describe what you would do - ACTUALLY RUN THE TOOL.""",
            agent=technical_writer_agent,
            expected_output="""A comprehensive technical report including:
            - Executive summary of all findings (discovery, QA, and security testing)
            - Detailed security analysis with OWASP categorization
            - Risk assessment matrix with CVSS scores
            - Vulnerability details and prioritized remediation steps
            - Final reports saved to discovered_endpoints.json and discovery_report.md"""
        )
        
        print("✅ Tasks created successfully")
        return [discovery_task, qa_task, security_task, report_task]
    
    def create_crew(self, agents: List[Agent], tasks: List[Task]) -> Crew:
        """Create the CrewAI crew."""
        print("🚀 Creating CrewAI crew...")
        
        crew = Crew(
            agents=agents,
            tasks=tasks,
            verbose=True,
            process=Process.sequential
        )
        
        print("✅ Crew created successfully")
        return crew
    
    def run_workflow(self):
        """Execute the complete workflow."""
        print("🚀 Executing CrewAI workflow...")
        print("=" * 50)
        
        try:
            # Create agents, tasks, and crew
            agents = self.create_agents()
            tasks = self.create_tasks(agents)
            crew = self.create_crew(agents, tasks)
            
            # Execute the workflow
            result = crew.kickoff()
            
            print("\n" + "=" * 50)
            print("🎉 WORKFLOW COMPLETED SUCCESSFULLY!")
            print("=" * 50)
            print(result)
            
            # Check for generated files
            self.check_generated_files()
            
        except Exception as e:
            print(f"\n❌ Workflow failed: {e}")
            import traceback
            traceback.print_exc()
    
    def check_generated_files(self):
        """Check what files were generated by the workflow."""
        print("\n📁 Checking generated files...")
        
        files_to_check = [
            "temp_discovery_results.json",
            "temp_qa_results.json",
            "temp_security_results.json",
            "security_assessment_report.json",
            "discovered_endpoints.json",
            "discovery_report.md"
        ]
        
        for filename in files_to_check:
            if os.path.exists(filename):
                file_size = os.path.getsize(filename)
                print(f"✅ {filename}: {file_size} bytes")
            else:
                print(f"❌ {filename}: Not found")

def main():
    """Main execution function."""
    print("🚀 VAmPI API Discovery & Security Testing Agent - CrewAI Orchestration Test")
    print("=" * 70)
    print(f"🐍 Python version: {sys.version}")
    print(f"🌐 Target VAmPI URL: {os.getenv('API_BASE_URL', 'http://localhost:5000')}")
    print(f"🔑 Gemini API Key: {os.getenv('GEMINI_API_KEY', 'Not set')[:10] if os.getenv('GEMINI_API_KEY') else 'Not set'}...")
    print()
    
    try:
        # Check if VAmPI is accessible
        import httpx
        response = httpx.get(os.getenv('API_BASE_URL', 'http://localhost:5000'))
        if response.status_code == 200:
            print("✅ VAmPI is running and accessible")
        else:
            print(f"⚠️  VAmPI returned status code: {response.status_code}")
    except Exception as e:
        print(f"⚠️  Could not connect to VAmPI: {e}")
    
    print()
    
    try:
        # Create and run the orchestrator
        orchestrator = CrewAITestOrchestrator()
        orchestrator.run_workflow()
        
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        print("   Please check your configuration and ensure VAmPI is accessible")
        print("   Verify that your GEMINI_API_KEY is valid and has sufficient quota")

if __name__ == "__main__":
    main() 