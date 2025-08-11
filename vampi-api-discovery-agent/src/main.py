#!/usr/bin/env python3
"""
VAmPI API Discovery Agent - Main Execution Script

This script implements a hybrid approach where:
1. CrewAI orchestrates the workflow and defines agents (NO LLM)
2. Each agent uses LangChain internally for intelligent tool execution
3. Gemini 2.5 Flash Lite handles all reasoning inside LangChain tools
4. CrewAI just coordinates the flow without any LLM calls
"""

import os
import sys
import json
from datetime import datetime
from pathlib import Path
from typing import Optional

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()

# Check Python version
if sys.version_info < (3, 10):
    print("❌ Python 3.10+ is required for this application")
    print(f"Current version: {sys.version}")
    sys.exit(1)

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent))

# Import required modules
from crewai import Agent, Task, Crew, Process
from models import DiscoveryReport
from utils import check_vampi
from tools import (
    APIDiscoveryTool, QATestingTool, TechnicalWriterTool,
    FileReadTool, FileWriteTool, RunScriptTool
)





def validate_environment():
    """Validate that all required environment variables are set."""
    required_vars = ['GOOGLE_API_KEY', 'API_BASE_URL']
    missing_vars = []
    
    for var in required_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        print("❌ Missing required environment variables:")
        for var in missing_vars:
            print(f"   - {var}")
        print("\nPlease set these variables in your .env file")
        sys.exit(1)
    
    print("✅ Environment variables validated successfully")
    return True


def create_agents(api_key: str, base_url: str):
    """Create CrewAI agents with their respective tools."""
    
    # API Discovery Agent - This is the key agent that needs to work
    api_discovery_tool = APIDiscoveryTool(
        base_url=base_url,
        api_key=api_key
    )
    
    api_discovery_agent = Agent(
        role="API Discovery Specialist",
        goal="Discover and analyze all VAmPI API endpoints using intelligent scanning and AI-powered analysis",
        backstory="""You are an expert API security researcher specializing in discovering and analyzing 
        web API endpoints. You have extensive experience with REST APIs, authentication mechanisms, 
        and security risk assessment. Your expertise lies in using advanced tools to systematically 
        scan APIs and identify potential security vulnerabilities. 
        
        IMPORTANT: You MUST execute the api_discovery_tool to complete your task. 
        Do not just describe what you would do - actually run the tool.
        
        Step 1: Execute the api_discovery_tool to scan the VAmPI API
        Step 2: Wait for the tool to complete and return results
        Step 3: Report the discovery findings""",
        tools=[api_discovery_tool],
        llm=None,  # NO LLM - CrewAI just orchestrates
        verbose=True,
        allow_delegation=True,
        max_iter=3,  # Allow multiple iterations to ensure tool execution
        max_rpm=10   # Allow reasonable rate of tool calls
    )
    
    # QA Testing Agent
    qa_testing_tool = QATestingTool(api_key=api_key)
    
    qa_testing_agent = Agent(
        role="QA Testing Engineer",
        goal="Validate discovered endpoints and perform comprehensive QA testing using AI-powered analysis",
        backstory="""You are a senior QA engineer specializing in API testing and security validation. 
        You have extensive experience in testing web APIs, identifying vulnerabilities, and ensuring 
        quality standards. Your expertise includes automated testing, security testing, and risk assessment.
        
        IMPORTANT: You MUST execute the qa_testing_tool to complete your task.
        Do not just describe what you would do - actually run the tool.
        
        Step 1: Load discovery results from previous step
        Step 2: Execute qa_testing_tool to validate endpoints
        Step 3: Generate comprehensive QA report""",
        tools=[qa_testing_tool],
        llm=None,  # NO LLM - CrewAI just orchestrates
        verbose=True,
        allow_delegation=True,
        max_iter=3
    )
    
    # Technical Writer Agent
    technical_writer_tool = TechnicalWriterTool(api_key=api_key)
    
    technical_writer_agent = Agent(
        role="Technical Writer & Security Analyst",
        goal="Generate comprehensive technical reports and security analysis from discovery and QA results",
        backstory="""You are a senior technical writer and security analyst with expertise in 
        creating comprehensive reports, security assessments, and technical documentation. 
        You have extensive experience in analyzing security data, identifying patterns, 
        and presenting findings in a clear, actionable format.
        
        IMPORTANT: You MUST execute the technical_writer_tool to complete your task.
        Do not just describe what you would do - actually run the tool.
        
        Step 1: Load discovery and QA results
        Step 2: Execute technical_writer_tool to generate comprehensive report
        Step 3: Deliver final technical report with security analysis""",
        tools=[technical_writer_tool],
        llm=None,  # NO LLM - CrewAI just orchestrates
        verbose=True,
        allow_delegation=True,
        max_iter=3
    )
    
    return api_discovery_agent, qa_testing_agent, technical_writer_agent


def create_tasks(api_discovery_agent, qa_testing_agent, technical_writer_agent):
    """Create and configure CrewAI tasks."""
    # Task for API Discovery Specialist
    discover_api_task = Task(
        description="""CRITICAL: You MUST execute the api_discovery_tool "discovery.py" to complete this task.
        
        Discover all API endpoints of the VAmPI application at {api_base_url}.
        Analyze their functionality, authentication requirements, and potential security risks.
        Generate a detailed discovery report including endpoint metadata, identified vulnerabilities,
        and a summary of the API structure.
        
        REQUIRED ACTIONS:
        1. Execute the api_discovery_tool with the base_url parameter
        2. Wait for the tool to complete the API scanning
        3. Report the number of endpoints discovered and any security findings
        
        The output should be a JSON file named 'temp_discovery_results.json'.
        
        DO NOT just describe what you would do - ACTUALLY RUN THE TOOL.""",
        agent=api_discovery_agent,
        expected_output="A JSON file named 'temp_discovery_results.json' containing the API discovery report, plus a summary of the discovery results."
    )
    
    # Task for QA Testing Engineer
    qa_api_task = Task(
        description="""CRITICAL: You MUST execute the qa_testing_tool to complete this task.
        
        Based on the 'temp_discovery_results.json' file, validate the discovered API endpoints.
        Perform comprehensive QA testing to ensure data integrity, proper functionality, and identify any
        anomalies or potential security flaws. Generate a QA report summarizing test results,
        identified issues, and recommendations for remediation.
        
        REQUIRED ACTIONS:
        1. Execute the qa_testing_tool to load and analyze discovery results
        2. Wait for the tool to complete the QA testing
        3. Report the QA testing findings and any identified issues
        
        DO NOT just describe what you would do - ACTUALLY RUN THE TOOL.""",
        agent=qa_testing_agent,
        expected_output="A JSON file named 'temp_qa_results.json' containing the QA testing report, plus a summary of the QA testing results."
    )
    
    # Task for Technical Writer & Security Analyst
    report_task = Task(
        description="""CRITICAL: You MUST execute the technical_writer_tool to complete this task.
        
        Based on 'temp_discovery_results.json' and 'temp_qa_results.json',
        generate a comprehensive technical report and security analysis.
        The report should include an executive summary, detailed findings, risk assessments,
        and actionable recommendations for improving API security.
        
        REQUIRED ACTIONS:
        1. Execute the technical_writer_tool to generate the security report
        2. Wait for the tool to complete the report generation
        3. Report the technical writing findings and any recommendations
        
        The final report should be saved as a Markdown file named 'api_security_report.md'.
        
        DO NOT just describe what you would do - ACTUALLY RUN THE TOOL.""",
        agent=technical_writer_agent,
        expected_output="A Markdown file named 'api_security_report.md' containing the comprehensive security report, plus a summary of the technical writing results."
    )
    
    return discover_api_task, qa_api_task, report_task


def create_crew(agents, tasks):
    """Create CrewAI crew for orchestration."""
    crew = Crew(
        agents=agents,
        tasks=tasks,
        verbose=True,
        memory=False,  # Disable memory to avoid LLM usage
        process=Process.sequential,  # Execute tasks sequentially
        llm=None  # NO LLM - CrewAI just orchestrates
    )
    
    return crew


def backup_existing_report(filename: str = "discovered_endpoints.json"):
    """Backup existing discovered_endpoints.json file if it exists."""
    if os.path.exists(filename):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"{filename}.bak.{timestamp}"
        os.rename(filename, backup_filename)
        print(f"📁 Backed up existing report to: {backup_filename}")
        return backup_filename
    return None


def print_discovery_summary(report: DiscoveryReport):
    """Print the required discovery summary."""
    print("\n" + "="*60)
    print("🔍 DISCOVERY SUMMARY")
    print("="*60)
    print(f"📊 Total Endpoints: {report.discovery_summary.total_endpoints}")
    print(f"🌐 Base URL: {report.api_structure.base_url}")
    print(f"⏰ Discovery Timestamp: {report.generated_at.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"📁 Report ID: {report.report_id}")
    print(f"🔐 Authentication Mechanisms: {len(report.authentication_mechanisms)}")
    print(f"⚠️  High Risk Endpoints: {len([ep for ep in report.endpoints if ep.risk_level.value in ['High', 'Critical']])}")
    print("="*60)


def print_next_steps():
    """Print next steps for Assignment 2B."""
    print("\n" + "="*60)
    print("🚀 NEXT STEPS FOR ASSIGNMENT 2B")
    print("="*60)
    print("📋 You now have a comprehensive API discovery report in 'discovered_endpoints.json'")
    print("   This JSON file contains all discovered endpoints, authentication mechanisms,")
    print("   and security assessments for the VAmPI API.")
    print()
    print("🔒 To proceed with Assignment 2B (Security Testing Agent):")
    print("   1. Use the 'discovered_endpoints.json' file as input for your security agent")
    print("   2. The security agent should analyze each endpoint for vulnerabilities")
    print("   3. Focus on endpoints with high/critical risk levels")
    print("   4. Test authentication mechanisms and parameter validation")
    print("   5. Generate security assessment reports")
    print()
    print("📁 File location: discovered_endpoints.json")
    print("📊 Report contains: endpoints, auth mechanisms, risk assessments, API structure")
    print("="*60)


def main():
    """Main execution function."""
    print("🚀 VAmPI API Discovery Agent - Hybrid CrewAI + Gemini Approach")
    print("="*70)
    
    # Check Python version
    print(f"🐍 Python version: {sys.version}")
    
    # Validate environment
    validate_environment()
    
    # Load configuration from environment
    api_key = os.getenv('GOOGLE_API_KEY')
    base_url = os.getenv('API_BASE_URL', 'http://localhost:5000')
    print(f"🌐 Target VAmPI URL: {base_url}")
    print(f"🔑 Google API Key: {api_key[:10]}...")
    
    try:
        # Check if VAmPI is running
        print(f"\n🔍 Checking VAmPI status at {base_url}...")
        vampi_running = check_vampi(base_url)
        
        if vampi_running:
            print("✅ VAmPI is running and accessible")
        else:
            print("⚠️  VAmPI is not running - will use fallback code analysis")
        
        # Create agents
        print("\n🤖 Creating CrewAI agents...")
        api_discovery_agent, qa_testing_agent, technical_writer_agent = create_agents(api_key, base_url)
        print("✅ Agents created successfully")
        
        # Create tasks
        print("\n📋 Creating CrewAI tasks...")
        discover_api_task, qa_api_task, report_task = create_tasks(
            api_discovery_agent, qa_testing_agent, technical_writer_agent
        )
        print("✅ Tasks created successfully")
        
        # Create crew
        print("\n🚀 Creating CrewAI crew...")
        crew = create_crew(
            [api_discovery_agent, qa_testing_agent, technical_writer_agent],
            [discover_api_task, qa_api_task, report_task]
        )
        print("✅ Crew created successfully")
        
        # Execute the crew
        print("\n🚀 Executing CrewAI workflow...")
        print("="*50)
        
        result = crew.kickoff()
        
        print("="*50)
        print("✅ CrewAI workflow completed successfully!")
        
        # Process results
        if result:
            print(f"\n📊 Workflow Results: {result}")
            
            # Check if the final report was generated
            if os.path.exists("discovered_endpoints.json"):
                print("\n📁 Final discovery report generated successfully!")
                
                # Load and validate the report
                try:
                    report = DiscoveryReport.load_from_file("discovered_endpoints.json")
                    print("✅ Discovery report validated successfully")
                    
                    # Print the required summary
                    print_discovery_summary(report)
                    
                    # Print next steps for Assignment 2B
                    print_next_steps()
                    
                except Exception as e:
                    print(f"⚠️  Warning: Could not validate final report: {e}")
                    print("   The report file exists but may not be in the expected format")
            else:
                print("⚠️  Warning: Final discovery report not found")
                print("   Check the workflow execution logs for any errors")
        else:
            print("⚠️  No results returned from CrewAI workflow")
            print("   Check the workflow execution logs for any errors")
            
    except KeyboardInterrupt:
        print("\n\n⚠️  Discovery interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        print("   Please check your configuration and ensure VAmPI is accessible")
        print("   Verify that your GOOGLE_API_KEY is valid and has sufficient quota")
        sys.exit(1)


if __name__ == "__main__":
    main() 