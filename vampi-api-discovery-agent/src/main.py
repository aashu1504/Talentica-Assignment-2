#!/usr/bin/env python3
"""
VAmPI API Discovery Agent - Main Execution Script

This script implements a hybrid approach where:
1. CrewAI orchestrates the workflow and defines agents
2. Agents use tools to perform their work
3. Gemini 2.5 Flash Lite handles all reasoning inside the tools
4. No LLM calls happen via CrewAI's own pipeline
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
from crewai.llms.base_llm import BaseLLM
from models import DiscoveryReport
from utils import check_vampi
from tools import (
    APIDiscoveryTool, QATestingTool, TechnicalWriterTool,
    FileReadTool, FileWriteTool, RunScriptTool
)


class DummyLLM(BaseLLM):
    """Dummy LLM that doesn't make any actual calls - used to satisfy CrewAI requirements."""
    
    def __init__(self):
        """Initialize the dummy LLM."""
        super().__init__(model="dummy")
    
    def call(self, prompt: str, **kwargs) -> str:
        """Return a dummy response without making any LLM calls."""
        return "Dummy response - no LLM calls made"
    
    def acall(self, prompt: str, **kwargs) -> str:
        """Async version of call."""
        return "Dummy response - no LLM calls made"
    
    @property
    def llm_type(self) -> str:
        """Return the LLM type."""
        return "dummy"


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
    
    # API Discovery Agent
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
        scan APIs and identify potential security vulnerabilities.""",
        tools=[api_discovery_tool],
        llm=DummyLLM(),  # Use dummy LLM to prevent CrewAI from trying to use external LLM
        verbose=True,
        allow_delegation=False
    )
    
    # QA Testing Agent
    qa_testing_tool = QATestingTool(api_key=api_key)
    
    qa_testing_agent = Agent(
        role="QA Testing Engineer",
        goal="Validate discovered endpoints and perform comprehensive QA testing with AI-powered test case generation",
        backstory="""You are a senior QA engineer with deep expertise in API testing and security validation. 
        You excel at creating comprehensive test plans, validating endpoint functionality, and identifying 
        potential issues. You use AI tools to enhance your testing approach and ensure thorough coverage.""",
        tools=[qa_testing_tool],
        llm=DummyLLM(),  # Use dummy LLM to prevent CrewAI from trying to use external LLM
        verbose=True,
        allow_delegation=False
    )
    
    # Technical Writer & Analyst Agent
    technical_writer_tool = TechnicalWriterTool(api_key=api_key)
    file_read_tool = FileReadTool(file_path="temp_discovery_results.json")
    # FileWriteTool will be used during execution when content is available
    file_write_tool = FileWriteTool(file_path="final_report.md", content="")
    
    technical_writer_agent = Agent(
        role="Technical Writer & Security Analyst",
        goal="Generate comprehensive technical reports and security analysis from discovery and QA results",
        backstory="""You are a senior technical writer and security analyst with expertise in creating 
        comprehensive security reports and technical documentation. You excel at analyzing complex data, 
        identifying security patterns, and presenting findings in clear, actionable formats. You use AI 
        tools to enhance your analysis and report generation capabilities.""",
        tools=[technical_writer_tool, file_read_tool, file_write_tool],
        llm=DummyLLM(),  # Use dummy LLM to prevent CrewAI from trying to use external LLM
        verbose=True,
        allow_delegation=False
    )
    
    return api_discovery_agent, qa_testing_agent, technical_writer_agent


def create_tasks(api_discovery_agent, qa_testing_agent, technical_writer_agent):
    """Create CrewAI tasks for the workflow."""
    
    # Task 1: API Discovery
    discovery_task = Task(
        description="""Discover and analyze all VAmPI API endpoints. Use the API discovery tool to:
        1. Scan the VAmPI API at the specified base URL
        2. Identify all available endpoints and their methods
        3. Analyze authentication requirements and security risks
        4. Generate comprehensive endpoint metadata
        5. Save results for further processing
        
        Focus on thorough coverage and accurate endpoint identification.""",
        agent=api_discovery_agent,
        expected_output="A comprehensive report of discovered API endpoints including total count, endpoint details, authentication requirements, security risk assessments, and Gemini AI analysis.",

        async_execution=False
    )
    
    # Task 2: QA Testing
    qa_testing_task = Task(
        description="""Validate discovered endpoints and perform QA testing. Use the QA testing tool to:
        1. Load the discovery results from the previous task
        2. Validate endpoint data completeness and accuracy
        3. Generate comprehensive test plans using AI
        4. Perform basic endpoint validation
        5. Identify high-risk endpoints for further testing
        6. Save QA results for report generation
        
        Ensure thorough validation and comprehensive test coverage.""",
        agent=qa_testing_agent,
        expected_output="A comprehensive QA testing report including validation results, AI-generated test plans, risk assessment validation, testing recommendations, and quality metrics.",

        async_execution=False
    )
    
    # Task 3: Technical Report Generation
    report_generation_task = Task(
        description="""Generate a comprehensive technical report and security analysis. Use the technical writer tool to:
        1. Load discovery and QA results from previous tasks
        2. Generate comprehensive security analysis using AI
        3. Create a structured technical report
        4. Include executive summary, risk assessments, and recommendations
        5. Save the final report in the required format
        6. Clean up temporary files
        
        Create a professional, actionable report suitable for security teams and stakeholders.""",
        agent=technical_writer_agent,
        expected_output="A comprehensive technical report including executive summary, detailed endpoint analysis, security risk assessment, authentication mechanism analysis, testing recommendations, compliance considerations, and final report saved to discovered_endpoints.json.",

        async_execution=False
    )
    
    return discovery_task, qa_testing_task, report_generation_task


def create_crew(agents, tasks):
    """Create the CrewAI crew with the defined agents and tasks."""
    
    crew = Crew(
        agents=agents,
        tasks=tasks,
        verbose=True,
        memory=False,  # Disable memory to avoid LLM usage
        process=Process.sequential,  # Execute tasks sequentially
        llm=DummyLLM()  # Use dummy LLM for crew to prevent external LLM usage
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
        discovery_task, qa_testing_task, report_generation_task = create_tasks(
            api_discovery_agent, qa_testing_agent, technical_writer_agent
        )
        print("✅ Tasks created successfully")
        
        # Create crew
        print("\n🚀 Creating CrewAI crew...")
        crew = create_crew(
            [api_discovery_agent, qa_testing_agent, technical_writer_agent],
            [discovery_task, qa_testing_task, report_generation_task]
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