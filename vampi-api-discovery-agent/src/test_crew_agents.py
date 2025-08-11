#!/usr/bin/env python3
"""
VAmPI API Discovery Agent - CrewAI Orchestration Test

This script uses CrewAI to orchestrate three specialized agents:
1. API Discovery Specialist - Discovers and analyzes API endpoints
2. QA Testing Engineer - Tests discovered endpoints for vulnerabilities
3. Technical Writer & Security Analyst - Generates comprehensive reports

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

# Import models for data validation
from models import DiscoveryReport, EndpointMetadata

class CrewAITestOrchestrator:
    """Orchestrates the VAmPI API discovery workflow using CrewAI."""
    
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
        """Create the three specialized agents."""
        print("🤖 Creating CrewAI agents...")
        
        # 1. API Discovery Specialist
        api_discovery_agent = Agent(
            role="API Discovery Specialist",
            goal="Discover and analyze all API endpoints of the VAmPI application",
            backstory="""You are an expert API security researcher with deep knowledge of 
            REST APIs, authentication mechanisms, and security vulnerabilities. Your expertise 
            lies in systematically discovering API endpoints and analyzing their security posture.""",
            verbose=True,
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
            verbose=True,
            allow_delegation=False,
            llm=self.llm,
            tools=[
                QATestingTool(base_url=self.base_url, api_key=self.api_key)
            ]
        )
        
        # 3. Technical Writer & Security Analyst
        technical_writer_agent = Agent(
            role="Technical Writer & Security Analyst",
            goal="Generate comprehensive security reports and technical documentation",
            backstory="""You are a technical writer and security analyst with expertise in 
            creating detailed security reports, risk assessments, and technical documentation. 
            You excel at translating complex security findings into actionable insights.""",
            verbose=True,
            allow_delegation=False,
            llm=self.llm,
            tools=[
                TechnicalWriterTool(base_url=self.base_url, api_key=self.api_key)
            ]
        )
        
        print("✅ Agents created successfully")
        return [api_discovery_agent, qa_testing_agent, technical_writer_agent]
    
    def create_tasks(self, agents: List[Agent]) -> List[Task]:
        """Create tasks for each agent."""
        print("📋 Creating CrewAI tasks...")
        
        api_discovery_agent, qa_testing_agent, technical_writer_agent = agents
        
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
        
        # Task 3: Technical Report Generation
        report_task = Task(
            description=f"""CRITICAL: You MUST execute the technical_writer_tool to complete this task.
            
            Using the discovery and QA testing results, generate a comprehensive technical report
            that includes security analysis, risk assessment, and actionable recommendations.
            
            REQUIRED ACTIONS:
            1. Read both discovery and QA results from the temporary files
            2. Execute the technical_writer_tool to generate the final report
            3. Create a comprehensive security analysis document
            4. Generate both JSON and Markdown formatted reports
            
            DO NOT just describe what you would do - ACTUALLY RUN THE TOOL.""",
            agent=technical_writer_agent,
            expected_output="""A comprehensive technical report including:
            - Executive summary of findings
            - Detailed security analysis
            - Risk assessment matrix
            - Vulnerability details and remediation steps
            - Final reports saved to discovered_endpoints.json and discovery_report.md"""
        )
        
        print("✅ Tasks created successfully")
        return [discovery_task, qa_task, report_task]
    
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
    print("🚀 VAmPI API Discovery Agent - CrewAI Orchestration Test")
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