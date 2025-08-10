#!/usr/bin/env python3
"""
VAmPI API Discovery Agent - Main Execution Script

This script provides the main entry point for running the API Discovery Agent
using CrewAI and Google Generative AI for reasoning support.
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
from crewai import Crew
from .agent import VAmPIDiscoveryAgent
from .models import DiscoveryReport
from .utils import check_vampi


def initialize_google_ai():
    """Initialize Google Generative AI with API key from environment."""
    try:
        import google.generativeai as genai
        
        api_key = os.getenv('GOOGLE_API_KEY')
        if not api_key:
            print("⚠️  GOOGLE_API_KEY not found in .env file")
            print("   Google AI reasoning support will be disabled")
            return None
        
        genai.configure(api_key=api_key)
        print("✅ Google Generative AI initialized successfully")
        return genai
        
    except ImportError:
        print("⚠️  google-generativeai package not installed")
        print("   Google AI reasoning support will be disabled")
        return None
    except Exception as e:
        print(f"⚠️  Failed to initialize Google AI: {e}")
        print("   Google AI reasoning support will be disabled")
        return None


def create_crew_with_agent(base_url: str):
    """Create CrewAI crew with the APIDiscoveryAgent."""
    try:
        # Initialize the VAmPI discovery agent
        agent = VAmPIDiscoveryAgent(base_url=base_url)
        
        # Create crew with the agent
        crew = Crew(
            agents=[agent.agent],
            tasks=[agent.task],
            verbose=os.getenv('CREWAI_VERBOSE', 'true').lower() == 'true',
            memory=False
        )
        
        print("✅ CrewAI crew initialized successfully")
        return crew, agent
        
    except Exception as e:
        print(f"❌ Failed to initialize CrewAI crew: {e}")
        raise


def backup_existing_report(filename: str = "discovered_endpoints.json"):
    """Backup existing discovered_endpoints.json file if it exists."""
    if os.path.exists(filename):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"{filename}.bak.{timestamp}"
        os.rename(filename, backup_filename)
        print(f"📁 Backed up existing report to: {backup_filename}")
        return backup_filename
    return None


def validate_discovery_report(result: any) -> Optional[DiscoveryReport]:
    """Validate the result against DiscoveryReport model."""
    try:
        # If result is already a DiscoveryReport, return it
        if isinstance(result, DiscoveryReport):
            return result
        
        # If result is a string, try to parse it as JSON
        if isinstance(result, str):
            try:
                data = json.loads(result)
                return DiscoveryReport(**data)
            except json.JSONDecodeError:
                print("⚠️  CrewAI result is not valid JSON")
                return None
        
        # If result is a dict, try to create DiscoveryReport
        if isinstance(result, dict):
            try:
                return DiscoveryReport(**result)
            except Exception as e:
                print(f"⚠️  Failed to create DiscoveryReport from dict: {e}")
                return None
        
        print(f"⚠️  Unexpected result type: {type(result)}")
        return None
        
    except Exception as e:
        print(f"❌ Failed to validate discovery report: {e}")
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
    print("🚀 VAmPI API Discovery Agent - Main Execution")
    print("="*50)
    
    # Check Python version
    print(f"🐍 Python version: {sys.version}")
    
    # Load configuration from environment
    base_url = os.getenv('API_BASE_URL', 'http://localhost:5000')
    print(f"🌐 Target VAmPI URL: {base_url}")
    
    # Initialize Google Generative AI (for reasoning support only)
    google_ai = initialize_google_ai()
    
    try:
        # Check if VAmPI is running
        print(f"\n🔍 Checking VAmPI status at {base_url}...")
        vampi_running = check_vampi(base_url)
        
        if vampi_running:
            print("✅ VAmPI is running and accessible")
        else:
            print("⚠️  VAmPI is not running - will use fallback code analysis")
        
        # Create CrewAI crew with the agent
        print("\n🤖 Initializing CrewAI crew...")
        crew, agent = create_crew_with_agent(base_url)
        
        # Run discovery directly using the agent (bypassing CrewAI LLM)
        print("\n🔍 Running discovery using local functions...")
        discovery_report = agent.run_discovery()
        
        print("✅ Discovery completed successfully")
        
        # Validate the result against DiscoveryReport model
        print("\n🔍 Validating discovery results...")
        if not isinstance(discovery_report, DiscoveryReport):
            print("❌ Discovery result is not a valid DiscoveryReport")
            sys.exit(1)
        
        if discovery_report:
            print("✅ Discovery report validated successfully")
            
            # Backup existing report if it exists
            backup_file = backup_existing_report()
            
            # Write the validated report to discovered_endpoints.json
            output_file = "discovered_endpoints.json"
            discovery_report.save_to_file(output_file)
            print(f"💾 Discovery report saved to: {output_file}")
            
            # Print the required summary
            print_discovery_summary(discovery_report)
            
            # Print next steps for Assignment 2B
            print_next_steps()
            
        else:
            print("❌ Failed to validate discovery report")
            print("   The CrewAI result could not be converted to a valid DiscoveryReport")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n\n⚠️  Discovery interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        print("   Please check your configuration and ensure VAmPI is accessible")
        sys.exit(1)


if __name__ == "__main__":
    main() 