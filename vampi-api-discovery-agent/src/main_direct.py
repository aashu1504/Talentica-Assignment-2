#!/usr/bin/env python3
"""
VAmPI API Discovery Agent - Direct Workflow Execution
Bypasses CrewAI to directly execute tools in sequence
"""

import os
import sys
import asyncio
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent))

# Import required modules
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


def backup_existing_report(filename: str = "discovered_endpoints.json"):
    """Backup existing discovery report if it exists."""
    if os.path.exists(filename):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"{filename}.bak.{timestamp}"
        os.rename(filename, backup_name)
        print(f"📁 Backed up existing report to: {backup_name}")
        return backup_name
    return None


def print_discovery_summary(report: DiscoveryReport):
    """Print a summary of the discovery results."""
    print("\n" + "="*60)
    print("🔍 DISCOVERY SUMMARY")
    print("="*60)
    print(f"📊 Total Endpoints: {report.discovery_summary.total_endpoints}")
    print(f"🌐 Base URL: {report.api_structure.base_url}")
    print(f"⏰ Discovery Timestamp: {report.discovery_summary.discovery_start_time}")
    print(f"📁 Report ID: {report.report_id}")
    print(f"🔐 Authentication Mechanisms: {len(report.authentication_mechanisms)}")
    print(f"⚠️  High Risk Endpoints: {report.discovery_summary.high_risk_endpoints}")
    print("="*60)


def print_next_steps():
    """Print next steps for the user."""
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


def execute_workflow():
    """Execute the API discovery workflow directly."""
    print("🚀 Starting Direct Workflow Execution...")
    print("="*60)
    
    # Step 1: API Discovery
    print("\n🔍 Step 1: API Discovery")
    print("-" * 40)
    
    api_discovery_tool = APIDiscoveryTool(
        base_url=os.getenv('API_BASE_URL'),
        api_key=os.getenv('GOOGLE_API_KEY')
    )
    
    print("Executing API discovery tool...")
    discovery_result = api_discovery_tool._run()
    print(f"✅ API Discovery completed: {discovery_result}")
    
    # Step 2: QA Testing
    print("\n🧪 Step 2: QA Testing")
    print("-" * 40)
    
    qa_testing_tool = QATestingTool(api_key=os.getenv('GOOGLE_API_KEY'))
    
    print("Executing QA testing tool...")
    qa_result = qa_testing_tool._run()
    print(f"✅ QA Testing completed: {qa_result}")
    
    # Step 3: Technical Report Generation
    print("\n📝 Step 3: Technical Report Generation")
    print("-" * 40)
    
    technical_writer_tool = TechnicalWriterTool(api_key=os.getenv('GOOGLE_API_KEY'))
    file_read_tool = FileReadTool(file_path="temp_discovery_results.json")
    file_write_tool = FileWriteTool(file_path="final_report.md", content="")
    
    print("Executing technical writer tool...")
    report_result = technical_writer_tool._run()
    print(f"✅ Technical Report Generation completed: {report_result}")
    
    print("\n🎉 Direct Workflow Execution Completed Successfully!")
    return True


def main():
    """Main function to run the VAmPI API Discovery Agent."""
    print("🚀 VAmPI API Discovery Agent - Direct Workflow Execution")
    print("="*70)
    print(f"🐍 Python version: {sys.version}")
    
    # Validate environment
    if not validate_environment():
        return
    
    # Get configuration
    api_key = os.getenv('GOOGLE_API_KEY')
    base_url = os.getenv('API_BASE_URL')
    
    print(f"🌐 Target VAmPI URL: {base_url}")
    print(f"🔑 Google API Key: {api_key[:10]}..." if len(api_key) > 10 else "🔑 Google API Key: Not set")
    print()
    
    # Check VAmPI status
    print("🔍 Checking VAmPI status at", base_url, "...")
    if not check_vampi(base_url):
        print("❌ VAmPI is not accessible. Please ensure it's running.")
        return
    
    print("✅ VAmPI is running and accessible")
    print()
    
    try:
        # Backup existing report
        backup_existing_report()
        
        # Execute workflow
        success = execute_workflow()
        
        if success:
            # Load and validate the final report
            try:
                from models import load_discovery_report
                report = load_discovery_report("discovered_endpoints.json")
                print_discovery_summary(report)
                print_next_steps()
            except Exception as e:
                print(f"⚠️  Warning: Could not load final report: {e}")
                print("📁 Check the discovered_endpoints.json file manually")
        else:
            print("❌ Workflow execution failed")
            
    except KeyboardInterrupt:
        print("\n⚠️  Workflow interrupted by user")
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        print("   Please check your configuration and ensure VAmPI is accessible")
        print("   Verify that your GOOGLE_API_KEY is valid and has sufficient quota")


if __name__ == "__main__":
    main() 