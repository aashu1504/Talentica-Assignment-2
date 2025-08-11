#!/usr/bin/env python3
"""
VAmPI API Discovery Agent Tools

This module implements a simplified hybrid approach:
1. CrewAI orchestrates the workflow and defines agents
2. Each tool uses Gemini directly for intelligent execution
3. CrewAI just coordinates the flow without needing its own LLM
"""

import os
import json
import asyncio
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
import httpx

# Import Google Generative AI
import google.generativeai as genai

from crewai.tools import BaseTool
from pydantic import BaseModel, Field

# Import models
from models import (
    DiscoveryReport, DiscoverySummary, EndpointMetadata,
    AuthenticationMechanism, APIStructure, RiskLevel, 
    AuthenticationType, DiscoveryMethod, EndpointParameters
)

# Import discovery engine
from discovery import VAmPIDiscoveryEngine, DiscoveryConfig

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class APIDiscoveryTool(BaseTool):
    """Tool for discovering VAmPI API endpoints."""
    
    name: str = "api_discovery_tool"
    description: str = "Discovers and analyzes VAmPI API endpoints. Scans the API systematically and generates a comprehensive discovery report."
    base_url: str = Field(..., description="Base URL for VAmPI API")
    api_key: str = Field(..., description="Google API key for Gemini LLM")
    
    def _run(self) -> str:
        """Execute the API discovery tool."""
        try:
            print(f"🔍 Starting API discovery for {self.base_url}")
            
            # Create discovery config
            from models import DiscoveryConfig
            config = DiscoveryConfig(
                base_url=self.base_url,
                timeout=30.0,
                max_concurrent_requests=5,
                max_retries=3,
                rate_limit_delay=1.0
            )
            
            # Initialize the discovery engine
            discovery_engine = VAmPIDiscoveryEngine(config)
            
            # Run discovery (handle async call)
            async def run_discovery():
                async with discovery_engine:
                    return await discovery_engine.discover_endpoints()
            
            # Execute discovery in event loop
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                discovery_result = loop.run_until_complete(run_discovery())
                loop.close()
                
                # Convert the result to a dictionary for JSON serialization
                # APIDiscoveryResult has: discovery_summary, endpoints, authentication_mechanisms, api_structure
                if hasattr(discovery_result, 'discovery_summary'):
                    # Extract the discovery data
                    discovery_data = {
                        "discovery_summary": discovery_result.discovery_summary.dict(),
                        "endpoints": [ep.dict() for ep in discovery_result.endpoints],
                        "authentication_mechanisms": [auth.dict() for auth in discovery_result.authentication_mechanisms],
                        "api_structure": discovery_result.api_structure.dict()
                    }
                    
                    # Create a result dictionary
                    result_data = {
                        "discovery_data": discovery_data,
                        "discovery_timestamp": str(datetime.now()),
                        "total_endpoints": discovery_result.discovery_summary.total_endpoints
                    }
                    
                    # Save to temporary file
                    with open("temp_discovery_results.json", "w") as f:
                        json.dump(result_data, f, indent=2, default=str)
                    
                    print("✅ Discovery results saved to temp_discovery_results.json")
                    
                    # Return a summary string
                    total_endpoints = discovery_result.discovery_summary.total_endpoints
                    return f"✅ API discovery completed successfully! Discovered {total_endpoints} endpoints. Results saved to temp_discovery_results.json"
                else:
                    # Fallback if the result structure is different
                    result_data = {
                        "discovery_data": discovery_result.__dict__,
                        "discovery_timestamp": str(datetime.now()),
                        "total_endpoints": 0
                    }
                    
                    with open("temp_discovery_results.json", "w") as f:
                        json.dump(result_data, f, indent=2, default=str)
                    
                    print("✅ Discovery results saved to temp_discovery_results.json")
                    return "✅ API discovery completed. Results saved to temp_discovery_results.json"
                    
            except Exception as e:
                loop.close()
                raise e
                
        except Exception as e:
            error_msg = f"❌ Discovery execution failed: {str(e)}"
            print(error_msg)
            return error_msg
    
    def _save_discovery_results(self, results: Dict[str, Any]):
        """Save discovery results to temporary file."""
        try:
            output_file = "temp_discovery_results.json"
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            logger.info(f"✅ Discovery results saved to {output_file}")
        except Exception as e:
            logger.error(f"❌ Failed to save discovery results: {e}")


class QATestingTool(BaseTool):
    """Tool for QA testing discovered endpoints."""
    
    name: str = "qa_testing_tool"
    description: str = "Validates discovered API endpoints and performs QA testing. Generates test cases and identifies high-risk endpoints."
    base_url: str = Field(..., description="Base URL for VAmPI API")
    api_key: str = Field(..., description="Google API key for Gemini LLM")
    
    def _run(self) -> str:
        """Execute the QA testing tool."""
        try:
            print("🧪 Starting QA testing of discovered endpoints...")
            
            # Check if discovery results exist
            if not os.path.exists("temp_discovery_results.json"):
                return "❌ No discovery results found. Please run the discovery tool first."
            
            # Load discovery results
            with open("temp_discovery_results.json", "r") as f:
                discovery_data = json.load(f)
            
            # Extract endpoints for testing
            endpoints = discovery_data.get("discovery_data", {}).get("endpoints", [])
            
            if not endpoints:
                return "❌ No endpoints found in discovery results."
            
            print(f"🔍 Testing {len(endpoints)} discovered endpoints...")
            
            # Initialize Gemini for analysis
            genai.configure(api_key=self.api_key)
            model = genai.GenerativeModel('gemini-2.0-flash-exp')
            
            # Test each endpoint
            test_results = []
            for endpoint in endpoints:
                endpoint_result = self._test_endpoint(endpoint, model)
                test_results.append(endpoint_result)
            
            # Generate comprehensive QA report
            qa_report = self._generate_qa_report(test_results, model)
            
            # Save QA results
            qa_data = {
                "qa_results": test_results,
                "qa_report": qa_report,
                "qa_timestamp": str(datetime.now()),
                "total_endpoints_tested": len(endpoints)
            }
            
            with open("temp_qa_results.json", "w") as f:
                json.dump(qa_data, f, indent=2, default=str)
            
            print("✅ QA testing completed. Results saved to temp_qa_results.json")
            
            return f"✅ QA testing completed successfully! Tested {len(endpoints)} endpoints. Results saved to temp_qa_results.json"
            
        except Exception as e:
            error_msg = f"❌ QA testing failed: {str(e)}"
            print(error_msg)
            return error_msg
    
    def _test_endpoint(self, endpoint: Dict[str, Any], model) -> Dict[str, Any]:
        """
        Tests a single endpoint using Gemini.
        Returns a dictionary with test results.
        """
        path = endpoint.get("path", "")
        methods = endpoint.get("methods", [])
        risk_level = endpoint.get("risk_level", "Medium")
        auth_required = endpoint.get("authentication_required", False)
        
        test_result = {
            "path": path,
            "methods": methods,
            "risk_level": risk_level,
            "authentication_required": auth_required,
            "test_status": "Not Tested",
            "test_details": "No details available",
            "test_timestamp": str(datetime.now())
        }
        
        try:
            for method in methods:
                url = f"{self.base_url}{path}"
                headers = {}
                if auth_required:
                    headers["Authorization"] = f"Bearer {self.api_key}" # Assuming api_key is available
                
                with httpx.Client() as client:
                    response = client.request(method, url, headers=headers)
                    response.raise_for_status() # Raise an exception for bad status codes
                    
                    test_result["test_status"] = "Passed"
                    test_result["test_details"] = f"Status: {response.status_code}, Headers: {response.headers}, Body: {response.text}"
                    break # Only test the first method for simplicity
                    
        except httpx.RequestError as e:
            test_result["test_status"] = "Failed"
            test_result["test_details"] = f"HTTP Request Error: {e}"
        except Exception as e:
            test_result["test_status"] = "Failed"
            test_result["test_details"] = f"Unexpected Error: {e}"
            
        return test_result
    
    def _generate_qa_report(self, test_results: List[Dict[str, Any]], model) -> str:
        """
        Generates a comprehensive QA report using Gemini.
        """
        report = f"# VAmPI API Test Report\n\n"
        report += f"## Overview\n"
        report += f"- Total Endpoints Tested: {len(test_results)}\n"
        report += f"- High Risk Endpoints: {len([ep for ep in test_results if ep.get('risk_level', 'Medium') in ['High', 'Critical']])}\n"
        report += f"- Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        report += f"## Test Results\n\n"
        
        for i, endpoint in enumerate(test_results, 1):
            report += f"### Test Case {i}: {endpoint.get('methods', [])} {endpoint.get('path', '')}\n"
            report += f"- **Risk Level**: {endpoint.get('risk_level', 'Medium')}\n"
            report += f"- **Authentication**: {'Required' if endpoint.get('authentication_required', False) else 'Not Required'}\n"
            report += f"- **Test Status**: {endpoint.get('test_status', 'N/A')}\n"
            report += f"- **Test Details**: {endpoint.get('test_details', 'N/A')}\n"
            report += f"- **Test Timestamp**: {endpoint.get('test_timestamp', 'N/A')}\n\n"
        
        report += f"## Recommendations\n"
        report += f"1. Implement proper authentication for all sensitive endpoints\n"
        report += f"2. Add input validation and sanitization\n"
        report += f"3. Implement rate limiting for public endpoints\n"
        report += f"4. Regular security audits and penetration testing\n"
        
        return report
    
    def _save_qa_results(self, results: Dict[str, Any]):
        """Save QA results to temporary file."""
        try:
            output_file = "temp_qa_results.json"
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            logger.info(f"✅ QA results saved to {output_file}")
        except Exception as e:
            logger.error(f"❌ Failed to save QA results: {e}")


class TechnicalWriterTool(BaseTool):
    """Tool for generating technical reports."""
    
    name: str = "technical_writer_tool"
    description: str = "Generates comprehensive technical reports from discovery and QA results. Creates security analysis and actionable recommendations."
    base_url: str = Field(..., description="Base URL for VAmPI API")
    api_key: str = Field(..., description="Google API key for Gemini LLM")
    
    def _run(self) -> str:
        """Execute the technical writer tool."""
        try:
            print("📝 Starting technical report generation...")
            
            # Check if required files exist
            if not os.path.exists("temp_discovery_results.json"):
                return "❌ No discovery results found. Please run the discovery tool first."
            
            if not os.path.exists("temp_qa_results.json"):
                return "❌ No QA results found. Please run the QA testing tool first."
            
            # Load discovery and QA results
            with open("temp_discovery_results.json", "r") as f:
                discovery_data = json.load(f)
            
            with open("temp_qa_results.json", "r") as f:
                qa_data = json.load(f)
            
            # Create comprehensive discovery report
            discovery_report = self._create_discovery_report(discovery_data)
            
            # Save final report
            self._save_final_report(discovery_report)
            
            # Generate markdown report
            self._generate_markdown_report(discovery_report)
            
            # Cleanup temporary files
            self._cleanup_temp_files()
            
            print("✅ Technical report generation completed successfully!")
            
            return f"✅ Technical report generation completed! Generated discovered_endpoints.json and discovery_report.md"
            
        except Exception as e:
            error_msg = f"❌ Technical report generation failed: {str(e)}"
            print(error_msg)
            return error_msg
    
    def _generate_technical_analysis(self, discovery_data: Dict[str, Any], qa_data: Dict[str, Any]) -> str:
        """Generate technical analysis of the discovered endpoints."""
        endpoints = discovery_data.get('endpoints', [])
        
        analysis = f"# VAmPI API Technical Analysis\n\n"
        analysis += f"## Security Assessment\n\n"
        
        # Count by risk level
        risk_counts = {}
        for endpoint in endpoints:
            risk = endpoint.get('risk_level', 'Medium')
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
        
        analysis += f"### Risk Distribution\n"
        for risk, count in risk_counts.items():
            analysis += f"- {risk}: {count} endpoints\n"
        
        # Authentication analysis
        auth_required = len([ep for ep in endpoints if ep.get('authentication_required', False)])
        auth_not_required = len(endpoints) - auth_required
        
        analysis += f"\n### Authentication Analysis\n"
        analysis += f"- Endpoints requiring authentication: {auth_required}\n"
        analysis += f"- Public endpoints: {auth_not_required}\n"
        
        # High-risk endpoint details
        high_risk = [ep for ep in endpoints if ep.get('risk_level', 'Medium') in ['High', 'Critical']]
        if high_risk:
            analysis += f"\n### High-Risk Endpoints\n"
            for endpoint in high_risk:
                analysis += f"- {endpoint.get('methods', [])} {endpoint.get('path', '')}: {endpoint.get('risk_level', 'Medium')}\n"
        
        analysis += f"\n## Recommendations\n"
        analysis += f"1. Implement proper authentication for all sensitive endpoints\n"
        analysis += f"2. Add input validation and sanitization\n"
        analysis += f"3. Implement rate limiting for public endpoints\n"
        analysis += f"4. Regular security audits and penetration testing\n"
        
        return analysis
    
    def _create_discovery_report(self, discovery_data: Dict[str, Any]) -> DiscoveryReport:
        """Create the final DiscoveryReport object."""
        try:
            # Extract endpoints from discovery data
            endpoints_data = discovery_data.get("discovery_data", {}).get("endpoints", [])
            
            # Convert to EndpointMetadata objects
            endpoints = []
            for ep_data in endpoints_data:
                # Create EndpointParameters
                parameters = EndpointParameters(
                    query_params=ep_data.get("parameters", {}).get("query_params", []),
                    path_params=ep_data.get("parameters", {}).get("path_params", []),
                    body_params=ep_data.get("parameters", {}).get("body_params", []),
                    headers=ep_data.get("parameters", {}).get("headers", [])
                )
                
                # Create EndpointMetadata
                endpoint = EndpointMetadata(
                    id=ep_data.get("id", ""),
                    path=ep_data.get("path", ""),
                    methods=ep_data.get("methods", ["GET"]),
                    description=ep_data.get("description", ""),
                    parameters=parameters,
                    authentication_required=ep_data.get("authentication_required", False),
                    authentication_type=ep_data.get("authentication_type", "None"),
                    risk_level=ep_data.get("risk_level", "Medium"),
                    risk_factors=ep_data.get("risk_factors", []),
                    response_types=ep_data.get("response_types", []),
                    discovered_via=ep_data.get("discovered_via", "endpoint_scanning"),
                    status_code=ep_data.get("status_code", 200)
                )
                endpoints.append(endpoint)
            
            # Create DiscoverySummary
            summary_data = discovery_data.get("discovery_data", {}).get("discovery_summary", {})
            summary = DiscoverySummary(
                total_endpoints=summary_data.get("total_endpoints", len(endpoints)),
                authenticated_endpoints=summary_data.get("authenticated_endpoints", 0),
                public_endpoints=summary_data.get("public_endpoints", 0),
                high_risk_endpoints=summary_data.get("high_risk_endpoints", 0),
                medium_risk_endpoints=summary_data.get("medium_risk_endpoints", 0),
                low_risk_endpoints=summary_data.get("low_risk_endpoints", 0),
                authentication_types=summary_data.get("authentication_types", []),
                discovery_coverage=summary_data.get("discovery_coverage", 100.0),
                parameter_coverage=summary_data.get("parameter_coverage", 0.0),
                discovery_start_time=summary_data.get("discovery_start_time"),
                discovery_end_time=summary_data.get("discovery_end_time"),
                discovery_duration=summary_data.get("discovery_duration", 0.0),
                total_parameters=summary_data.get("total_parameters", 0),
                unique_parameters=summary_data.get("unique_parameters", 0)
            )
            
            # Create APIStructure
            api_data = discovery_data.get("discovery_data", {}).get("api_structure", {})
            api_structure = APIStructure(
                base_url=api_data.get("base_url", ""),
                version=api_data.get("version"),
                title=api_data.get("title", "VAmPI API"),
                description=api_data.get("description", "VAmPI API discovered through endpoint scanning"),
                base_path=api_data.get("base_path"),
                schemes=api_data.get("schemes", []),
                host=api_data.get("host"),
                port=api_data.get("port"),
                endpoint_groups=api_data.get("endpoint_groups", {}),
                contact_info=api_data.get("contact_info"),
                license_info=api_data.get("license_info"),
                external_docs=api_data.get("external_docs"),
                discovered_at=api_data.get("discovered_at"),
                discovery_method=api_data.get("discovery_method", "endpoint_scanning")
            )
            
            # Create DiscoveryReport
            report = DiscoveryReport(
                endpoints=endpoints,
                discovery_summary=summary,
                api_structure=api_structure,
                report_id=f"vampi_discovery_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                notes=f"Technical Analysis: Generated from discovery data"
            )
            
            return report
            
        except Exception as e:
            print(f"❌ Error creating discovery report: {e}")
            raise
    
    def _save_final_report(self, report: DiscoveryReport):
        """Save the final discovery report."""
        try:
            # Backup existing report if it exists
            if os.path.exists("discovered_endpoints.json"):
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_file = f"discovered_endpoints.json.bak.{timestamp}"
                os.rename("discovered_endpoints.json", backup_file)
                logger.info(f"Backed up existing report to {backup_file}")
            
            # Save new report
            report.save_to_file("discovered_endpoints.json")
            logger.info("Final discovery report saved successfully")
            
        except Exception as e:
            logger.error(f"Failed to save final report: {e}")
            raise
    
    def _cleanup_temp_files(self):
        """Clean up temporary files."""
        temp_files = ["temp_discovery_results.json", "temp_qa_results.json"]
        for temp_file in temp_files:
            try:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
                    logger.info(f"Cleaned up {temp_file}")
            except Exception as e:
                logger.warning(f"Failed to clean up {temp_file}: {e}")


class FileReadTool(BaseTool):
    """Tool for reading files."""
    
    name: str = "file_read_tool"
    description: str = "Reads the contents of a file and returns its content as a string."
    file_path: str = Field(default="", description="Path to the file to read")
    
    def _run(self, **kwargs) -> str:
        """Read file content."""
        try:
            file_path = kwargs.get('file_path', self.file_path)
            if not os.path.exists(file_path):
                return f"❌ File not found: {file_path}"
            
            with open(file_path, 'r') as f:
                content = f.read()
            
            return f"✅ File content read successfully:\n\n{content}"
            
        except Exception as e:
            return f"❌ Failed to read file: {str(e)}"


class FileWriteTool(BaseTool):
    """Tool for writing content to files."""
    
    name: str = "file_write_tool"
    description: str = "Writes content to a file. If the file exists, it will be overwritten."
    file_path: str = Field(default="", description="Path to the file to write")
    content: str = Field(default="", description="Content to write to the file")
    
    def _run(self, **kwargs) -> str:
        """Write content to file."""
        try:
            file_path = kwargs.get('file_path', self.file_path)
            content = kwargs.get('content', self.content)
            
            if not file_path:
                return "❌ No file path specified"
            
            if not content:
                return "❌ No content specified"
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            with open(file_path, 'w') as f:
                f.write(content)
            
            return f"✅ Content written successfully to {file_path}"
            
        except Exception as e:
            return f"❌ Failed to write file: {str(e)}"


class RunScriptTool(BaseTool):
    """Tool for running Python scripts and functions."""
    
    name: str = "run_script_tool"
    description: str = "Executes Python scripts or functions and returns the results."
    script_path: str = Field(default="", description="Path to the Python script to run")
    function_name: str = Field(default="", description="Name of the function to call (optional)")
    
    def _run(self, **kwargs) -> str:
        """Run Python script or function."""
        try:
            script_path = kwargs.get('script_path', self.script_path)
            function_name = kwargs.get('function_name', self.function_name)
            
            if not script_path:
                return "❌ No script path specified"
            
            if not os.path.exists(script_path):
                return f"❌ Script not found: {script_path}"
            
            # Import and execute the script
            import importlib.util
            spec = importlib.util.spec_from_file_location("script_module", script_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            if function_name:
                if hasattr(module, function_name):
                    func = getattr(module, function_name)
                    if callable(func):
                        result = func()
                        return f"✅ Function {function_name} executed successfully:\n{result}"
                    else:
                        return f"❌ {function_name} is not callable"
                else:
                    return f"❌ Function {function_name} not found in script"
            else:
                # Just import the module
                return f"✅ Script {script_path} imported successfully"
            
        except Exception as e:
            return f"❌ Failed to run script: {str(e)}" 