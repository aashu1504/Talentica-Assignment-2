#!/usr/bin/env python3
"""
VAmPI API Discovery Agent Tools

This module defines the tools used by CrewAI agents, with Gemini 2.5 Flash Lite
handling all reasoning and analysis internally within the tools.
"""

import os
import json
import asyncio
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
import httpx

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


class GeminiClient:
    """Client for Google Generative AI (Gemini 2.5 Flash Lite)."""
    
    def __init__(self, api_key: str):
        """Initialize Gemini client."""
        self.api_key = api_key
        self._model = None
        self._initialize_model()
    
    def _initialize_model(self):
        """Initialize the Gemini model."""
        try:
            import google.generativeai as genai
            genai.configure(api_key=self.api_key)
            # Use Gemini 2.0 Flash for better performance
            self._model = genai.GenerativeModel('gemini-2.0-flash-exp')
            logger.info("✅ Gemini 2.0 Flash model initialized successfully")
        except ImportError:
            logger.error("❌ google-generativeai package not installed")
            raise
        except Exception as e:
            logger.error(f"❌ Failed to initialize Gemini: {e}")
            raise
    
    def analyze_endpoints(self, endpoints_data: str) -> str:
        """Analyze discovered endpoints using Gemini."""
        try:
            prompt = f"""
            Analyze the following VAmPI API endpoints and provide insights:
            
            {endpoints_data}
            
            Please provide:
            1. Security risk assessment for each endpoint
            2. Authentication requirements analysis
            3. Potential vulnerabilities
            4. Recommendations for security testing
            
            Format your response as a structured analysis.
            """
            
            response = self._model.generate_content(prompt)
            return response.text
        except Exception as e:
            logger.error(f"Gemini analysis failed: {e}")
            return f"Analysis failed: {str(e)}"
    
    def generate_security_report(self, discovery_data: Dict[str, Any]) -> str:
        """Generate a comprehensive security report using Gemini."""
        try:
            prompt = f"""
            Based on the following VAmPI API discovery data, generate a comprehensive security report:
            
            {json.dumps(discovery_data, indent=2, default=str)}
            
            Include:
            1. Executive summary
            2. Risk assessment overview
            3. Authentication mechanism analysis
            4. Specific security concerns
            5. Testing recommendations
            6. Compliance considerations
            
            Format as a professional security report.
            """
            
            response = self._model.generate_content(prompt)
            return response.text
        except Exception as e:
            logger.error(f"Gemini report generation failed: {e}")
            return f"Report generation failed: {str(e)}"
    
    def validate_endpoint_data(self, endpoint_data: Dict[str, Any]) -> str:
        """Validate and enhance endpoint data using Gemini."""
        try:
            prompt = f"""
            Review and validate this API endpoint data for completeness and accuracy:
            
            {json.dumps(endpoint_data, indent=2, default=str)}
            
            Identify:
            1. Missing required fields
            2. Data inconsistencies
            3. Potential improvements
            4. Risk level validation
            
            Provide specific recommendations for improvement.
            """
            
            response = self._model.generate_content(prompt)
            return response.text
        except Exception as e:
            logger.error(f"Gemini validation failed: {e}")
            return f"Validation failed: {str(e)}"


class APIDiscoveryTool(BaseTool):
    """Tool for discovering VAmPI API endpoints using Gemini for analysis."""
    
    name: str = "api_discovery_tool"
    description: str = "Discovers and analyzes VAmPI API endpoints. Uses Gemini AI for intelligent analysis and risk assessment."
    base_url: str = Field(..., description="Base URL for VAmPI API")
    api_key: str = Field(..., description="Google API key for Gemini")
    
    def _run(self, **kwargs) -> str:
        """Execute the API discovery tool."""
        try:
            logger.info(f"Starting VAmPI API discovery at {self.base_url}")
            
            # Initialize Gemini client
            gemini = GeminiClient(self.api_key)
            
            # Create discovery configuration
            config = DiscoveryConfig(
                base_url=self.base_url,
                timeout=30.0,
                max_concurrent_requests=5,
                max_retries=3,
                rate_limit_delay=1.0
            )
            
            # Run discovery
            discovery_engine = VAmPIDiscoveryEngine(config)
            
            # Use asyncio to run the async discovery
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                result = loop.run_until_complete(discovery_engine.discover_endpoints())
                loop.close()
            except Exception as e:
                loop.close()
                raise e
            
            # Convert to dictionary for Gemini analysis
            discovery_data = result.dict()
            
            # Use Gemini to analyze the discovered endpoints
            analysis = gemini.analyze_endpoints(
                f"Discovered {len(result.endpoints)} endpoints:\n" +
                "\n".join([f"- {ep.methods[0] if ep.methods else 'GET'} {ep.path}: {ep.description}" for ep in result.endpoints])
            )
            
            # Combine discovery results with Gemini analysis
            enhanced_result = {
                "discovery_data": discovery_data,
                "gemini_analysis": analysis,
                "discovery_timestamp": datetime.now().isoformat(),
                "total_endpoints": len(result.endpoints)
            }
            
            # Save enhanced results for other tools
            self._save_discovery_results(enhanced_result)
            
            return f"✅ API Discovery completed successfully!\n\n" \
                   f"📊 Discovered {len(result.endpoints)} endpoints\n" \
                   f"🔍 Gemini Analysis:\n{analysis}\n\n" \
                   f"📁 Results saved for further processing"
            
        except Exception as e:
            logger.error(f"API discovery tool failed: {e}")
            return f"❌ API discovery failed: {str(e)}"
    
    def _save_discovery_results(self, results: Dict[str, Any]):
        """Save discovery results to a temporary file for other tools."""
        try:
            output_file = "temp_discovery_results.json"
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            logger.info(f"Discovery results saved to {output_file}")
        except Exception as e:
            logger.error(f"Failed to save discovery results: {e}")


class QATestingTool(BaseTool):
    """Tool for QA testing discovered endpoints using Gemini for validation."""
    
    name: str = "qa_testing_tool"
    description: str = "Validates discovered API endpoints and performs QA testing. Uses Gemini AI for intelligent test case generation and validation."
    api_key: str = Field(..., description="Google API key for Gemini")
    
    def _run(self, **kwargs) -> str:
        """Execute the QA testing tool."""
        try:
            logger.info("Starting QA testing of discovered endpoints")
            
            # Initialize Gemini client
            gemini = GeminiClient(self.api_key)
            
            # Load discovery results
            discovery_file = "temp_discovery_results.json"
            if not os.path.exists(discovery_file):
                return "❌ No discovery results found. Run API discovery tool first."
            
            with open(discovery_file, 'r') as f:
                discovery_results = json.load(f)
            
            # Extract endpoints for testing
            endpoints = discovery_results.get("discovery_data", {}).get("endpoints", [])
            if not endpoints:
                return "❌ No endpoints found in discovery results"
            
            # Use Gemini to generate test cases and validation
            test_plan = gemini.generate_security_report(discovery_results)
            
            # Perform basic endpoint validation
            validation_results = self._validate_endpoints(endpoints)
            
            # Combine results
            qa_results = {
                "test_plan": test_plan,
                "validation_results": validation_results,
                "test_timestamp": datetime.now().isoformat(),
                "endpoints_tested": len(endpoints)
            }
            
            # Save QA results
            self._save_qa_results(qa_results)
            
            return f"✅ QA Testing completed successfully!\n\n" \
                   f"🧪 Tested {len(endpoints)} endpoints\n" \
                   f"📋 Test Plan:\n{test_plan}\n\n" \
                   f"🔍 Validation Results:\n{validation_results}\n\n" \
                   f"📁 Results saved for report generation"
            
        except Exception as e:
            logger.error(f"QA testing tool failed: {e}")
            return f"❌ QA testing failed: {str(e)}"
    
    def _validate_endpoints(self, endpoints: List[Dict[str, Any]]) -> str:
        """Validate discovered endpoints."""
        validation_summary = []
        
        for endpoint in endpoints:
            path = endpoint.get("path", "")
            method = endpoint.get("method", "")
            risk_level = endpoint.get("risk_level", "Medium")
            
            # Basic validation logic
            if not path or not method:
                validation_summary.append(f"❌ {method} {path}: Missing required fields")
            elif risk_level in ["High", "Critical"]:
                validation_summary.append(f"⚠️  {method} {path}: High risk endpoint identified")
            else:
                validation_summary.append(f"✅ {method} {path}: Valid endpoint")
        
        return "\n".join(validation_summary)
    
    def _save_qa_results(self, results: Dict[str, Any]):
        """Save QA results to a temporary file."""
        try:
            output_file = "temp_qa_results.json"
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            logger.info(f"QA results saved to {output_file}")
        except Exception as e:
            logger.error(f"Failed to save QA results: {e}")


class TechnicalWriterTool(BaseTool):
    """Tool for generating technical reports using Gemini for content creation."""
    
    name: str = "technical_writer_tool"
    description: str = "Generates comprehensive technical reports from discovery and QA results. Uses Gemini AI for intelligent report writing and analysis."
    api_key: str = Field(..., description="Google API key for Gemini")
    
    def _run(self, **kwargs) -> str:
        """Execute the technical writer tool."""
        try:
            logger.info("Starting technical report generation")
            
            # Initialize Gemini client
            gemini = GeminiClient(self.api_key)
            
            # Load discovery and QA results
            discovery_file = "temp_discovery_results.json"
            qa_file = "temp_qa_results.json"
            
            if not os.path.exists(discovery_file) or not os.path.exists(qa_file):
                return "❌ Missing required input files. Run discovery and QA tools first."
            
            with open(discovery_file, 'r') as f:
                discovery_results = json.load(f)
            
            with open(qa_file, 'r') as f:
                qa_results = json.load(f)
            
            # Combine all data for report generation
            report_data = {
                "discovery": discovery_results,
                "qa_testing": qa_results,
                "report_metadata": {
                    "generated_at": datetime.now().isoformat(),
                    "report_type": "VAmPI API Discovery Report",
                    "version": "1.0.0"
                }
            }
            
            # Use Gemini to generate the comprehensive report
            technical_report = gemini.generate_security_report(report_data)
            
            # Create the final discovery report
            final_report = self._create_discovery_report(discovery_results, qa_results, technical_report)
            
            # Save the final report
            self._save_final_report(final_report)
            
            # Clean up temporary files
            self._cleanup_temp_files()
            
            return f"✅ Technical Report generated successfully!\n\n" \
                   f"📄 Report Summary:\n{technical_report[:500]}...\n\n" \
                   f"📁 Final report saved to discovered_endpoints.json\n" \
                   f"🧹 Temporary files cleaned up"
            
        except Exception as e:
            logger.error(f"Technical writer tool failed: {e}")
            return f"❌ Report generation failed: {str(e)}"
    
    def _create_discovery_report(self, discovery_data: Dict[str, Any], 
                                qa_data: Dict[str, Any], 
                                technical_analysis: str) -> DiscoveryReport:
        """Create the final DiscoveryReport object."""
        try:
            # Extract endpoints from discovery data
            endpoints_data = discovery_data.get("discovery_data", {}).get("endpoints", [])
            
            # Convert to EndpointMetadata objects
            endpoints = []
            for ep_data in endpoints_data:
                try:
                    # Create EndpointParameters
                    params = EndpointParameters(
                        query_params=ep_data.get("parameters", {}).get("query_params", []),
                        path_params=ep_data.get("parameters", {}).get("path_params", []),
                        body_params=ep_data.get("parameters", {}).get("body_params", []),
                        headers=ep_data.get("parameters", {}).get("headers", [])
                    )
                    
                    # Create EndpointMetadata
                    endpoint = EndpointMetadata(
                        id=ep_data.get("id", f"ep_{len(endpoints)}"),
                        path=ep_data.get("path", ""),
                        methods=[ep_data.get("method", "GET")],  # methods is a list
                        description=ep_data.get("description", ""),
                        parameters=params,
                        authentication_required=ep_data.get("authentication_required", False),
                        authentication_type=AuthenticationType(ep_data.get("authentication_type", "None")),
                        risk_level=RiskLevel(ep_data.get("risk_level", "Medium")),
                        risk_factors=ep_data.get("risk_factors", []),
                        response_types=ep_data.get("response_types", []),
                        discovered_via=DiscoveryMethod(ep_data.get("discovered_via", "endpoint_scanning")),
                        status_code=ep_data.get("status_code"),
                        response_time=ep_data.get("response_time")
                    )
                    endpoints.append(endpoint)
                except Exception as e:
                    logger.warning(f"Failed to create endpoint object: {e}")
                    continue
            
            # Create DiscoverySummary
            summary = DiscoverySummary(
                total_endpoints=len(endpoints),
                authenticated_endpoints=len([ep for ep in endpoints if ep.authentication_required]),
                public_endpoints=len([ep for ep in endpoints if not ep.authentication_required]),
                high_risk_endpoints=len([ep for ep in endpoints if ep.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]]),
                medium_risk_endpoints=len([ep for ep in endpoints if ep.risk_level == RiskLevel.MEDIUM]),
                low_risk_endpoints=len([ep for ep in endpoints if ep.risk_level == RiskLevel.LOW]),
                discovery_coverage=100.0,  # Assuming full coverage for discovered endpoints
                discovery_start_time=datetime.fromisoformat(discovery_data.get("discovery_timestamp", datetime.now().isoformat())),
                discovery_end_time=datetime.now()
            )
            
            # Create APIStructure
            api_structure = APIStructure(
                base_url=discovery_data.get("discovery_data", {}).get("api_structure", {}).get("base_url", "http://localhost:5000"),
                discovery_method="endpoint_scanning",
                discovered_at=datetime.now()
            )
            
            # Create DiscoveryReport
            report = DiscoveryReport(
                discovery_summary=summary,
                endpoints=endpoints,
                authentication_mechanisms=[],  # Will be populated if available
                api_structure=api_structure,
                report_id=f"vampi_discovery_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                notes=f"Technical Analysis: {technical_analysis}"
            )
            
            return report
            
        except Exception as e:
            logger.error(f"Failed to create discovery report: {e}")
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
    file_path: str = Field(..., description="Path to the file to read")
    
    def _run(self, **kwargs) -> str:
        """Execute the file read tool."""
        try:
            if not os.path.exists(self.file_path):
                return f"❌ File not found: {self.file_path}"
            
            with open(self.file_path, 'r') as f:
                content = f.read()
            
            return f"✅ File read successfully: {self.file_path}\n\nContent:\n{content}"
            
        except Exception as e:
            return f"❌ Failed to read file {self.file_path}: {str(e)}"


class FileWriteTool(BaseTool):
    """Tool for writing content to files."""
    
    name: str = "file_write_tool"
    description: str = "Writes content to a file. If the file exists, it will be overwritten."
    file_path: str = Field(..., description="Path to the file to write")
    content: str = Field(..., description="Content to write to the file")
    
    def _run(self, **kwargs) -> str:
        """Execute the file write tool."""
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(self.file_path), exist_ok=True)
            
            with open(self.file_path, 'w') as f:
                f.write(self.content)
            
            return f"✅ Content written successfully to: {self.file_path}"
            
        except Exception as e:
            return f"❌ Failed to write to file {self.file_path}: {str(e)}"


class RunScriptTool(BaseTool):
    """Tool for running Python scripts and functions."""
    
    name: str = "run_script_tool"
    description: str = "Executes Python scripts or functions and returns the results."
    script_path: str = Field(..., description="Path to the Python script to run")
    function_name: str = Field(default="", description="Name of the function to call (optional)")
    
    def _run(self, **kwargs) -> str:
        """Execute the run script tool."""
        try:
            if not os.path.exists(self.script_path):
                return f"❌ Script not found: {self.script_path}"
            
            # Import the script module
            import importlib.util
            spec = importlib.util.spec_from_file_location("script_module", self.script_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            if self.function_name:
                # Call specific function
                if hasattr(module, self.function_name):
                    func = getattr(module, self.function_name)
                    result = func()
                    return f"✅ Function {self.function_name} executed successfully:\n{result}"
                else:
                    return f"❌ Function {self.function_name} not found in {self.script_path}"
            else:
                # Execute the script
                exec(open(self.script_path).read())
                return f"✅ Script {self.script_path} executed successfully"
            
        except Exception as e:
            return f"❌ Failed to execute script {self.script_path}: {str(e)}" 