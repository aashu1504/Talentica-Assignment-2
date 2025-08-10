"""
Simplified API Discovery Agent for VAmPI.

This module implements a simplified API Discovery Agent that focuses on
core discovery functionality without the complexity of CrewAI.
"""

import asyncio
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path

# Handle both direct execution and module import
try:
    from .models import (
        APIDiscoveryResult, DiscoveryConfig, DiscoveryTask,
        RiskLevel, AuthenticationType
    )
    from .discovery import VAmPIDiscoveryEngine
    from .utils import (
        setup_logging, load_config_from_env, save_discovery_result,
        create_output_directory
    )
except ImportError:
    from models import (
        APIDiscoveryResult, DiscoveryConfig, DiscoveryTask,
        RiskLevel, AuthenticationType
    )
    from discovery import VAmPIDiscoveryEngine
    from utils import (
        setup_logging, load_config_from_env, save_discovery_result,
        create_output_directory
    )


class APIDiscoveryAgent:
    """
    Simplified API Discovery Agent for VAmPI.
    
    This agent orchestrates the discovery process and provides analysis
    of discovered VAmPI endpoints with security context.
    """
    
    def __init__(self, config: Optional[DiscoveryConfig] = None):
        """
        Initialize the API Discovery Agent.
        
        Args:
            config: Discovery configuration, loads from env if not provided
        """
        self.config = config or load_config_from_env()
        self.logger = setup_logging()
        
        # Discovery engine
        self.discovery_engine = VAmPIDiscoveryEngine(self.config)
        
        # Output configuration
        self.output_dir = "output"
        create_output_directory(self.output_dir)
    
    async def execute_discovery(self) -> APIDiscoveryResult:
        """
        Execute the complete discovery process.
        
        Returns:
            APIDiscoveryResult with all discovery information
        """
        self.logger.info("Starting VAmPI API discovery process...")
        
        try:
            # Run endpoint discovery
            discovery_result = await self._execute_endpoint_discovery()
            
            # Enhance with additional analysis
            enhanced_result = await self._enhance_discovery_result(discovery_result)
            
            # Save results
            self._save_results(enhanced_result)
            
            self.logger.info("Discovery process completed successfully")
            return enhanced_result
            
        except Exception as e:
            self.logger.error(f"Discovery process failed: {e}")
            raise
    
    async def _execute_endpoint_discovery(self) -> APIDiscoveryResult:
        """
        Execute the core endpoint discovery.
        
        Returns:
            APIDiscoveryResult with discovered endpoints
        """
        self.logger.info("Executing endpoint discovery...")
        
        async with self.discovery_engine as engine:
            result = await engine.discover_endpoints()
            
        self.logger.info(f"Discovered {result.discovery_summary.total_endpoints} endpoints")
        return result
    
    async def _enhance_discovery_result(self, discovery_result: APIDiscoveryResult) -> APIDiscoveryResult:
        """
        Enhance the discovery result with additional analysis.
        
        Args:
            discovery_result: Basic discovery result
            
        Returns:
            Enhanced discovery result
        """
        self.logger.info("Enhancing discovery result with additional analysis...")
        
        # Enhance endpoint analysis
        enhanced_endpoints = await self._enhance_endpoint_analysis(discovery_result.endpoints)
        
        # Create enhanced result
        enhanced_result = APIDiscoveryResult(
            discovery_summary=discovery_result.discovery_summary,
            endpoints=enhanced_endpoints,
            authentication_mechanisms=discovery_result.authentication_mechanisms,
            api_structure=discovery_result.api_structure,
            security_insights=self._generate_security_insights(enhanced_endpoints),
            recommendations=self._generate_recommendations(enhanced_endpoints)
        )
        
        return enhanced_result
    
    async def _enhance_endpoint_analysis(self, endpoints: List) -> List:
        """
        Enhance endpoint analysis with additional insights.
        
        Args:
            endpoints: List of discovered endpoints
            
        Returns:
            Enhanced endpoints
        """
        enhanced_endpoints = []
        
        for endpoint in endpoints:
            # Enhance risk assessment
            enhanced_risk = self._enhance_risk_assessment(endpoint)
            
            # Enhance description
            enhanced_description = self._enhance_description(endpoint)
            
            # Create enhanced endpoint
            enhanced_endpoint = endpoint.model_copy(update={
                'risk_level': enhanced_risk,
                'description': enhanced_description
            })
            
            enhanced_endpoints.append(enhanced_endpoint)
        
        return enhanced_endpoints
    
    def _enhance_risk_assessment(self, endpoint) -> RiskLevel:
        """
        Enhance risk assessment for an endpoint.
        
        Args:
            endpoint: Endpoint to assess
            
        Returns:
            Enhanced risk level
        """
        # Base risk level
        base_risk = endpoint.risk_level
        
        # Additional risk factors
        additional_risk_factors = []
        
        # Check for sensitive operations
        if any(method in ['DELETE', 'PUT', 'POST'] for method in endpoint.methods):
            if '/users' in endpoint.path or '/admin' in endpoint.path:
                additional_risk_factors.append("Sensitive operation on user/admin data")
        
        # Check for authentication bypass potential
        if not endpoint.authentication_required:
            if any(sensitive in endpoint.path for sensitive in ['/admin', '/users', '/auth']):
                additional_risk_factors.append("No authentication required for sensitive endpoint")
        
        # Update risk level based on factors
        if additional_risk_factors:
            if base_risk == RiskLevel.LOW:
                base_risk = RiskLevel.MEDIUM
            elif base_risk == RiskLevel.MEDIUM:
                base_risk = RiskLevel.HIGH
        
        return base_risk
    
    def _enhance_description(self, endpoint) -> str:
        """
        Enhance endpoint description with additional context.
        
        Args:
            endpoint: Endpoint to enhance
            
        Returns:
            Enhanced description
        """
        base_description = endpoint.description
        
        # Add authentication context
        if endpoint.authentication_required:
            auth_context = f"Requires {endpoint.authentication_type.value} authentication"
        else:
            auth_context = "No authentication required"
        
        # Add risk context
        risk_context = f"Risk level: {endpoint.risk_level.value}"
        
        # Combine descriptions
        enhanced_description = f"{base_description}. {auth_context}. {risk_context}."
        
        return enhanced_description
    
    def _generate_security_insights(self, endpoints: List) -> Dict[str, Any]:
        """
        Generate security insights from discovered endpoints.
        
        Args:
            endpoints: List of discovered endpoints
            
        Returns:
            Dictionary of security insights
        """
        insights = {
            "total_endpoints": len(endpoints),
            "authentication_coverage": 0,
            "high_risk_endpoints": 0,
            "critical_risk_endpoints": 0,
            "sensitive_operations": 0,
            "potential_vulnerabilities": []
        }
        
        for endpoint in endpoints:
            # Count authentication coverage
            if endpoint.authentication_required:
                insights["authentication_coverage"] += 1
            
            # Count risk levels
            if endpoint.risk_level == RiskLevel.HIGH:
                insights["high_risk_endpoints"] += 1
            elif endpoint.risk_level == RiskLevel.CRITICAL:
                insights["critical_risk_endpoints"] += 1
            
            # Count sensitive operations
            if any(method in ['DELETE', 'PUT', 'POST'] for method in endpoint.methods):
                if '/users' in endpoint.path or '/admin' in endpoint.path:
                    insights["sensitive_operations"] += 1
            
            # Identify potential vulnerabilities
            if not endpoint.authentication_required:
                if any(sensitive in endpoint.path for sensitive in ['/admin', '/users', '/auth']):
                    insights["potential_vulnerabilities"].append(
                        f"Unauthenticated access to {endpoint.path}"
                    )
        
        # Calculate percentages
        if insights["total_endpoints"] > 0:
            insights["authentication_coverage_percentage"] = (
                insights["authentication_coverage"] / insights["total_endpoints"] * 100
            )
        
        return insights
    
    def _generate_recommendations(self, endpoints: List) -> List[str]:
        """
        Generate security recommendations based on discovered endpoints.
        
        Args:
            endpoints: List of discovered endpoints
            
        Returns:
            List of security recommendations
        """
        recommendations = []
        
        # Check for unauthenticated sensitive endpoints
        unauthenticated_sensitive = [
            ep for ep in endpoints 
            if not ep.authentication_required and 
            any(sensitive in ep.path for sensitive in ['/admin', '/users', '/auth'])
        ]
        
        if unauthenticated_sensitive:
            recommendations.append(
                f"Implement authentication for {len(unauthenticated_sensitive)} sensitive endpoints"
            )
        
        # Check for high-risk endpoints
        high_risk_endpoints = [
            ep for ep in endpoints 
            if ep.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
        ]
        
        if high_risk_endpoints:
            recommendations.append(
                f"Review and secure {len(high_risk_endpoints)} high-risk endpoints"
            )
        
        # General recommendations
        recommendations.extend([
            "Implement rate limiting for all endpoints",
            "Use HTTPS for all communications",
            "Implement proper input validation",
            "Add security headers (CORS, CSP, etc.)",
            "Regular security audits and penetration testing"
        ])
        
        return recommendations
    
    def _save_results(self, result: APIDiscoveryResult) -> None:
        """
        Save discovery results to files.
        
        Args:
            result: Discovery result to save
        """
        try:
            # Save main result
            timestamp = result.discovery_summary.discovery_timestamp.strftime("%Y%m%d_%H%M%S")
            filename = f"vampi_discovery_{timestamp}.json"
            
            saved_path = save_discovery_result(result, self.output_dir, filename)
            if saved_path:
                self.logger.info(f"Main results saved to: {saved_path}")
            
            # Save summary report
            summary_path = self._save_summary_report(result)
            if summary_path:
                self.logger.info(f"Summary report saved to: {summary_path}")
                
        except Exception as e:
            self.logger.error(f"Failed to save results: {e}")
    
    def _save_summary_report(self, result: APIDiscoveryResult) -> Optional[str]:
        """
        Save a human-readable summary report.
        
        Args:
            result: Discovery result
            
        Returns:
            Path to saved summary report, or None if failed
        """
        try:
            summary_content = self._generate_summary_report(result)
            
            timestamp = result.discovery_summary.discovery_timestamp.strftime("%Y%m%d_%H%M%S")
            filename = f"vampi_summary_{timestamp}.txt"
            file_path = Path(self.output_dir) / filename
            
            with open(file_path, 'w') as f:
                f.write(summary_content)
            
            return str(file_path)
            
        except Exception as e:
            self.logger.error(f"Failed to save summary report: {e}")
            return None
    
    def _generate_summary_report(self, result: APIDiscoveryResult) -> str:
        """
        Generate a human-readable summary report.
        
        Args:
            result: Discovery result
            
        Returns:
            Summary report content
        """
        summary = []
        summary.append("=" * 80)
        summary.append("VAmPI API Discovery Summary Report")
        summary.append("=" * 80)
        summary.append("")
        
        # Discovery summary
        summary.append("DISCOVERY SUMMARY:")
        summary.append(f"  Target Application: {result.discovery_summary.target_application}")
        summary.append(f"  Base URL: {result.discovery_summary.base_url}")
        summary.append(f"  Discovery Timestamp: {result.discovery_summary.discovery_timestamp}")
        summary.append(f"  Total Endpoints: {result.discovery_summary.total_endpoints}")
        summary.append(f"  Scan Duration: {result.discovery_summary.scan_duration:.2f}s")
        summary.append(f"  Success Rate: {result.discovery_summary.success_rate:.1f}%")
        summary.append("")
        
        # Security insights
        if result.security_insights:
            summary.append("SECURITY INSIGHTS:")
            insights = result.security_insights
            summary.append(f"  Authentication Coverage: {insights.get('authentication_coverage_percentage', 0):.1f}%")
            summary.append(f"  High Risk Endpoints: {insights.get('high_risk_endpoints', 0)}")
            summary.append(f"  Critical Risk Endpoints: {insights.get('critical_risk_endpoints', 0)}")
            summary.append(f"  Sensitive Operations: {insights.get('sensitive_operations', 0)}")
            summary.append("")
        
        # High-risk endpoints
        high_risk_endpoints = [
            ep for ep in result.endpoints 
            if ep.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
        ]
        
        if high_risk_endpoints:
            summary.append("HIGH-RISK ENDPOINTS:")
            for ep in high_risk_endpoints:
                summary.append(f"  - {ep.path} ({', '.join(ep.methods)}) - {ep.risk_level.value}")
                summary.append(f"    Risk Factors: {', '.join(ep.risk_factors)}")
                summary.append(f"    Authentication: {'Required' if ep.authentication_required else 'Not Required'}")
                summary.append("")
        
        # Recommendations
        if result.recommendations:
            summary.append("SECURITY RECOMMENDATIONS:")
            for i, rec in enumerate(result.recommendations, 1):
                summary.append(f"  {i}. {rec}")
            summary.append("")
        
        summary.append("=" * 80)
        summary.append("Report generated by VAmPI API Discovery Agent")
        summary.append("=" * 80)
        
        return "\n".join(summary)
    
    def get_agent_status(self) -> Dict[str, Any]:
        """
        Get the current status of the agent.
        
        Returns:
            Dictionary with agent status information
        """
        return {
            "status": "ready",
            "config": {
                "base_url": self.config.base_url,
                "timeout": self.config.timeout,
                "max_retries": self.config.max_retries,
                "rate_limit_delay": self.config.rate_limit_delay
            },
            "output_directory": self.output_dir,
            "discovery_engine_ready": True
        }


async def run_discovery_agent(config: Optional[DiscoveryConfig] = None) -> APIDiscoveryResult:
    """
    Convenience function to run the discovery agent.
    
    Args:
        config: Optional discovery configuration
        
    Returns:
        Discovery result
    """
    agent = APIDiscoveryAgent(config)
    return await agent.execute_discovery()


# For backward compatibility
async def main():
    """Main function for standalone execution."""
    config = load_config_from_env()
    result = await run_discovery_agent(config)
    print(f"Discovery completed. Found {result.discovery_summary.total_endpoints} endpoints.")
    return result


if __name__ == "__main__":
    asyncio.run(main()) 