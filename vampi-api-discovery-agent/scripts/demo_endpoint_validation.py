#!/usr/bin/env python3
"""
Enhanced Endpoint Validation Demo

This script demonstrates the enhanced endpoint validation system that ensures
discovered endpoints are accessible and suitable for security testing.
"""

import asyncio
import json
import sys
from pathlib import Path

# Add src directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from endpoint_validator import EndpointValidator


class EndpointValidationDemo:
    """Demo class for enhanced endpoint validation"""
    
    def __init__(self, base_url: str = "http://localhost:5000"):
        self.base_url = base_url
        self.validator = None
        
    def print_header(self, title: str):
        """Print a formatted header"""
        print("\n" + "="*60)
        print(f"🔍 {title}")
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
            import httpx
            async with httpx.AsyncClient() as client:
                response = await client.head(self.base_url, timeout=5)
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
    
    async def check_discovery_results(self) -> bool:
        """Check if discovery results exist"""
        self.print_section("Checking Discovery Results")
        
        discovery_file = "temp_discovery_results.json"
        if not Path(discovery_file).exists():
            self.print_error(f"Discovery results file not found: {discovery_file}")
            self.print_info("Please run API discovery first:")
            self.print_info("  python src/test_crew_agents.py")
            return False
        
        try:
            with open(discovery_file, 'r') as f:
                discovery_data = json.load(f)
            
            endpoints = discovery_data.get('discovery_data', {}).get('endpoints', [])
            if not endpoints:
                self.print_error("No endpoints found in discovery results")
                return False
            
            self.print_success(f"Found {len(endpoints)} endpoints in discovery results")
            return True
            
        except Exception as e:
            self.print_error(f"Failed to read discovery results: {e}")
            return False
    
    async def demonstrate_endpoint_validation(self):
        """Demonstrate the enhanced endpoint validation system"""
        self.print_section("Enhanced Endpoint Validation Demonstration")
        
        try:
            # Initialize the endpoint validator
            self.validator = EndpointValidator(self.base_url, timeout=30)
            self.print_success("Endpoint validator initialized")
            
            # Run comprehensive validation
            self.print_info("Running enhanced endpoint validation...")
            validation_result = await self.validator.validate_endpoints_for_testing()
            
            if not validation_result:
                self.print_error("Endpoint validation failed")
                return False
            
            # Display validation results
            self._display_validation_results(validation_result)
            
            # Check if validation was successful
            if validation_result.get('validation_status') == 'SUCCESS':
                self.print_success("✅ Endpoint validation completed successfully!")
                return True
            else:
                self.print_warning("⚠️  Endpoint validation completed with issues")
                return False
                
        except Exception as e:
            self.print_error(f"Endpoint validation demonstration failed: {e}")
            return False
    
    def _display_validation_results(self, validation_result: dict):
        """Display validation results in a formatted way"""
        self.print_section("Validation Results Summary")
        
        print(f"🔍 Base URL: {validation_result.get('base_url', 'Unknown')}")
        print(f"📅 Timestamp: {validation_result.get('validation_timestamp', 'Unknown')}")
        print(f"📊 Total Endpoints: {validation_result.get('total_endpoints', 0)}")
        print(f"✅ Accessible Endpoints: {validation_result.get('accessible_endpoints', 0)}")
        print(f"❌ Inaccessible Endpoints: {validation_result.get('inaccessible_endpoints', 0)}")
        print(f"📈 Accessibility Rate: {validation_result.get('accessibility_rate', 0):.1f}%")
        print(f"🔧 Total Methods: {validation_result.get('total_methods', 0)}")
        print(f"✅ Accessible Methods: {validation_result.get('accessible_methods', 0)}")
        print(f"📈 Method Accessibility Rate: {validation_result.get('method_accessibility_rate', 0):.1f}%")
        print(f"⏱️  Average Response Time: {validation_result.get('average_response_time', 0)}s")
        print(f"⚠️  Total Warnings: {validation_result.get('total_warnings', 0)}")
        print(f"❌ Total Errors: {validation_result.get('total_errors', 0)}")
        print(f"🎯 Validation Status: {validation_result.get('validation_status', 'Unknown')}")
        
        # Display detailed results for first few endpoints
        validation_results = validation_result.get('validation_results', [])
        if validation_results:
            self.print_section("Detailed Validation Results (First 5 Endpoints)")
            
            for i, result in enumerate(validation_results[:5]):
                print(f"\n🔍 Endpoint {i+1}: {result.get('endpoint_path', 'Unknown')}")
                print(f"   Methods: {', '.join(result.get('methods', []))}")
                print(f"   Accessible: {'✅ Yes' if result.get('is_accessible') else '❌ No'}")
                print(f"   Accessible Methods: {', '.join(result.get('accessible_methods', []))}")
                print(f"   Reason: {result.get('reason', 'Unknown')}")
                
                if result.get('warnings'):
                    print(f"   ⚠️  Warnings: {len(result.get('warnings', []))}")
                
                if result.get('validation_errors'):
                    print(f"   ❌ Errors: {len(result.get('validation_errors', []))}")
    
    async def demonstrate_validation_integration(self):
        """Demonstrate how validation integrates with security testing"""
        self.print_section("Validation Integration with Security Testing")
        
        try:
            # Check if validated endpoints file was created
            validated_file = "validated_endpoints_for_testing.json"
            if Path(validated_file).exists():
                with open(validated_file, 'r') as f:
                    validated_data = json.load(f)
                
                self.print_success(f"✅ Validated endpoints file created: {validated_file}")
                self.print_info(f"📊 Contains {validated_data.get('total_accessible', 0)} validated endpoints")
                
                # Show sample of validated endpoints
                endpoints = validated_data.get('accessible_endpoints', [])
                if endpoints:
                    self.print_info("📋 Sample of validated endpoints:")
                    for i, endpoint in enumerate(endpoints[:3]):
                        print(f"   {i+1}. {endpoint.get('path', 'Unknown')} - {', '.join(endpoint.get('methods', []))}")
                
                return True
            else:
                self.print_warning(f"Validated endpoints file not found: {validated_file}")
                return False
                
        except Exception as e:
            self.print_error(f"Validation integration demonstration failed: {e}")
            return False
    
    async def run_complete_demo(self):
        """Run the complete endpoint validation demo"""
        self.print_header("Enhanced Endpoint Validation Demo")
        
        # Step 1: Check VAmPI status
        if not await self.check_vampi_status():
            self.print_error("Cannot proceed without VAmPI API running")
            return False
        
        # Step 2: Check discovery results
        if not await self.check_discovery_results():
            self.print_error("Cannot proceed without discovery results")
            return False
        
        # Step 3: Demonstrate endpoint validation
        if not await self.demonstrate_endpoint_validation():
            self.print_error("Endpoint validation demonstration failed")
            return False
        
        # Step 4: Demonstrate validation integration
        await self.demonstrate_validation_integration()
        
        # Final summary
        self.print_header("Demo Completed Successfully!")
        self.print_success("Enhanced endpoint validation system demonstrated")
        self.print_success("Generated files:")
        self.print_info("  - endpoint_validation_summary.json (Validation results)")
        self.print_info("  - validated_endpoints_for_testing.json (Accessible endpoints)")
        
        return True


async def main():
    """Main function to run the demo"""
    demo = EndpointValidationDemo()
    
    try:
        success = await demo.run_complete_demo()
        if success:
            print("\n🎉 Demo completed successfully!")
            print("The enhanced endpoint validation system is working correctly.")
            print("Endpoints are now properly validated before security testing.")
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