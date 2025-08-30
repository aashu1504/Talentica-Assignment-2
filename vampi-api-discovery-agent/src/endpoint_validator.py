#!/usr/bin/env python3
"""
Enhanced Endpoint Validation Module

This module provides comprehensive validation of discovered endpoints to ensure they are
accessible and suitable for security testing. It includes:
- Endpoint accessibility testing
- Response validation
- Authentication requirement verification
- Data structure validation
- Performance testing
"""

import asyncio
import json
import logging
import time
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
import httpx
from pathlib import Path

from security_testing.models import EndpointSecurityReport, SecurityTest, VulnerabilitySeverity, OWASPCategory


class EndpointValidator:
    """Enhanced endpoint validation for security testing"""
    
    def __init__(self, base_url: str, timeout: int = 30, max_retries: int = 3):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.max_retries = max_retries
        self.logger = logging.getLogger(__name__)
        
        # Validation thresholds
        self.max_response_time = 10.0  # seconds
        self.min_response_size = 10    # bytes
        self.max_response_size = 10 * 1024 * 1024  # 10MB
        
    async def validate_endpoints_for_testing(self, discovery_file: str = "temp_discovery_results.json") -> Dict[str, Any]:
        """
        Validate discovered endpoints to ensure they are accessible for security testing.
        
        Args:
            discovery_file: Path to discovery results file
            
        Returns:
            Validation results with accessible endpoints and validation details
        """
        self.logger.info("🔍 Starting enhanced endpoint validation for security testing...")
        
        try:
            # Load discovery results
            discovery_data = self._load_discovery_data(discovery_file)
            if not discovery_data:
                return self._create_validation_error("Failed to load discovery data")
            
            # Extract endpoints
            endpoints = discovery_data.get('discovery_data', {}).get('endpoints', [])
            if not endpoints:
                return self._create_validation_error("No endpoints found in discovery data")
            
            self.logger.info(f"📊 Validating {len(endpoints)} discovered endpoints...")
            
            # Validate each endpoint
            validation_results = []
            accessible_endpoints = []
            
            for i, endpoint in enumerate(endpoints):
                self.logger.info(f"🔍 Validating endpoint {i+1}/{len(endpoints)}: {endpoint.get('path', 'Unknown')}")
                
                validation_result = await self._validate_single_endpoint(endpoint)
                validation_results.append(validation_result)
                
                if validation_result['is_accessible']:
                    accessible_endpoints.append(endpoint)
                    self.logger.info(f"✅ Endpoint accessible: {endpoint.get('path', 'Unknown')}")
                else:
                    self.logger.warning(f"❌ Endpoint not accessible: {endpoint.get('path', 'Unknown')} - {validation_result['reason']}")
            
            # Generate validation summary
            validation_summary = self._generate_validation_summary(validation_results, accessible_endpoints)
            
            # Save validation results
            self._save_validation_results(validation_summary, accessible_endpoints)
            
            return validation_summary
            
        except Exception as e:
            self.logger.error(f"❌ Endpoint validation failed: {e}")
            return self._create_validation_error(f"Validation failed: {str(e)}")
    
    async def _validate_single_endpoint(self, endpoint: Dict[str, Any]) -> Dict[str, Any]:
        """Validate a single endpoint for accessibility and testing suitability"""
        start_time = time.time()
        
        endpoint_path = endpoint.get('path', '')
        methods = endpoint.get('methods', ['GET'])
        
        validation_result = {
            'endpoint_path': endpoint_path,
            'methods': methods,
            'is_accessible': False,
            'accessible_methods': [],
            'response_times': {},
            'status_codes': {},
            'response_sizes': {},
            'authentication_status': {},
            'validation_errors': [],
            'warnings': [],
            'validation_duration': 0.0
        }
        
        try:
            # Test each HTTP method
            for method in methods:
                method_validation = await self._test_method_accessibility(endpoint_path, method)
                
                if method_validation['is_accessible']:
                    validation_result['accessible_methods'].append(method)
                    validation_result['response_times'][method] = method_validation['response_time']
                    validation_result['status_codes'][method] = method_validation['status_code']
                    validation_result['response_sizes'][method] = method_validation['response_size']
                    validation_result['authentication_status'][method] = method_validation['auth_status']
                
                # Collect warnings
                if method_validation['warnings']:
                    validation_result['warnings'].extend(method_validation['warnings'])
            
            # Determine overall accessibility
            validation_result['is_accessible'] = len(validation_result['accessible_methods']) > 0
            
            if not validation_result['is_accessible']:
                validation_result['reason'] = "No HTTP methods are accessible"
            else:
                validation_result['reason'] = f"Accessible via: {', '.join(validation_result['accessible_methods'])}"
            
            # Validate endpoint data structure
            structure_validation = self._validate_endpoint_structure(endpoint)
            if not structure_validation['is_valid']:
                validation_result['warnings'].extend(structure_validation['warnings'])
            
            validation_result['validation_duration'] = time.time() - start_time
            
        except Exception as e:
            validation_result['validation_errors'].append(f"Validation failed: {str(e)}")
            validation_result['reason'] = f"Validation error: {str(e)}"
        
        return validation_result
    
    async def _test_method_accessibility(self, endpoint_path: str, method: str) -> Dict[str, Any]:
        """Test if a specific HTTP method is accessible for an endpoint"""
        result = {
            'is_accessible': False,
            'response_time': 0.0,
            'status_code': None,
            'response_size': 0,
            'auth_status': 'unknown',
            'warnings': []
        }
        
        try:
            url = f"{self.base_url}{endpoint_path}"
            start_time = time.time()
            
            # Test with retries
            for attempt in range(self.max_retries):
                try:
                    async with httpx.AsyncClient(timeout=self.timeout) as client:
                        response = await client.request(method, url)
                        
                        # Record response details
                        result['status_code'] = response.status_code
                        result['response_size'] = len(response.content)
                        result['response_time'] = time.time() - start_time
                        
                        # Determine accessibility based on status code
                        if response.status_code in [200, 201, 202, 204]:
                            result['is_accessible'] = True
                            result['auth_status'] = 'none_required'
                        elif response.status_code in [401, 403]:
                            result['is_accessible'] = True
                            result['auth_status'] = 'required'
                        elif response.status_code in [404, 405, 406]:
                            result['is_accessible'] = False
                            result['auth_status'] = 'not_found'
                        elif response.status_code >= 500:
                            result['is_accessible'] = False
                            result['auth_status'] = 'server_error'
                        else:
                            result['is_accessible'] = True
                            result['auth_status'] = 'unknown'
                        
                        # Check response time
                        if result['response_time'] > self.max_response_time:
                            result['warnings'].append(f"Slow response time: {result['response_time']:.2f}s")
                        
                        # Check response size
                        if result['response_size'] < self.min_response_size:
                            result['warnings'].append(f"Very small response: {result['response_size']} bytes")
                        elif result['response_size'] > self.max_response_size:
                            result['warnings'].append(f"Very large response: {result['response_size']} bytes")
                        
                        break  # Success, exit retry loop
                        
                except httpx.TimeoutException:
                    if attempt == self.max_retries - 1:
                        result['warnings'].append(f"Request timeout after {self.max_retries} attempts")
                    else:
                        await asyncio.sleep(0.5 * (attempt + 1))  # Exponential backoff
                        
                except httpx.RequestError as e:
                    if attempt == self.max_retries - 1:
                        result['warnings'].append(f"Request failed: {str(e)}")
                    else:
                        await asyncio.sleep(0.5 * (attempt + 1))
                        
        except Exception as e:
            result['warnings'].append(f"Unexpected error: {str(e)}")
        
        return result
    
    def _validate_endpoint_structure(self, endpoint: Dict[str, Any]) -> Dict[str, Any]:
        """Validate endpoint data structure for completeness"""
        result = {
            'is_valid': True,
            'warnings': []
        }
        
        # Check required fields
        required_fields = ['path', 'methods']
        for field in required_fields:
            if field not in endpoint:
                result['is_valid'] = False
                result['warnings'].append(f"Missing required field: {field}")
        
        # Validate path
        if 'path' in endpoint:
            path = endpoint['path']
            if not path or not isinstance(path, str):
                result['warnings'].append("Invalid path format")
            elif not path.startswith('/'):
                result['warnings'].append("Path should start with '/'")
        
        # Validate methods
        if 'methods' in endpoint:
            methods = endpoint['methods']
            if not isinstance(methods, list) or len(methods) == 0:
                result['warnings'].append("Methods should be a non-empty list")
            else:
                valid_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
                for method in methods:
                    if method not in valid_methods:
                        result['warnings'].append(f"Invalid HTTP method: {method}")
        
        # Validate parameters structure
        if 'parameters' in endpoint:
            params = endpoint['parameters']
            if not isinstance(params, dict):
                result['warnings'].append("Parameters should be a dictionary")
        
        # Check for optional but recommended fields
        recommended_fields = ['description', 'risk_level', 'authentication_required']
        for field in recommended_fields:
            if field not in endpoint:
                result['warnings'].append(f"Missing recommended field: {field}")
        
        return result
    
    def _load_discovery_data(self, discovery_file: str) -> Optional[Dict[str, Any]]:
        """Load discovery data from JSON file"""
        try:
            file_path = Path(discovery_file)
            if not file_path.exists():
                self.logger.error(f"Discovery file not found: {discovery_file}")
                return None
            
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            self.logger.info(f"✅ Loaded discovery data from {discovery_file}")
            return data
            
        except Exception as e:
            self.logger.error(f"Failed to load discovery data: {e}")
            return None
    
    def _generate_validation_summary(self, validation_results: List[Dict[str, Any]], 
                                   accessible_endpoints: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate comprehensive validation summary"""
        total_endpoints = len(validation_results)
        accessible_count = len(accessible_endpoints)
        inaccessible_count = total_endpoints - accessible_count
        
        # Calculate statistics
        total_methods = sum(len(result.get('methods', [])) for result in validation_results)
        accessible_methods = sum(len(result.get('accessible_methods', [])) for result in validation_results)
        
        # Collect all warnings and errors
        all_warnings = []
        all_errors = []
        for result in validation_results:
            all_warnings.extend(result.get('warnings', []))
            all_errors.extend(result.get('validation_errors', []))
        
        # Calculate average response times
        response_times = []
        for result in validation_results:
            for method, time_val in result.get('response_times', {}).items():
                if isinstance(time_val, (int, float)) and time_val > 0:
                    response_times.append(time_val)
        
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0
        
        summary = {
            "validation_timestamp": datetime.now().isoformat(),
            "base_url": self.base_url,
            "total_endpoints": total_endpoints,
            "accessible_endpoints": accessible_count,
            "inaccessible_endpoints": inaccessible_count,
            "accessibility_rate": (accessible_count / total_endpoints * 100) if total_endpoints > 0 else 0,
            "total_methods": total_methods,
            "accessible_methods": accessible_methods,
            "method_accessibility_rate": (accessible_methods / total_methods * 100) if total_methods > 0 else 0,
            "average_response_time": round(avg_response_time, 3),
            "total_warnings": len(all_warnings),
            "total_errors": len(all_errors),
            "validation_results": validation_results,
            "accessible_endpoints_data": accessible_endpoints,
            "validation_status": "SUCCESS" if accessible_count > 0 else "FAILED"
        }
        
        return summary
    
    def _save_validation_results(self, validation_summary: Dict[str, Any], 
                               accessible_endpoints: List[Dict[str, Any]]):
        """Save validation results to files"""
        try:
            # Save validation summary
            with open("endpoint_validation_summary.json", "w") as f:
                json.dump(validation_summary, f, indent=2, default=str)
            
            # Save accessible endpoints for security testing
            accessible_data = {
                "validation_timestamp": validation_summary["validation_timestamp"],
                "base_url": self.base_url,
                "total_accessible": len(accessible_endpoints),
                "accessible_endpoints": accessible_endpoints
            }
            
            with open("validated_endpoints_for_testing.json", "w") as f:
                json.dump(accessible_data, f, indent=2, default=str)
            
            self.logger.info("✅ Validation results saved to endpoint_validation_summary.json")
            self.logger.info("✅ Accessible endpoints saved to validated_endpoints_for_testing.json")
            
        except Exception as e:
            self.logger.error(f"Failed to save validation results: {e}")
    
    def _create_validation_error(self, message: str) -> Dict[str, Any]:
        """Create error response for validation failures"""
        return {
            "validation_timestamp": datetime.now().isoformat(),
            "base_url": self.base_url,
            "validation_status": "FAILED",
            "error_message": message,
            "total_endpoints": 0,
            "accessible_endpoints": 0,
            "accessibility_rate": 0
        }


async def main():
    """Main function for testing the endpoint validator"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Validate discovered endpoints for security testing")
    parser.add_argument("--url", default="http://localhost:5000", help="Base URL for validation")
    parser.add_argument("--file", default="temp_discovery_results.json", help="Discovery results file")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds")
    
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Run validation
    validator = EndpointValidator(args.url, timeout=args.timeout)
    
    try:
        results = await validator.validate_endpoints_for_testing(args.file)
        
        # Print summary
        print("\n" + "="*60)
        print("ENDPOINT VALIDATION RESULTS")
        print("="*60)
        print(f"Base URL: {results['base_url']}")
        print(f"Total Endpoints: {results['total_endpoints']}")
        print(f"Accessible Endpoints: {results['accessible_endpoints']}")
        print(f"Accessibility Rate: {results['accessibility_rate']:.1f}%")
        print(f"Method Accessibility: {results['method_accessibility_rate']:.1f}%")
        print(f"Average Response Time: {results['average_response_time']}s")
        print(f"Total Warnings: {results['total_warnings']}")
        print(f"Total Errors: {results['total_errors']}")
        print(f"Validation Status: {results['validation_status']}")
        print("="*60)
        
        if results['accessible_endpoints'] > 0:
            print("✅ Endpoints validated successfully - ready for security testing!")
        else:
            print("❌ No endpoints are accessible for security testing")
            
    except Exception as e:
        print(f"❌ Validation failed: {e}")
        return False
    
    return True


if __name__ == "__main__":
    asyncio.run(main()) 