#!/usr/bin/env python3
"""
VAmPI Validation Script
Checks if VAmPI is running and accessible at the specified URL
"""

import httpx
import sys
import time
from typing import Optional
import os
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from utils import get_logger

logger = get_logger(__name__)

class VAmPIValidator:
    """Validates VAmPI API accessibility and health"""
    
    def __init__(self, base_url: str = "http://localhost:5000", timeout: int = 10):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.client = httpx.Client(timeout=timeout)
    
    def check_health_endpoint(self) -> bool:
        """Check if VAmPI health endpoint is accessible"""
        try:
            response = self.client.get(f"{self.base_url}/health")
            if response.status_code == 200:
                logger.info(f"✅ Health endpoint accessible: {response.status_code}")
                return True
            else:
                logger.warning(f"⚠️  Health endpoint returned status: {response.status_code}")
                return False
        except httpx.RequestError as e:
            logger.error(f"❌ Health endpoint request failed: {e}")
            return False
    
    def check_root_endpoint(self) -> bool:
        """Check if VAmPI root endpoint is accessible"""
        try:
            response = self.client.get(f"{self.base_url}/")
            if response.status_code in [200, 404, 405]:  # Accept various responses
                logger.info(f"✅ Root endpoint accessible: {response.status_code}")
                return True
            else:
                logger.warning(f"⚠️  Root endpoint returned status: {response.status_code}")
                return False
        except httpx.RequestError as e:
            logger.error(f"❌ Root endpoint request failed: {e}")
            return False
    
    def check_api_endpoints(self) -> bool:
        """Check if some common VAmPI API endpoints are accessible"""
        common_endpoints = [
            "/api/users",
            "/api/auth",
            "/api/admin",
            "/docs",
            "/swagger"
        ]
        
        accessible_count = 0
        for endpoint in common_endpoints:
            try:
                response = self.client.get(f"{self.base_url}{endpoint}")
                if response.status_code in [200, 401, 403, 404]:  # Accept various responses
                    accessible_count += 1
                    logger.debug(f"✅ Endpoint {endpoint}: {response.status_code}")
                else:
                    logger.debug(f"⚠️  Endpoint {endpoint}: {response.status_code}")
            except httpx.RequestError:
                logger.debug(f"❌ Endpoint {endpoint}: Request failed")
        
        logger.info(f"📊 API endpoints check: {accessible_count}/{len(common_endpoints)} accessible")
        return accessible_count > 0
    
    def validate(self) -> dict:
        """Run complete validation and return results"""
        logger.info(f"🔍 Starting VAmPI validation for: {self.base_url}")
        
        results = {
            "base_url": self.base_url,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "health_endpoint": False,
            "root_endpoint": False,
            "api_endpoints": False,
            "overall_status": False
        }
        
        # Check health endpoint
        results["health_endpoint"] = self.check_health_endpoint()
        
        # Check root endpoint
        results["root_endpoint"] = self.check_root_endpoint()
        
        # Check API endpoints
        results["api_endpoints"] = self.check_api_endpoints()
        
        # Determine overall status
        results["overall_status"] = (
            results["health_endpoint"] or 
            results["root_endpoint"] or 
            results["api_endpoints"]
        )
        
        # Log results
        if results["overall_status"]:
            logger.info("🎉 VAmPI validation: SUCCESS")
        else:
            logger.error("💥 VAmPI validation: FAILED")
        
        return results
    
    def close(self):
        """Close the HTTP client"""
        self.client.close()

def main():
    """Main validation function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Validate VAmPI API accessibility")
    parser.add_argument(
        "--url", 
        default="http://localhost:5000",
        help="VAmPI base URL (default: http://localhost:5000)"
    )
    parser.add_argument(
        "--timeout", 
        type=int, 
        default=10,
        help="Request timeout in seconds (default: 10)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        import logging
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Run validation
    validator = VAmPIValidator(args.url, args.timeout)
    
    try:
        results = validator.validate()
        
        # Print summary
        print("\n" + "="*50)
        print("VAmPI VALIDATION RESULTS")
        print("="*50)
        print(f"Base URL: {results['base_url']}")
        print(f"Timestamp: {results['timestamp']}")
        print(f"Health Endpoint: {'✅' if results['health_endpoint'] else '❌'}")
        print(f"Root Endpoint: {'✅' if results['root_endpoint'] else '❌'}")
        print(f"API Endpoints: {'✅' if results['api_endpoints'] else '❌'}")
        print(f"Overall Status: {'✅ SUCCESS' if results['overall_status'] else '❌ FAILED'}")
        print("="*50)
        
        # Exit with appropriate code
        sys.exit(0 if results['overall_status'] else 1)
        
    finally:
        validator.close()

if __name__ == "__main__":
    main() 