#!/usr/bin/env python3
"""
Utility functions for VAmPI API Discovery Agent
"""

import httpx
import json
import sys
from typing import Optional
from datetime import datetime

def check_vampi(base_url: str) -> bool:
    """
    Check if VAmPI is running and accessible at the specified base URL.
    
    Args:
        base_url (str): The base URL to check (e.g., "http://localhost:5000")
        
    Returns:
        bool: True if VAmPI is accessible, False otherwise
    """
    try:
        # Clean up the URL
        base_url = base_url.rstrip('/')
        
        print(f"🔍 Checking VAmPI at: {base_url}")
        
        # Perform GET request with timeout
        with httpx.Client(timeout=10.0) as client:
            response = client.get(base_url)
            
            # Check if status is 200
            if response.status_code == 200:
                # Check if response body contains VAmPI markers
                content = response.text.lower()
                vampi_markers = ["vampi", "vulnerable api", "api", "swagger", "openapi"]
                
                if any(marker in content for marker in vampi_markers):
                    print("✅ VAmPI is running and accessible!")
                    return True
                else:
                    print("⚠️  HTTP 200 received but response doesn't contain expected VAmPI markers")
                    print(f"   Response preview: {response.text[:200]}...")
                    return False
                    
            else:
                print(f"❌ HTTP {response.status_code} received")
                _print_troubleshooting_steps(base_url, response.status_code)
                return False
                
    except httpx.ConnectError:
        print("❌ Connection failed - cannot reach the server")
        _print_troubleshooting_steps(base_url, connection_error=True)
        return False
        
    except httpx.TimeoutException:
        print("❌ Request timed out")
        _print_troubleshooting_steps(base_url, timeout_error=True)
        return False
        
    except httpx.RequestError as e:
        print(f"❌ Request error: {e}")
        _print_troubleshooting_steps(base_url, request_error=True)
        return False
        
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        _print_troubleshooting_steps(base_url, unexpected_error=True)
        return False

def _print_troubleshooting_steps(base_url: str, status_code: Optional[int] = None, 
                               connection_error: bool = False, timeout_error: bool = False,
                               request_error: bool = False, unexpected_error: bool = False):
    """Print helpful troubleshooting steps based on the error type."""
    
    print("\n🔧 Troubleshooting Steps:")
    print("=" * 50)
    
    if connection_error:
        print("1. Check if VAmPI is running:")
        print("   - Navigate to vampi-local directory")
        print("   - Run: npm start")
        print("   - Or: npm run dev")
        print()
        print("2. Check if MongoDB is running:")
        print("   - In another terminal: mongod --dbpath /path/to/data/db")
        print("   - Or use MongoDB Atlas and update MONGODB_URI in .env")
        print()
        print("3. Verify the port in your .env file:")
        print("   - Check PORT=5000 in vampi-local/.env")
        print("   - Ensure no other service is using port 5000")
        
    elif timeout_error:
        print("1. VAmPI might be starting up (can take a few minutes)")
        print("   - Wait a bit and try again")
        print("   - Check VAmPI logs for any errors")
        print()
        print("2. Check system resources:")
        print("   - Ensure sufficient memory and CPU")
        print("   - Check if MongoDB is responsive")
        
    elif status_code == 404:
        print("1. VAmPI is running but the root endpoint might be different")
        print("   - Try: {}/health".format(base_url))
        print("   - Try: {}/api".format(base_url))
        print("   - Check VAmPI documentation for correct endpoints")
        
    elif status_code == 500:
        print("1. VAmPI is running but encountering internal errors")
        print("   - Check VAmPI logs for error details")
        print("   - Verify MongoDB connection")
        print("   - Check .env configuration")
        
    elif status_code in [401, 403]:
        print("1. VAmPI is running but requires authentication")
        print("   - This is expected behavior for secure endpoints")
        print("   - VAmPI is accessible but protected")
        
    else:
        print("1. General troubleshooting:")
        print("   - Ensure VAmPI is running: npm start")
        print("   - Check MongoDB: mongod --dbpath /path/to/data/db")
        print("   - Verify port configuration in .env")
        print("   - Check VAmPI logs for errors")
    
    print()
    print("2. Quick setup commands:")
    print("   cd vampi-local")
    print("   npm install")
    print("   npm start")
    print()
    print("3. Check VAmPI status:")
    print("   - Look for 'Server running on port 5000' in logs")
    print("   - Ensure no error messages in terminal")
    
    print("=" * 50)

def get_logger(name: str):
    """Simple logger function for compatibility with existing code."""
    import logging
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger

if __name__ == "__main__":
    # Test the function if run directly
    test_url = "http://localhost:5000"
    print(f"Testing VAmPI check for: {test_url}")
    result = check_vampi(test_url)
    print(f"Result: {result}") 