#!/usr/bin/env python3
"""
Utility functions for VAmPI API Discovery Agent
"""
import asyncio
import re
import time
from typing import List, Optional
from urllib.parse import urljoin, urlparse
import httpx


def check_vampi(base_url: str) -> bool:
    """
    Check if VAmPI is running and accessible at the specified base URL.
    
    Args:
        base_url: Base URL to check (e.g., "http://localhost:5000")
        
    Returns:
        True if VAmPI is running and accessible, False otherwise
    """
    try:
        response = httpx.get(base_url, timeout=5)
        if response.status_code == 200:
            # Check if response contains VAmPI indicators
            content = response.text.lower()
            if "vampi" in content or "api" in content or "swagger" in content:
                print(f"✅ VAmPI is running at {base_url}")
                return True
            else:
                print(f"⚠️  Server responded with 200 but content doesn't match VAmPI")
                return False
        else:
            print(f"❌ Server responded with status {response.status_code}")
            return False
    except httpx.ConnectError:
        print(f"❌ Cannot connect to {base_url}")
        print("\n🔧 Troubleshooting steps:")
        print("1. Make sure VAmPI is running: npm start (in VAmPI directory)")
        print("2. Check if MongoDB is running: mongod")
        print("3. Verify the port number (default: 5000)")
        print("4. Check if another service is using the port")
        return False
    except httpx.TimeoutException:
        print(f"❌ Request to {base_url} timed out")
        return False
    except Exception as e:
        print(f"❌ Error checking VAmPI: {e}")
        return False


def normalize_url(base_url: str, path: str) -> str:
    """
    Normalize a URL by joining base URL with path and ensuring proper formatting.
    
    Args:
        base_url: Base URL
        path: Path to append
        
    Returns:
        Normalized full URL
    """
    if not path.startswith('/'):
        path = '/' + path
    return urljoin(base_url.rstrip('/') + '/', path.lstrip('/'))


def extract_path_parameters(path: str) -> List[str]:
    """
    Extract path parameters from a URL path.
    
    Args:
        path: URL path (e.g., "/users/{id}/books/{book_id}")
        
    Returns:
        List of parameter names
    """
    pattern = r'\{([^}]+)\}'
    return re.findall(pattern, path)


def rate_limit_delay(delay: float = 1.0) -> None:
    """
    Add a delay to respect rate limits.
    
    Args:
        delay: Delay in seconds
    """
    time.sleep(delay)


async def async_rate_limit_delay(delay: float = 1.0) -> None:
    """
    Add an async delay to respect rate limits.
    
    Args:
        delay: Delay in seconds
    """
    await asyncio.sleep(delay)


def calculate_success_rate(successful: int, total: int) -> float:
    """
    Calculate success rate as a percentage.
    
    Args:
        successful: Number of successful operations
        total: Total number of operations
        
    Returns:
        Success rate as a float between 0.0 and 1.0
    """
    if total == 0:
        return 0.0
    return successful / total


def is_valid_url(url: str) -> bool:
    """
    Check if a URL is valid.
    
    Args:
        url: URL to validate
        
    Returns:
        True if URL is valid, False otherwise
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False 