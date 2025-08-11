#!/usr/bin/env python3
"""
Simple test script for API Discovery Tool
"""

import os
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent))

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

from tools import APIDiscoveryTool

def main():
    """Test the API discovery tool."""
    print("🔍 Testing API Discovery Tool")
    print("=" * 50)
    
    # Get API key and base URL
    api_key = os.getenv('GOOGLE_API_KEY')
    base_url = os.getenv('API_BASE_URL', 'http://localhost:5000')
    
    if not api_key:
        print("❌ GOOGLE_API_KEY not found in environment")
        return
    
    print(f"🌐 Target URL: {base_url}")
    print(f"🔑 API Key: {api_key[:10]}...")
    print()
    
    try:
        # Create and run the discovery tool
        discovery_tool = APIDiscoveryTool(base_url=base_url, api_key=api_key)
        
        print("🚀 Starting API discovery...")
        result = discovery_tool._run()
        
        print("\n" + "=" * 50)
        print("📊 DISCOVERY RESULTS")
        print("=" * 50)
        print(result)
        
        # Check if results were saved
        if os.path.exists("temp_discovery_results.json"):
            print("\n✅ Discovery results saved to temp_discovery_results.json")
            
            # Show file size
            file_size = os.path.getsize("temp_discovery_results.json")
            print(f"📁 File size: {file_size} bytes")
        else:
            print("\n⚠️  No discovery results file found")
            
    except Exception as e:
        print(f"\n❌ Error during discovery: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main() 