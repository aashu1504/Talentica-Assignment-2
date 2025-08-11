#!/usr/bin/env python3
"""
Test script to verify APIDiscoveryTool works independently of CrewAI.
"""

import os
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

from tools import APIDiscoveryTool

def test_api_discovery_tool():
    """Test the API discovery tool directly."""
    print("🧪 Testing APIDiscoveryTool directly...")
    
    # Get configuration from environment
    api_key = os.getenv('GOOGLE_API_KEY')
    base_url = os.getenv('API_BASE_URL', 'http://localhost:5000')
    
    if not api_key:
        print("❌ GOOGLE_API_KEY not found in environment")
        return False
    
    print(f"🔑 API Key: {api_key[:10]}...")
    print(f"🌐 Base URL: {base_url}")
    
    try:
        # Create and run the tool
        tool = APIDiscoveryTool(base_url=base_url, api_key=api_key)
        print("\n🚀 Executing tool...")
        
        result = tool._run()
        print(f"\n✅ Tool execution result:\n{result}")
        
        # Check if temp file was created
        if os.path.exists("temp_discovery_results.json"):
            print("\n📁 Temporary results file created successfully!")
            with open("temp_discovery_results.json", "r") as f:
                import json
                data = json.load(f)
                print(f"📊 File contains {len(data.get('discovery_data', {}).get('endpoints', []))} endpoints")
        else:
            print("\n⚠️  No temporary results file created")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Tool execution failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_api_discovery_tool()
    if success:
        print("\n🎉 Tool test completed successfully!")
    else:
        print("\n💥 Tool test failed!")
        sys.exit(1) 