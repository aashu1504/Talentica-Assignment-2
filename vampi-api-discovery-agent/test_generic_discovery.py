#!/usr/bin/env python3
"""
Test script for the Generic API Discovery Engine.

This script demonstrates how the generic discovery engine can work with
any API, not just VAmPI.
"""

import asyncio
import sys
import os
from pathlib import Path

# Add src directory to Python path
sys.path.append(str(Path(__file__).parent / "src"))

from generic_discovery import GenericAPIDiscoveryEngine
from models import DiscoveryConfig


async def test_generic_discovery():
    """Test the generic discovery engine with different APIs."""
    
    print("🚀 Testing Generic API Discovery Engine")
    print("=" * 50)
    
    # Test configuration
    config = DiscoveryConfig(
        base_url="http://localhost:5000",  # VAmPI for testing
        timeout=30.0,
        max_concurrent_requests=5,
        user_agent="Generic-Discovery-Agent/1.0"
    )
    
    try:
        # Initialize generic discovery engine
        async with GenericAPIDiscoveryEngine(config) as engine:
            print("✅ Generic discovery engine initialized")
            
            # Run discovery
            print("\n🔍 Starting universal API discovery...")
            result = await engine.discover_endpoints()
            
            print(f"\n📊 Discovery Results:")
            print(f"   - Total Endpoints: {len(result.endpoints)}")
            print(f"   - Framework Detected: {result.framework_info.get('detected_framework', 'Unknown')}")
            print(f"   - Confidence: {result.framework_info.get('confidence', 0.0):.2f}")
            print(f"   - Discovery Coverage: {result.discovery_summary.discovery_coverage:.2f}%")
            
            print(f"\n🏗️  Framework Information:")
            framework_info = result.framework_info
            print(f"   - Detected Framework: {framework_info.get('detected_framework', 'Unknown')}")
            print(f"   - Confidence Score: {framework_info.get('confidence', 0.0):.2f}")
            print(f"   - Technology Stack: {', '.join(framework_info.get('technology_stack', []))}")
            
            if framework_info.get('indicators'):
                print(f"   - Detection Indicators:")
                for indicator in framework_info['indicators']:
                    print(f"     • {indicator}")
            
            print(f"\n🔐 Authentication Analysis:")
            print(f"   - Authenticated Endpoints: {result.discovery_summary.authenticated_endpoints}")
            print(f"   - Public Endpoints: {result.discovery_summary.public_endpoints}")
            print(f"   - Authentication Types: {', '.join(result.discovery_summary.authentication_types)}")
            
            print(f"\n⚠️  Risk Assessment:")
            print(f"   - High Risk: {result.discovery_summary.high_risk_endpoints}")
            print(f"   - Medium Risk: {result.discovery_summary.medium_risk_endpoints}")
            print(f"   - Low Risk: {result.discovery_summary.low_risk_endpoints}")
            
            print(f"\n📁 API Structure:")
            api_structure = result.api_structure
            print(f"   - Base Paths: {', '.join(api_structure.base_paths)}")
            print(f"   - Versions: {', '.join(api_structure.versions)}")
            print(f"   - Common Patterns: {', '.join(api_structure.common_patterns)}")
            print(f"   - Endpoint Groups: {len(api_structure.endpoint_groups)} groups")
            print(f"   - Discovery Method: {api_structure.discovery_method}")
            
            print(f"\n🔍 Sample Discovered Endpoints:")
            for i, endpoint in enumerate(result.endpoints[:5]):  # Show first 5
                print(f"   {i+1}. {endpoint.path}")
                print(f"      Methods: {', '.join(endpoint.methods)}")
                print(f"      Risk: {endpoint.risk_level}")
                print(f"      Auth Required: {endpoint.authentication_required}")
                print(f"      Risk Factors: {', '.join(endpoint.risk_factors)}")
                print()
            
            print("✅ Generic discovery test completed successfully!")
            
    except Exception as e:
        print(f"❌ Error during generic discovery: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    # Run the test
    asyncio.run(test_generic_discovery()) 