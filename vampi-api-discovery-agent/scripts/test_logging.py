#!/usr/bin/env python3
"""
Test script for the VAmPI API Discovery Agent logging system
"""

import os
import sys
from pathlib import Path

# Add src directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from logger import AgentRunLogger


def test_logging_system():
    """Test the logging system functionality"""
    print("🧪 Testing VAmPI API Discovery Agent Logging System")
    print("=" * 60)
    
    # Initialize logger
    logger = AgentRunLogger()
    
    # Test 1: Log a run start
    print("\n1. Testing run start logging...")
    run_id = "test_run_001"
    config = {"base_url": "http://localhost:5000", "test": True}
    logger.log_run_start(run_id, config)
    print("✅ Run start logged successfully")
    
    # Test 2: Log a discovery step
    print("\n2. Testing discovery step logging...")
    logger.log_discovery_step(run_id, "documentation_parsing", {"step": 1, "endpoints_found": 5})
    print("✅ Discovery step logged successfully")
    
    # Test 3: Log performance metrics
    print("\n3. Testing performance metric logging...")
    logger.log_performance_metric(run_id, "scan_duration", 2.5, "seconds")
    logger.log_performance_metric(run_id, "endpoints_discovered", 12, "count")
    print("✅ Performance metrics logged successfully")
    
    # Test 4: Log run completion
    print("\n4. Testing run completion logging...")
    from models import DiscoverySummary, APIDiscoveryResult
    
    # Create a mock discovery summary
    from datetime import datetime
    now = datetime.now()
    
    summary = DiscoverySummary(
        target_application="VAmPI",
        base_url="http://localhost:5000",
        total_endpoints=12,
        authenticated_endpoints=8,
        public_endpoints=4,
        high_risk_endpoints=3,
        medium_risk_endpoints=0,
        low_risk_endpoints=3,
        authentication_types=[],
        discovery_coverage=100.0,
        parameter_coverage=100.0,
        discovery_start_time=now,
        discovery_end_time=now,
        discovery_duration=2.5,
        total_parameters=172,
        unique_parameters=16
    )
    
    # Create a mock result
    from models import APIStructure
    
    # Create a minimal APIStructure
    api_structure = APIStructure(
        base_url="http://localhost:5000",
        discovery_method="test_discovery",
        base_paths=["/users/v1", "/books/v1"],
        versions=["v1"],
        common_patterns=["REST", "JSON_responses"],
        endpoint_groups={
            "user_management": ["/users/v1", "/users/v1/register", "/users/v1/login"],
            "book_management": ["/books/v1", "/books/v1/{book_title}"]
        }
    )
    
    result = APIDiscoveryResult(
        discovery_summary=summary,
        endpoints=[],
        authentication_mechanisms=[],
        api_structure=api_structure,
        validation_metrics={
            "accuracy": {"overall_accuracy": 95.0},
            "completeness": {"overall_completeness": 100.0}
        }
    )
    
    performance_metrics = {
        "total_duration": 2.5,
        "total_endpoints": 12,
        "discovery_coverage": 100.0,
        "parameter_coverage": 100.0
    }
    
    logger.log_run_complete(run_id, result, performance_metrics)
    print("✅ Run completion logged successfully")
    
    # Test 5: Check log files
    print("\n5. Checking log files...")
    today = logger.get_run_history()
    print(f"✅ Log files created successfully")
    print(f"   - Run log entries: {len(today)}")
    
    # Test 6: Generate daily report
    print("\n6. Testing daily report generation...")
    daily_report = logger.generate_daily_report()
    print(f"✅ Daily report generated successfully")
    print(f"   - Date: {daily_report.get('date', 'N/A')}")
    print(f"   - Run count: {daily_report.get('run_count', 0)}")
    
    # Test 7: Check performance summary
    print("\n7. Testing performance summary...")
    perf_summary = logger.get_performance_summary()
    if perf_summary:
        print(f"✅ Performance summary retrieved successfully")
        print(f"   - Total runs: {perf_summary.get('total_runs', 0)}")
        print(f"   - Average duration: {perf_summary.get('average_duration', 0):.2f}s")
    else:
        print("ℹ️ No performance data available yet")
    
    print("\n🎉 All logging tests completed successfully!")
    print("\n📁 Log files created in:")
    print(f"   - Runs: {logger.log_dir / 'runs'}")
    print(f"   - Performance: {logger.log_dir / 'performance'}")
    print(f"   - Discovery: {logger.log_dir / 'discovery'}")
    print(f"   - Errors: {logger.log_dir / 'errors'}")
    
    return True


if __name__ == "__main__":
    try:
        test_logging_system()
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1) 