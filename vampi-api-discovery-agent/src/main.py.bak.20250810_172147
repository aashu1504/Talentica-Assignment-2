#!/usr/bin/env python3
"""
VAmPI API Discovery Agent - Main Execution Script.

This script provides the main entry point for running the API Discovery Agent.
It handles command-line arguments, configuration, and orchestrates the discovery process.
"""

import asyncio
import argparse
import sys
import os
from pathlib import Path
from typing import Optional

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent))

# Use absolute imports when running as script
if __name__ == "__main__":
    from models import DiscoveryConfig
    from agent import APIDiscoveryAgent, run_discovery_agent
    from utils import setup_logging, load_config_from_env
    from discovery import VAmPIDiscoveryEngine
else:
    from .models import DiscoveryConfig
    from .agent import APIDiscoveryAgent, run_discovery_agent
    from .utils import setup_logging, load_config_from_env
    from .discovery import VAmPIDiscoveryEngine


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="VAmPI API Discovery Agent - Discover and analyze VAmPI API endpoints",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run with default configuration
  python main.py
  
  # Run with custom VAmPI URL
  python main.py --url http://localhost:3000
  
  # Run with custom timeout and rate limiting
  python main.py --timeout 60 --rate-limit-delay 2.0
  
  # Run in verbose mode
  python main.py --verbose
  
  # Run discovery only (skip CrewAI analysis)
  python main.py --discovery-only
        """
    )
    
    # VAmPI configuration
    parser.add_argument(
        "--url", "-u",
        type=str,
        help="VAmPI base URL (default: from .env or http://localhost:5000)"
    )
    
    parser.add_argument(
        "--timeout", "-t",
        type=int,
        help="Request timeout in seconds (default: 30)"
    )
    
    # Discovery configuration
    parser.add_argument(
        "--rate-limit-delay", "-r",
        type=float,
        help="Delay between requests in seconds (default: 1.0)"
    )
    
    parser.add_argument(
        "--max-retries", "-m",
        type=int,
        help="Maximum retry attempts (default: 3)"
    )
    
    parser.add_argument(
        "--user-agent", "-a",
        type=str,
        help="Custom user agent string"
    )
    
    # Output configuration
    parser.add_argument(
        "--output-dir", "-o",
        type=str,
        default="output",
        help="Output directory for results (default: output)"
    )
    
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Disable automatic file backup"
    )
    
    # Execution options
    parser.add_argument(
        "--discovery-only",
        action="store_true",
        help="Run only endpoint discovery, skip CrewAI analysis"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    parser.add_argument(
        "--log-file",
        type=str,
        help="Log file path"
    )
    
    # Testing options
    parser.add_argument(
        "--test-connection",
        action="store_true",
        help="Test connection to VAmPI before running discovery"
    )
    
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without executing"
    )
    
    return parser.parse_args()


def create_custom_config(args) -> DiscoveryConfig:
    """
    Create custom configuration from command line arguments.
    
    Args:
        args: Parsed command line arguments
        
    Returns:
        DiscoveryConfig instance
    """
    # Load base config from environment
    config = load_config_from_env()
    
    # Override with command line arguments
    if args.url:
        config.base_url = args.url
    
    if args.timeout:
        config.timeout = args.timeout
    
    if args.rate_limit_delay:
        config.rate_limit_delay = args.rate_limit_delay
    
    if args.max_retries:
        config.max_retries = args.max_retries
    
    if args.user_agent:
        config.user_agent = args.user_agent
    
    return config


async def test_vampi_connection(config: DiscoveryConfig) -> bool:
    """
    Test connection to VAmPI application.
    
    Args:
        config: Discovery configuration
        
    Returns:
        True if connection successful, False otherwise
    """
    print(f"Testing connection to VAmPI at {config.base_url}...")
    
    try:
        async with VAmPIDiscoveryEngine(config) as engine:
            # Simple connection test
            import httpx
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(config.base_url)
                if response.status_code == 200:
                    print(f"✅ Connection successful! Status: {response.status_code}")
                    return True
                else:
                    print(f"⚠️  Connection established but unexpected status: {response.status_code}")
                    return False
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return False


def print_banner():
    """Print the application banner."""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║                    VAmPI API Discovery Agent                ║
║                                                              ║
║  Discover • Analyze • Secure                                ║
║                                                              ║
║  Built with CrewAI for intelligent API reconnaissance       ║
╚══════════════════════════════════════════════════════════════╝
"""
    print(banner)


def print_config_summary(config: DiscoveryConfig):
    """Print configuration summary."""
    print("Configuration:")
    print(f"  VAmPI URL: {config.base_url}")
    print(f"  Timeout: {config.timeout}s")
    print(f"  Rate Limit Delay: {config.rate_limit_delay}s")
    print(f"  Max Retries: {config.max_retries}")
    print(f"  User Agent: {config.user_agent}")
    print(f"  Respect Rate Limits: {config.respect_rate_limits}")
    print()


async def run_discovery_only(config: DiscoveryConfig, output_dir: str) -> bool:
    """
    Run only the endpoint discovery without CrewAI analysis.
    
    Args:
        config: Discovery configuration
        output_dir: Output directory
        
    Returns:
        True if successful, False otherwise
    """
    print("Running endpoint discovery only...")
    
    try:
        async with VAmPIDiscoveryEngine(config) as engine:
            result = await engine.discover_endpoints()
            
            # Save results
            from utils import save_discovery_result
            timestamp = result.discovery_summary.discovery_timestamp.strftime("%Y%m%d_%H%M%S")
            filename = f"vampi_discovery_{timestamp}.json"
            
            saved_path = save_discovery_result(result, output_dir, filename)
            if saved_path:
                print(f"✅ Discovery results saved to: {saved_path}")
            
            # Print summary
            print(f"\nDiscovery Summary:")
            print(f"  Total Endpoints: {result.discovery_summary.total_endpoints}")
            print(f"  Scan Duration: {result.discovery_summary.scan_duration:.2f}s")
            print(f"  Success Rate: {result.discovery_summary.success_rate:.1f}%")
            
            return True
            
    except Exception as e:
        print(f"❌ Discovery failed: {e}")
        return False


async def main():
    """Main execution function."""
    # Parse arguments
    args = parse_arguments()
    
    # Print banner
    print_banner()
    
    # Setup logging
    log_level = "DEBUG" if args.verbose else "INFO"
    logger = setup_logging(log_level, args.log_file)
    
    try:
        # Create configuration
        config = create_custom_config(args)
        
        # Print configuration summary
        print_config_summary(config)
        
        # Test connection if requested
        if args.test_connection:
            connection_ok = await test_vampi_connection(config)
            if not connection_ok:
                print("❌ Cannot proceed without VAmPI connection. Please ensure VAmPI is running.")
                sys.exit(1)
            print()
        
        # Dry run mode
        if args.dry_run:
            print("🔍 DRY RUN MODE - No actual discovery will be performed")
            print("Configuration looks good. Run without --dry-run to execute discovery.")
            return
        
        # Create output directory
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        print(f"Output directory: {output_dir.absolute()}")
        print()
        
        # Run discovery
        if args.discovery_only:
            success = await run_discovery_only(config, args.output_dir)
            if not success:
                sys.exit(1)
        else:
            # Run full agent with CrewAI
            print("🚀 Starting VAmPI API Discovery Agent...")
            print("This will run both endpoint discovery and AI-powered analysis.")
            print()
            
            agent = APIDiscoveryAgent(config)
            result = await agent.execute_discovery()
            
            print(f"\n✅ Discovery completed successfully!")
            print(f"  Total Endpoints: {result.discovery_summary.total_endpoints}")
            print(f"  Scan Duration: {result.discovery_summary.scan_duration:.2f}s")
            print(f"  Authentication Mechanisms: {len(result.authentication_mechanisms)}")
            print(f"  High/Critical Risk Endpoints: {len([ep for ep in result.endpoints if ep.risk_level.value in ['High', 'Critical']])}")
            
            # Print high-risk endpoints
            high_risk_endpoints = [ep for ep in result.endpoints if ep.risk_level.value in ['High', 'Critical']]
            if high_risk_endpoints:
                print(f"\n⚠️  High/Critical Risk Endpoints:")
                for ep in high_risk_endpoints:
                    print(f"  - {ep.path} ({', '.join(ep.methods)}) - {ep.risk_level}")
                    print(f"    Risk Factors: {', '.join(ep.risk_factors)}")
        
        print(f"\n📁 Results saved to: {output_dir.absolute()}")
        print("🎯 Ready for Assignment 2B: Security Testing Agent!")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Discovery interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    # Check Python version
    if sys.version_info < (3, 10):
        print("❌ Python 3.10+ is required for this application")
        print(f"Current version: {sys.version}")
        sys.exit(1)
    
    # Run main function
    asyncio.run(main()) 