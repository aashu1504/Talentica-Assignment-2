#!/usr/bin/env python3
"""
Log Analysis Script for VAmPI API Discovery Agent
Analyzes and displays comprehensive logging data from agent runs
"""

import os
import sys
import json
from datetime import datetime, timedelta
from pathlib import Path
import argparse

# Add src directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from logger import AgentRunLogger


def display_run_summary(logger: AgentRunLogger, date: str = None):
    """Display summary of runs for a specific date"""
    if date is None:
        date = datetime.now().strftime('%Y-%m-%d')
    
    print(f"\n📊 RUN SUMMARY FOR {date}")
    print("=" * 50)
    
    # Get performance summary
    perf_summary = logger.get_performance_summary(date)
    if perf_summary:
        print(f"Total Runs: {perf_summary.get('total_runs', 0)}")
        print(f"Average Duration: {perf_summary.get('average_duration', 0):.2f} seconds")
        print(f"Average Endpoints: {perf_summary.get('average_endpoints', 0):.1f}")
        print(f"Average Coverage: {perf_summary.get('average_coverage', 0):.1f}%")
    else:
        print("No performance data available for this date")
    
    # Get error summary
    error_summary = logger.get_error_summary(date)
    if error_summary:
        print(f"\nTotal Errors: {error_summary.get('total_errors', 0)}")
        if error_summary.get('error_types'):
            print("Error Types:")
            for error_type, count in error_summary['error_types'].items():
                print(f"  - {error_type}: {count}")
    else:
        print("\nNo errors recorded for this date")
    
    # Get run count
    run_count = logger.get_run_history(date)
    print(f"\nDetailed Run Records: {len(run_count)}")


def display_run_history(logger: AgentRunLogger, date: str = None, limit: int = 10):
    """Display detailed run history"""
    if date is None:
        date = datetime.now().strftime('%Y-%m-%d')
    
    print(f"\n📋 RUN HISTORY FOR {date} (Last {limit} runs)")
    print("=" * 60)
    
    runs = logger.get_run_history(date, limit)
    
    if not runs:
        print("No runs recorded for this date")
        return
    
    for i, run in enumerate(reversed(runs), 1):
        print(f"\n{i}. Run ID: {run.get('run_id', 'N/A')}")
        print(f"   Timestamp: {run.get('timestamp', 'N/A')}")
        print(f"   Status: {run.get('status', 'N/A')}")
        print(f"   Type: {run.get('type', 'N/A')}")
        
        if run.get('type') == 'run_complete':
            summary = run.get('summary', {})
            print(f"   Endpoints: {summary.get('total_endpoints', 0)}")
            print(f"   Coverage: {summary.get('discovery_coverage', 0)}%")
            print(f"   Parameters: {summary.get('total_parameters', 0)}")
        
        elif run.get('type') == 'run_error':
            print(f"   Error: {run.get('error_type', 'N/A')}")
            print(f"   Message: {run.get('error_message', 'N/A')}")


def display_performance_metrics(logger: AgentRunLogger, date: str = None):
    """Display detailed performance metrics"""
    if date is None:
        date = datetime.now().strftime('%Y-%m-%d')
    
    print(f"\n⚡ PERFORMANCE METRICS FOR {date}")
    print("=" * 50)
    
    perf_log_file = logger.log_dir / "performance" / f"performance_{date}.jsonl"
    
    if not perf_log_file.exists():
        print("No performance data available for this date")
        return
    
    runs = []
    with open(perf_log_file, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                runs.append(json.loads(line))
    
    if not runs:
        print("No performance data available")
        return
    
    print(f"Total Performance Records: {len(runs)}")
    
    # Calculate statistics
    durations = [r['metrics'].get('total_duration', 0) for r in runs]
    endpoints = [r['metrics'].get('total_endpoints', 0) for r in runs]
    coverages = [r['metrics'].get('discovery_coverage', 0) for r in runs]
    
    if durations:
        print(f"\nDuration Statistics:")
        print(f"  Min: {min(durations):.2f}s")
        print(f"  Max: {max(durations):.2f}s")
        print(f"  Average: {sum(durations)/len(durations):.2f}s")
    
    if endpoints:
        print(f"\nEndpoint Statistics:")
        print(f"  Min: {min(endpoints)}")
        print(f"  Max: {max(endpoints)}")
        print(f"  Average: {sum(endpoints)/len(endpoints):.1f}")
    
    if coverages:
        print(f"\nCoverage Statistics:")
        print(f"  Min: {min(coverages):.1f}%")
        print(f"  Max: {max(coverages):.1f}%")
        print(f"  Average: {sum(coverages)/len(coverages):.1f}%")


def display_discovery_results(logger: AgentRunLogger, date: str = None, limit: int = 5):
    """Display discovery results summary"""
    if date is None:
        date = datetime.now().strftime('%Y-%m-%d')
    
    print(f"\n🔍 DISCOVERY RESULTS FOR {date} (Last {limit} runs)")
    print("=" * 60)
    
    discovery_log_file = logger.log_dir / "discovery" / f"discovery_{date}.jsonl"
    
    if not discovery_log_file.exists():
        print("No discovery data available for this date")
        return
    
    runs = []
    with open(discovery_log_file, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                runs.append(json.loads(line))
    
    if not runs:
        print("No discovery data available")
        return
    
    # Show last few runs
    for i, run in enumerate(runs[-limit:], 1):
        print(f"\n{i}. Run ID: {run.get('run_id', 'N/A')}")
        print(f"   Timestamp: {run.get('timestamp', 'N/A')}")
        
        summary = run.get('summary', {})
        print(f"   Endpoints: {summary.get('total_endpoints', 0)}")
        print(f"   Coverage: {summary.get('discovery_coverage', 0)}%")
        print(f"   Parameters: {summary.get('total_parameters', 0)}")
        print(f"   Authenticated: {summary.get('authenticated_endpoints', 0)}")
        print(f"   Public: {summary.get('public_endpoints', 0)}")


def display_error_details(logger: AgentRunLogger, date: str = None, limit: int = 5):
    """Display detailed error information"""
    if date is None:
        date = datetime.now().strftime('%Y-%m-%d')
    
    print(f"\n❌ ERROR DETAILS FOR {date} (Last {limit} errors)")
    print("=" * 60)
    
    error_log_file = logger.log_dir / "errors" / f"errors_{date}.jsonl"
    
    if not error_log_file.exists():
        print("No error data available for this date")
        return
    
    errors = []
    with open(error_log_file, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                errors.append(json.loads(line))
    
    if not errors:
        print("No errors recorded for this date")
        return
    
    # Show last few errors
    for i, error in enumerate(errors[-limit:], 1):
        print(f"\n{i}. Run ID: {error.get('run_id', 'N/A')}")
        print(f"   Timestamp: {error.get('timestamp', 'N/A')}")
        print(f"   Error Type: {error.get('error_type', 'N/A')}")
        print(f"   Message: {error.get('error_message', 'N/A')}")
        
        context = error.get('context', {})
        if context:
            print(f"   Context: {context}")


def display_available_dates(logger: AgentRunLogger):
    """Display available dates with log data"""
    print("\n📅 AVAILABLE LOG DATES")
    print("=" * 30)
    
    runs_dir = logger.log_dir / "runs"
    if not runs_dir.exists():
        print("No log data available")
        return
    
    dates = set()
    for log_file in runs_dir.glob("runs_*.jsonl"):
        # Extract date from filename: runs_2025-08-22.jsonl
        date = log_file.stem.replace("runs_", "")
        dates.add(date)
    
    if dates:
        sorted_dates = sorted(dates, reverse=True)
        for date in sorted_dates:
            print(f"  - {date}")
    else:
        print("No log data available")


def cleanup_old_logs(logger: AgentRunLogger, days: int = 30):
    """Clean up old log files"""
    print(f"\n🧹 CLEANING UP LOGS OLDER THAN {days} DAYS")
    print("=" * 50)
    
    logger.cleanup_old_logs(days)
    print("Cleanup completed!")


def main():
    parser = argparse.ArgumentParser(description="Analyze VAmPI API Discovery Agent logs")
    parser.add_argument("--date", "-d", help="Date to analyze (YYYY-MM-DD format, default: today)")
    parser.add_argument("--limit", "-l", type=int, default=10, help="Number of records to show (default: 10)")
    parser.add_argument("--cleanup", "-c", type=int, metavar="DAYS", help="Clean up logs older than DAYS")
    parser.add_argument("--all", "-a", action="store_true", help="Show all available information")
    
    args = parser.parse_args()
    
    # Initialize logger
    logger = AgentRunLogger()
    
    # Set date
    date = args.date if args.date else datetime.now().strftime('%Y-%m-%d')
    
    print("🔍 VAmPI API Discovery Agent - Log Analysis")
    print("=" * 60)
    print(f"Analyzing logs for: {date}")
    
    if args.cleanup:
        cleanup_old_logs(logger, args.cleanup)
        return
    
    if args.all:
        # Show all available information
        display_available_dates(logger)
        display_run_summary(logger, date)
        display_run_history(logger, date, args.limit)
        display_performance_metrics(logger, date)
        display_discovery_results(logger, date, args.limit)
        display_error_details(logger, date, args.limit)
    else:
        # Show summary by default
        display_run_summary(logger, date)
        display_run_history(logger, date, args.limit)
        
        # Ask user what they want to see
        print(f"\n💡 Use --all to see complete information, or specify individual sections:")
        print(f"   --performance: Performance metrics")
        print(f"   --discovery: Discovery results")
        print(f"   --errors: Error details")
        print(f"   --cleanup DAYS: Clean old logs")


if __name__ == "__main__":
    main() 