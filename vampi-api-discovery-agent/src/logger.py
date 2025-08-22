#!/usr/bin/env python3
"""
Comprehensive Logging System for VAmPI API Discovery Agent
Handles datewise log files, performance tracking, and run history
"""

import os
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List
import sys

# Add src directory to path for imports
sys.path.append(os.path.dirname(__file__))

from models import DiscoveryReport, EndpointMetadata


class AgentRunLogger:
    """
    Comprehensive logging system for tracking all agent runs
    with datewise organization and detailed performance metrics
    """
    
    def __init__(self, log_dir: str = "logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        # Create subdirectories
        (self.log_dir / "runs").mkdir(exist_ok=True)
        (self.log_dir / "performance").mkdir(exist_ok=True)
        (self.log_dir / "errors").mkdir(exist_ok=True)
        (self.log_dir / "discovery").mkdir(exist_ok=True)
        
        # Setup logging
        self._setup_logging()
        
    def _setup_logging(self):
        """Setup comprehensive logging configuration"""
        # Main logger
        self.logger = logging.getLogger('vampi_discovery_agent')
        self.logger.setLevel(logging.INFO)
        
        # Prevent duplicate handlers
        if self.logger.handlers:
            self.logger.handlers.clear()
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
        # File handler for daily logs
        today = datetime.now().strftime('%Y-%m-%d')
        daily_log_file = self.log_dir / f"agent_runs_{today}.log"
        file_handler = logging.FileHandler(daily_log_file)
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        self.logger.addHandler(file_handler)
        
    def log_run_start(self, run_id: str, config: Dict[str, Any]) -> None:
        """Log the start of an agent run"""
        run_data = {
            "run_id": run_id,
            "timestamp": datetime.now().isoformat(),
            "status": "started",
            "config": config,
            "type": "run_start"
        }
        
        self._write_run_log(run_data)
        self.logger.info(f"Agent run started: {run_id}")
        
    def log_run_complete(self, run_id: str, report: DiscoveryReport, 
                        performance_metrics: Dict[str, Any]) -> None:
        """Log the completion of an agent run with results"""
        run_data = {
            "run_id": run_id,
            "timestamp": datetime.now().isoformat(),
            "status": "completed",
            "type": "run_complete",
            "summary": {
                "total_endpoints": report.discovery_summary.total_endpoints,
                "discovery_coverage": report.discovery_summary.discovery_coverage,
                "parameter_coverage": report.discovery_summary.parameter_coverage,
                "authenticated_endpoints": report.discovery_summary.authenticated_endpoints,
                "public_endpoints": report.discovery_summary.public_endpoints,
                "total_parameters": report.discovery_summary.total_parameters,
                "unique_parameters": report.discovery_summary.unique_parameters
            },
            "performance": performance_metrics,
            "validation_metrics": getattr(report, 'validation_metrics', {}).dict() if hasattr(report, 'validation_metrics') and report.validation_metrics else {}
        }
        
        self._write_run_log(run_data)
        self._write_performance_log(run_id, performance_metrics)
        self._write_discovery_log(run_id, report)
        
        self.logger.info(f"Agent run completed: {run_id} - "
                        f"Endpoints: {report.discovery_summary.total_endpoints}, "
                        f"Coverage: {report.discovery_summary.discovery_coverage}%")
        
    def log_run_error(self, run_id: str, error: Exception, 
                     context: Optional[Dict[str, Any]] = None) -> None:
        """Log errors during agent runs"""
        error_data = {
            "run_id": run_id,
            "timestamp": datetime.now().isoformat(),
            "status": "error",
            "type": "run_error",
            "error_type": type(error).__name__,
            "error_message": str(error),
            "context": context or {}
        }
        
        self._write_run_log(error_data)
        self._write_error_log(run_id, error, context)
        
        self.logger.error(f"Agent run error: {run_id} - {error}")
        
    def log_discovery_step(self, run_id: str, step: str, 
                          details: Dict[str, Any]) -> None:
        """Log individual discovery steps"""
        step_data = {
            "run_id": run_id,
            "timestamp": datetime.now().isoformat(),
            "type": "discovery_step",
            "step": step,
            "details": details
        }
        
        self._write_run_log(step_data)
        self.logger.debug(f"Discovery step: {step} - {details}")
        
    def log_performance_metric(self, run_id: str, metric_name: str, 
                              value: Any, unit: str = "") -> None:
        """Log individual performance metrics"""
        metric_data = {
            "run_id": run_id,
            "timestamp": datetime.now().isoformat(),
            "type": "performance_metric",
            "metric": metric_name,
            "value": value,
            "unit": unit
        }
        
        self._write_run_log(metric_data)
        
    def _write_run_log(self, data: Dict[str, Any]) -> None:
        """Write run log entry to daily log file"""
        today = datetime.now().strftime('%Y-%m-%d')
        run_log_file = self.log_dir / "runs" / f"runs_{today}.jsonl"
        
        with open(run_log_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(data, default=str) + '\n')
            
    def _write_performance_log(self, run_id: str, 
                              performance_metrics: Dict[str, Any]) -> None:
        """Write performance metrics to performance log"""
        today = datetime.now().strftime('%Y-%m-%d')
        perf_log_file = self.log_dir / "performance" / f"performance_{today}.jsonl"
        
        perf_data = {
            "run_id": run_id,
            "timestamp": datetime.now().isoformat(),
            "metrics": performance_metrics
        }
        
        with open(perf_log_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(perf_data, default=str) + '\n')
            
    def _write_discovery_log(self, run_id: str, report: DiscoveryReport) -> None:
        """Write discovery results to discovery log"""
        today = datetime.now().strftime('%Y-%m-%d')
        discovery_log_file = self.log_dir / "discovery" / f"discovery_{today}.jsonl"
        
        discovery_data = {
            "run_id": run_id,
            "timestamp": datetime.now().isoformat(),
            "endpoints": [ep.dict() for ep in report.endpoints],
            "summary": report.discovery_summary.dict(),
            "structure": report.api_structure.dict() if report.api_structure else {}
        }
        
        with open(discovery_log_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(discovery_data, default=str) + '\n')
            
    def _write_error_log(self, run_id: str, error: Exception, 
                        context: Optional[Dict[str, Any]]) -> None:
        """Write error details to error log"""
        today = datetime.now().strftime('%Y-%m-%d')
        error_log_file = self.log_dir / "errors" / f"errors_{today}.jsonl"
        
        error_data = {
            "run_id": run_id,
            "timestamp": datetime.now().isoformat(),
            "error_type": type(error).__name__,
            "error_message": str(error),
            "error_traceback": self._get_traceback(error),
            "context": context or {}
        }
        
        with open(error_log_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(error_data, default=str) + '\n')
            
    def _get_traceback(self, error: Exception) -> str:
        """Get formatted traceback for error logging"""
        import traceback
        return ''.join(traceback.format_exception(type(error), error, error.__traceback__))
        
    def get_run_history(self, date: Optional[str] = None, 
                       limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve run history for a specific date or all dates"""
        if date is None:
            date = datetime.now().strftime('%Y-%m-%d')
            
        run_log_file = self.log_dir / "runs" / f"runs_{date}.jsonl"
        
        if not run_log_file.exists():
            return []
            
        runs = []
        with open(run_log_file, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    runs.append(json.loads(line))
                    
        # Return most recent runs up to limit
        return runs[-limit:] if len(runs) > limit else runs
        
    def get_performance_summary(self, date: Optional[str] = None) -> Dict[str, Any]:
        """Get performance summary for a specific date"""
        if date is None:
            date = datetime.now().strftime('%Y-%m-%d')
            
        perf_log_file = self.log_dir / "performance" / f"performance_{date}.jsonl"
        
        if not perf_log_file.exists():
            return {}
            
        total_runs = 0
        total_duration = 0
        total_endpoints = 0
        total_coverage = 0
        
        with open(perf_log_file, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    data = json.loads(line)
                    total_runs += 1
                    metrics = data.get('metrics', {})
                    total_duration += metrics.get('total_duration', 0)
                    total_endpoints += metrics.get('total_endpoints', 0)
                    total_coverage += metrics.get('discovery_coverage', 0)
                    
        if total_runs == 0:
            return {}
            
        return {
            "date": date,
            "total_runs": total_runs,
            "average_duration": total_duration / total_runs,
            "average_endpoints": total_endpoints / total_runs,
            "average_coverage": total_coverage / total_runs
        }
        
    def get_error_summary(self, date: Optional[str] = None) -> Dict[str, Any]:
        """Get error summary for a specific date"""
        if date is None:
            date = datetime.now().strftime('%Y-%m-%d')
            
        error_log_file = self.log_dir / "errors" / f"errors_{date}.jsonl"
        
        if not error_log_file.exists():
            return {}
            
        error_counts = {}
        total_errors = 0
        
        with open(error_log_file, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    data = json.loads(line)
                    total_errors += 1
                    error_type = data.get('error_type', 'Unknown')
                    error_counts[error_type] = error_counts.get(error_type, 0) + 1
                    
        return {
            "date": date,
            "total_errors": total_errors,
            "error_types": error_counts
        }
        
    def cleanup_old_logs(self, days_to_keep: int = 30) -> None:
        """Clean up log files older than specified days"""
        cutoff_date = datetime.now().timestamp() - (days_to_keep * 24 * 60 * 60)
        
        for log_type in ["runs", "performance", "errors", "discovery"]:
            log_dir = self.log_dir / log_type
            if log_dir.exists():
                for log_file in log_dir.glob("*.jsonl"):
                    if log_file.stat().st_mtime < cutoff_date:
                        log_file.unlink()
                        self.logger.info(f"Cleaned up old log file: {log_file}")
                        
    def generate_daily_report(self, date: Optional[str] = None) -> Dict[str, Any]:
        """Generate comprehensive daily report"""
        if date is None:
            date = datetime.now().strftime('%Y-%m-%d')
            
        return {
            "date": date,
            "performance_summary": self.get_performance_summary(date),
            "error_summary": self.get_error_summary(date),
            "run_count": len(self.get_run_history(date)),
            "log_files": {
                "runs": str(self.log_dir / "runs" / f"runs_{date}.jsonl"),
                "performance": str(self.log_dir / "performance" / f"performance_{date}.jsonl"),
                "errors": str(self.log_dir / "errors" / f"errors_{date}.jsonl"),
                "discovery": str(self.log_dir / "discovery" / f"discovery_{date}.jsonl")
            }
        }


# Global logger instance
agent_logger = AgentRunLogger()


def log_agent_run(func):
    """Decorator to automatically log agent run functions"""
    def wrapper(*args, **kwargs):
        run_id = f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        try:
            # Log run start
            agent_logger.log_run_start(run_id, {"function": func.__name__})
            
            # Execute function
            result = func(*args, **kwargs)
            
            # Log run completion if result is a DiscoveryReport
            if hasattr(result, 'discovery_summary'):
                performance_metrics = {
                    "total_duration": getattr(result.discovery_summary, 'discovery_duration', 0),
                    "total_endpoints": result.discovery_summary.total_endpoints,
                    "discovery_coverage": result.discovery_summary.discovery_coverage
                }
                agent_logger.log_run_complete(run_id, result, performance_metrics)
            
            return result
            
        except Exception as e:
            # Log error
            agent_logger.log_run_error(run_id, e, {"function": func.__name__})
            raise
            
    return wrapper 