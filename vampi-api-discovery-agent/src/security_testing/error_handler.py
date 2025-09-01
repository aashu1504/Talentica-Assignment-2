#!/usr/bin/env python3
"""
Comprehensive Error Handling Module for Security Testing Engine

This module provides robust error handling, recovery mechanisms, and comprehensive
logging for security audit trails during API security testing.
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass
from enum import Enum
import yaml
import os

from .models import SecurityTest, VulnerabilitySeverity


class ErrorType(Enum):
    """Types of errors that can occur during security testing"""
    NETWORK_FAILURE = "network_failure"
    AUTHENTICATION_FAILURE = "authentication_failure"
    AUTHORIZATION_FAILURE = "authorization_failure"
    TIMEOUT_ERROR = "timeout_error"
    VALIDATION_ERROR = "validation_error"
    CONFIGURATION_ERROR = "configuration_error"
    UNEXPECTED_ERROR = "unexpected_error"


class ErrorSeverity(Enum):
    """Severity levels for errors"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ErrorContext:
    """Context information for error handling"""
    error_type: ErrorType
    severity: ErrorSeverity
    endpoint: str
    method: str
    operation: str
    timestamp: datetime
    error_message: str
    stack_trace: Optional[str] = None
    request_details: Optional[Dict[str, Any]] = None
    response_details: Optional[Dict[str, Any]] = None
    payload: Optional[str] = None
    retry_count: int = 0


class CircuitBreaker:
    """Circuit breaker pattern implementation for fault tolerance"""
    
    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 60):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time = None
        self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN
        
    def call(self, func: Callable, *args, **kwargs):
        """Execute function with circuit breaker protection"""
        if self.state == "OPEN":
            if self._should_attempt_reset():
                self.state = "HALF_OPEN"
            else:
                raise Exception("Circuit breaker is OPEN - too many failures")
        
        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except Exception as e:
            self._on_failure()
            raise e
    
    def _on_success(self):
        """Handle successful execution"""
        self.failure_count = 0
        self.state = "CLOSED"
        
    def _on_failure(self):
        """Handle execution failure"""
        self.failure_count += 1
        self.last_failure_time = datetime.now()
        
        if self.failure_count >= self.failure_threshold:
            self.state = "OPEN"
    
    def _should_attempt_reset(self) -> bool:
        """Check if circuit breaker should attempt reset"""
        if self.last_failure_time is None:
            return True
        
        return (datetime.now() - self.last_failure_time).total_seconds() >= self.recovery_timeout


class RateLimiter:
    """Rate limiting for authentication and other sensitive operations"""
    
    def __init__(self, max_attempts: int, time_window: int):
        self.max_attempts = max_attempts
        self.time_window = time_window
        self.attempts = []
        
    def is_allowed(self) -> bool:
        """Check if operation is allowed under rate limiting"""
        now = datetime.now()
        
        # Remove old attempts outside the time window
        self.attempts = [attempt for attempt in self.attempts 
                        if (now - attempt).total_seconds() < self.time_window]
        
        if len(self.attempts) < self.max_attempts:
            self.attempts.append(now)
            return True
        
        return False
    
    def get_wait_time(self) -> int:
        """Get time to wait before next attempt is allowed"""
        if not self.attempts:
            return 0
        
        oldest_attempt = min(self.attempts)
        return max(0, self.time_window - (datetime.now() - oldest_attempt).total_seconds())


class SecurityErrorHandler:
    """Comprehensive error handler for security testing operations"""
    
    def __init__(self, config_file: str = "config/error_handling_config.yaml"):
        self.config = self._load_config(config_file)
        self.logger = logging.getLogger('security_error_handler')
        self.security_logger = logging.getLogger('security_audit_trail')
        
        # Initialize error tracking
        self.error_counts = {error_type: 0 for error_type in ErrorType}
        self.circuit_breakers = {}
        self.rate_limiters = {}
        
        # Setup logging
        self._setup_logging()
        
        # Initialize circuit breakers for different error types
        self._initialize_circuit_breakers()
        
        # Initialize rate limiters
        self._initialize_rate_limiters()
    
    def _load_config(self, config_file: str) -> Dict[str, Any]:
        """Load error handling configuration"""
        try:
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    return yaml.safe_load(f)
            else:
                # Return default configuration
                return self._get_default_config()
        except Exception as e:
            logging.warning(f"Failed to load error handling config: {e}")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default error handling configuration"""
        return {
            "network_failures": {
                "max_retries": 3,
                "retry_delay": 2,
                "threshold_before_stop": 5
            },
            "authentication_failures": {
                "threshold_before_stop": 3,
                "rate_limiting": {
                    "max_attempts_per_minute": 10,
                    "block_duration": 300
                }
            },
            "security_logging": {
                "enabled": True,
                "log_level": "DEBUG"
            }
        }
    
    def _setup_logging(self):
        """Setup comprehensive logging for error handling"""
        # Create logs directory if it doesn't exist
        os.makedirs("logs", exist_ok=True)
        
        # Security audit trail handler
        security_handler = logging.FileHandler('logs/security_audit_trail.log')
        security_handler.setLevel(logging.DEBUG)
        
        security_formatter = logging.Formatter(
            '%(asctime)s - SECURITY_ERROR_HANDLER - %(levelname)s - %(message)s'
        )
        security_handler.setFormatter(security_formatter)
        
        if not self.security_logger.handlers:
            self.security_logger.addHandler(security_handler)
            self.security_logger.setLevel(logging.DEBUG)
    
    def _initialize_circuit_breakers(self):
        """Initialize circuit breakers for different error types"""
        if self.config.get("recovery", {}).get("circuit_breaker", {}).get("enabled", False):
            cb_config = self.config["recovery"]["circuit_breaker"]
            
            for error_type in ErrorType:
                self.circuit_breakers[error_type] = CircuitBreaker(
                    failure_threshold=cb_config.get("failure_threshold", 5),
                    recovery_timeout=cb_config.get("recovery_timeout", 60)
                )
    
    def _initialize_rate_limiters(self):
        """Initialize rate limiters for sensitive operations"""
        auth_config = self.config.get("authentication_failures", {})
        rate_config = auth_config.get("rate_limiting", {})
        
        self.rate_limiters["authentication"] = RateLimiter(
            max_attempts=rate_config.get("max_attempts_per_minute", 10),
            time_window=60  # 1 minute
        )
    
    def handle_error(self, error: Exception, context: ErrorContext) -> Dict[str, Any]:
        """Handle an error with comprehensive logging and recovery logic"""
        # Increment error count
        self.error_counts[context.error_type] += 1
        
        # Log error for security audit
        self._log_error_for_audit(context)
        
        # Check if we should stop operations
        if self._should_stop_operations(context.error_type):
            self._log_critical_error(context)
            raise Exception(f"Critical error threshold exceeded for {context.error_type.value}")
        
        # Apply rate limiting if applicable
        if context.error_type == ErrorType.AUTHENTICATION_FAILURE:
            if not self.rate_limiters["authentication"].is_allowed():
                wait_time = self.rate_limiters["authentication"].get_wait_time()
                return {
                    "handled": True,
                    "retry_recommended": False,
                    "wait_time": wait_time,
                    "message": f"Rate limit exceeded. Wait {wait_time:.0f} seconds."
                }
        
        # Determine recovery action
        recovery_action = self._determine_recovery_action(context)
        
        return recovery_action
    
    def _log_error_for_audit(self, context: ErrorContext):
        """Log error details for security audit trail"""
        log_entry = {
            "timestamp": context.timestamp.isoformat(),
            "error_type": context.error_type.value,
            "severity": context.severity.value,
            "endpoint": context.endpoint,
            "method": context.method,
            "operation": context.operation,
            "error_message": context.error_message,
            "retry_count": context.retry_count,
            "error_counts": self.error_counts.copy(),
            "request_details": context.request_details,
            "payload": context.payload
        }
        
        if context.severity in [ErrorSeverity.HIGH, ErrorSeverity.CRITICAL]:
            self.security_logger.error(json.dumps(log_entry))
        elif context.severity == ErrorSeverity.MEDIUM:
            self.security_logger.warning(json.dumps(log_entry))
        else:
            self.security_logger.info(json.dumps(log_entry))
    
    def _log_critical_error(self, context: ErrorContext):
        """Log critical errors that cause operations to stop"""
        critical_log = {
            "timestamp": context.timestamp.isoformat(),
            "event_type": "CRITICAL_ERROR_THRESHOLD_EXCEEDED",
            "error_type": context.error_type.value,
            "endpoint": context.endpoint,
            "method": context.method,
            "total_errors": self.error_counts[context.error_type],
            "message": f"Stopping operations due to {context.error_type.value} threshold exceeded"
        }
        
        self.security_logger.critical(json.dumps(critical_log))
    
    def _should_stop_operations(self, error_type: ErrorType) -> bool:
        """Check if operations should stop due to error threshold"""
        thresholds = {
            ErrorType.NETWORK_FAILURE: self.config.get("network_failures", {}).get("threshold_before_stop", 5),
            ErrorType.AUTHENTICATION_FAILURE: self.config.get("authentication_failures", {}).get("threshold_before_stop", 3),
            ErrorType.AUTHORIZATION_FAILURE: self.config.get("authorization_failures", {}).get("threshold_before_stop", 5)
        }
        
        threshold = thresholds.get(error_type, 10)
        return self.error_counts[error_type] >= threshold
    
    def _determine_recovery_action(self, context: ErrorContext) -> Dict[str, Any]:
        """Determine the appropriate recovery action for an error"""
        if context.error_type == ErrorType.NETWORK_FAILURE:
            return {
                "handled": True,
                "retry_recommended": True,
                "retry_delay": self.config.get("network_failures", {}).get("retry_delay", 2),
                "max_retries": self.config.get("network_failures", {}).get("max_retries", 3)
            }
        
        elif context.error_type == ErrorType.AUTHENTICATION_FAILURE:
            return {
                "handled": True,
                "retry_recommended": False,
                "message": "Authentication failure - credentials may be invalid"
            }
        
        elif context.error_type == ErrorType.AUTHORIZATION_FAILURE:
            return {
                "handled": True,
                "retry_recommended": False,
                "message": "Authorization failure - insufficient permissions"
            }
        
        else:
            return {
                "handled": True,
                "retry_recommended": False,
                "message": "Error handled but no specific recovery action defined"
            }
    
    def get_error_summary(self) -> Dict[str, Any]:
        """Get comprehensive error summary for monitoring"""
        return {
            "error_counts": self.error_counts.copy(),
            "total_errors": sum(self.error_counts.values()),
            "circuit_breaker_states": {
                error_type: cb.state for error_type, cb in self.circuit_breakers.items()
            },
            "rate_limiter_status": {
                "authentication": {
                    "attempts_in_window": len(self.rate_limiters["authentication"].attempts),
                    "max_attempts": self.rate_limiters["authentication"].max_attempts,
                    "is_allowed": self.rate_limiters["authentication"].is_allowed()
                }
            },
            "health_status": {
                "healthy": all(count < 5 for count in self.error_counts.values()),
                "warnings": [error_type.value for error_type, count in self.error_counts.items() if count >= 3],
                "critical": [error_type.value for error_type, count in self.error_counts.items() if count >= 5]
            }
        }
    
    def reset_error_counts(self, error_type: Optional[ErrorType] = None):
        """Reset error counts for recovery"""
        if error_type:
            self.error_counts[error_type] = 0
        else:
            self.error_counts = {error_type: 0 for error_type in ErrorType}
        
        self.security_logger.info(f"Error counts reset for {error_type.value if error_type else 'all error types'}")
    
    def is_healthy(self) -> bool:
        """Check if the system is healthy based on error counts"""
        return all(count < 5 for count in self.error_counts.values())


# Global error handler instance
security_error_handler = SecurityErrorHandler()


def handle_security_error(error: Exception, error_type: ErrorType, severity: ErrorSeverity,
                         endpoint: str, method: str, operation: str, **kwargs) -> Dict[str, Any]:
    """Convenience function for handling security testing errors"""
    context = ErrorContext(
        error_type=error_type,
        severity=severity,
        endpoint=endpoint,
        method=method,
        operation=operation,
        timestamp=datetime.now(),
        error_message=str(error),
        **kwargs
    )
    
    return security_error_handler.handle_error(error, context) 