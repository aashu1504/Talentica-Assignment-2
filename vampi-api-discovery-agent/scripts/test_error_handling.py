#!/usr/bin/env python3
"""
Test Script for Comprehensive Error Handling in Security Testing Engine

This script demonstrates the error handling capabilities including:
- Network failure handling with retry logic
- Authentication failure handling with rate limiting
- Authorization failure handling
- Comprehensive security audit logging
- Circuit breaker pattern implementation
- Error recovery mechanisms
"""

import sys
import os
import time
import logging
from datetime import datetime

# Add src directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from security_testing.error_handler import (
    SecurityErrorHandler, ErrorType, ErrorSeverity, ErrorContext,
    CircuitBreaker, RateLimiter, handle_security_error
)


def test_network_failure_handling():
    """Test network failure handling with retry logic"""
    print("\n=== Testing Network Failure Handling ===")
    
    error_handler = SecurityErrorHandler()
    
    # Simulate network failures
    for i in range(3):
        try:
            # Simulate a network error
            network_error = Exception("Connection timeout")
            context = ErrorContext(
                error_type=ErrorType.NETWORK_FAILURE,
                severity=ErrorSeverity.MEDIUM,
                endpoint="/api/test",
                method="GET",
                operation="security_test",
                timestamp=datetime.now(),
                error_message=str(network_error)
            )
            
            result = error_handler.handle_error(network_error, context)
            print(f"Network failure {i+1}: {result}")
            
        except Exception as e:
            print(f"Network failure {i+1} exceeded threshold: {e}")
            break
    
    # Get error summary
    summary = error_handler.get_error_summary()
    print(f"Error summary: {summary}")


def test_authentication_failure_handling():
    """Test authentication failure handling with rate limiting"""
    print("\n=== Testing Authentication Failure Handling ===")
    
    error_handler = SecurityErrorHandler()
    
    # Simulate authentication failures
    for i in range(5):
        try:
            auth_error = Exception("Invalid credentials")
            context = ErrorContext(
                error_type=ErrorType.AUTHENTICATION_FAILURE,
                severity=ErrorSeverity.HIGH,
                endpoint="/api/auth",
                method="POST",
                operation="login_attempt",
                timestamp=datetime.now(),
                error_message=str(auth_error)
            )
            
            result = error_handler.handle_error(auth_error, context)
            print(f"Auth failure {i+1}: {result}")
            
            if "wait_time" in result:
                print(f"Rate limited - wait {result['wait_time']:.0f} seconds")
                time.sleep(1)  # Simulate time passing
            
        except Exception as e:
            print(f"Auth failure {i+1} exceeded threshold: {e}")
            break
    
    # Get error summary
    summary = error_handler.get_error_summary()
    print(f"Error summary: {summary}")


def test_authorization_failure_handling():
    """Test authorization failure handling"""
    print("\n=== Testing Authorization Failure Handling ===")
    
    error_handler = SecurityErrorHandler()
    
    # Simulate authorization failures
    for i in range(3):
        try:
            authz_error = Exception("Insufficient permissions")
            context = ErrorContext(
                error_type=ErrorType.AUTHORIZATION_FAILURE,
                severity=ErrorSeverity.MEDIUM,
                endpoint="/api/admin",
                method="GET",
                operation="access_admin_panel",
                timestamp=datetime.now(),
                error_message=str(authz_error)
            )
            
            result = error_handler.handle_error(authz_error, context)
            print(f"Authorization failure {i+1}: {result}")
            
        except Exception as e:
            print(f"Authorization failure {i+1} exceeded threshold: {e}")
            break
    
    # Get error summary
    summary = error_handler.get_error_summary()
    print(f"Error summary: {summary}")


def test_circuit_breaker():
    """Test circuit breaker pattern implementation"""
    print("\n=== Testing Circuit Breaker Pattern ===")
    
    cb = CircuitBreaker(failure_threshold=3, recovery_timeout=5)
    
    def failing_function():
        raise Exception("Simulated failure")
    
    def successful_function():
        return "Success"
    
    # Test circuit breaker with failing function
    print("Testing circuit breaker with failing function...")
    for i in range(4):
        try:
            result = cb.call(failing_function)
            print(f"Call {i+1}: {result}")
        except Exception as e:
            print(f"Call {i+1} failed: {e}")
            print(f"Circuit breaker state: {cb.state}")
    
    # Wait for recovery timeout
    print(f"Waiting for recovery timeout ({cb.recovery_timeout} seconds)...")
    time.sleep(cb.recovery_timeout + 1)
    
    # Test circuit breaker with successful function
    print("Testing circuit breaker with successful function...")
    try:
        result = cb.call(successful_function)
        print(f"Recovery call: {result}")
        print(f"Circuit breaker state: {cb.state}")
    except Exception as e:
        print(f"Recovery call failed: {e}")


def test_rate_limiter():
    """Test rate limiting functionality"""
    print("\n=== Testing Rate Limiter ===")
    
    rate_limiter = RateLimiter(max_attempts=3, time_window=5)
    
    print("Testing rate limiting...")
    for i in range(5):
        allowed = rate_limiter.is_allowed()
        print(f"Attempt {i+1}: {'Allowed' if allowed else 'Blocked'}")
        
        if not allowed:
            wait_time = rate_limiter.get_wait_time()
            print(f"Wait time: {wait_time:.0f} seconds")
        
        time.sleep(1)  # Simulate time passing


def test_comprehensive_error_handling():
    """Test comprehensive error handling with the convenience function"""
    print("\n=== Testing Comprehensive Error Handling ===")
    
    # Test different error types
    error_types = [
        (ErrorType.NETWORK_FAILURE, ErrorSeverity.MEDIUM),
        (ErrorType.AUTHENTICATION_FAILURE, ErrorSeverity.HIGH),
        (ErrorType.AUTHORIZATION_FAILURE, ErrorSeverity.MEDIUM),
        (ErrorType.TIMEOUT_ERROR, ErrorSeverity.LOW),
        (ErrorType.UNEXPECTED_ERROR, ErrorSeverity.CRITICAL)
    ]
    
    for error_type, severity in error_types:
        try:
            error = Exception(f"Simulated {error_type.value}")
            result = handle_security_error(
                error=error,
                error_type=error_type,
                severity=severity,
                endpoint="/api/test",
                method="POST",
                operation="security_test",
                payload="test_payload"
            )
            print(f"{error_type.value}: {result}")
            
        except Exception as e:
            print(f"{error_type.value} exceeded threshold: {e}")


def test_security_audit_logging():
    """Test security audit trail logging"""
    print("\n=== Testing Security Audit Trail Logging ===")
    
    error_handler = SecurityErrorHandler()
    
    # Test logging different types of security events
    test_events = [
        {
            "error_type": ErrorType.NETWORK_FAILURE,
            "severity": ErrorSeverity.MEDIUM,
            "message": "Connection timeout during security scan"
        },
        {
            "error_type": ErrorType.AUTHENTICATION_FAILURE,
            "severity": ErrorSeverity.HIGH,
            "message": "Invalid API key used in security test"
        },
        {
            "error_type": ErrorType.VULNERABILITY_DISCOVERED,
            "severity": ErrorSeverity.CRITICAL,
            "message": "SQL injection vulnerability found"
        }
    ]
    
    for event in test_events:
        context = ErrorContext(
            error_type=event["error_type"],
            severity=event["severity"],
            endpoint="/api/security",
            method="POST",
            operation="vulnerability_scan",
            timestamp=datetime.now(),
            error_message=event["message"],
            payload="malicious_payload"
        )
        
        result = error_handler.handle_error(Exception(event["message"]), context)
        print(f"Logged {event['error_type'].value}: {result}")
    
    # Check if log file was created
    log_file = "logs/security_audit_trail.log"
    if os.path.exists(log_file):
        print(f"Security audit log created: {log_file}")
        # Show last few lines
        with open(log_file, 'r') as f:
            lines = f.readlines()
            print("Last 3 log entries:")
            for line in lines[-3:]:
                print(f"  {line.strip()}")
    else:
        print("Security audit log not created")


def test_error_recovery():
    """Test error recovery mechanisms"""
    print("\n=== Testing Error Recovery Mechanisms ===")
    
    error_handler = SecurityErrorHandler()
    
    # Simulate some errors
    for i in range(2):
        error = Exception(f"Test error {i+1}")
        context = ErrorContext(
            error_type=ErrorType.NETWORK_FAILURE,
            severity=ErrorSeverity.LOW,
            endpoint="/api/test",
            method="GET",
            operation="test_operation",
            timestamp=datetime.now(),
            error_message=str(error)
        )
        
        error_handler.handle_error(error, context)
    
    # Show current error counts
    summary = error_handler.get_error_summary()
    print(f"Before recovery: {summary['error_counts']}")
    
    # Reset error counts
    error_handler.reset_error_counts(ErrorType.NETWORK_FAILURE)
    
    # Show updated error counts
    summary = error_handler.get_error_summary()
    print(f"After recovery: {summary['error_counts']}")
    
    # Check system health
    print(f"System healthy: {error_handler.is_healthy()}")


def main():
    """Run all error handling tests"""
    print("Comprehensive Error Handling Test Suite")
    print("=" * 50)
    
    # Setup logging
    logging.basicConfig(level=logging.INFO)
    
    try:
        # Run all tests
        test_network_failure_handling()
        test_authentication_failure_handling()
        test_authorization_failure_handling()
        test_circuit_breaker()
        test_rate_limiter()
        test_comprehensive_error_handling()
        test_security_audit_logging()
        test_error_recovery()
        
        print("\n" + "=" * 50)
        print("All error handling tests completed successfully!")
        print("Check the logs/ directory for security audit trail logs.")
        
    except Exception as e:
        print(f"\nError during testing: {e}")
        logging.exception("Test execution failed")


if __name__ == "__main__":
    main() 