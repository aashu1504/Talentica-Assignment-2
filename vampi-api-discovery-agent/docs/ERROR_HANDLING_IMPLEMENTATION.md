# Error Handling Implementation for VAmPI Security Testing Engine

## Overview

This document describes the comprehensive error handling implementation that addresses the three critical areas:

1. **Graceful handling of network failures during testing**
2. **Recovery from authentication or authorization failures**
3. **Comprehensive logging for security audit trails**

## Architecture

The error handling system is built with a layered approach:

```
┌─────────────────────────────────────────────────────────────┐
│                    Security Testing Engine                  │
├─────────────────────────────────────────────────────────────┤
│                 Error Handling Layer                        │
│  ┌─────────────────┐ ┌─────────────────┐ ┌──────────────┐ │
│  │ Network Failure │ │ Authentication  │ │ Authorization│ │
│  │    Handler      │ │   Failure       │ │   Failure    │ │
│  │                 │ │    Handler      │ │    Handler   │ │
│  └─────────────────┘ └─────────────────┘ └──────────────┘ │
├─────────────────────────────────────────────────────────────┤
│                 Recovery Mechanisms                        │
│  ┌─────────────────┐ ┌─────────────────┐ ┌──────────────┐ │
│  │ Circuit Breaker │ │ Rate Limiting   │ │ Retry Logic  │ │
│  │                 │ │                 │ │              │ │
│  └─────────────────┘ └─────────────────┘ └──────────────┘ │
├─────────────────────────────────────────────────────────────┤
│                 Security Audit Logging                     │
│  ┌─────────────────┐ ┌─────────────────┐ ┌──────────────┐ │
│  │ Event Logging   │ │ Error Tracking  │ │ Audit Trail  │ │
│  │                 │ │                 │ │              │ │
│  └─────────────────┘ └─────────────────┘ └──────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## 1. Network Failure Handling

### Features
- **Automatic Retry Logic**: Configurable retry attempts with exponential backoff
- **Timeout Management**: Separate connection, read, and total timeouts
- **Circuit Breaker Pattern**: Prevents cascading failures
- **Threshold-based Stopping**: Stops testing after excessive network failures

### Implementation

```python
def _safe_request(self, method: str, url: str, **kwargs) -> requests.Response:
    """Make HTTP request with comprehensive error handling and retry logic"""
    for attempt in range(self.max_retries + 1):
        try:
            response = self.session.request(method, url, **kwargs)
            return response
        except requests.exceptions.ConnectionError as e:
            error_handling = self._handle_network_failure(e, url, f"{method} request")
            if not error_handling["retry_recommended"] or attempt == self.max_retries:
                break
            time.sleep(self.retry_delay * (attempt + 1))
```

### Configuration
```yaml
network_failures:
  max_retries: 3
  retry_delay: 2
  exponential_backoff: true
  threshold_before_stop: 5
  timeout_settings:
    connection_timeout: 10
    read_timeout: 30
    total_timeout: 60
```

## 2. Authentication Failure Handling

### Features
- **Rate Limiting**: Prevents brute force attacks
- **Threshold Management**: Stops testing after excessive auth failures
- **Credential Protection**: Configurable logging of sensitive information
- **Automatic Blocking**: Temporary blocking after threshold exceeded

### Implementation

```python
def _handle_authentication_failure(self, error: Exception, endpoint: str, operation: str):
    """Handle authentication failures with comprehensive logging"""
    self.auth_failures += 1
    
    # Check rate limiting
    if not self.rate_limiters["authentication"].is_allowed():
        wait_time = self.rate_limiters["authentication"].get_wait_time()
        return {
            "handled": True,
            "retry_recommended": False,
            "wait_time": wait_time
        }
    
    # Check threshold
    if self.auth_failures >= self.auth_failure_threshold:
        raise Exception(f"Authentication failure threshold exceeded")
```

### Configuration
```yaml
authentication_failures:
  threshold_before_stop: 3
  log_credentials: false
  track_failed_attempts: true
  rate_limiting:
    max_attempts_per_minute: 10
    block_duration: 300
```

## 3. Authorization Failure Handling

### Features
- **Access Control Tracking**: Logs all authorization attempts
- **Privilege Escalation Detection**: Tracks privilege escalation attempts
- **Threshold Management**: Configurable stopping thresholds
- **Comprehensive Logging**: Detailed audit trail for compliance

### Implementation

```python
def _handle_authorization_failure(self, error: Exception, endpoint: str, operation: str):
    """Handle authorization failures with comprehensive logging"""
    self.authorization_failures += 1
    
    # Log for security audit
    self._log_security_event(
        "AUTHORIZATION_FAILURE",
        {
            "endpoint": endpoint,
            "operation": operation,
            "failure_count": self.authorization_failures
        },
        "WARNING"
    )
```

## 4. Security Audit Trail Logging

### Features
- **Comprehensive Event Logging**: All security events logged with context
- **Structured Logging**: JSON-formatted logs for easy parsing
- **Log Rotation**: Automatic log file management
- **Multiple Severity Levels**: INFO, WARNING, ERROR, CRITICAL
- **Context Preservation**: Full context for each security event

### Log Events

| Event Type | Description | Severity |
|------------|-------------|----------|
| `NETWORK_FAILURE` | Network connectivity issues | WARNING |
| `AUTHENTICATION_FAILURE` | Failed authentication attempts | WARNING |
| `AUTHORIZATION_FAILURE` | Failed authorization attempts | WARNING |
| `VULNERABILITY_DISCOVERED` | Security vulnerabilities found | WARNING |
| `TEST_EXECUTION` | Test execution details | INFO |
| `REQUEST_SUCCESS` | Successful HTTP requests | INFO |
| `REQUEST_FAILED_AFTER_RETRIES` | Requests that failed after retries | ERROR |
| `UNEXPECTED_ERROR` | Unexpected errors during testing | ERROR |

### Log Format
```json
{
  "timestamp": "2025-01-15T10:30:00.123456",
  "event_type": "VULNERABILITY_DISCOVERED",
  "severity": "WARNING",
  "details": {
    "test_name": "SQL Injection Test - username",
    "endpoint": "/api/login",
    "method": "POST",
    "vulnerability_details": "SQL injection vulnerability detected",
    "severity": "CRITICAL",
    "payload": "' OR '1'='1"
  },
  "engine_state": {
    "network_failures": 0,
    "auth_failures": 1,
    "authorization_failures": 0,
    "test_errors": 0
  }
}
```

## 5. Recovery Mechanisms

### Circuit Breaker Pattern
- **States**: CLOSED, OPEN, HALF_OPEN
- **Failure Threshold**: Configurable failure count before opening
- **Recovery Timeout**: Time to wait before attempting recovery
- **Automatic Recovery**: Gradual recovery with limited attempts

### Rate Limiting
- **Time Windows**: Configurable time windows for rate limiting
- **Attempt Tracking**: Tracks attempts within time windows
- **Automatic Blocking**: Blocks operations when limits exceeded
- **Wait Time Calculation**: Provides wait time for blocked operations

### Retry Logic
- **Exponential Backoff**: Increasing delays between retries
- **Maximum Retries**: Configurable retry limits
- **Smart Retry**: Different retry strategies for different error types
- **Failure Tracking**: Comprehensive tracking of retry attempts

## 6. Configuration

### Error Handling Configuration File
Located at `config/error_handling_config.yaml`, this file provides:

- **Network failure settings**: Retry logic, timeouts, thresholds
- **Authentication settings**: Rate limiting, thresholds, logging
- **Authorization settings**: Tracking, thresholds, logging
- **Security logging**: Log levels, file paths, rotation settings
- **Recovery settings**: Circuit breaker, automatic recovery
- **Monitoring settings**: Health checks, metrics, alerting

### Environment Variables
```bash
# Override configuration file settings
export VAMPI_MAX_RETRIES=5
export VAMPI_NETWORK_TIMEOUT=45
export VAMPI_AUTH_THRESHOLD=5
export VAMPI_LOG_LEVEL=DEBUG
```

## 7. Usage Examples

### Basic Error Handling
```python
from security_testing.error_handler import handle_security_error, ErrorType, ErrorSeverity

try:
    # Perform security test
    result = perform_security_test()
except Exception as e:
    # Handle error with comprehensive logging
    result = handle_security_error(
        error=e,
        error_type=ErrorType.NETWORK_FAILURE,
        severity=ErrorSeverity.MEDIUM,
        endpoint="/api/test",
        method="POST",
        operation="security_test"
    )
```

### Error Handler Instance
```python
from security_testing.error_handler import SecurityErrorHandler

error_handler = SecurityErrorHandler()

# Get error summary
summary = error_handler.get_error_summary()
print(f"System health: {error_handler.is_healthy()}")

# Reset error counts
error_handler.reset_error_counts()
```

### Circuit Breaker Usage
```python
from security_testing.error_handler import CircuitBreaker

cb = CircuitBreaker(failure_threshold=3, recovery_timeout=60)

# Use circuit breaker for critical operations
try:
    result = cb.call(critical_function)
except Exception as e:
    print(f"Circuit breaker opened: {e}")
```

## 8. Testing

### Test Script
Run the comprehensive error handling test suite:

```bash
cd vampi-api-discovery-agent
python3 scripts/test_error_handling.py
```

### Test Coverage
The test suite covers:
- Network failure handling with retry logic
- Authentication failure handling with rate limiting
- Authorization failure handling
- Circuit breaker pattern implementation
- Rate limiting functionality
- Comprehensive error handling
- Security audit trail logging
- Error recovery mechanisms

## 9. Monitoring and Health Checks

### Health Status
```python
# Check system health
error_handler = SecurityErrorHandler()
health_status = error_handler.get_error_summary()["health_status"]

print(f"System healthy: {health_status['healthy']}")
print(f"Warnings: {health_status['warnings']}")
print(f"Critical issues: {health_status['critical']}")
```

### Metrics Collection
- **Error Counts**: Per-error-type tracking
- **Circuit Breaker States**: Current state of all circuit breakers
- **Rate Limiter Status**: Current rate limiting status
- **Performance Metrics**: Response times, success rates
- **Security Metrics**: Vulnerability discovery rates

## 10. Best Practices

### Error Handling
1. **Always use the error handler**: Don't catch exceptions without proper handling
2. **Provide context**: Include endpoint, method, and operation details
3. **Use appropriate severity levels**: Match severity to actual impact
4. **Monitor thresholds**: Regularly check error counts and system health

### Logging
1. **Structured logging**: Use JSON format for machine-readable logs
2. **Context preservation**: Include all relevant context in log entries
3. **Log rotation**: Configure appropriate log file sizes and retention
4. **Security considerations**: Don't log sensitive information

### Recovery
1. **Gradual recovery**: Use circuit breakers and rate limiting
2. **Monitor recovery**: Track recovery attempts and success rates
3. **Configurable thresholds**: Adjust thresholds based on environment
4. **Automatic vs manual**: Use automatic recovery where safe

## 11. Troubleshooting

### Common Issues

#### High Error Counts
- Check network connectivity
- Verify authentication credentials
- Review authorization permissions
- Check system resources

#### Circuit Breaker Stuck Open
- Wait for recovery timeout
- Check failure threshold configuration
- Verify underlying issue resolution
- Consider manual reset if needed

#### Rate Limiting Issues
- Check rate limiting configuration
- Verify time window settings
- Monitor attempt counts
- Adjust limits if necessary

### Debug Mode
Enable debug logging for detailed error information:

```yaml
security_logging:
  log_level: "DEBUG"
  include_stack_traces: true
  include_request_details: true
```

## 12. Future Enhancements

### Planned Features
- **Machine Learning**: Predictive error handling based on patterns
- **Advanced Metrics**: Prometheus/Grafana integration
- **Distributed Tracing**: OpenTelemetry integration
- **Automated Remediation**: Self-healing capabilities
- **Integration**: SIEM system integration

### Extensibility
The error handling system is designed to be extensible:
- **Custom Error Types**: Add new error types as needed
- **Custom Handlers**: Implement custom error handling logic
- **Custom Recovery**: Add custom recovery mechanisms
- **Custom Logging**: Extend logging capabilities

## Conclusion

The comprehensive error handling implementation provides:

1. **Robust Network Failure Handling**: Automatic retry, circuit breakers, and threshold management
2. **Secure Authentication/Authorization Handling**: Rate limiting, threshold management, and comprehensive logging
3. **Complete Security Audit Trails**: Structured logging, event tracking, and compliance support

This implementation ensures the security testing engine can operate reliably in various network conditions while maintaining comprehensive security audit trails for compliance and investigation purposes. 