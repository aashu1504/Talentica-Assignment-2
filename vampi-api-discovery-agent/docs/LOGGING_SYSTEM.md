# 📊 VAmPI API Discovery Agent - Comprehensive Logging System

## Overview

The VAmPI API Discovery Agent now includes a comprehensive logging system that automatically tracks all agent runs, performance metrics, discovery results, and errors with datewise organization. This system provides complete visibility into the agent's operation and enables detailed analysis of performance trends and issues.

## 🏗️ Architecture

### Core Components

1. **AgentRunLogger** - Main logging class that orchestrates all logging operations
2. **Log Decorators** - Automatic logging for agent functions
3. **Structured Log Files** - JSONL format for easy parsing and analysis
4. **Datewise Organization** - Separate log files for each date
5. **Performance Tracking** - Comprehensive metrics collection
6. **Error Monitoring** - Detailed error tracking with context

### Directory Structure

```
logs/
├── agent_runs_YYYY-MM-DD.log          # Main daily log file
├── runs/
│   └── runs_YYYY-MM-DD.jsonl         # Run history and events
├── performance/
│   └── performance_YYYY-MM-DD.jsonl   # Performance metrics
├── discovery/
│   └── discovery_YYYY-MM-DD.jsonl     # Discovery results
└── errors/
    └── errors_YYYY-MM-DD.jsonl        # Error details and stack traces
```

## 🚀 Features

### Automatic Logging

- **Run Start/Complete** - Automatically logged for all agent operations
- **Discovery Steps** - Individual step tracking with progress metrics
- **Performance Metrics** - Duration, endpoint count, coverage tracking
- **Error Handling** - Comprehensive error logging with context
- **Validation Results** - Discovery accuracy and completeness metrics

### Data Collection

- **Run Metadata** - Timestamps, run IDs, configuration details
- **Performance Data** - Execution time, resource usage, throughput
- **Discovery Results** - Endpoint counts, coverage percentages, parameter details
- **Error Information** - Exception types, messages, stack traces, context
- **Authentication Data** - Auth mechanisms, endpoint requirements
- **Risk Assessment** - Security analysis results and categorizations

### Analysis Capabilities

- **Daily Reports** - Comprehensive summaries for each day
- **Performance Trends** - Statistical analysis of metrics over time
- **Error Analysis** - Error type distribution and frequency
- **Run History** - Complete audit trail of all operations
- **Coverage Tracking** - Discovery accuracy and completeness trends

## 📋 Usage

### Basic Logging

```python
from logger import agent_logger

# Log a run start
run_id = "run_20250822_143022"
agent_logger.log_run_start(run_id, {"base_url": "http://localhost:5000"})

# Log discovery steps
agent_logger.log_discovery_step(run_id, "documentation_parsing", {"endpoints_found": 5})

# Log performance metrics
agent_logger.log_performance_metric(run_id, "scan_duration", 2.5, "seconds")

# Log run completion
agent_logger.log_run_complete(run_id, discovery_result, performance_metrics)

# Log errors
agent_logger.log_run_error(run_id, exception, {"context": "additional_info"})
```

### Automatic Logging with Decorators

```python
from logger import log_agent_run

@log_agent_run
def discover_endpoints():
    # This function will be automatically logged
    # Start, completion, and errors are tracked
    pass
```

### Log Analysis

```bash
# View today's summary
python3 scripts/analyze_logs.py

# View specific date
python3 scripts/analyze_logs.py --date 2025-08-22

# View all information
python3 scripts/analyze_logs.py --all

# Clean up old logs
python3 scripts/analyze_logs.py --cleanup 30
```

## 📊 Log File Formats

### Run Log (runs_YYYY-MM-DD.jsonl)

Each line contains a JSON object with run information:

```json
{
  "run_id": "run_20250822_143022",
  "timestamp": "2025-08-22T14:30:22.123456",
  "status": "started|completed|error",
  "type": "run_start|run_complete|discovery_step|performance_metric|run_error",
  "config": {...},
  "summary": {...},
  "performance": {...},
  "validation_metrics": {...}
}
```

### Performance Log (performance_YYYY-MM-DD.jsonl)

Performance metrics for each run:

```json
{
  "run_id": "run_20250822_143022",
  "timestamp": "2025-08-22T14:30:22.123456",
  "metrics": {
    "total_duration": 2.5,
    "total_endpoints": 12,
    "discovery_coverage": 100.0,
    "parameter_coverage": 100.0
  }
}
```

### Discovery Log (discovery_YYYY-MM-DD.jsonl)

Detailed discovery results:

```json
{
  "run_id": "run_20250822_143022",
  "timestamp": "2025-08-22T14:30:22.123456",
  "endpoints": [...],
  "summary": {...},
  "structure": {...}
}
```

### Error Log (errors_YYYY-MM-DD.jsonl)

Error details and stack traces:

```json
{
  "run_id": "run_20250822_143022",
  "timestamp": "2025-08-22T14:30:22.123456",
  "error_type": "ConnectionError",
  "error_message": "Connection refused",
  "error_traceback": "...",
  "context": {...}
}
```

## 🔍 Analysis Commands

### View Available Dates

```bash
python3 scripts/analyze_logs.py --all
```

### Performance Summary

```bash
python3 scripts/analyze_logs.py --performance
```

### Discovery Results

```bash
python3 scripts/analyze_logs.py --discovery
```

### Error Analysis

```bash
python3 scripts/analyze_logs.py --errors
```

### Custom Date Range

```bash
python3 scripts/analyze_logs.py --date 2025-08-21
```

### Log Cleanup

```bash
# Keep logs for 30 days
python3 scripts/analyze_logs.py --cleanup 30

# Keep logs for 7 days
python3 scripts/analyze_logs.py --cleanup 7
```

## 📈 Performance Metrics

### Tracked Metrics

- **Execution Duration** - Total time for discovery operations
- **Endpoint Discovery** - Number of endpoints found per run
- **Coverage Percentage** - Discovery and parameter coverage
- **Authentication Analysis** - Auth mechanism detection time
- **Risk Assessment** - Security analysis performance
- **Memory Usage** - Resource consumption tracking
- **Network Performance** - Request/response timing

### Statistical Analysis

- **Min/Max/Average** values for all metrics
- **Trend Analysis** over time periods
- **Performance Regression** detection
- **Resource Usage** patterns
- **Throughput** calculations

## 🛠️ Configuration

### Log Directory

```python
# Custom log directory
logger = AgentRunLogger(log_dir="custom_logs")

# Default: ./logs/
```

### Log Retention

```python
# Clean up logs older than 30 days
logger.cleanup_old_logs(days_to_keep=30)

# Clean up logs older than 7 days
logger.cleanup_old_logs(days_to_keep=7)
```

### Log Levels

```python
# Console logging level
console_handler.setLevel(logging.INFO)

# File logging level
file_handler.setLevel(logging.DEBUG)
```

## 🔧 Integration

### With Discovery Engine

The logging system is automatically integrated with the VAmPIDiscoveryEngine:

```python
# Automatic logging in discover_endpoints method
async def discover_endpoints(self) -> APIDiscoveryResult:
    run_id = f"discovery_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    # Log start
    agent_logger.log_run_start(run_id, {"base_url": self.config.base_url})
    
    try:
        # Discovery logic...
        
        # Log completion
        agent_logger.log_run_complete(run_id, result, performance_metrics)
        return result
        
    except Exception as e:
        # Log error
        agent_logger.log_run_error(run_id, e, {"context": "discovery_execution"})
        raise
```

### With CrewAI Tools

The APIDiscoveryTool automatically logs all operations:

```python
@log_agent_run
def _run(self) -> str:
    # Automatic logging of start, completion, and errors
    pass
```

## 📊 Reporting

### Daily Reports

```python
daily_report = logger.generate_daily_report()
# Returns comprehensive daily summary
```

### Performance Summaries

```python
perf_summary = logger.get_performance_summary()
# Returns performance statistics for a date
```

### Error Summaries

```python
error_summary = logger.get_error_summary()
# Returns error statistics for a date
```

### Run History

```python
runs = logger.get_run_history(date="2025-08-22", limit=100)
# Returns run history for a specific date
```

## 🚨 Monitoring and Alerts

### Error Tracking

- **Error Frequency** monitoring
- **Error Type** categorization
- **Performance Degradation** detection
- **Coverage Drops** alerts

### Performance Monitoring

- **Response Time** thresholds
- **Resource Usage** limits
- **Coverage Targets** tracking
- **Throughput** monitoring

## 🔒 Security and Privacy

### Data Protection

- **No Sensitive Data** logging
- **Configurable Retention** policies
- **Access Control** for log files
- **Audit Trail** maintenance

### Compliance

- **GDPR Compliance** for data retention
- **Audit Requirements** fulfillment
- **Security Standards** adherence
- **Documentation** requirements

## 🚀 Future Enhancements

### Planned Features

- **Real-time Monitoring** dashboard
- **Alert System** for critical issues
- **Performance Optimization** recommendations
- **Machine Learning** insights
- **Integration** with monitoring tools
- **Advanced Analytics** and reporting

### Extensibility

- **Custom Log Formats** support
- **External Log Aggregators** integration
- **Custom Metrics** collection
- **Plugin Architecture** for log processors

## 📚 Examples

### Complete Logging Example

```python
from logger import agent_logger
from datetime import datetime

def run_discovery_operation():
    run_id = f"discovery_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    try:
        # Log start
        agent_logger.log_run_start(run_id, {
            "operation": "api_discovery",
            "target": "VAmPI",
            "base_url": "http://localhost:5000"
        })
        
        # Log discovery steps
        agent_logger.log_discovery_step(run_id, "initialization", {"status": "started"})
        agent_logger.log_discovery_step(run_id, "documentation_parsing", {"endpoints_found": 5})
        agent_logger.log_discovery_step(run_id, "active_scanning", {"endpoints_found": 7})
        
        # Log performance metrics
        agent_logger.log_performance_metric(run_id, "total_duration", 3.2, "seconds")
        agent_logger.log_performance_metric(run_id, "endpoints_discovered", 12, "count")
        
        # Simulate completion
        result = {"endpoints": 12, "coverage": 100.0}
        performance_metrics = {"total_duration": 3.2, "total_endpoints": 12}
        
        # Log completion
        agent_logger.log_run_complete(run_id, result, performance_metrics)
        
        return result
        
    except Exception as e:
        # Log error
        agent_logger.log_run_error(run_id, e, {
            "operation": "api_discovery",
            "step": "execution"
        })
        raise
```

### Log Analysis Example

```python
from logger import AgentRunLogger

# Initialize logger
logger = AgentRunLogger()

# Get today's performance summary
today_perf = logger.get_performance_summary()
print(f"Today's runs: {today_perf.get('total_runs', 0)}")
print(f"Average duration: {today_perf.get('average_duration', 0):.2f}s")

# Get run history
runs = logger.get_run_history(limit=10)
for run in runs:
    if run.get('type') == 'run_complete':
        print(f"Run {run['run_id']}: {run['summary']['total_endpoints']} endpoints")

# Generate daily report
report = logger.generate_daily_report()
print(f"Daily report: {report['run_count']} runs, {report['performance_summary']}")
```

## 📞 Support

For questions or issues with the logging system:

1. **Check Log Files** - Review the generated log files for errors
2. **Run Analysis Script** - Use `scripts/analyze_logs.py` for diagnostics
3. **Review Configuration** - Ensure proper setup and permissions
4. **Check Integration** - Verify logging calls in discovery engine

## 🎯 Best Practices

### Logging Guidelines

1. **Use Descriptive Run IDs** - Include date, time, and operation type
2. **Log All Major Steps** - Track progress through discovery process
3. **Include Context** - Provide relevant information for debugging
4. **Monitor Performance** - Track metrics for optimization
5. **Regular Cleanup** - Maintain log retention policies
6. **Error Handling** - Always log errors with context

### Performance Optimization

1. **Batch Logging** - Group related log entries when possible
2. **Async Logging** - Use async methods for non-blocking operations
3. **Selective Logging** - Log only essential information in production
4. **Regular Analysis** - Monitor trends and identify issues early

---

**The comprehensive logging system provides complete visibility into the VAmPI API Discovery Agent's operations, enabling detailed analysis, performance optimization, and reliable monitoring of all discovery activities.** 