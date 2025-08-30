# Security Testing Module for VAmPI API Discovery Agent

## Overview

The Security Testing Module provides comprehensive OWASP API security testing capabilities that integrate seamlessly with the existing VAmPI API Discovery Agent framework. This module implements a complete end-to-end security assessment platform that combines API discovery with in-depth vulnerability testing.

## Features

### 🔒 OWASP API Top 10 Security Testing
- **Injection Testing**: SQL, XSS, and NoSQL injection attack vectors
- **Authentication Analysis**: JWT token security and authentication bypass detection
- **Authorization Testing**: Object-level and function-level access control validation
- **Security Misconfiguration**: Missing security headers and information disclosure detection

### 📊 Comprehensive Vulnerability Assessment
- **CVSS v3.1 Scoring**: Accurate risk assessment using industry-standard metrics
- **Risk Categorization**: Critical, High, Medium, Low, and Info severity levels
- **Detailed Reporting**: Individual endpoint security reports with actionable recommendations
- **Proof of Concept**: Working exploit demonstrations for identified vulnerabilities

### 🚀 CrewAI Integration
- **Intelligent Agent**: AI-powered security testing specialist using CrewAI framework
- **Automated Workflow**: Sequential API discovery → Security testing pipeline
- **Data Exchange**: Seamless consumption of discovered endpoints for security analysis
- **Error Handling**: Graceful handling of discovery failures and incomplete data

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Security Testing Module                   │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐    ┌─────────────────┐               │
│  │   Models        │    │     Engine      │               │
│  │                 │    │                 │               │
│  │ • SecurityTest  │    │ • Injection     │               │
│  │ • CVSSMetrics   │    │ • Auth Testing  │               │
│  │ • Reports       │    │ • Auth Testing  │               │
│  │ • Enums         │    │ • Config Tests  │               │
│  └─────────────────┘    └─────────────────┘               │
│           │                       │                        │
│           └───────────────────────┼────────────────────────┘
│                                   │                        │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │                    CrewAI Agent                        │ │
│  │                                                         │ │
│  │ • Security Testing Specialist                          │ │
│  │ • OWASP Expertise                                      │ │
│  │ • Automated Workflow                                   │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                   │                        │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │                 Integration Layer                      │ │
│  │                                                         │ │
│  │ • API Discovery Integration                            │ │
│  │ • Endpoint Data Processing                             │ │
│  │ • Report Generation                                    │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Components

### 1. Security Testing Models (`models.py`)
Defines the data structures for security testing results, CVSS scoring, and vulnerability assessment reports.

**Key Classes:**
- `SecurityTest`: Individual security test result
- `EndpointSecurityReport`: Security report for a single endpoint
- `SecurityAssessmentReport`: Complete security assessment report
- `CVSSMetrics`: CVSS v3.1 base score metrics
- `OWASPCategory`: OWASP API Top 10 security categories

### 2. Security Testing Engine (`engine.py`)
Core engine that implements the actual security testing logic and vulnerability detection.

**Testing Capabilities:**
- SQL Injection detection using malicious payloads
- XSS vulnerability testing with script injection
- Authentication bypass testing
- JWT token validation testing
- IDOR vulnerability detection
- Security header analysis
- Information disclosure detection

### 3. Security Testing Agent (`agent.py`)
CrewAI agent that orchestrates the security testing workflow and generates comprehensive reports.

**Agent Features:**
- OWASP API security expertise
- Automated test execution
- Comprehensive reporting
- CVSS scoring and risk assessment
- Actionable recommendations

### 4. Integrated Agent (`integrated_agent.py`)
Combines API discovery with security testing to create a complete end-to-end security assessment platform.

**Workflow:**
1. **Phase 1**: API Discovery using existing framework
2. **Phase 2**: Comprehensive security testing
3. **Phase 3**: Integrated reporting and recommendations

## Usage

### Basic Security Testing

```python
from security_testing import SecurityTestingEngine

# Initialize security testing engine
engine = SecurityTestingEngine("http://localhost:5000")

# Test endpoint security
endpoint_data = {
    'path': '/users',
    'methods': ['GET', 'POST'],
    'parameters': {
        'query_params': ['id', 'name'],
        'body_params': ['username', 'email']
    }
}

# Run security tests
endpoint_report = await engine.test_endpoint_security(endpoint_data)
print(f"Vulnerabilities found: {endpoint_report.vulnerabilities_found}")
```

### Using the Security Testing Agent

```python
from security_testing import SecurityTestingAgent

# Initialize agent
agent = SecurityTestingAgent("http://localhost:5000")

# Run security assessment
result = agent.run_security_assessment()
print(f"Assessment result: {result}")
```

### Complete Integrated Assessment

```python
from integrated_agent import IntegratedVAmPIAgent

# Initialize integrated agent
agent = IntegratedVAmPIAgent("http://localhost:5000")

# Run complete assessment (discovery + security testing)
result = agent.run_integrated_assessment()
print(f"Integrated assessment result: {result}")
```

## Demo Script

Run the comprehensive demo to see all capabilities in action:

```bash
python scripts/demo_integrated_security.py
```

The demo script will:
1. Check VAmPI API status
2. Demonstrate individual components
3. Run complete integrated assessment
4. Generate comprehensive reports

## Generated Reports

### 1. API Discovery Report (`discovered_endpoints.json`)
- Complete endpoint inventory
- Parameter analysis
- Authentication requirements
- Risk level assessment

### 2. Security Assessment Report (`security_assessment_report.json`)
- Detailed vulnerability findings
- CVSS scores and risk levels
- OWASP categorization
- Technical recommendations

### 3. Integrated Report (`integrated_security_assessment.json`)
- Combined discovery and security findings
- Executive summary
- Risk analysis
- Remediation priorities

## Security Testing Categories

### 1. Injection Vulnerabilities
- **SQL Injection**: Database query manipulation
- **XSS**: Cross-site scripting attacks
- **NoSQL Injection**: Document database attacks
- **Command Injection**: System command execution

### 2. Authentication Vulnerabilities
- **Missing Authentication**: Endpoints without auth checks
- **Weak Authentication**: Insufficient auth mechanisms
- **JWT Vulnerabilities**: Token manipulation and validation
- **Session Fixation**: Session management issues

### 3. Authorization Vulnerabilities
- **IDOR**: Insecure Direct Object Reference
- **Horizontal Privilege Escalation**: Accessing other users' data
- **Vertical Privilege Escalation**: Gaining admin access
- **Function Level Access Control**: Missing permission checks

### 4. Security Misconfigurations
- **Missing Security Headers**: CSP, X-Frame-Options, HSTS
- **Information Disclosure**: Sensitive data exposure
- **Debug Information**: Development data in production
- **Error Handling**: Detailed error messages

## CVSS Scoring

The module implements CVSS v3.1 base score calculation based on:

- **Attack Vector**: Network, Adjacent, Local, Physical
- **Attack Complexity**: Low, High
- **Privileges Required**: None, Low, High
- **User Interaction**: None, Required
- **Scope**: Unchanged, Changed
- **Impact**: Confidentiality, Integrity, Availability

## Configuration

### Test Suite Configuration

```python
from security_testing.models import SecurityTestSuite, OWASPCategory

test_suite = SecurityTestSuite(
    suite_name="Custom OWASP Test Suite",
    suite_version="1.0.0",
    owasp_categories=[
        OWASPCategory.INJECTION,
        OWASPCategory.BROKEN_USER_AUTHENTICATION,
        OWASPCategory.SECURITY_MISCONFIGURATION
    ],
    injection_payloads=[
        "' OR '1'='1",
        "<script>alert('XSS')</script>",
        "admin'--"
    ]
)
```

### Engine Configuration

```python
from security_testing import SecurityTestingEngine

engine = SecurityTestingEngine(
    base_url="http://localhost:5000",
    timeout=30
)
```

## Error Handling

The module includes comprehensive error handling:

- **Discovery Failures**: Graceful fallback to existing data
- **Testing Errors**: Individual endpoint error reporting
- **Connection Issues**: Timeout and retry mechanisms
- **Data Validation**: Input sanitization and validation

## Integration Points

### Existing Framework Integration
- **Models**: Extends existing discovery models
- **Discovery Engine**: Consumes discovered endpoints
- **Reporting**: Integrates with existing report structure
- **Configuration**: Uses existing configuration patterns

### CrewAI Integration
- **Agent Definition**: Security testing specialist role
- **Task Orchestration**: Automated workflow management
- **Tool Integration**: Security testing tools as CrewAI tools
- **Result Processing**: Structured output generation

## Performance Considerations

- **Concurrent Testing**: Configurable concurrency limits
- **Timeout Management**: Configurable request timeouts
- **Resource Usage**: Efficient memory and CPU utilization
- **Scalability**: Support for large endpoint inventories

## Security Considerations

- **Safe Testing**: Non-destructive vulnerability testing
- **Payload Sanitization**: Safe handling of malicious inputs
- **Error Handling**: Secure error message generation
- **Logging**: Secure logging practices

## Future Enhancements

- **Additional OWASP Categories**: Rate limiting, cryptography testing
- **Custom Payloads**: User-defined test payloads
- **Advanced Detection**: Machine learning-based vulnerability detection
- **Integration APIs**: REST API for external tool integration
- **Dashboard**: Web-based security assessment dashboard

## Troubleshooting

### Common Issues

1. **VAmPI Not Running**
   - Ensure VAmPI is started: `cd vampi-local && npm start`
   - Check port 5000 availability

2. **Import Errors**
   - Verify Python path includes `src` directory
   - Check all dependencies are installed

3. **Testing Failures**
   - Review logs for specific error messages
   - Check network connectivity to target API
   - Verify endpoint accessibility

### Debug Mode

Enable detailed logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Contributing

To contribute to the security testing module:

1. Follow existing code patterns and style
2. Add comprehensive tests for new features
3. Update documentation for new capabilities
4. Ensure backward compatibility
5. Follow security best practices

## License

This module is part of the VAmPI API Discovery Agent project and follows the same licensing terms.

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review the demo script examples
3. Examine the generated reports
4. Check the logs for detailed error information 