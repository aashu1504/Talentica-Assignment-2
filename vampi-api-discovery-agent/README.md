# VAmPI API Discovery Agent

This project implements an API Discovery Agent using CrewAI to discover, catalog, and analyze VAmPI endpoints with security context.

DO NOT EDIT THIS HEADER

## Overview

The VAmPI API Discovery Agent is a sophisticated tool designed to automatically discover and analyze API endpoints from the VAmPI (Vulnerable API) application. It provides comprehensive endpoint mapping, security risk assessment, and detailed analysis reports to support security testing and API documentation efforts.

## Features

- **Automated Endpoint Discovery**: Systematic scanning of VAmPI API endpoints
- **Security Risk Assessment**: Automated risk categorization and vulnerability identification
- **Authentication Analysis**: Detection and analysis of authentication mechanisms
- **Comprehensive Reporting**: Detailed JSON and markdown reports
- **Configurable Scanning**: Customizable timeouts, rate limiting, and discovery parameters
- **Async Processing**: High-performance asynchronous HTTP scanning

## Project Structure

```
vampi-api-discovery-agent/
├── PROJECT_MANIFEST.md          # Project manifest and status
├── requirements.txt             # Python dependencies
├── .env                        # Environment configuration template
├── README.md                   # This documentation file
├── src/                        # Source code directory
│   ├── main.py                # Main execution script
│   ├── agent.py               # CrewAI agent implementation
│   ├── discovery.py           # VAmPI endpoint discovery engine
│   ├── models.py              # Data models and schemas
│   └── utils.py               # Utility functions
├── tests/                      # Test suite
│   └── test_discovery.py      # Discovery engine tests
├── docs/                       # Documentation
│   └── discovery_report.md    # Discovery report template
└── venv/                      # Python virtual environment
```

## Prerequisites

- Python 3.10 or higher
- Node.js (for running VAmPI)
- MongoDB (for VAmPI backend)

## Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd vampi-api-discovery-agent
   ```

2. **Create virtual environment**
   ```bash
   python3.10 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env with your VAmPI configuration
   ```

## Configuration

The agent can be configured through environment variables or command-line arguments:

### Environment Variables (.env)
```bash
VAMPI_URL=http://localhost:5000
VAMPI_TIMEOUT=30
VAMPI_RATE_LIMIT_DELAY=1.0
VAMPI_MAX_RETRIES=3
VAMPI_USER_AGENT=VAmPI-Discovery-Agent/1.0
```

### Command Line Options
```bash
python src/main.py --help
python src/main.py --url http://localhost:3000 --timeout 60
python src/main.py --discovery-only --verbose
```

## Usage

### Basic Discovery
```bash
# Run with default configuration
python src/main.py

# Run with custom VAmPI URL
python src/main.py --url http://localhost:3000

# Run discovery only (skip CrewAI analysis)
python src/main.py --discovery-only
```

### Advanced Options
```bash
# Custom timeout and rate limiting
python src/main.py --timeout 60 --rate-limit-delay 2.0

# Verbose output
python src/main.py --verbose

# Custom output directory
python src/main.py --output-dir ./results
```

## VAmPI Setup

Before running the discovery agent, ensure VAmPI is running. We provide automated setup scripts for convenience:

### Automated Setup (Recommended)

**On macOS/Linux:**
```bash
./setup-vampi.sh
```

**On Windows:**
```cmd
setup-vampi.bat
```

### Manual Setup

1. **Clone VAmPI repository**
   ```bash
   git clone https://github.com/erev0s/VAmPI.git vampi-local
   cd vampi-local
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Create environment configuration**
   ```bash
   cat > .env <<'ENV'
   PORT=5000
   MONGODB_URI=mongodb://localhost:27017/vampi
   JWT_SECRET=supersecret
   ENV
   ```

4. **Start MongoDB**
   ```bash
   mongod --dbpath /path/to/data/db
   ```

5. **Start VAmPI**
   ```bash
   npm start
   ```

### Validation

After setting up VAmPI, validate that it's running correctly:

```bash
# Basic validation
python src/validate_vampi.py

# Custom URL validation
python src/validate_vampi.py --url http://localhost:5000

# Verbose validation
python src/validate_vampi.py --verbose

# Custom timeout
python src/validate_vampi.py --timeout 15
```

The validation script checks:
- Health endpoint accessibility
- Root endpoint accessibility  
- Common API endpoints
- Overall service status

## Output

The agent generates comprehensive output including:

- **JSON Catalog**: Complete endpoint discovery results
- **Markdown Report**: Human-readable discovery report
- **Security Analysis**: Risk assessment and vulnerability summary
- **API Structure**: Endpoint organization and relationships

### Sample Output Structure
```json
{
  "discovery_summary": {
    "total_endpoints": 15,
    "discovery_date": "2024-08-10T14:20:00Z",
    "base_url": "http://localhost:5000"
  },
  "endpoints": [
    {
      "path": "/users/v1/register",
      "method": "POST",
      "risk_level": "HIGH",
      "authentication_required": false,
      "description": "User registration endpoint"
    }
  ],
  "security_insights": {
    "high_risk_endpoints": 3,
    "authentication_mechanisms": ["JWT"],
    "recommendations": [...]
  }
}
```

## Testing

Run the test suite to verify functionality:

```bash
# Run all tests
python -m pytest tests/

# Run specific test file
python -m pytest tests/test_discovery.py

# Run with coverage
python -m pytest --cov=src tests/
```

## Development

### Adding New Discovery Methods
1. Extend the `VAmPIDiscoveryEngine` class
2. Implement new discovery logic in `discover_endpoints()`
3. Add corresponding tests
4. Update documentation

### Customizing Risk Assessment
1. Modify risk patterns in `_assess_risk_level()`
2. Add new risk categories to `RiskLevel` enum
3. Update risk assessment logic

## Troubleshooting

### Common Issues

1. **Connection Refused**
   - Ensure VAmPI is running
   - Check port configuration
   - Verify firewall settings

2. **Authentication Errors**
   - Check VAmPI authentication setup
   - Verify token validity
   - Review authentication headers

3. **Rate Limiting**
   - Increase `rate_limit_delay` in configuration
   - Check VAmPI rate limiting settings
   - Monitor request frequency

### Debug Mode
Enable verbose logging for troubleshooting:
```bash
python src/main.py --verbose --log-level DEBUG
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and questions:
- Create an issue in the repository
- Check the troubleshooting section
- Review the documentation

## Roadmap

- [ ] Integration with OWASP ZAP
- [ ] Advanced vulnerability scanning
- [ ] Custom rule engine for risk assessment
- [ ] API documentation generation
- [ ] CI/CD pipeline integration

---

*VAmPI API Discovery Agent v1.0*
*Built with Python, CrewAI, and security best practices* 