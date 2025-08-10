# VAmPI API Discovery Agent - Project Manifest

## Project Overview
This project implements an API Discovery Agent using CrewAI to discover, catalog, and analyze VAmPI endpoints with security context.

## File Manifest

### Created Files
- [x] PROJECT_MANIFEST.md - This manifest file
- [x] requirements.txt - Python dependencies
- [x] .env - Environment configuration
- [x] src/main.py - Main execution script
- [x] src/agent.py - CrewAI agent implementation
- [x] src/discovery.py - VAmPI endpoint discovery engine
- [x] src/models.py - Data models and schemas
- [x] src/utils.py - Utility functions
- [x] tests/__init__.py - Test package initialization
- [x] tests/test_discovery.py - Discovery engine tests
- [x] tests/test_agent.py - Agent tests
- [x] docs/README.md - Project documentation
- [x] docs/API_SCHEMA.md - API output schema documentation

### Backed Up Files
*No files were backed up during initial creation*

### Updated Files
*No files were updated during initial creation*

## Project Structure
```
vampi-api-discovery-agent/
├── PROJECT_MANIFEST.md
├── requirements.txt
├── .env
├── src/
│   ├── main.py
│   ├── agent.py
│   ├── discovery.py
│   ├── models.py
│   └── utils.py
├── tests/
│   ├── __init__.py
│   ├── test_discovery.py
│   └── test_agent.py
└── docs/
    ├── README.md
    └── API_SCHEMA.md
```

## Setup Commands
```bash
# Create virtual environment (Python 3.10+)
python3.10 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the agent
python src/main.py
```

## VAmPI Setup Commands
```bash
# Start VAmPI using Node.js + MongoDB (non-Docker)
# Follow the non-Docker setup instructions from VAmPI documentation
# The agent will connect to http://localhost:5000 by default
```

## Discovery Output
The agent will generate a comprehensive JSON catalog of VAmPI endpoints including:
- Endpoint discovery summary
- Detailed endpoint metadata
- Authentication mechanisms
- API structure analysis
- Risk assessment and categorization

## Next Steps
1. Set up VAmPI locally (non-Docker)
2. Configure environment variables in .env
3. Run the discovery agent
4. Review generated API catalog
5. Prepare for Assignment 2B (Security Testing Agent) 