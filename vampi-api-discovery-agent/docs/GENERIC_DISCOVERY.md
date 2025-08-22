# Generic API Discovery Engine

## Overview

The Generic API Discovery Engine is a framework-agnostic implementation that can discover and analyze endpoints from any REST API, regardless of the underlying technology stack. This enhancement makes the discovery agent truly universal and reusable across different projects.

## Key Features

### 🚀 **Framework-Agnostic Discovery**
- **Universal Patterns**: Common API patterns that work across different frameworks
- **Framework Detection**: Automatic detection of Flask, Django, FastAPI, Express, Spring, ASP.NET
- **Technology Stack Identification**: Server technology and framework indicators

### 🔍 **Universal Endpoint Discovery**
- **Common Resources**: `/users`, `/products`, `/orders`, `/files`, etc.
- **Authentication**: `/auth`, `/login`, `/register`, `/oauth`, etc.
- **Administration**: `/admin`, `/settings`, `/config`, `/system`, etc.
- **Documentation**: `/docs`, `/swagger`, `/openapi`, `/redoc`, etc.
- **System**: `/health`, `/status`, `/metrics`, `/logs`, etc.
- **Data Operations**: `/search`, `/query`, `/export`, `/import`, etc.

### 🛡️ **Generic Security Assessment**
- **Universal Risk Patterns**: Framework-independent risk assessment
- **Authentication Detection**: Generic auth requirement detection
- **Parameter Analysis**: Universal parameter extraction and validation

## Architecture

### **Discovery Phases**

1. **Universal Pattern Discovery**: Test common API patterns across frameworks
2. **Framework-Specific Discovery**: Use detected framework indicators
3. **Intelligent Path Generation**: Generate variations based on discovered patterns
4. **Response Analysis**: Enhance endpoints with response details
5. **Framework Detection**: Identify technology stack and framework

### **Framework Detection**

```python
framework_indicators = {
    "flask": {
        "headers": ["X-Powered-By: Flask"],
        "patterns": ["/static/", "/templates/"],
        "responses": ["werkzeug", "flask"]
    },
    "django": {
        "headers": ["X-Powered-By: Django", "X-Frame-Options"],
        "patterns": ["/admin/", "/static/", "/media/"],
        "responses": ["django", "csrf", "sessionid"]
    },
    "fastapi": {
        "headers": ["X-Powered-By: FastAPI"],
        "patterns": ["/docs", "/redoc", "/openapi.json"],
        "responses": ["fastapi", "pydantic"]
    }
    # ... more frameworks
}
```

## Usage

### **Basic Usage**

```python
from generic_discovery import GenericAPIDiscoveryEngine
from models import DiscoveryConfig

# Configure for any API
config = DiscoveryConfig(
    base_url="https://api.example.com",
    timeout=30.0,
    user_agent="Generic-Discovery-Agent/1.0"
)

# Run discovery
async with GenericAPIDiscoveryEngine(config) as engine:
    result = await engine.discover_endpoints()
    
    print(f"Framework: {result.framework_info['detected_framework']}")
    print(f"Endpoints: {len(result.endpoints)}")
    print(f"Coverage: {result.discovery_summary.discovery_coverage}%")
```

### **Configuration**

```yaml
# config/discovery_config.yaml
universal_patterns:
  common_resources:
    - "/users"
    - "/products"
    - "/orders"
  
  authentication:
    - "/auth"
    - "/login"
    - "/register"
  
  administration:
    - "/admin"
    - "/settings"
    - "/config"
```

## Benefits

### **✅ Universal Compatibility**
- Works with any REST API (Flask, Django, FastAPI, Express, Spring, etc.)
- No framework-specific code dependencies
- Configurable patterns for different API types

### **✅ Enhanced Discovery**
- Discovers endpoints beyond framework-specific patterns
- Intelligent path generation based on discovered patterns
- Framework-aware endpoint categorization

### **✅ Better Security Assessment**
- Universal risk patterns applicable to any API
- Framework-independent authentication detection
- Consistent security categorization across platforms

### **✅ Maintainability**
- Single codebase for multiple API types
- Easy to extend with new frameworks
- Centralized configuration management

## Testing

### **Run Generic Discovery Test**

```bash
# Test with VAmPI (or any other API)
python test_generic_discovery.py
```

### **Expected Output**

```
🚀 Testing Generic API Discovery Engine
==================================================
✅ Generic discovery engine initialized

🔍 Starting universal API discovery...

📊 Discovery Results:
   - Total Endpoints: 42
   - Framework Detected: flask
   - Confidence: 0.85
   - Discovery Coverage: 92.45%

🏗️  Framework Information:
   - Detected Framework: flask
   - Confidence Score: 0.85
   - Technology Stack: flask, REST API, HTTP/1.1
   - Detection Indicators:
     • pattern: /static/
     • response: werkzeug

🔐 Authentication Analysis:
   - Authenticated Endpoints: 28
   - Public Endpoints: 14
   - Authentication Types: JWT, NONE

⚠️  Risk Assessment:
   - High Risk: 12
   - Medium Risk: 18
   - Low Risk: 12
```

## Migration from VAmPI-Specific

### **Before (VAmPI-Specific)**
```python
# Hardcoded VAmPI patterns
self.common_paths = [
    "/users/v1",
    "/books/v1",
    "/users/v1/{user_id}"
]
```

### **After (Generic)**
```python
# Universal patterns + framework detection
self.universal_patterns = {
    "common_resources": ["/users", "/books", "/products"],
    "authentication": ["/auth", "/login", "/register"],
    "administration": ["/admin", "/settings", "/config"]
}

# Framework-specific patterns added automatically
framework_endpoints = await self._framework_specific_discovery()
```

## Extending

### **Add New Framework**

```python
def _initialize_framework_indicators(self):
    return {
        # ... existing frameworks
        "new_framework": {
            "headers": ["X-Powered-By: NewFramework"],
            "patterns": ["/new_pattern/", "/custom/"],
            "responses": ["newframework", "custom"]
        }
    }
```

### **Add New Universal Patterns**

```yaml
# config/discovery_config.yaml
universal_patterns:
  new_category:
    - "/new_endpoint"
    - "/another_endpoint"
```

## Performance

### **Discovery Speed**
- **Phase 1**: Universal patterns (~30% of time)
- **Phase 2**: Framework-specific (~20% of time)
- **Phase 3**: Intelligent generation (~25% of time)
- **Phase 4**: Response enhancement (~15% of time)
- **Phase 5**: Framework detection (~10% of time)

### **Optimization Tips**
- Use appropriate timeouts for different API types
- Configure concurrent request limits
- Cache framework detection results
- Skip known non-existent patterns

## Troubleshooting

### **Common Issues**

1. **Framework Not Detected**
   - Check if API returns framework indicators in headers
   - Verify response content contains framework signatures
   - Adjust confidence thresholds if needed

2. **Low Discovery Coverage**
   - Review universal patterns configuration
   - Check if API follows REST conventions
   - Verify network connectivity and timeouts

3. **Authentication Detection Issues**
   - Check response status codes (401, 403)
   - Verify authentication headers
   - Review path-based authentication patterns

## Future Enhancements

### **Planned Features**
- **GraphQL Support**: Native GraphQL endpoint discovery
- **SOAP Support**: SOAP service detection and analysis
- **API Versioning**: Automatic version detection and handling
- **Rate Limiting**: Adaptive discovery based on API limits
- **Authentication Testing**: Active authentication mechanism testing

### **Integration Opportunities**
- **Security Testing**: Framework-aware security testing
- **Documentation Generation**: Framework-specific documentation
- **Performance Testing**: Framework-optimized performance tests
- **Compliance Checking**: Framework-specific compliance validation 