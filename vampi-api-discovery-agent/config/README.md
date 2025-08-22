# API Discovery Configuration

This directory contains configuration files for the VAmPI API Discovery Agent, making it easy to customize discovery behavior without modifying code.

## Files

- `discovery_config.yaml` - Main configuration file for API discovery settings
- `README.md` - This documentation file

## Configuration Structure

### Common API Paths
```yaml
common_paths:
  - "/users/v1"
  - "/books/v1"
  - "/api/v1"
  # Add more paths to scan
```

### HTTP Methods
```yaml
http_methods:
  - "GET"
  - "POST"
  - "PUT"
  - "DELETE"
```

### Risk Assessment Patterns
```yaml
risk_patterns:
  user_management:
    - "/users"
    - "/auth"
  data_exposure:
    - "/users"
    - "/books"
  # Add more risk categories
```

### Pattern Templates
```yaml
pattern_templates:
  - "/users/v1/{user_id}"
  - "/books/v1/{book_title}"
  # Add more parameterized patterns
```

### Sample Values
```yaml
sample_values:
  user_id: "1"
  book_title: "test_book"
  # Add more sample values for testing
```

### Enhanced Discovery Patterns
```yaml
enhanced_patterns:
  - "/health"
  - "/status"
  - "/docs"
  # Add more potential endpoints
```

## Usage

### 1. Validate Configuration
```bash
python scripts/manage_config.py validate
```

### 2. View Configuration Info
```bash
python scripts/manage_config.py info
```

### 3. Export Configuration
```bash
python scripts/manage_config.py export my_config.yaml
```

### 4. Create Default Configuration
```bash
python scripts/manage_config.py create
```

## Customization

### Adding New API Endpoints
1. Edit `discovery_config.yaml`
2. Add new paths to `common_paths` or `enhanced_patterns`
3. Run validation: `python scripts/manage_config.py validate`

### Modifying Risk Patterns
1. Edit the `risk_patterns` section
2. Add new risk categories or modify existing ones
3. Ensure patterns match your API structure

### Changing HTTP Methods
1. Modify the `http_methods` list
2. Add or remove methods as needed
3. Consider rate limiting implications

## Benefits

✅ **Configurable**: Easy to modify without code changes  
✅ **Maintainable**: Centralized configuration management  
✅ **Extensible**: Add new patterns and endpoints easily  
✅ **Validatable**: Built-in configuration validation  
✅ **Portable**: Share configurations between environments  

## Example: Adding a New API

To add support for a new API (e.g., a payment service):

```yaml
# Add to common_paths
common_paths:
  - "/payments/v1"
  - "/payments/v1/transactions"

# Add to pattern_templates
pattern_templates:
  - "/payments/v1/transactions/{transaction_id}"

# Add to sample_values
sample_values:
  transaction_id: "txn_123"

# Add to risk_patterns
risk_patterns:
  financial_data:
    - "/payments"
    - "/transactions"
```

## Troubleshooting

### Configuration Not Loading
- Check file path: `config/discovery_config.yaml`
- Verify YAML syntax
- Run validation: `python scripts/manage_config.py validate`

### Missing Endpoints
- Ensure paths are added to `common_paths` or `enhanced_patterns`
- Check pattern templates for parameterized endpoints
- Verify sample values are appropriate

### Validation Errors
- Check required fields are present
- Ensure YAML syntax is correct
- Verify file encoding (UTF-8) 