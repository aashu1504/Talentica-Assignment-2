"""
Configuration loader for API discovery settings.

This module provides a centralized way to load and manage discovery configuration
from YAML files, making the discovery engine more flexible and configurable.
"""

import os
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass


@dataclass
class DiscoveryConfig:
    """Configuration data class for discovery settings."""
    
    # Common API paths to scan
    common_paths: List[str]
    
    # HTTP methods to test
    http_methods: List[str]
    
    # Risk assessment patterns
    risk_patterns: Dict[str, List[str]]
    
    # Pattern-based discovery templates
    pattern_templates: List[str]
    
    # Sample values for parameter testing
    sample_values: Dict[str, str]
    
    # Enhanced discovery patterns
    enhanced_patterns: List[str]


class ConfigLoader:
    """Loads and manages discovery configuration from YAML files."""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the configuration loader.
        
        Args:
            config_path: Path to the configuration file. If None, uses default.
        """
        if config_path is None:
            # Default to config/discovery_config.yaml relative to project root
            project_root = Path(__file__).parent.parent
            config_path = project_root / "config" / "discovery_config.yaml"
        
        self.config_path = Path(config_path)
        self.config: Optional[DiscoveryConfig] = None
    
    def load_config(self) -> DiscoveryConfig:
        """
        Load configuration from the YAML file.
        
        Returns:
            DiscoveryConfig object with loaded settings
            
        Raises:
            FileNotFoundError: If configuration file doesn't exist
            yaml.YAMLError: If configuration file is invalid
        """
        if not self.config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {self.config_path}")
        
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config_data = yaml.safe_load(f)
            
            # Validate and create config object
            self.config = DiscoveryConfig(
                common_paths=config_data.get('common_paths', []),
                http_methods=config_data.get('http_methods', []),
                risk_patterns=config_data.get('risk_patterns', {}),
                pattern_templates=config_data.get('pattern_templates', []),
                sample_values=config_data.get('sample_values', {}),
                enhanced_patterns=config_data.get('enhanced_patterns', [])
            )
            
            return self.config
            
        except yaml.YAMLError as e:
            raise yaml.YAMLError(f"Invalid YAML in configuration file: {e}")
        except Exception as e:
            raise Exception(f"Error loading configuration: {e}")
    
    def get_config(self) -> DiscoveryConfig:
        """
        Get the loaded configuration, loading it if necessary.
        
        Returns:
            DiscoveryConfig object
        """
        if self.config is None:
            return self.load_config()
        return self.config
    
    def reload_config(self) -> DiscoveryConfig:
        """
        Reload configuration from file.
        
        Returns:
            Updated DiscoveryConfig object
        """
        self.config = None
        return self.load_config()
    
    def validate_config(self) -> List[str]:
        """
        Validate the loaded configuration and return any issues.
        
        Returns:
            List of validation error messages (empty if valid)
        """
        if self.config is None:
            return ["Configuration not loaded"]
        
        errors = []
        
        # Check required fields
        if not self.config.common_paths:
            errors.append("No common paths configured")
        
        if not self.config.http_methods:
            errors.append("No HTTP methods configured")
        
        if not self.config.risk_patterns:
            errors.append("No risk patterns configured")
        
        if not self.config.pattern_templates:
            errors.append("No pattern templates configured")
        
        if not self.config.sample_values:
            errors.append("No sample values configured")
        
        if not self.config.enhanced_patterns:
            errors.append("No enhanced patterns configured")
        
        return errors
    
    def get_api_type(self) -> str:
        """
        Determine the API type based on configuration patterns.
        
        Returns:
            String indicating API type (e.g., "REST", "GraphQL", "SOAP")
        """
        if self.config is None:
            return "Unknown"
        
        # Analyze patterns to determine API type
        patterns = ' '.join(self.config.common_paths + self.config.pattern_templates)
        patterns_lower = patterns.lower()
        
        if any(pattern in patterns_lower for pattern in ['/graphql', 'graphql']):
            return "GraphQL"
        elif any(pattern in patterns_lower for pattern in ['/soap', 'soap']):
            return "SOAP"
        elif any(pattern in patterns_lower for pattern in ['/v1', '/v2', '/api']):
            return "REST"
        else:
            return "REST"  # Default assumption
    
    def get_supported_versions(self) -> List[str]:
        """
        Extract supported API versions from configuration.
        
        Returns:
            List of version strings (e.g., ["v1", "v2"])
        """
        if self.config is None:
            return []
        
        versions = set()
        all_patterns = self.config.common_paths + self.config.pattern_templates
        
        for pattern in all_patterns:
            if '/v' in pattern:
                import re
                version_match = re.search(r'/v(\d+)', pattern)
                if version_match:
                    versions.add(f"v{version_match.group(1)}")
        
        return sorted(list(versions))
    
    def export_config(self, output_path: str) -> None:
        """
        Export current configuration to a new file.
        
        Args:
            output_path: Path where to save the exported configuration
        """
        if self.config is None:
            raise ValueError("No configuration loaded to export")
        
        export_data = {
            'common_paths': self.config.common_paths,
            'http_methods': self.config.http_methods,
            'risk_patterns': self.config.risk_patterns,
            'pattern_templates': self.config.pattern_templates,
            'sample_values': self.config.sample_values,
            'enhanced_patterns': self.config.enhanced_patterns
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            yaml.dump(export_data, f, default_flow_style=False, indent=2)


# Default configuration for fallback
DEFAULT_CONFIG = DiscoveryConfig(
    common_paths=[
        "/",
        "/health",
        "/status",
        "/docs",
        "/api",
        "/v1"
    ],
    http_methods=["GET", "POST", "PUT", "DELETE"],
    risk_patterns={
        "general": ["/admin", "/config", "/settings"],
        "data": ["/users", "/data", "/files"]
    },
    pattern_templates=[
        "/{resource}",
        "/{resource}/{id}",
        "/api/{version}/{resource}"
    ],
    sample_values={
        "resource": "test",
        "id": "1",
        "version": "v1"
    },
    enhanced_patterns=[
        "/health", "/status", "/info", "/docs", "/swagger"
    ]
) 