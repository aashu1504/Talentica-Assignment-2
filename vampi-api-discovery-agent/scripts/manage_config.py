#!/usr/bin/env python3
"""
Configuration Management Script for VAmPI API Discovery

This script provides utilities to manage, validate, and export discovery configurations.
"""

import sys
import os
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from config_loader import ConfigLoader, DEFAULT_CONFIG


def validate_config():
    """Validate the current configuration file."""
    print("🔍 Validating discovery configuration...")
    
    try:
        config_loader = ConfigLoader()
        config = config_loader.load_config()
        
        # Validate configuration
        errors = config_loader.validate_config()
        
        if errors:
            print("❌ Configuration validation failed:")
            for error in errors:
                print(f"   - {error}")
            return False
        else:
            print("✅ Configuration validation passed!")
            
            # Display configuration summary
            print(f"\n📊 Configuration Summary:")
            print(f"   - Common paths: {len(config.common_paths)}")
            print(f"   - HTTP methods: {len(config.http_methods)}")
            print(f"   - Risk patterns: {len(config.risk_patterns)}")
            print(f"   - Pattern templates: {len(config.pattern_templates)}")
            print(f"   - Sample values: {len(config.sample_values)}")
            print(f"   - Enhanced patterns: {len(config.enhanced_patterns)}")
            
            # API type detection
            api_type = config_loader.get_api_type()
            versions = config_loader.get_supported_versions()
            print(f"   - API Type: {api_type}")
            print(f"   - Supported versions: {versions}")
            
            return True
            
    except Exception as e:
        print(f"❌ Error validating configuration: {e}")
        return False


def export_config(output_path: str):
    """Export current configuration to a new file."""
    print(f"📤 Exporting configuration to: {output_path}")
    
    try:
        config_loader = ConfigLoader()
        config_loader.load_config()
        config_loader.export_config(output_path)
        print("✅ Configuration exported successfully!")
        
    except Exception as e:
        print(f"❌ Error exporting configuration: {e}")


def create_default_config():
    """Create a default configuration file if none exists."""
    config_path = Path(__file__).parent.parent / "config" / "discovery_config.yaml"
    
    if config_path.exists():
        print(f"⚠️  Configuration file already exists: {config_path}")
        return
    
    print(f"📝 Creating default configuration file: {config_path}")
    
    # Ensure config directory exists
    config_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Export default configuration
    config_loader = ConfigLoader()
    config_loader.config = DEFAULT_CONFIG
    config_loader.export_config(str(config_path))
    
    print("✅ Default configuration file created!")


def show_config_info():
    """Show detailed information about the current configuration."""
    print("📋 Configuration Information:")
    
    try:
        config_loader = ConfigLoader()
        config = config_loader.get_config()
        
        print(f"\n📍 Configuration file: {config_loader.config_path}")
        print(f"📊 API Type: {config_loader.get_api_type()}")
        print(f"🔄 Supported versions: {config_loader.get_supported_versions()}")
        
        print(f"\n🛣️  Common paths ({len(config.common_paths)}):")
        for path in config.common_paths[:10]:  # Show first 10
            print(f"   - {path}")
        if len(config.common_paths) > 10:
            print(f"   ... and {len(config.common_paths) - 10} more")
        
        print(f"\n🔧 HTTP methods ({len(config.http_methods)}):")
        for method in config.http_methods:
            print(f"   - {method}")
        
        print(f"\n⚠️  Risk patterns ({len(config.risk_patterns)}):")
        for category, patterns in config.risk_patterns.items():
            print(f"   - {category}: {len(patterns)} patterns")
        
        print(f"\n📝 Pattern templates ({len(config.pattern_templates)}):")
        for template in config.pattern_templates[:5]:  # Show first 5
            print(f"   - {template}")
        if len(config.pattern_templates) > 5:
            print(f"   ... and {len(config.pattern_templates) - 5} more")
        
        print(f"\n🔍 Enhanced patterns ({len(config.enhanced_patterns)}):")
        for pattern in config.enhanced_patterns[:5]:  # Show first 5
            print(f"   - {pattern}")
        if len(config.enhanced_patterns) > 5:
            print(f"   ... and {len(config.enhanced_patterns) - 5} more")
        
    except Exception as e:
        print(f"❌ Error showing configuration info: {e}")


def main():
    """Main function for configuration management."""
    print("🚀 VAmPI API Discovery Configuration Manager")
    print("=" * 50)
    
    if len(sys.argv) < 2:
        print("Usage: python manage_config.py <command> [options]")
        print("\nCommands:")
        print("  validate     - Validate current configuration")
        print("  export <file> - Export configuration to file")
        print("  create       - Create default configuration file")
        print("  info         - Show configuration information")
        print("  help         - Show this help message")
        return
    
    command = sys.argv[1].lower()
    
    if command == "validate":
        validate_config()
    elif command == "export":
        if len(sys.argv) < 3:
            print("❌ Please specify output file path")
            return
        export_config(sys.argv[2])
    elif command == "create":
        create_default_config()
    elif command == "info":
        show_config_info()
    elif command == "help":
        print("Usage: python manage_config.py <command> [options]")
        print("\nCommands:")
        print("  validate     - Validate current configuration")
        print("  export <file> - Export configuration to file")
        print("  create       - Create default configuration file")
        print("  info         - Show configuration information")
        print("  help         - Show this help message")
    else:
        print(f"❌ Unknown command: {command}")
        print("Use 'help' command to see available options")


if __name__ == "__main__":
    main() 