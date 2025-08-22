#!/usr/bin/env python3
"""
Risk Assessment System Demonstration

This script demonstrates the new pluggable risk assessment architecture
with runtime loading, custom plugins, and dynamic configuration.
"""

import sys
import os
import yaml
from pathlib import Path

# Add src directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from risk_assessment.factory import RiskAssessorFactory
from risk_assessment.modules import (
    UserManagementRiskAssessor,
    DataExposureRiskAssessor,
    AuthenticationRiskAssessor,
    AdminAccessRiskAssessor,
    FileOperationsRiskAssessor,
    DatabaseOperationsRiskAssessor
)


def load_config(config_path: str) -> dict:
    """Load configuration from YAML file."""
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"Error loading config: {e}")
        return {}


def demonstrate_builtin_assessors():
    """Demonstrate the built-in risk assessors."""
    print("🔒 **BUILT-IN RISK ASSESSORS DEMONSTRATION**")
    print("=" * 60)
    
    # Create factory
    factory = RiskAssessorFactory()
    
    # Register built-in assessors
    factory.register_assessor(UserManagementRiskAssessor())
    factory.register_assessor(DataExposureRiskAssessor())
    factory.register_assessor(AuthenticationRiskAssessor())
    factory.register_assessor(AdminAccessRiskAssessor())
    factory.register_assessor(FileOperationsRiskAssessor())
    factory.register_assessor(DatabaseOperationsRiskAssessor())
    
    print(f"✅ Registered {len(factory)} built-in risk assessors")
    
    # List all assessors
    print("\n📋 **Registered Risk Assessors:**")
    for assessor_info in factory.list_assessors():
        print(f"  • {assessor_info['name']} (Priority: {assessor_info['priority']})")
        print(f"    - {assessor_info['description']}")
        print(f"    - Supported patterns: {', '.join(assessor_info['supported_patterns'][:3])}...")
        print()
    
    # Test risk assessment
    print("🧪 **RISK ASSESSMENT TESTING:**")
    print("-" * 40)
    
    test_endpoints = [
        {
            "path": "/users/v1/{user_id}",
            "methods": ["GET", "PUT", "DELETE"],
            "parameters": {"path_params": ["user_id"]},
            "headers": ["Authorization"]
        },
        {
            "path": "/admin/users",
            "methods": ["GET", "POST"],
            "parameters": {"query_params": ["limit", "offset"]},
            "headers": []
        },
        {
            "path": "/books/v1/{book_title}",
            "methods": ["GET", "PUT"],
            "parameters": {"path_params": ["book_title"]},
            "headers": ["Authorization"]
        }
    ]
    
    for i, endpoint in enumerate(test_endpoints, 1):
        print(f"\n🔍 **Endpoint {i}: {endpoint['path']}**")
        print(f"   Methods: {', '.join(endpoint['methods'])}")
        print(f"   Headers: {', '.join(endpoint['headers']) if endpoint['headers'] else 'None'}")
        
        # Assess risk
        assessments = factory.assess_endpoint_risk(
            endpoint['path'],
            endpoint['methods'],
            endpoint['parameters'],
            endpoint['headers']
        )
        
        if assessments:
            print(f"   📊 **Risk Assessments ({len(assessments)}):**")
            for assessment in assessments:
                print(f"      • {assessment.category.value.upper()} (Score: {assessment.score:.1f})")
                print(f"        Factors: {', '.join(assessment.factors[:2])}...")
                print(f"        Confidence: {assessment.confidence:.2f}")
        else:
            print("   ✅ No specific risks identified")
    
    return factory


def demonstrate_plugin_loading():
    """Demonstrate plugin discovery and loading."""
    print("\n🔌 **PLUGIN DISCOVERY AND LOADING DEMONSTRATION**")
    print("=" * 60)
    
    # Create new factory for plugins
    plugin_factory = RiskAssessorFactory()
    
    # Load from configuration
    config_path = Path(__file__).parent.parent / "config" / "risk_assessors.yaml"
    config = load_config(str(config_path))
    
    if config:
        print("📁 **Loading from configuration file...**")
        plugin_factory.load_from_config(config)
        print(f"✅ Loaded {len(plugin_factory)} assessors from config")
    
    # Discover plugins
    plugin_dir = Path(__file__).parent.parent / "plugins" / "risk_assessors"
    if plugin_dir.exists():
        print(f"\n🔍 **Discovering plugins in: {plugin_dir}**")
        plugin_factory.discover_plugins(str(plugin_dir))
        print(f"✅ Discovered {len(plugin_factory)} total assessors")
    
    # List all assessors including plugins
    print("\n📋 **All Risk Assessors (Built-in + Plugins):**")
    for assessor_info in plugin_factory.list_assessors():
        print(f"  • {assessor_info['name']} (Priority: {assessor_info['priority']})")
        print(f"    - {assessor_info['description']}")
        print(f"    - Version: {assessor_info['version']}")
        print(f"    - Enabled: {assessor_info['enabled']}")
        print()
    
    return plugin_factory


def demonstrate_dynamic_configuration():
    """Demonstrate dynamic configuration changes."""
    print("\n⚙️ **DYNAMIC CONFIGURATION DEMONSTRATION**")
    print("=" * 60)
    
    factory = RiskAssessorFactory()
    
    # Register assessors
    user_assessor = UserManagementRiskAssessor()
    admin_assessor = AdminAccessRiskAssessor()
    
    factory.register_assessor(user_assessor)
    factory.register_assessor(admin_assessor)
    
    print(f"✅ Initial setup: {len(factory)} assessors")
    
    # Demonstrate priority changes
    print("\n🔄 **Priority Management:**")
    print(f"  User Management priority: {user_assessor.priority}")
    print(f"  Admin Access priority: {admin_assessor.priority}")
    
    # Change priorities
    user_assessor.set_priority(5)
    admin_assessor.set_priority(15)
    
    print(f"  After change - User Management priority: {user_assessor.priority}")
    print(f"  After change - Admin Access priority: {admin_assessor.priority}")
    
    # Demonstrate enable/disable
    print("\n🔄 **Enable/Disable Management:**")
    print(f"  User Management enabled: {user_assessor.is_enabled()}")
    print(f"  Admin Access enabled: {admin_assessor.is_enabled()}")
    
    # Disable one assessor
    user_assessor.disable()
    print(f"  After disabling User Management: {user_assessor.is_enabled()}")
    
    # Show execution order
    print(f"\n📋 **Execution Order (Enabled only):**")
    enabled_assessors = factory.get_enabled_assessors()
    for i, assessor in enumerate(enabled_assessors, 1):
        print(f"  {i}. {assessor.name} (Priority: {assessor.priority})")
    
    # Re-enable
    user_assessor.enable()
    print(f"\n✅ Re-enabled User Management: {user_assessor.is_enabled()}")


def demonstrate_custom_risk_assessment():
    """Demonstrate custom risk assessment with plugins."""
    print("\n🎯 **CUSTOM RISK ASSESSMENT DEMONSTRATION**")
    print("=" * 60)
    
    factory = RiskAssessorFactory()
    
    # Load all assessors including plugins
    config_path = Path(__file__).parent.parent / "config" / "risk_assessors.yaml"
    config = load_config(str(config_path))
    if config:
        factory.load_from_config(config)
    
    plugin_dir = Path(__file__).parent.parent / "plugins" / "risk_assessors"
    if plugin_dir.exists():
        factory.discover_plugins(str(plugin_dir))
    
    print(f"✅ Loaded {len(factory)} total assessors")
    
    # Test with custom endpoints
    custom_endpoints = [
        {
            "path": "/business/revenue/2024",
            "methods": ["GET"],
            "parameters": {"query_params": ["quarter", "region"]},
            "headers": ["Authorization"]
        },
        {
            "path": "/payment/process",
            "methods": ["POST"],
            "parameters": {"body_params": ["amount", "currency", "card_number"]},
            "headers": ["Authorization", "X-API-Key"]
        },
        {
            "path": "/custom/internal/metrics",
            "methods": ["GET", "POST"],
            "parameters": {"path_params": ["metric_type"]},
            "headers": []
        }
    ]
    
    print("\n🧪 **Testing Custom Risk Assessment:**")
    for i, endpoint in enumerate(custom_endpoints, 1):
        print(f"\n🔍 **Custom Endpoint {i}: {endpoint['path']}**")
        
        assessments = factory.assess_endpoint_risk(
            endpoint['path'],
            endpoint['methods'],
            endpoint['parameters'],
            endpoint['headers']
        )
        
        if assessments:
            print(f"   📊 **Risk Assessments ({len(assessments)}):**")
            for assessment in assessments:
                print(f"      • {assessment.category.value.upper()} (Score: {assessment.score:.1f})")
                print(f"        Factors: {', '.join(assessment.factors)}")
                print(f"        Recommendations: {', '.join(assessment.recommendations[:2])}...")
                print(f"        Confidence: {assessment.confidence:.2f}")
        else:
            print("   ✅ No specific risks identified")


def main():
    """Main demonstration function."""
    print("🚀 **VAmPI API Discovery - Pluggable Risk Assessment System**")
    print("=" * 80)
    print("This demonstration showcases the new pluggable risk assessment architecture")
    print("with runtime loading, custom plugins, and dynamic configuration.\n")
    
    try:
        # Demonstrate built-in assessors
        factory1 = demonstrate_builtin_assessors()
        
        # Demonstrate plugin loading
        factory2 = demonstrate_plugin_loading()
        
        # Demonstrate dynamic configuration
        demonstrate_dynamic_configuration()
        
        # Demonstrate custom risk assessment
        demonstrate_custom_risk_assessment()
        
        print("\n🎉 **DEMONSTRATION COMPLETED SUCCESSFULLY!**")
        print("=" * 60)
        print("✅ Built-in risk assessors working")
        print("✅ Plugin discovery and loading working")
        print("✅ Dynamic configuration working")
        print("✅ Custom risk assessment working")
        print("\n🚀 The risk assessment system is now fully pluggable and extensible!")
        
    except Exception as e:
        print(f"\n❌ **ERROR during demonstration: {e}**")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main() 