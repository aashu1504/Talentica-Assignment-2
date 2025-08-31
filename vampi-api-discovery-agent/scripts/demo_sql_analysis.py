#!/usr/bin/env python3
"""
SQL Analysis Demo using sqlparse

This script demonstrates the enhanced SQL injection testing capabilities
that leverage the sqlparse library for intelligent SQL analysis and
database fingerprinting.
"""

import os
import sys
from pathlib import Path

# Add src directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from security_testing.sql_analyzer import (
    SQLAnalyzer, DatabaseType, analyze_sql_payload, 
    fingerprint_database, generate_payloads
)


def print_header(title: str):
    """Print a formatted header"""
    print("\n" + "="*60)
    print(f"🔍 {title}")
    print("="*60)


def print_section(title: str):
    """Print a formatted section header"""
    print(f"\n📋 {title}")
    print("-" * 40)


def print_success(message: str):
    """Print a success message"""
    print(f"✅ {message}")


def print_info(message: str):
    """Print an info message"""
    print(f"ℹ️  {message}")


def print_warning(message: str):
    """Print a warning message"""
    print(f"⚠️  {message}")


def print_error(message: str):
    """Print an error message"""
    print(f"❌ {message}")


def demo_sql_payload_analysis():
    """Demonstrate SQL payload analysis capabilities"""
    print_section("SQL Payload Analysis Demo")
    
    # Sample SQL injection payloads
    payloads = [
        "' OR '1'='1' --",
        "' UNION SELECT 1,2,3 --",
        "'; DROP TABLE users; --",
        "admin'--",
        "1' UNION SELECT sqlite_version(),2,3 --",
        "'; EXEC xp_cmdshell('dir');--",
        "invalid_sql_payload"
    ]
    
    analyzer = SQLAnalyzer()
    
    for i, payload in enumerate(payloads, 1):
        print(f"\n🔍 Payload {i}: {payload}")
        
        # Analyze the payload
        analysis = analyzer.analyze_sql_payload(payload)
        
        print(f"  - Valid SQL: {analysis.is_valid_sql}")
        print(f"  - SQL Type: {analysis.sql_type or 'Unknown'}")
        print(f"  - Database Type: {analysis.database_type.value}")
        print(f"  - Vulnerability Level: {analysis.vulnerability_level}")
        print(f"  - Confidence Score: {analysis.confidence_score:.2f}")
        
        if analysis.tables:
            print(f"  - Tables: {', '.join(analysis.tables)}")
        
        if analysis.syntax_errors:
            print(f"  - Syntax Errors: {', '.join(analysis.syntax_errors)}")
        
        # Format the payload
        formatted = analyzer.format_sql_payload(payload)
        if formatted != payload:
            print(f"  - Formatted: {formatted}")


def demo_database_fingerprinting():
    """Demonstrate database fingerprinting capabilities"""
    print_section("Database Fingerprinting Demo")
    
    # Sample error responses from different databases
    error_responses = {
        "SQLite": "sqlite3.OperationalError: no such table: users",
        "MySQL": "mysql.connector.errors.ProgrammingError: 1146 (42S02): Table 'test.users' doesn't exist",
        "PostgreSQL": "psycopg2.errors.UndefinedTable: relation \"users\" does not exist",
        "Oracle": "cx_Oracle.DatabaseError: ORA-00942: table or view does not exist",
        "SQL Server": "pyodbc.Error: ('42S02', \"[42S02] [Microsoft][ODBC SQL Server Driver][SQL Server]Invalid object name 'users'.\")"
    }
    
    analyzer = SQLAnalyzer()
    
    for db_name, error_response in error_responses.items():
        print(f"\n🗄️ {db_name} Error Response:")
        print(f"  Error: {error_response}")
        
        # Fingerprint the database
        fingerprint = analyzer.fingerprint_database_from_error(error_response)
        
        print(f"  Detected DB: {fingerprint.database_type.value}")
        print(f"  Confidence: {fingerprint.confidence_score:.2f}")
        print(f"  Evidence: {', '.join(fingerprint.evidence)}")
        
        if fingerprint.specific_features:
            print(f"  Features: {', '.join(fingerprint.specific_features)}")
        
        if fingerprint.version_hints:
            print(f"  Version Hints: {', '.join(fingerprint.version_hints)}")


def demo_database_specific_payloads():
    """Demonstrate database-specific payload generation"""
    print_section("Database-Specific Payload Generation Demo")
    
    analyzer = SQLAnalyzer()
    
    # Test payload generation for different database types
    database_types = [
        DatabaseType.SQLITE,
        DatabaseType.MYSQL,
        DatabaseType.POSTGRESQL,
        DatabaseType.ORACLE,
        DatabaseType.SQLSERVER
    ]
    
    for db_type in database_types:
        print(f"\n🚀 {db_type.value.upper()} Payloads:")
        
        payloads = analyzer.generate_database_specific_payloads(db_type)
        
        for i, payload in enumerate(payloads[:3], 1):  # Show first 3 payloads
            print(f"  {i}. {payload}")
        
        if len(payloads) > 3:
            print(f"  ... and {len(payloads) - 3} more")


def demo_sql_fragment_extraction():
    """Demonstrate SQL fragment extraction capabilities"""
    print_section("SQL Fragment Extraction Demo")
    
    # Sample text with embedded SQL fragments
    sample_texts = [
        "Error occurred while executing: SELECT * FROM users WHERE id = 1",
        "Database query failed: INSERT INTO logs VALUES ('error', '2024-01-01')",
        "SQL execution error: UPDATE users SET status='active' WHERE id=123",
        "Query failed: DELETE FROM temp_table WHERE created_at < NOW() - INTERVAL 1 DAY"
    ]
    
    analyzer = SQLAnalyzer()
    
    for i, text in enumerate(sample_texts, 1):
        print(f"\n📝 Text {i}: {text}")
        
        # Extract SQL fragments
        fragments = analyzer.extract_sql_fragments(text)
        
        if fragments:
            print(f"  Extracted SQL fragments:")
            for j, fragment in enumerate(fragments, 1):
                print(f"    {j}. {fragment}")
                
                # Analyze each fragment
                analysis = analyzer.analyze_sql_payload(fragment)
                print(f"      - Type: {analysis.sql_type}")
                print(f"      - Valid: {analysis.is_valid_sql}")
        else:
            print(f"  No SQL fragments detected")


def demo_vulnerability_assessment():
    """Demonstrate vulnerability level assessment"""
    print_section("Vulnerability Level Assessment Demo")
    
    # Sample payloads with different risk levels
    risk_payloads = {
        "Critical": [
            "'; DROP TABLE users; --",
            "'; EXEC xp_cmdshell('dir');--",
            "1' UNION SELECT * FROM information_schema.tables --"
        ],
        "High": [
            "' OR '1'='1' --",
            "' UNION SELECT 1,2,3 --",
            "admin'--"
        ],
        "Medium": [
            "' OR 1=1 --",
            "'; SELECT * FROM users --"
        ],
        "Low": [
            "'",
            "1'",
            "admin"
        ]
    }
    
    analyzer = SQLAnalyzer()
    
    for risk_level, payloads in risk_payloads.items():
        print(f"\n🔥 {risk_level} Risk Payloads:")
        
        for payload in payloads:
            analysis = analyzer.analyze_sql_payload(payload)
            print(f"  - {payload}")
            print(f"    Detected Level: {analysis.vulnerability_level}")
            print(f"    Confidence: {analysis.confidence_score:.2f}")


def demo_sql_structure_validation():
    """Demonstrate SQL structure validation"""
    print_section("SQL Structure Validation Demo")
    
    # Sample SQL statements for validation
    sql_statements = [
        "SELECT * FROM users WHERE id = 1",
        "INSERT INTO users (name, email) VALUES ('John', 'john@example.com')",
        "UPDATE users SET status = 'active' WHERE id = 123",
        "DELETE FROM users WHERE id = 456",
        "SELECT u.name, u.email FROM users u JOIN profiles p ON u.id = p.user_id",
        "invalid sql statement",
        "just some text",
        "SELECT * FROM users; DROP TABLE users;"
    ]
    
    analyzer = SQLAnalyzer()
    
    for i, statement in enumerate(sql_statements, 1):
        print(f"\n🔍 Statement {i}: {statement}")
        
        # Validate SQL structure
        is_valid = analyzer.validate_sql_structure(statement)
        print(f"  Valid SQL Structure: {is_valid}")
        
        if is_valid:
            # Format the SQL
            formatted = analyzer.format_sql_payload(statement)
            if formatted != statement:
                print(f"  Formatted: {formatted}")


def run_complete_demo():
    """Run the complete SQL analysis demo"""
    print_header("SQL Analysis Demo using sqlparse")
    
    print_info("This demo showcases the enhanced SQL injection testing capabilities")
    print_info("that leverage the sqlparse library for intelligent analysis.")
    
    try:
        # Test 1: SQL Payload Analysis
        demo_sql_payload_analysis()
        
        # Test 2: Database Fingerprinting
        demo_database_fingerprinting()
        
        # Test 3: Database-Specific Payloads
        demo_database_specific_payloads()
        
        # Test 4: SQL Fragment Extraction
        demo_sql_fragment_extraction()
        
        # Test 5: Vulnerability Assessment
        demo_vulnerability_assessment()
        
        # Test 6: SQL Structure Validation
        demo_sql_structure_validation()
        
        print_header("Demo Completed Successfully!")
        print_success("All sqlparse-enhanced features demonstrated")
        print_info("Your SQL injection testing is now more intelligent and accurate!")
        
    except Exception as e:
        print_error(f"Demo failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    run_complete_demo() 