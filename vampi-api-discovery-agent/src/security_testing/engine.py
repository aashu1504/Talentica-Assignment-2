#!/usr/bin/env python3
"""
Security Testing Engine for OWASP API Security Testing

This module implements comprehensive API security testing capabilities
including injection testing, authentication analysis, and authorization testing.
"""

import asyncio
import json
import logging
import time
from datetime import datetime
from typing import List, Dict, Optional, Any, Tuple
import requests
import re

from .models import (
    SecurityTest, EndpointSecurityReport, SecurityAssessmentReport,
    SecurityTestSuite, SecurityTestResult, CVSSMetrics,
    OWASPCategory, VulnerabilitySeverity, AttackVector, AttackComplexity,
    PrivilegesRequired, UserInteraction, Scope, Impact
)


class SecurityTestingEngine:
    """Main engine for performing API security testing"""
    
    def __init__(self, base_url: str, timeout: int = 30):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.logger = logging.getLogger(__name__)
        
        # Default test suite configuration
        self.test_suite = SecurityTestSuite(
            suite_name="OWASP API Security Test Suite",
            suite_version="1.0.0",
            owasp_categories=[
                OWASPCategory.INJECTION,
                OWASPCategory.BROKEN_USER_AUTHENTICATION,
                OWASPCategory.BROKEN_OBJECT_LEVEL_AUTHORIZATION,
                OWASPCategory.BROKEN_FUNCTION_LEVEL_AUTHORIZATION,
                OWASPCategory.SECURITY_MISCONFIGURATION
            ],
            injection_payloads=[
                "' OR '1'='1",
                "'; DROP TABLE users; --",
                "<script>alert('XSS')</script>",
                "admin'--",
                "1' UNION SELECT * FROM users--",
                "'; EXEC xp_cmdshell('dir');--"
            ],
            authentication_tests=[
                "jwt_token_manipulation",
                "missing_authentication",
                "weak_authentication",
                "session_fixation"
            ],
            authorization_tests=[
                "horizontal_privilege_escalation",
                "vertical_privilege_escalation",
                "idor_vulnerability",
                "function_level_access_control"
            ]
        )
    
    async def test_endpoint_security(self, endpoint_data: Dict[str, Any]) -> EndpointSecurityReport:
        """Test security of a single endpoint"""
        start_time = time.time()
        
        endpoint_path = endpoint_data.get('path', '')
        http_methods = endpoint_data.get('methods', ['GET'])
        parameters = endpoint_data.get('parameters', {})
        
        self.logger.info(f"Testing endpoint: {endpoint_path}")
        
        security_tests = []
        total_tests = 0
        tests_passed = 0
        tests_failed = 0
        vulnerabilities_found = 0
        
        # Test each HTTP method
        for method in http_methods:
            method_tests = await self._test_method_security(
                endpoint_path, method, parameters
            )
            security_tests.extend(method_tests)
            
            for test in method_tests:
                total_tests += 1
                if test.vulnerability_found:
                    tests_failed += 1
                    vulnerabilities_found += 1
                else:
                    tests_passed += 1
        
        # Calculate overall risk score
        overall_risk_score = self._calculate_endpoint_risk_score(security_tests)
        
        # Count vulnerabilities by severity
        critical_vulns = len([t for t in security_tests if t.severity == VulnerabilitySeverity.CRITICAL])
        high_vulns = len([t for t in security_tests if t.severity == VulnerabilitySeverity.HIGH])
        medium_vulns = len([t for t in security_tests if t.severity == VulnerabilitySeverity.MEDIUM])
        low_vulns = len([t for t in security_tests if t.severity == VulnerabilitySeverity.LOW])
        
        # Generate summary and recommendations
        summary = self._generate_endpoint_summary(security_tests, vulnerabilities_found)
        recommendations = self._generate_endpoint_recommendations(security_tests)
        
        return EndpointSecurityReport(
            endpoint_path=endpoint_path,
            http_methods=http_methods,
            total_tests=total_tests,
            tests_passed=tests_passed,
            tests_failed=tests_failed,
            vulnerabilities_found=vulnerabilities_found,
            critical_vulnerabilities=critical_vulns,
            high_vulnerabilities=high_vulns,
            medium_vulnerabilities=medium_vulns,
            low_vulnerabilities=low_vulns,
            overall_risk_score=overall_risk_score,
            security_tests=security_tests,
            summary=summary,
            recommendations=recommendations,
            test_timestamp=datetime.now()
        )
    
    async def _test_method_security(self, endpoint_path: str, method: str, 
                                  parameters: Dict[str, Any]) -> List[SecurityTest]:
        """Test security for a specific HTTP method"""
        tests = []
        
        # Injection testing
        tests.extend(await self._test_injection_vulnerabilities(endpoint_path, method, parameters))
        
        # Authentication testing
        tests.extend(await self._test_authentication_vulnerabilities(endpoint_path, method, parameters))
        
        # Authorization testing
        tests.extend(await self._test_authorization_vulnerabilities(endpoint_path, method, parameters))
        
        # Security misconfiguration testing
        tests.extend(await self._test_security_misconfigurations(endpoint_path, method, parameters))
        
        return tests
    
    async def _test_injection_vulnerabilities(self, endpoint_path: str, method: str,
                                            parameters: Dict[str, Any]) -> List[SecurityTest]:
        """Test for injection vulnerabilities"""
        tests = []
        
        # SQL Injection testing
        if method in ['GET', 'POST'] and parameters.get('query_params'):
            for param in parameters['query_params']:
                for payload in self.test_suite.injection_payloads:
                    test_result = await self._test_sql_injection(
                        endpoint_path, method, param, payload
                    )
                    tests.append(test_result)
        
        # XSS testing for body parameters
        if method in ['POST', 'PUT'] and parameters.get('body_params'):
            for param in parameters['body_params']:
                xss_payload = "<script>alert('XSS')</script>"
                test_result = await self._test_xss_injection(
                    endpoint_path, method, param, xss_payload
                )
                tests.append(test_result)
        
        return tests
    
    async def _test_sql_injection(self, endpoint_path: str, method: str, 
                                param: str, payload: str) -> SecurityTest:
        """Test for SQL injection vulnerability"""
        start_time = time.time()
        
        try:
            if method == 'GET':
                url = f"{self.base_url}{endpoint_path}"
                params = {param: payload}
                response = self.session.get(url, params=params, timeout=self.timeout)
            else:
                url = f"{self.base_url}{endpoint_path}"
                data = {param: payload}
                response = self.session.post(url, json=data, timeout=self.timeout)
            
            # Analyze response for SQL injection indicators
            vulnerability_found = self._detect_sql_injection(response)
            
            if vulnerability_found:
                cvss_metrics = CVSSMetrics(
                    attack_vector=AttackVector.NETWORK,
                    attack_complexity=AttackComplexity.LOW,
                    privileges_required=PrivilegesRequired.NONE,
                    user_interaction=UserInteraction.NONE,
                    scope=Scope.CHANGED,
                    confidentiality_impact=Impact.HIGH,
                    integrity_impact=Impact.HIGH,
                    availability_impact=Impact.HIGH
                )
                
                severity = VulnerabilitySeverity.CRITICAL
                risk_score = 9.0
                recommendations = [
                    "Implement input validation and sanitization",
                    "Use parameterized queries or prepared statements",
                    "Apply proper input length restrictions",
                    "Implement WAF rules for SQL injection detection"
                ]
            else:
                cvss_metrics = None
                severity = VulnerabilitySeverity.INFO
                risk_score = 0.0
                recommendations = []
            
            execution_time = time.time() - start_time
            
            return SecurityTest(
                test_name=f"SQL Injection Test - {param}",
                test_category=OWASPCategory.INJECTION,
                test_description=f"Testing {param} parameter for SQL injection using payload: {payload}",
                test_method=f"HTTP {method} with malicious payload",
                payload_used=payload,
                request_details={"method": method, "parameter": param, "payload": payload},
                response_details={"status_code": response.status_code, "response_length": len(response.text)},
                vulnerability_found=vulnerability_found,
                vulnerability_details="SQL injection vulnerability detected" if vulnerability_found else None,
                cvss_metrics=cvss_metrics,
                severity=severity,
                risk_score=risk_score,
                recommendations=recommendations,
                test_duration=execution_time
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            return SecurityTest(
                test_name=f"SQL Injection Test - {param}",
                test_category=OWASPCategory.INJECTION,
                test_description=f"Testing {param} parameter for SQL injection",
                test_method=f"HTTP {method} with malicious payload",
                payload_used=payload,
                vulnerability_found=False,
                severity=VulnerabilitySeverity.INFO,
                risk_score=0.0,
                recommendations=[],
                test_duration=execution_time
            )
    
    def _detect_sql_injection(self, response: requests.Response) -> bool:
        """Detect SQL injection vulnerability from response"""
        response_text = response.text.lower()
        
        # Common SQL error messages
        sql_error_patterns = [
            "sql syntax",
            "mysql error",
            "oracle error",
            "postgresql error",
            "sqlite error",
            "syntax error",
            "unclosed quotation mark",
            "division by zero",
            "invalid column name",
            "table doesn't exist"
        ]
        
        for pattern in sql_error_patterns:
            if pattern in response_text:
                return True
        
        # Check for unusual response patterns
        if response.status_code == 500 and len(response_text) > 100:
            return True
        
        return False
    
    async def _test_xss_injection(self, endpoint_path: str, method: str,
                                param: str, payload: str) -> SecurityTest:
        """Test for XSS injection vulnerability"""
        start_time = time.time()
        
        try:
            url = f"{self.base_url}{endpoint_path}"
            data = {param: payload}
            response = self.session.post(url, json=data, timeout=self.timeout)
            
            # Check if XSS payload is reflected in response
            vulnerability_found = payload in response.text
            
            if vulnerability_found:
                cvss_metrics = CVSSMetrics(
                    attack_vector=AttackVector.NETWORK,
                    attack_complexity=AttackComplexity.LOW,
                    privileges_required=PrivilegesRequired.NONE,
                    user_interaction=UserInteraction.REQUIRED,
                    scope=Scope.CHANGED,
                    confidentiality_impact=Impact.LOW,
                    integrity_impact=Impact.LOW,
                    availability_impact=Impact.NONE
                )
                
                severity = VulnerabilitySeverity.MEDIUM
                risk_score = 6.0
                recommendations = [
                    "Implement input validation and sanitization",
                    "Use output encoding for user input",
                    "Apply Content Security Policy (CSP)",
                    "Validate and sanitize all user inputs"
                ]
            else:
                cvss_metrics = None
                severity = VulnerabilitySeverity.INFO
                risk_score = 0.0
                recommendations = []
            
            execution_time = time.time() - start_time
            
            return SecurityTest(
                test_name=f"XSS Injection Test - {param}",
                test_category=OWASPCategory.INJECTION,
                test_description=f"Testing {param} parameter for XSS injection",
                test_method=f"HTTP {method} with XSS payload",
                payload_used=payload,
                request_details={"method": method, "parameter": param, "payload": payload},
                response_details={"status_code": response.status_code, "response_length": len(response.text)},
                vulnerability_found=vulnerability_found,
                vulnerability_details="XSS vulnerability detected" if vulnerability_found else None,
                cvss_metrics=cvss_metrics,
                severity=severity,
                risk_score=risk_score,
                recommendations=recommendations,
                test_duration=execution_time
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            return SecurityTest(
                test_name=f"XSS Injection Test - {param}",
                test_category=OWASPCategory.INJECTION,
                test_description=f"Testing {param} parameter for XSS injection",
                test_method=f"HTTP {method} with XSS payload",
                payload_used=payload,
                vulnerability_found=False,
                severity=VulnerabilitySeverity.INFO,
                risk_score=0.0,
                recommendations=[],
                test_duration=execution_time
            )
    
    async def _test_authentication_vulnerabilities(self, endpoint_path: str, method: str,
                                                 parameters: Dict[str, Any]) -> List[SecurityTest]:
        """Test for authentication vulnerabilities"""
        tests = []
        
        # Test missing authentication
        if parameters.get('headers') and 'Authorization' in parameters['headers']:
            test_result = await self._test_missing_authentication(endpoint_path, method)
            tests.append(test_result)
        
        # Test JWT token manipulation
        if 'Authorization' in str(parameters):
            test_result = await self._test_jwt_vulnerabilities(endpoint_path, method)
            tests.append(test_result)
        
        return tests
    
    async def _test_missing_authentication(self, endpoint_path: str, method: str) -> SecurityTest:
        """Test if endpoint can be accessed without authentication"""
        start_time = time.time()
        
        try:
            url = f"{self.base_url}{endpoint_path}"
            
            if method == 'GET':
                response = self.session.get(url, timeout=self.timeout)
            else:
                response = self.session.post(url, timeout=self.timeout)
            
            # Check if access was granted without authentication
            vulnerability_found = response.status_code not in [401, 403]
            
            if vulnerability_found:
                cvss_metrics = CVSSMetrics(
                    attack_vector=AttackVector.NETWORK,
                    attack_complexity=AttackComplexity.LOW,
                    privileges_required=PrivilegesRequired.NONE,
                    user_interaction=UserInteraction.NONE,
                    scope=Scope.CHANGED,
                    confidentiality_impact=Impact.HIGH,
                    integrity_impact=Impact.HIGH,
                    availability_impact=Impact.MEDIUM
                )
                
                severity = VulnerabilitySeverity.HIGH
                risk_score = 8.0
                recommendations = [
                    "Implement proper authentication for all protected endpoints",
                    "Use middleware to enforce authentication",
                    "Apply authentication checks before route handlers",
                    "Implement proper session management"
                ]
            else:
                cvss_metrics = None
                severity = VulnerabilitySeverity.INFO
                risk_score = 0.0
                recommendations = []
            
            execution_time = time.time() - start_time
            
            return SecurityTest(
                test_name="Missing Authentication Test",
                test_category=OWASPCategory.BROKEN_USER_AUTHENTICATION,
                test_description="Testing if endpoint can be accessed without authentication",
                test_method=f"HTTP {method} without Authorization header",
                request_details={"method": method, "authentication": "None"},
                response_details={"status_code": response.status_code},
                vulnerability_found=vulnerability_found,
                vulnerability_details="Missing authentication vulnerability detected" if vulnerability_found else None,
                cvss_metrics=cvss_metrics,
                severity=severity,
                risk_score=risk_score,
                recommendations=recommendations,
                test_duration=execution_time
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            return SecurityTest(
                test_name="Missing Authentication Test",
                test_category=OWASPCategory.BROKEN_USER_AUTHENTICATION,
                test_description="Testing if endpoint can be accessed without authentication",
                test_method=f"HTTP {method} without Authorization header",
                vulnerability_found=False,
                severity=VulnerabilitySeverity.INFO,
                risk_score=0.0,
                recommendations=[],
                test_duration=execution_time
            )
    
    async def _test_jwt_vulnerabilities(self, endpoint_path: str, method: str) -> SecurityTest:
        """Test for JWT token vulnerabilities"""
        start_time = time.time()
        
        try:
            # Create a fake JWT token
            fake_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
            
            url = f"{self.base_url}{endpoint_path}"
            headers = {"Authorization": f"Bearer {fake_token}"}
            
            if method == 'GET':
                response = self.session.get(url, headers=headers, timeout=self.timeout)
            else:
                response = self.session.post(url, headers=headers, timeout=self.timeout)
            
            # Check if fake token was accepted
            vulnerability_found = response.status_code not in [401, 403]
            
            if vulnerability_found:
                cvss_metrics = CVSSMetrics(
                    attack_vector=AttackVector.NETWORK,
                    attack_complexity=AttackComplexity.LOW,
                    privileges_required=PrivilegesRequired.NONE,
                    user_interaction=UserInteraction.NONE,
                    scope=Scope.CHANGED,
                    confidentiality_impact=Impact.HIGH,
                    integrity_impact=Impact.HIGH,
                    availability_impact=Impact.MEDIUM
                )
                
                severity = VulnerabilitySeverity.HIGH
                risk_score = 8.0
                recommendations = [
                    "Implement proper JWT token validation",
                    "Use strong secret keys for JWT signing",
                    "Implement token expiration and refresh mechanisms",
                    "Validate token signature and claims"
                ]
            else:
                cvss_metrics = None
                severity = VulnerabilitySeverity.INFO
                risk_score = 0.0
                recommendations = []
            
            execution_time = time.time() - start_time
            
            return SecurityTest(
                test_name="JWT Token Validation Test",
                test_category=OWASPCategory.BROKEN_USER_AUTHENTICATION,
                test_description="Testing JWT token validation with fake token",
                test_method=f"HTTP {method} with fake JWT token",
                payload_used=fake_token,
                request_details={"method": method, "fake_token": fake_token},
                response_details={"status_code": response.status_code},
                vulnerability_found=vulnerability_found,
                vulnerability_details="JWT validation vulnerability detected" if vulnerability_found else None,
                cvss_metrics=cvss_metrics,
                severity=severity,
                risk_score=risk_score,
                recommendations=recommendations,
                test_duration=execution_time
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            return SecurityTest(
                test_name="JWT Token Validation Test",
                test_category=OWASPCategory.BROKEN_USER_AUTHENTICATION,
                test_description="Testing JWT token validation with fake token",
                test_method=f"HTTP {method} with fake JWT token",
                vulnerability_found=False,
                severity=VulnerabilitySeverity.INFO,
                risk_score=0.0,
                recommendations=[],
                test_duration=execution_time
            )
    
    async def _test_authorization_vulnerabilities(self, endpoint_path: str, method: str,
                                                parameters: Dict[str, Any]) -> List[SecurityTest]:
        """Test for authorization vulnerabilities"""
        tests = []
        
        # Test IDOR vulnerability
        if 'id' in str(parameters) or any('id' in param.lower() for param in parameters.get('path_params', [])):
            test_result = await self._test_idor_vulnerability(endpoint_path, method)
            tests.append(test_result)
        
        return tests
    
    async def _test_idor_vulnerability(self, endpoint_path: str, method: str) -> SecurityTest:
        """Test for Insecure Direct Object Reference vulnerability"""
        start_time = time.time()
        
        try:
            # Test with different user IDs
            test_ids = ["1", "2", "999", "admin", "user123"]
            
            for test_id in test_ids:
                # Replace {id} placeholder in path
                test_path = endpoint_path.replace("{id}", test_id)
                url = f"{self.base_url}{test_path}"
                
                if method == 'GET':
                    response = self.session.get(url, timeout=self.timeout)
                else:
                    response = self.session.post(url, timeout=self.timeout)
                
                # Check if different IDs return different data (potential IDOR)
                if response.status_code == 200 and len(response.text) > 0:
                    vulnerability_found = True
                    break
            else:
                vulnerability_found = False
            
            if vulnerability_found:
                cvss_metrics = CVSSMetrics(
                    attack_vector=AttackVector.NETWORK,
                    attack_complexity=AttackComplexity.LOW,
                    privileges_required=PrivilegesRequired.LOW,
                    user_interaction=UserInteraction.NONE,
                    scope=Scope.CHANGED,
                    confidentiality_impact=Impact.HIGH,
                    integrity_impact=Impact.MEDIUM,
                    availability_impact=Impact.LOW
                )
                
                severity = VulnerabilitySeverity.MEDIUM
                risk_score = 6.0
                recommendations = [
                    "Implement proper access control checks",
                    "Validate user permissions for each resource",
                    "Use session-based authorization",
                    "Implement resource ownership validation"
                ]
            else:
                cvss_metrics = None
                severity = VulnerabilitySeverity.INFO
                risk_score = 0.0
                recommendations = []
            
            execution_time = time.time() - start_time
            
            return SecurityTest(
                test_name="IDOR Vulnerability Test",
                test_category=OWASPCategory.BROKEN_OBJECT_LEVEL_AUTHORIZATION,
                test_description="Testing for Insecure Direct Object Reference vulnerability",
                test_method=f"HTTP {method} with different user IDs",
                payload_used="Multiple test IDs",
                request_details={"method": method, "test_ids": test_ids},
                response_details={"status_code": response.status_code},
                vulnerability_found=vulnerability_found,
                vulnerability_details="IDOR vulnerability detected" if vulnerability_found else None,
                cvss_metrics=cvss_metrics,
                severity=severity,
                risk_score=risk_score,
                recommendations=recommendations,
                test_duration=execution_time
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            return SecurityTest(
                test_name="IDOR Vulnerability Test",
                test_category=OWASPCategory.BROKEN_OBJECT_LEVEL_AUTHORIZATION,
                test_description="Testing for Insecure Direct Object Reference vulnerability",
                test_method=f"HTTP {method} with different user IDs",
                vulnerability_found=False,
                severity=VulnerabilitySeverity.INFO,
                risk_score=0.0,
                recommendations=[],
                test_duration=execution_time
            )
    
    async def _test_security_misconfigurations(self, endpoint_path: str, method: str,
                                             parameters: Dict[str, Any]) -> List[SecurityTest]:
        """Test for security misconfigurations"""
        tests = []
        
        # Test for information disclosure
        test_result = await self._test_information_disclosure(endpoint_path, method)
        tests.append(test_result)
        
        # Test for missing security headers
        test_result = await self._test_security_headers(endpoint_path, method)
        tests.append(test_result)
        
        return tests
    
    async def _test_information_disclosure(self, endpoint_path: str, method: str) -> SecurityTest:
        """Test for information disclosure vulnerabilities"""
        start_time = time.time()
        
        try:
            url = f"{self.base_url}{endpoint_path}"
            
            if method == 'GET':
                response = self.session.get(url, timeout=self.timeout)
            else:
                response = self.session.post(url, timeout=self.timeout)
            
            # Check for sensitive information in response
            sensitive_patterns = [
                "error", "exception", "stack trace", "debug", "internal",
                "database", "password", "secret", "key", "token"
            ]
            
            vulnerability_found = any(pattern in response.text.lower() for pattern in sensitive_patterns)
            
            if vulnerability_found:
                cvss_metrics = CVSSMetrics(
                    attack_vector=AttackVector.NETWORK,
                    attack_complexity=AttackComplexity.LOW,
                    privileges_required=PrivilegesRequired.NONE,
                    user_interaction=UserInteraction.NONE,
                    scope=Scope.UNCHANGED,
                    confidentiality_impact=Impact.MEDIUM,
                    integrity_impact=Impact.NONE,
                    availability_impact=Impact.NONE
                )
                
                severity = VulnerabilitySeverity.MEDIUM
                risk_score = 5.0
                recommendations = [
                    "Remove debug information from production responses",
                    "Implement proper error handling",
                    "Use generic error messages",
                    "Configure logging levels appropriately"
                ]
            else:
                cvss_metrics = None
                severity = VulnerabilitySeverity.INFO
                risk_score = 0.0
                recommendations = []
            
            execution_time = time.time() - start_time
            
            return SecurityTest(
                test_name="Information Disclosure Test",
                test_category=OWASPCategory.SECURITY_MISCONFIGURATION,
                test_description="Testing for information disclosure in responses",
                test_method=f"HTTP {method} and analyze response content",
                request_details={"method": method},
                response_details={"status_code": response.status_code, "response_length": len(response.text)},
                vulnerability_found=vulnerability_found,
                vulnerability_details="Information disclosure vulnerability detected" if vulnerability_found else None,
                cvss_metrics=cvss_metrics,
                severity=severity,
                risk_score=risk_score,
                recommendations=recommendations,
                test_duration=execution_time
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            return SecurityTest(
                test_name="Information Disclosure Test",
                test_category=OWASPCategory.SECURITY_MISCONFIGURATION,
                test_description="Testing for information disclosure in responses",
                test_method=f"HTTP {method} and analyze response content",
                vulnerability_found=False,
                severity=VulnerabilitySeverity.INFO,
                risk_score=0.0,
                recommendations=[],
                test_duration=execution_time
            )
    
    async def _test_security_headers(self, endpoint_path: str, method: str) -> SecurityTest:
        """Test for missing security headers"""
        start_time = time.time()
        
        try:
            url = f"{self.base_url}{endpoint_path}"
            
            if method == 'GET':
                response = self.session.get(url, timeout=self.timeout)
            else:
                response = self.session.post(url, timeout=self.timeout)
            
            # Check for important security headers
            required_headers = [
                "X-Content-Type-Options",
                "X-Frame-Options",
                "X-XSS-Protection",
                "Strict-Transport-Security",
                "Content-Security-Policy"
            ]
            
            missing_headers = [header for header in required_headers if header not in response.headers]
            vulnerability_found = len(missing_headers) > 0
            
            if vulnerability_found:
                cvss_metrics = CVSSMetrics(
                    attack_vector=AttackVector.NETWORK,
                    attack_complexity=AttackComplexity.LOW,
                    privileges_required=PrivilegesRequired.NONE,
                    user_interaction=UserInteraction.NONE,
                    scope=Scope.UNCHANGED,
                    confidentiality_impact=Impact.LOW,
                    integrity_impact=Impact.LOW,
                    availability_impact=Impact.NONE
                )
                
                severity = VulnerabilitySeverity.LOW
                risk_score = 3.0
                recommendations = [
                    f"Implement {', '.join(missing_headers)} security headers",
                    "Configure proper Content Security Policy",
                    "Enable XSS protection headers",
                    "Implement HSTS for HTTPS enforcement"
                ]
            else:
                cvss_metrics = None
                severity = VulnerabilitySeverity.INFO
                risk_score = 0.0
                recommendations = []
            
            execution_time = time.time() - start_time
            
            return SecurityTest(
                test_name="Security Headers Test",
                test_category=OWASPCategory.SECURITY_MISCONFIGURATION,
                test_description="Testing for presence of security headers",
                test_method=f"HTTP {method} and check response headers",
                request_details={"method": method},
                response_details={"status_code": response.status_code, "headers": dict(response.headers)},
                vulnerability_found=vulnerability_found,
                vulnerability_details=f"Missing security headers: {', '.join(missing_headers)}" if vulnerability_found else None,
                cvss_metrics=cvss_metrics,
                severity=severity,
                risk_score=risk_score,
                recommendations=recommendations,
                test_duration=execution_time
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            return SecurityTest(
                test_name="Security Headers Test",
                test_category=OWASPCategory.SECURITY_MISCONFIGURATION,
                test_description="Testing for presence of security headers",
                test_method=f"HTTP {method} and check response headers",
                vulnerability_found=False,
                severity=VulnerabilitySeverity.INFO,
                risk_score=0.0,
                recommendations=[],
                test_duration=execution_time
            )
    
    def _calculate_endpoint_risk_score(self, security_tests: List[SecurityTest]) -> float:
        """Calculate overall risk score for an endpoint"""
        if not security_tests:
            return 0.0
        
        total_score = sum(test.risk_score for test in security_tests)
        return min(10.0, total_score / len(security_tests))
    
    def _generate_endpoint_summary(self, security_tests: List[SecurityTest], 
                                 vulnerabilities_found: int) -> str:
        """Generate summary for endpoint security assessment"""
        if vulnerabilities_found == 0:
            return "No security vulnerabilities detected. Endpoint appears to be secure."
        
        critical_count = len([t for t in security_tests if t.severity == VulnerabilitySeverity.CRITICAL])
        high_count = len([t for t in security_tests if t.severity == VulnerabilitySeverity.HIGH])
        medium_count = len([t for t in security_tests if t.severity == VulnerabilitySeverity.MEDIUM])
        low_count = len([t for t in security_tests if t.severity == VulnerabilitySeverity.LOW])
        
        summary = f"Found {vulnerabilities_found} security vulnerabilities: "
        if critical_count > 0:
            summary += f"{critical_count} Critical, "
        if high_count > 0:
            summary += f"{high_count} High, "
        if medium_count > 0:
            summary += f"{medium_count} Medium, "
        if low_count > 0:
            summary += f"{low_count} Low"
        
        summary = summary.rstrip(", ")
        summary += ". Immediate attention required for critical and high severity issues."
        
        return summary
    
    def _generate_endpoint_recommendations(self, security_tests: List[SecurityTest]) -> List[str]:
        """Generate security recommendations for endpoint"""
        recommendations = []
        
        # Collect unique recommendations from all tests
        for test in security_tests:
            if test.recommendations:
                recommendations.extend(test.recommendations)
        
        # Remove duplicates while preserving order
        unique_recommendations = []
        for rec in recommendations:
            if rec not in unique_recommendations:
                unique_recommendations.append(rec)
        
        return unique_recommendations[:10]  # Limit to top 10 recommendations 