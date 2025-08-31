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

# SQL analyzer imports for enhanced SQL injection testing
from .sql_analyzer import SQLAnalyzer, DatabaseType, analyze_sql_payload, fingerprint_database


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
        summary_dict = self._generate_endpoint_summary(endpoint_path, http_methods, security_tests)
        summary_text = summary_dict.get("summary", "No summary available")
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
            summary=summary_text,
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
        
        # NoSQL Injection testing
        if method in ['GET', 'POST'] and parameters.get('query_params'):
            for param in parameters['query_params']:
                nosql_payloads = [
                    '{"$gt": ""}',
                    '{"$ne": null}',
                    '{"$where": "1==1"}',
                    '{"$regex": ".*"}',
                    '{"$exists": true}',
                    '{"$in": ["admin", "user"]}'
                ]
                for payload in nosql_payloads:
                    test_result = await self._test_nosql_injection(
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
        """Test for SQL injection vulnerability using sqlparse analysis"""
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
            
            # Enhanced SQL analysis using sqlparse
            sql_analyzer = SQLAnalyzer()
            payload_analysis = sql_analyzer.analyze_sql_payload(payload)
            db_fingerprint = sql_analyzer.fingerprint_database_from_error(response.text)
            
            # Analyze response for SQL injection indicators
            vulnerability_found = self._detect_sql_injection(response)
            
            if vulnerability_found:
                # Enhanced recommendations based on database type
                recommendations = [
                    "Implement input validation and sanitization",
                    "Use parameterized queries or prepared statements",
                    "Apply proper input length restrictions",
                    "Implement WAF rules for SQL injection detection"
                ]
                
                # Add database-specific recommendations
                if db_fingerprint.database_type != DatabaseType.UNKNOWN:
                    recommendations.append(f"Database detected: {db_fingerprint.database_type.value}")
                    if db_fingerprint.specific_features:
                        recommendations.append(f"Features: {', '.join(db_fingerprint.specific_features)}")
                
                # Add payload analysis insights
                if payload_analysis.is_valid_sql:
                    recommendations.append(f"Payload SQL type: {payload_analysis.sql_type}")
                    recommendations.append(f"Payload vulnerability level: {payload_analysis.vulnerability_level}")
                
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
            else:
                cvss_metrics = None
                severity = VulnerabilitySeverity.INFO
                risk_score = 0.0
                recommendations = []
            
            execution_time = time.time() - start_time
            
            # Enhanced test description with sqlparse analysis
            test_description = f"Testing {param} parameter for SQL injection using payload: {payload}"
            if payload_analysis.is_valid_sql:
                test_description += f" (SQL Type: {payload_analysis.sql_type}, Level: {payload_analysis.vulnerability_level})"
            if db_fingerprint.database_type != DatabaseType.UNKNOWN:
                test_description += f" (DB: {db_fingerprint.database_type.value}, Confidence: {db_fingerprint.confidence_score:.2f})"
            
            return SecurityTest(
                test_name=f"SQL Injection Test - {param}",
                test_category=OWASPCategory.INJECTION,
                test_description=test_description,
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
                proof_of_concept=self._generate_proof_of_concept("SQL Injection", payload, endpoint_path, method, param) if vulnerability_found else None,
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
    
    async def _test_nosql_injection(self, endpoint_path: str, method: str, 
                                  param: str, payload: str) -> SecurityTest:
        """Test for NoSQL injection vulnerability"""
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
            
            # Analyze response for NoSQL injection indicators
            vulnerability_found = self._detect_nosql_injection(response)
            
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
                    "Use parameterized queries or ORM methods",
                    "Apply proper input length restrictions",
                    "Implement WAF rules for NoSQL injection detection",
                    "Use MongoDB/MongoDB-like database security best practices"
                ]
            else:
                cvss_metrics = None
                severity = VulnerabilitySeverity.INFO
                risk_score = 0.0
                recommendations = []
            
            execution_time = time.time() - start_time
            
            return SecurityTest(
                test_name=f"NoSQL Injection Test - {param}",
                test_category=OWASPCategory.INJECTION,
                test_description=f"Testing {param} parameter for NoSQL injection using payload: {payload}",
                test_method=f"HTTP {method} with NoSQL payload",
                payload_used=payload,
                request_details={"method": method, "parameter": param, "payload": payload},
                response_details={"status_code": response.status_code, "response_length": len(response.text)},
                vulnerability_found=vulnerability_found,
                vulnerability_details="NoSQL injection vulnerability detected" if vulnerability_found else None,
                cvss_metrics=cvss_metrics,
                severity=severity,
                risk_score=risk_score,
                recommendations=recommendations,
                proof_of_concept=self._generate_proof_of_concept("NoSQL Injection", payload, endpoint_path, method, param) if vulnerability_found else None,
                test_duration=execution_time
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            return SecurityTest(
                test_name=f"NoSQL Injection Test - {param}",
                test_category=OWASPCategory.INJECTION,
                test_description=f"Testing {param} parameter for NoSQL injection",
                test_method=f"HTTP {method} with NoSQL payload",
                payload_used=payload,
                vulnerability_found=False,
                severity=VulnerabilitySeverity.INFO,
                risk_score=0.0,
                recommendations=[],
                test_duration=execution_time
            )
    
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
                proof_of_concept=self._generate_proof_of_concept("XSS", payload, endpoint_path, method, param) if vulnerability_found else None,
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
                proof_of_concept=self._generate_proof_of_concept("Authentication Bypass", "", endpoint_path, method) if vulnerability_found else None,
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
                proof_of_concept=self._generate_proof_of_concept("JWT Vulnerability", fake_token, endpoint_path, method) if vulnerability_found else None,
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
        """Enhanced test for authorization vulnerabilities with comprehensive coverage"""
        tests = []
        
        try:
            # Test IDOR vulnerability with enhanced authentication context
            # Only test endpoints that have ID parameters or path parameters
            if ('id' in str(parameters) or 
                any('id' in str(param).lower() for param in parameters.get('path_params', [])) or
                any('id' in str(param).lower() for param in parameters.get('query_params', []))):
                try:
                    test_result = await self._test_idor_vulnerability(endpoint_path, method)
                    tests.append(test_result)
                except Exception as e:
                    # Log error but don't fail the entire test suite
                    self.logger.warning(f"IDOR test failed for {endpoint_path}: {e}")
                    # Add a basic IDOR test as fallback
                    tests.append(await self._test_basic_idor_vulnerability(endpoint_path, method))
            
            # Test role-based access control (RBAC) - only for protected endpoints
            if method in ['POST', 'PUT', 'DELETE'] or 'admin' in endpoint_path.lower() or 'user' in endpoint_path.lower():
                try:
                    test_result = await self._test_rbac_vulnerabilities(endpoint_path, method)
                    tests.append(test_result)
                except Exception as e:
                    self.logger.warning(f"RBAC test failed for {endpoint_path}: {e}")
            
            # Test privilege escalation - only for endpoints with role-based access
            if any(keyword in endpoint_path.lower() for keyword in ['admin', 'user', 'profile', 'settings']):
                try:
                    test_result = await self._test_privilege_escalation(endpoint_path, method)
                    tests.append(test_result)
                except Exception as e:
                    self.logger.warning(f"Privilege escalation test failed for {endpoint_path}: {e}")
            
            # Test function-level authorization - only for administrative functions
            if any(keyword in endpoint_path.lower() for keyword in ['admin', 'system', 'config', 'settings']):
                try:
                    test_result = await self._test_function_level_authorization(endpoint_path, method)
                    tests.append(test_result)
                except Exception as e:
                    self.logger.warning(f"Function-level authorization test failed for {endpoint_path}: {e}")
                    
        except Exception as e:
            self.logger.error(f"Authorization testing failed for {endpoint_path}: {e}")
            # Return empty list to prevent test suite failure
        
        return tests
    
    async def _test_basic_idor_vulnerability(self, endpoint_path: str, method: str) -> SecurityTest:
        """Basic IDOR vulnerability test as fallback"""
        start_time = time.time()
        
        try:
            # Simple IDOR test that won't fail
            test_ids = ["1", "2", "999"]
            vulnerability_found = False
            
            for test_id in test_ids:
                # Replace {id} placeholder in path
                test_path = endpoint_path.replace("{id}", test_id)
                url = f"{self.base_url}{test_path}"
                
                try:
                    if method == 'GET':
                        response = self.session.get(url, timeout=self.timeout)
                    else:
                        response = self.session.post(url, timeout=self.timeout)
                    
                    # Basic vulnerability detection
                    if response.status_code == 200 and len(response.text) > 0:
                        vulnerability_found = True
                        break
                        
                except Exception:
                    continue
            
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
                    "Use session-based authorization"
                ]
            else:
                cvss_metrics = None
                severity = VulnerabilitySeverity.INFO
                risk_score = 0.0
                recommendations = []
            
            execution_time = time.time() - start_time
            
            return SecurityTest(
                test_name="Basic IDOR Vulnerability Test",
                test_category=OWASPCategory.BROKEN_OBJECT_LEVEL_AUTHORIZATION,
                test_description="Testing for Insecure Direct Object Reference vulnerability",
                test_method=f"HTTP {method} with different user IDs",
                payload_used="Multiple test IDs",
                request_details={"method": method, "test_ids": test_ids},
                response_details={"status_code": 200 if vulnerability_found else 404},
                vulnerability_found=vulnerability_found,
                vulnerability_details="IDOR vulnerability detected" if vulnerability_found else None,
                cvss_metrics=cvss_metrics,
                severity=severity,
                risk_score=risk_score,
                recommendations=recommendations,
                proof_of_concept=None,
                test_duration=execution_time
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            return SecurityTest(
                test_name="Basic IDOR Vulnerability Test",
                test_category=OWASPCategory.BROKEN_OBJECT_LEVEL_AUTHORIZATION,
                test_description="Testing for Insecure Direct Object Reference vulnerability",
                test_method=f"HTTP {method} with different user IDs",
                vulnerability_found=False,
                severity=VulnerabilitySeverity.INFO,
                risk_score=0.0,
                recommendations=[],
                test_duration=execution_time
            )
    
    async def _test_idor_vulnerability(self, endpoint_path: str, method: str) -> SecurityTest:
        """Enhanced test for Insecure Direct Object Reference vulnerability with authentication context"""
        start_time = time.time()
        
        try:
            # Test with different user IDs and authentication scenarios
            test_scenarios = [
                {"id": "1", "auth": "none", "description": "Unauthenticated access"},
                {"id": "2", "auth": "none", "description": "Unauthenticated access"},
                {"id": "999", "auth": "none", "description": "Unauthenticated access"},
                {"id": "admin", "auth": "none", "description": "Unauthenticated access"},
                {"id": "user123", "auth": "none", "description": "Unauthenticated access"},
                {"id": "1", "auth": "valid_user", "description": "Valid user token"},
                {"id": "2", "auth": "valid_user", "description": "Valid user token"},
                {"id": "999", "auth": "valid_user", "description": "Valid user token"},
                {"id": "1", "auth": "admin_user", "description": "Admin user token"},
                {"id": "2", "auth": "admin_user", "description": "Admin user token"},
                {"id": "999", "auth": "admin_user", "description": "Admin user token"},
                {"id": "1", "auth": "expired_token", "description": "Expired token"},
                {"id": "1", "auth": "invalid_token", "description": "Invalid token"},
                {"id": "1", "auth": "other_user", "description": "Other user's token"}
            ]
            
            vulnerability_found = False
            vulnerability_details = []
            test_results = []
            
            for scenario in test_scenarios:
                test_id = scenario["id"]
                auth_type = scenario["auth"]
                description = scenario["description"]
                
                try:
                    # Replace {id} placeholder in path
                    test_path = endpoint_path.replace("{id}", test_id)
                    url = f"{self.base_url}{test_path}"
                    
                    # Prepare headers based on authentication type
                    headers = self._prepare_auth_headers(auth_type, test_id)
                    
                    if method == 'GET':
                        response = self.session.get(url, headers=headers, timeout=self.timeout)
                    else:
                        response = self.session.post(url, headers=headers, timeout=self.timeout)
                    
                    # Enhanced vulnerability detection
                    scenario_result = self._analyze_idor_response(response, test_id, auth_type, description)
                    test_results.append(scenario_result)
                    
                    if scenario_result["vulnerability_found"]:
                        vulnerability_found = True
                        vulnerability_details.append(scenario_result["vulnerability_details"])
                        
                except Exception as e:
                    # Log individual scenario failure but continue testing
                    self.logger.debug(f"IDOR scenario failed for {description}: {e}")
                    test_results.append({
                        "scenario": description,
                        "vulnerability_found": False,
                        "error": str(e),
                        "status_code": None
                    })
            
            # Determine overall vulnerability assessment
            overall_assessment = self._assess_idor_vulnerability_level(test_results)
            
            if vulnerability_found:
                cvss_metrics = CVSSMetrics(
                    attack_vector=AttackVector.NETWORK,
                    attack_complexity=AttackComplexity.LOW,
                    privileges_required=PrivilegesRequired.LOW,
                    user_interaction=UserInteraction.NONE,
                    scope=Scope.CHANGED,
                    confidentiality_impact=Impact.HIGH,
                    integrity_impact=Impact.HIGH,
                    availability_impact=Impact.MEDIUM
                )
                
                severity = VulnerabilitySeverity.CRITICAL if "CRITICAL" in overall_assessment else VulnerabilitySeverity.HIGH
                risk_score = 9.0 if "CRITICAL" in overall_assessment else 7.0
                
                recommendations = [
                    "Implement proper access control checks for all resources",
                    "Validate user permissions and resource ownership for each request",
                    "Use session-based authorization with proper token validation",
                    "Implement resource-level access control (RLAC)",
                    "Add audit logging for all authorization decisions",
                    "Test authorization with different user roles and contexts"
                ]
            else:
                cvss_metrics = None
                severity = VulnerabilitySeverity.INFO
                risk_score = 0.0
                recommendations = []
            
            execution_time = time.time() - start_time
            
            return SecurityTest(
                test_name="Enhanced IDOR Vulnerability Test",
                test_category=OWASPCategory.BROKEN_OBJECT_LEVEL_AUTHORIZATION,
                test_description=f"Comprehensive testing for Insecure Direct Object Reference with authentication context. Tested {len(test_scenarios)} scenarios including unauthenticated, authenticated, and role-based access.",
                test_method=f"HTTP {method} with multiple authentication contexts and user IDs",
                payload_used=f"Multiple test IDs: {', '.join(set([s['id'] for s in test_scenarios]))}",
                request_details={"method": method, "test_scenarios": test_scenarios, "total_tests": len(test_scenarios)},
                response_details={"test_results": test_results, "vulnerability_count": len(vulnerability_details)},
                vulnerability_found=vulnerability_found,
                vulnerability_details="; ".join(vulnerability_details) if vulnerability_details else None,
                cvss_metrics=cvss_metrics,
                severity=severity,
                risk_score=risk_score,
                recommendations=recommendations,
                proof_of_concept=self._generate_enhanced_idor_poc(endpoint_path, method, test_results) if vulnerability_found else None,
                test_duration=execution_time
            )
            
        except Exception as e:
            # If enhanced test fails completely, fall back to basic test
            self.logger.warning(f"Enhanced IDOR test failed for {endpoint_path}: {e}")
            return await self._test_basic_idor_vulnerability(endpoint_path, method)
    
    async def _test_rbac_vulnerabilities(self, endpoint_path: str, method: str) -> SecurityTest:
        """Test for Role-Based Access Control vulnerabilities"""
        start_time = time.time()
        
        try:
            # Test different user roles accessing the same endpoint
            role_scenarios = [
                {"role": "anonymous", "token": None, "description": "Anonymous user access"},
                {"role": "regular_user", "token": "Bearer regular_user_token", "description": "Regular user access"},
                {"role": "admin_user", "token": "Bearer admin_user_token", "description": "Admin user access"},
                {"role": "super_admin", "token": "Bearer super_admin_token", "description": "Super admin access"},
                {"role": "invalid_role", "token": "Bearer invalid_role_token", "description": "Invalid role token"}
            ]
            
            test_results = []
            vulnerability_found = False
            vulnerability_details = []
            
            for scenario in role_scenarios:
                try:
                    headers = {"Content-Type": "application/json"}
                    if scenario["token"]:
                        headers["Authorization"] = scenario["token"]
                    
                    url = f"{self.base_url}{endpoint_path}"
                    
                    if method == 'GET':
                        response = self.session.get(url, headers=headers, timeout=self.timeout)
                    else:
                        response = self.session.post(url, headers=headers, timeout=self.timeout)
                    
                    # Analyze RBAC response
                    rbac_result = self._analyze_rbac_response(response, scenario)
                    test_results.append(rbac_result)
                    
                    if rbac_result["vulnerability_found"]:
                        vulnerability_found = True
                        vulnerability_details.append(rbac_result["vulnerability_details"])
                        
                except Exception as e:
                    # Log individual scenario failure but continue testing
                    self.logger.debug(f"RBAC scenario failed for {scenario['description']}: {e}")
                    test_results.append({
                        "role": scenario["role"],
                        "vulnerability_found": False,
                        "error": str(e),
                        "status_code": None
                    })
            
            # Assess overall RBAC vulnerability
            overall_assessment = self._assess_rbac_vulnerability_level(test_results)
            
            if vulnerability_found:
                cvss_metrics = CVSSMetrics(
                    attack_vector=AttackVector.NETWORK,
                    attack_complexity=AttackComplexity.LOW,
                    privileges_required=PrivilegesRequired.LOW,
                    user_interaction=UserInteraction.NONE,
                    scope=Scope.CHANGED,
                    confidentiality_impact=Impact.HIGH,
                    integrity_impact=Impact.HIGH,
                    availability_impact=Impact.MEDIUM
                )
                
                severity = VulnerabilitySeverity.CRITICAL if "CRITICAL" in overall_assessment else VulnerabilitySeverity.HIGH
                risk_score = 8.0 if "CRITICAL" in overall_assessment else 6.0
                
                recommendations = [
                    "Implement strict role-based access control (RBAC)",
                    "Validate user roles and permissions for each request",
                    "Use principle of least privilege",
                    "Implement role hierarchy and inheritance",
                    "Add audit logging for role-based access decisions",
                    "Regularly review and update role permissions"
                ]
            else:
                cvss_metrics = None
                severity = VulnerabilitySeverity.INFO
                risk_score = 0.0
                recommendations = []
            
            execution_time = time.time() - start_time
            
            return SecurityTest(
                test_name="RBAC Vulnerability Test",
                test_category=OWASPCategory.BROKEN_FUNCTION_LEVEL_AUTHORIZATION,
                test_description=f"Testing for Role-Based Access Control vulnerabilities. Tested {len(role_scenarios)} different user roles.",
                test_method=f"HTTP {method} with multiple role-based authentication contexts",
                payload_used=f"Role scenarios: {', '.join([s['role'] for s in role_scenarios])}",
                request_details={"method": method, "role_scenarios": role_scenarios},
                response_details={"test_results": test_results, "vulnerability_count": len(vulnerability_details)},
                vulnerability_found=vulnerability_found,
                vulnerability_details="; ".join(vulnerability_details) if vulnerability_details else None,
                cvss_metrics=cvss_metrics,
                severity=severity,
                risk_score=risk_score,
                recommendations=recommendations,
                proof_of_concept=self._generate_rbac_poc(endpoint_path, method, test_results) if vulnerability_found else None,
                test_duration=execution_time
            )
            
        except Exception as e:
            # If RBAC test fails completely, return a safe default
            self.logger.warning(f"RBAC test failed for {endpoint_path}: {e}")
            execution_time = time.time() - start_time
            return SecurityTest(
                test_name="RBAC Vulnerability Test",
                test_category=OWASPCategory.BROKEN_FUNCTION_LEVEL_AUTHORIZATION,
                test_description="Testing for Role-Based Access Control vulnerabilities",
                test_method=f"HTTP {method} with role-based authentication",
                vulnerability_found=False,
                severity=VulnerabilitySeverity.INFO,
                risk_score=0.0,
                recommendations=[],
                test_duration=execution_time
            )
    
    async def _test_privilege_escalation(self, endpoint_path: str, method: str) -> SecurityTest:
        """Test for privilege escalation vulnerabilities"""
        start_time = time.time()
        
        try:
            # Test privilege escalation scenarios
            escalation_scenarios = [
                {"current_role": "user", "target_role": "admin", "description": "User to Admin escalation"},
                {"current_role": "guest", "target_role": "user", "description": "Guest to User escalation"},
                {"current_role": "user", "target_role": "super_admin", "description": "User to Super Admin escalation"},
                {"current_role": "readonly", "target_role": "write", "description": "Read-only to Write escalation"}
            ]
            
            test_results = []
            vulnerability_found = False
            vulnerability_details = []
            
            for scenario in escalation_scenarios:
                # Simulate current role token
                current_token = f"Bearer {scenario['current_role']}_token"
                headers = {"Content-Type": "application/json", "Authorization": current_token}
                
                # Try to access admin-only functionality
                url = f"{self.base_url}{endpoint_path}"
                
                try:
                    if method == 'GET':
                        response = self.session.get(url, headers=headers, timeout=self.timeout)
                    else:
                        response = self.session.post(url, headers=headers, timeout=self.timeout)
                    
                    # Analyze privilege escalation response
                    escalation_result = self._analyze_privilege_escalation(response, scenario)
                    test_results.append(escalation_result)
                    
                    if escalation_result["vulnerability_found"]:
                        vulnerability_found = True
                        vulnerability_details.append(escalation_result["vulnerability_details"])
                        
                except Exception as e:
                    test_results.append({
                        "scenario": scenario["description"],
                        "vulnerability_found": False,
                        "error": str(e),
                        "status_code": None
                    })
            
            # Assess overall privilege escalation vulnerability
            overall_assessment = self._assess_privilege_escalation_level(test_results)
            
            if vulnerability_found:
                cvss_metrics = CVSSMetrics(
                    attack_vector=AttackVector.NETWORK,
                    attack_complexity=AttackComplexity.LOW,
                    privileges_required=PrivilegesRequired.LOW,
                    user_interaction=UserInteraction.NONE,
                    scope=Scope.CHANGED,
                    confidentiality_impact=Impact.HIGH,
                    integrity_impact=Impact.HIGH,
                    availability_impact=Impact.HIGH
                )
                
                severity = VulnerabilitySeverity.CRITICAL
                risk_score = 9.0
                
                recommendations = [
                    "Implement strict privilege separation",
                    "Use principle of least privilege",
                    "Validate user permissions for each action",
                    "Implement role-based access control (RBAC)",
                    "Add privilege escalation detection and logging",
                    "Regular security audits of user permissions"
                ]
            else:
                cvss_metrics = None
                severity = VulnerabilitySeverity.INFO
                risk_score = 0.0
                recommendations = []
            
            execution_time = time.time() - start_time
            
            return SecurityTest(
                test_name="Privilege Escalation Test",
                test_category=OWASPCategory.BROKEN_FUNCTION_LEVEL_AUTHORIZATION,
                test_description=f"Testing for privilege escalation vulnerabilities. Tested {len(escalation_scenarios)} escalation scenarios.",
                test_method=f"HTTP {method} with privilege escalation attempts",
                payload_used=f"Escalation scenarios: {', '.join([s['description'] for s in escalation_scenarios])}",
                request_details={"method": method, "escalation_scenarios": escalation_scenarios},
                response_details={"test_results": test_results, "vulnerability_count": len(vulnerability_details)},
                vulnerability_found=vulnerability_found,
                vulnerability_details="; ".join(vulnerability_details) if vulnerability_details else None,
                cvss_metrics=cvss_metrics,
                severity=severity,
                risk_score=risk_score,
                recommendations=recommendations,
                proof_of_concept=self._generate_privilege_escalation_poc(endpoint_path, method, test_results) if vulnerability_found else None,
                test_duration=execution_time
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            return SecurityTest(
                test_name="Privilege Escalation Test",
                test_category=OWASPCategory.BROKEN_FUNCTION_LEVEL_AUTHORIZATION,
                test_description="Testing for privilege escalation vulnerabilities",
                test_method=f"HTTP {method} with privilege escalation attempts",
                vulnerability_found=False,
                severity=VulnerabilitySeverity.INFO,
                risk_score=0.0,
                recommendations=[],
                test_duration=execution_time
            )
    
    async def _test_function_level_authorization(self, endpoint_path: str, method: str) -> SecurityTest:
        """Test for function-level authorization vulnerabilities"""
        start_time = time.time()
        
        try:
            # Test function-level access control
            function_scenarios = [
                {"function": "read", "role": "guest", "description": "Guest read access"},
                {"function": "write", "role": "user", "description": "User write access"},
                {"function": "delete", "role": "admin", "description": "Admin delete access"},
                {"function": "admin", "role": "user", "description": "User admin function access"},
                {"function": "system", "role": "admin", "description": "Admin system function access"}
            ]
            
            test_results = []
            vulnerability_found = False
            vulnerability_details = []
            
            for scenario in function_scenarios:
                # Simulate role token
                role_token = f"Bearer {scenario['role']}_token"
                headers = {"Content-Type": "application/json", "Authorization": role_token}
                
                # Try to access function-level functionality
                url = f"{self.base_url}{endpoint_path}"
                
                try:
                    if method == 'GET':
                        response = self.session.get(url, headers=headers, timeout=self.timeout)
                    else:
                        response = self.session.post(url, headers=headers, timeout=self.timeout)
                    
                    # Analyze function-level authorization response
                    function_result = self._analyze_function_authorization(response, scenario)
                    test_results.append(function_result)
                    
                    if function_result["vulnerability_found"]:
                        vulnerability_found = True
                        vulnerability_details.append(function_result["vulnerability_details"])
                        
                except Exception as e:
                    test_results.append({
                        "scenario": scenario["description"],
                        "vulnerability_found": False,
                        "error": str(e),
                        "status_code": None
                    })
            
            # Assess overall function-level authorization vulnerability
            overall_assessment = self._assess_function_authorization_level(test_results)
            
            if vulnerability_found:
                cvss_metrics = CVSSMetrics(
                    attack_vector=AttackVector.NETWORK,
                    attack_complexity=AttackComplexity.LOW,
                    privileges_required=PrivilegesRequired.LOW,
                    user_interaction=UserInteraction.NONE,
                    scope=Scope.CHANGED,
                    confidentiality_impact=Impact.HIGH,
                    integrity_impact=Impact.HIGH,
                    availability_impact=Impact.MEDIUM
                )
                
                severity = VulnerabilitySeverity.HIGH
                risk_score = 7.0
                
                recommendations = [
                    "Implement function-level access control",
                    "Validate user permissions for each function",
                    "Use principle of least privilege",
                    "Implement action-based authorization",
                    "Add function access logging and monitoring",
                    "Regular review of function permissions"
                ]
            else:
                cvss_metrics = None
                severity = VulnerabilitySeverity.INFO
                risk_score = 0.0
                recommendations = []
            
            execution_time = time.time() - start_time
            
            return SecurityTest(
                test_name="Function-Level Authorization Test",
                test_category=OWASPCategory.BROKEN_FUNCTION_LEVEL_AUTHORIZATION,
                test_description=f"Testing for function-level authorization vulnerabilities. Tested {len(function_scenarios)} function scenarios.",
                test_method=f"HTTP {method} with function-level authorization testing",
                payload_used=f"Function scenarios: {', '.join([s['description'] for s in function_scenarios])}",
                request_details={"method": method, "function_scenarios": function_scenarios},
                response_details={"test_results": test_results, "vulnerability_count": len(vulnerability_details)},
                vulnerability_found=vulnerability_found,
                vulnerability_details="; ".join(vulnerability_details) if vulnerability_details else None,
                cvss_metrics=cvss_metrics,
                severity=severity,
                risk_score=risk_score,
                recommendations=recommendations,
                proof_of_concept=self._generate_function_authorization_poc(endpoint_path, method, test_results) if vulnerability_found else None,
                test_duration=execution_time
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            return SecurityTest(
                test_name="Function-Level Authorization Test",
                test_category=OWASPCategory.BROKEN_FUNCTION_LEVEL_AUTHORIZATION,
                test_description="Testing for function-level authorization vulnerabilities",
                test_method=f"HTTP {method} with function-level authorization testing",
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
        
        try:
            # Test for information disclosure
            test_result = await self._test_information_disclosure(endpoint_path, method)
            tests.append(test_result)
            
            # Test for missing security headers
            test_result = await self._test_security_headers(endpoint_path, method)
            tests.append(test_result)
            
        except Exception as e:
            self.logger.warning(f"Security misconfiguration testing failed for {endpoint_path}: {e}")
        
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
                payload_used=None,
                request_details={"method": method},
                response_details={"status_code": response.status_code, "response_length": len(response.text)},
                vulnerability_found=vulnerability_found,
                vulnerability_details="Information disclosure vulnerability detected" if vulnerability_found else None,
                cvss_metrics=cvss_metrics,
                severity=severity,
                risk_score=risk_score,
                recommendations=recommendations,
                proof_of_concept=None,
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
            
            # Check for essential security headers
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
                payload_used=None,
                request_details={"method": method},
                response_details={"status_code": response.status_code, "headers": dict(response.headers)},
                vulnerability_found=vulnerability_found,
                vulnerability_details=f"Missing security headers: {', '.join(missing_headers)}" if vulnerability_found else None,
                cvss_metrics=cvss_metrics,
                severity=severity,
                risk_score=risk_score,
                recommendations=recommendations,
                proof_of_concept=self._generate_proof_of_concept("Missing Security Headers", "", endpoint_path, method) if vulnerability_found else None,
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
    
    def _prepare_auth_headers(self, auth_type: str, user_id: str) -> Dict[str, str]:
        """Prepare authentication headers for different test scenarios"""
        headers = {"Content-Type": "application/json"}
        
        if auth_type == "valid_user":
            # Simulate valid user token (in real testing, this would be obtained from login)
            headers["Authorization"] = f"Bearer valid_user_token_{user_id}"
        elif auth_type == "admin_user":
            # Simulate admin user token
            headers["Authorization"] = f"Bearer admin_token_{user_id}"
        elif auth_type == "expired_token":
            # Simulate expired token
            headers["Authorization"] = "Bearer expired_token_12345"
        elif auth_type == "invalid_token":
            # Simulate invalid/malformed token
            headers["Authorization"] = "Bearer invalid_token_format"
        elif auth_type == "other_user":
            # Simulate token from different user
            headers["Authorization"] = f"Bearer other_user_token_{int(user_id) + 100}"
        
        return headers
    
    def _analyze_idor_response(self, response: requests.Response, test_id: str, auth_type: str, description: str) -> Dict:
        """Analyze response for IDOR vulnerability indicators"""
        result = {
            "scenario": description,
            "test_id": test_id,
            "auth_type": auth_type,
            "status_code": response.status_code,
            "response_length": len(response.text),
            "vulnerability_found": False,
            "vulnerability_details": None,
            "risk_level": "LOW"
        }
        
        # Check for various IDOR indicators
        if response.status_code == 200:
            if auth_type == "none" and len(response.text) > 0:
                # Unauthenticated access to protected resource
                result["vulnerability_found"] = True
                result["vulnerability_details"] = f"CRITICAL: Unauthenticated access to resource ID {test_id}"
                result["risk_level"] = "CRITICAL"
            elif auth_type in ["valid_user", "admin_user"] and len(response.text) > 0:
                # Check if response contains user-specific data
                if self._contains_user_specific_data(response.text, test_id):
                    result["vulnerability_found"] = True
                    result["vulnerability_details"] = f"HIGH: Potential data exposure for resource ID {test_id}"
                    result["risk_level"] = "HIGH"
        
        elif response.status_code == 401:
            # Proper authentication required
            result["vulnerability_found"] = False
            result["vulnerability_details"] = "Proper authentication enforcement"
        
        elif response.status_code == 403:
            # Proper authorization enforcement
            result["vulnerability_found"] = False
            result["vulnerability_details"] = "Proper authorization enforcement"
        
        elif response.status_code == 404:
            # Resource not found (could be good or bad depending on context)
            if auth_type != "none":
                result["vulnerability_found"] = False
                result["vulnerability_details"] = "Resource not found (proper access control)"
        
        return result
    
    def _contains_user_specific_data(self, response_text: str, user_id: str) -> bool:
        """Check if response contains user-specific data that shouldn't be accessible"""
        # Look for patterns that suggest user data exposure
        user_patterns = [
            f"user_id\":\"{user_id}\"",
            f"user_id\":{user_id}",
            f"id\":\"{user_id}\"",
            f"id\":{user_id}",
            "email", "password", "phone", "address", "ssn", "credit_card"
        ]
        
        return any(pattern in response_text.lower() for pattern in user_patterns)
    
    def _assess_idor_vulnerability_level(self, test_results: List[Dict]) -> str:
        """Assess overall IDOR vulnerability level based on test results"""
        critical_count = sum(1 for r in test_results if r.get("risk_level") == "CRITICAL")
        high_count = sum(1 for r in test_results if r.get("risk_level") == "HIGH")
        medium_count = sum(1 for r in test_results if r.get("risk_level") == "MEDIUM")
        
        if critical_count > 0:
            return "CRITICAL"
        elif high_count > 0:
            return "HIGH"
        elif medium_count > 0:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _generate_enhanced_idor_poc(self, endpoint_path: str, method: str, test_results: List[Dict]) -> str:
        """Generate enhanced proof-of-concept for IDOR vulnerabilities"""
        vulnerable_scenarios = [r for r in test_results if r.get("vulnerability_found")]
        
        poc = f"""# Enhanced IDOR Vulnerability Proof of Concept
# Target: {endpoint_path}
# Method: {method}
# Vulnerabilities Found: {len(vulnerable_scenarios)}

import requests

url = "{self.base_url}{endpoint_path}"

# Test Results Summary:
"""
        
        for scenario in vulnerable_scenarios:
            poc += f"""
# {scenario['scenario']}
# - Test ID: {scenario['test_id']}
# - Auth Type: {scenario['auth_type']}
# - Risk Level: {scenario['risk_level']}
# - Vulnerability: {scenario['vulnerability_details']}
"""
        
        poc += f"""
# Proof of Concept Script
def test_idor_vulnerability():
    # Test unauthenticated access
    response = requests.get(url.replace("{{id}}", "1"))
    print(f"Unauthenticated access (ID=1): {{response.status_code}}")
    
    # Test with different user IDs
    test_ids = ["1", "2", "999", "admin", "user123"]
    
    for test_id in test_ids:
        test_url = url.replace("{{id}}", test_id)
        
        # Test without authentication
        response = requests.get(test_url)
        print(f"ID {{test_id}} (no auth): {{response.status_code}} - {{len(response.text)}} chars")
        
        # Test with fake authentication
        headers = {{"Authorization": f"Bearer fake_token_{{test_id}}"}}
        response = requests.get(test_url, headers=headers)
        print(f"ID {{test_id}} (fake auth): {{response.status_code}} - {{len(response.text)}} chars")

if __name__ == "__main__":
    test_idor_vulnerability()
    print("\\n🔍 Check responses for unauthorized data access!")
    print("✅ If you can access other users' data, IDOR vulnerability confirmed!")
"""
        
        return poc
    
    def _analyze_rbac_response(self, response: requests.Response, scenario: Dict) -> Dict:
        """Analyze response for RBAC vulnerability indicators"""
        result = {
            "role": scenario["role"],
            "status_code": response.status_code,
            "response_length": len(response.text),
            "vulnerability_found": False,
            "vulnerability_details": None,
            "risk_level": "LOW"
        }
        
        # Check for RBAC violations
        if response.status_code == 200:
            if scenario["role"] == "anonymous" and len(response.text) > 0:
                # Anonymous user accessing protected resource
                result["vulnerability_found"] = True
                result["vulnerability_details"] = f"CRITICAL: Anonymous user can access {scenario['role']} functionality"
                result["risk_level"] = "CRITICAL"
            elif scenario["role"] in ["regular_user", "invalid_role"] and len(response.text) > 0:
                # Regular user accessing admin functionality
                if self._contains_admin_functionality(response.text):
                    result["vulnerability_found"] = True
                    result["vulnerability_details"] = f"HIGH: {scenario['role']} can access admin functionality"
                    result["risk_level"] = "HIGH"
        
        elif response.status_code == 401:
            # Proper authentication required
            result["vulnerability_found"] = False
            result["vulnerability_details"] = "Proper authentication enforcement"
        
        elif response.status_code == 403:
            # Proper authorization enforcement
            result["vulnerability_found"] = False
            result["vulnerability_details"] = "Proper authorization enforcement"
        
        return result
    
    def _analyze_privilege_escalation(self, response: requests.Response, scenario: Dict) -> Dict:
        """Analyze response for privilege escalation indicators"""
        result = {
            "scenario": scenario["description"],
            "current_role": scenario["current_role"],
            "target_role": scenario["target_role"],
            "status_code": response.status_code,
            "response_length": len(response.text),
            "vulnerability_found": False,
            "vulnerability_details": None,
            "risk_level": "LOW"
        }
        
        # Check for privilege escalation
        if response.status_code == 200 and len(response.text) > 0:
            if scenario["current_role"] in ["user", "guest"] and scenario["target_role"] in ["admin", "super_admin"]:
                result["vulnerability_found"] = True
                result["vulnerability_details"] = f"CRITICAL: {scenario['current_role']} can access {scenario['target_role']} functionality"
                result["risk_level"] = "CRITICAL"
            elif scenario["current_role"] == "readonly" and scenario["target_role"] == "write":
                result["vulnerability_found"] = True
                result["vulnerability_details"] = f"HIGH: {scenario['current_role']} can perform {scenario['target_role']} operations"
                result["risk_level"] = "HIGH"
        
        elif response.status_code == 403:
            # Proper privilege enforcement
            result["vulnerability_found"] = False
            result["vulnerability_details"] = "Proper privilege enforcement"
        
        return result
    
    def _analyze_function_authorization(self, response: requests.Response, scenario: Dict) -> Dict:
        """Analyze response for function-level authorization indicators"""
        result = {
            "scenario": scenario["description"],
            "function": scenario["function"],
            "role": scenario["role"],
            "status_code": response.status_code,
            "response_length": len(response.text),
            "vulnerability_found": False,
            "vulnerability_details": None,
            "risk_level": "LOW"
        }
        
        # Check for function-level authorization violations
        if response.status_code == 200 and len(response.text) > 0:
            if scenario["function"] in ["admin", "system"] and scenario["role"] in ["user", "guest"]:
                result["vulnerability_found"] = True
                result["vulnerability_details"] = f"HIGH: {scenario['role']} can access {scenario['function']} functions"
                result["risk_level"] = "HIGH"
            elif scenario["function"] == "delete" and scenario["role"] == "user":
                result["vulnerability_found"] = True
                result["vulnerability_details"] = f"MEDIUM: {scenario['role']} can perform {scenario['function']} operations"
                result["risk_level"] = "MEDIUM"
        
        elif response.status_code == 403:
            # Proper function-level authorization enforcement
            result["vulnerability_found"] = False
            result["vulnerability_details"] = "Proper function-level authorization enforcement"
        
        return result
    
    def _contains_admin_functionality(self, response_text: str) -> bool:
        """Check if response contains admin functionality indicators"""
        admin_patterns = [
            "admin", "administrator", "super_user", "root", "system",
            "delete", "remove", "drop", "truncate", "exec", "execute",
            "config", "settings", "users", "roles", "permissions"
        ]
        
        return any(pattern in response_text.lower() for pattern in admin_patterns)
    
    def _assess_rbac_vulnerability_level(self, test_results: List[Dict]) -> str:
        """Assess overall RBAC vulnerability level"""
        critical_count = sum(1 for r in test_results if r.get("risk_level") == "CRITICAL")
        high_count = sum(1 for r in test_results if r.get("risk_level") == "HIGH")
        
        if critical_count > 0:
            return "CRITICAL"
        elif high_count > 0:
            return "HIGH"
        else:
            return "LOW"
    
    def _assess_privilege_escalation_level(self, test_results: List[Dict]) -> str:
        """Assess overall privilege escalation vulnerability level"""
        critical_count = sum(1 for r in test_results if r.get("risk_level") == "CRITICAL")
        high_count = sum(1 for r in test_results if r.get("risk_level") == "HIGH")
        
        if critical_count > 0:
            return "CRITICAL"
        elif high_count > 0:
            return "HIGH"
        else:
            return "LOW"
    
    def _assess_function_authorization_level(self, test_results: List[Dict]) -> str:
        """Assess overall function-level authorization vulnerability level"""
        high_count = sum(1 for r in test_results if r.get("risk_level") == "HIGH")
        medium_count = sum(1 for r in test_results if r.get("risk_level") == "MEDIUM")
        
        if high_count > 0:
            return "HIGH"
        elif medium_count > 0:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _generate_rbac_poc(self, endpoint_path: str, method: str, test_results: List[Dict]) -> str:
        """Generate proof-of-concept for RBAC vulnerabilities"""
        vulnerable_scenarios = [r for r in test_results if r.get("vulnerability_found")]
        
        poc = f"""# RBAC Vulnerability Proof of Concept
# Target: {endpoint_path}
# Method: {method}
# Vulnerabilities Found: {len(vulnerable_scenarios)}

import requests

url = "{self.base_url}{endpoint_path}"

# Test Results Summary:
"""
        
        for scenario in vulnerable_scenarios:
            poc += f"""
# Role: {scenario['role']}
# - Risk Level: {scenario['risk_level']}
# - Vulnerability: {scenario['vulnerability_details']}
"""
        
        poc += f"""
# Proof of Concept Script
def test_rbac_vulnerability():
    # Test anonymous access
    response = requests.get(url)
    print(f"Anonymous access: {{response.status_code}} - {{len(response.text)}} chars")
    
    # Test different role tokens
    role_tokens = {{
        "guest": "Bearer guest_token",
        "user": "Bearer user_token", 
        "admin": "Bearer admin_token",
        "super_admin": "Bearer super_admin_token"
    }}
    
    for role, token in role_tokens.items():
        headers = {{"Authorization": token}}
        response = requests.get(url, headers=headers)
        print(f"{{role}} role: {{response.status_code}} - {{len(response.text)}} chars")

if __name__ == "__main__":
    test_rbac_vulnerability()
    print("\\n🔍 Check responses for unauthorized role access!")
    print("✅ If lower roles can access admin functions, RBAC vulnerability confirmed!")
"""
        
        return poc
    
    def _generate_privilege_escalation_poc(self, endpoint_path: str, method: str, test_results: List[Dict]) -> str:
        """Generate proof-of-concept for privilege escalation vulnerabilities"""
        vulnerable_scenarios = [r for r in test_results if r.get("vulnerability_found")]
        
        poc = f"""# Privilege Escalation Vulnerability Proof of Concept
# Target: {endpoint_path}
# Method: {method}
# Vulnerabilities Found: {len(vulnerable_scenarios)}

import requests

url = "{self.base_url}{endpoint_path}"

# Test Results Summary:
"""
        
        for scenario in vulnerable_scenarios:
            poc += f"""
# {scenario['scenario']}
# - Current Role: {scenario['current_role']}
# - Target Role: {scenario['target_role']}
# - Risk Level: {scenario['risk_level']}
# - Vulnerability: {scenario['vulnerability_details']}
"""
        
        poc += f"""
# Proof of Concept Script
def test_privilege_escalation():
    # Test privilege escalation scenarios
    escalation_tests = [
        {{"current": "user", "target": "admin", "token": "Bearer user_token"}},
        {{"current": "guest", "target": "user", "token": "Bearer guest_token"}},
        {{"current": "readonly", "target": "write", "token": "Bearer readonly_token"}}
    ]
    
    for test in escalation_tests:
        headers = {{"Authorization": test['token']}}
        response = requests.get(url, headers=headers)
        print(f"{{test['current']}} -> {{test['target']}}: {{response.status_code}} - {{len(response.text)}} chars")

if __name__ == "__main__":
    test_privilege_escalation()
    print("\\n🔍 Check responses for privilege escalation!")
    print("✅ If lower privileges can access higher functions, escalation vulnerability confirmed!")
"""
        
        return poc
    
    def _generate_function_authorization_poc(self, endpoint_path: str, method: str, test_results: List[Dict]) -> str:
        """Generate proof-of-concept for function-level authorization vulnerabilities"""
        vulnerable_scenarios = [r for r in test_results if r.get("vulnerability_found")]
        
        poc = f"""# Function-Level Authorization Vulnerability Proof of Concept
# Target: {endpoint_path}
# Method: {method}
# Vulnerabilities Found: {len(vulnerable_scenarios)}

import requests

url = "{self.base_url}{endpoint_path}"

# Test Results Summary:
"""
        
        for scenario in vulnerable_scenarios:
            poc += f"""
# {scenario['scenario']}
# - Function: {scenario['function']}
# - Role: {scenario['role']}
# - Risk Level: {scenario['risk_level']}
# - Vulnerability: {scenario['vulnerability_details']}
"""
        
        poc += f"""
# Proof of Concept Script
def test_function_authorization():
    # Test function-level access control
    function_tests = [
        {{"function": "read", "role": "guest", "token": "Bearer guest_token"}},
        {{"function": "write", "role": "user", "token": "Bearer user_token"}},
        {{"function": "admin", "role": "user", "token": "Bearer user_token"}},
        {{"function": "system", "role": "admin", "token": "Bearer admin_token"}}
    ]
    
    for test in function_tests:
        headers = {{"Authorization": test['token']}}
        response = requests.get(url, headers=headers)
        print(f"{{test['function']}} function with {{test['role']}} role: {{response.status_code}} - {{len(response.text)}} chars")

if __name__ == "__main__":
    test_function_authorization()
    print("\\n🔍 Check responses for function-level authorization bypass!")
    print("✅ If unauthorized roles can access restricted functions, vulnerability confirmed!")
"""
        
        return poc
    
    def _detect_sql_injection(self, response: requests.Response) -> bool:
        """Detect SQL injection vulnerability from response"""
        if response.status_code == 500:
            response_text = response.text.lower()
            sql_error_patterns = [
                "sql syntax", "mysql", "postgresql", "oracle", "sqlite",
                "syntax error", "unclosed quotation mark", "incorrect syntax",
                "division by zero", "overflow", "conversion failed"
            ]
            return any(pattern in response_text for pattern in sql_error_patterns)
        return False
    
    def _detect_nosql_injection(self, response: requests.Response) -> bool:
        """Detect NoSQL injection vulnerability from response"""
        if response.status_code == 500:
            response_text = response.text.lower()
            nosql_error_patterns = [
                "mongodb", "mongoose", "bson", "json", "javascript",
                "eval", "where", "regex", "aggregation", "pipeline"
            ]
            return any(pattern in response_text for pattern in nosql_error_patterns)
        return False
    
    def _generate_proof_of_concept(self, vulnerability_type: str, payload: str, 
                                  endpoint_path: str, method: str, param: str = None) -> str:
        """Generate proof-of-concept for vulnerabilities"""
        poc = f"""# {vulnerability_type} Vulnerability Proof of Concept
# Target: {endpoint_path}
# Method: {method}
# Parameter: {param if param else 'N/A'}

import requests

url = "{self.base_url}{endpoint_path}"
"""
        
        if vulnerability_type == "SQL Injection":
            poc += f"""
# SQL Injection POC
payload = "{payload}"

if "{method}" == "GET":
    params = {{"{param}": payload}} if "{param}" else {{}}
    response = requests.get(url, params=params)
else:
    data = {{"{param}": payload}} if "{param}" else {{}}
    response = requests.post(url, json=data)

print(f"Status: {{response.status_code}}")
print(f"Response: {{response.text[:200]}}...")

# Check for SQL errors in response
if response.status_code == 500 and any(error in response.text.lower() for error in ["sql", "mysql", "syntax"]):
    print("✅ SQL Injection vulnerability confirmed!")
"""
        elif vulnerability_type == "NoSQL Injection":
            poc += f"""
# NoSQL Injection POC
payload = {payload}

if "{method}" == "GET":
    params = {{"{param}": payload}} if "{param}" else {{}}
    response = requests.get(url, params=params)
else:
    data = {{"{param}": payload}} if "{param}" else {{}}
    response = requests.post(url, json=data)

print(f"Status: {{response.status_code}}")
print(f"Response: {{response.text[:200]}}...")

# Check for NoSQL errors in response
if response.status_code == 500 and any(error in response.text.lower() for error in ["mongodb", "bson", "json"]):
    print("✅ NoSQL Injection vulnerability confirmed!")
"""
        elif vulnerability_type == "XSS":
            poc += f"""
# XSS Injection POC
payload = "{payload}"

if "{method}" == "GET":
    params = {{"{param}": payload}} if "{param}" else {{}}
    response = requests.get(url, params=params)
else:
    data = {{"{param}": payload}} if "{param}" else {{}}
    response = requests.post(url, json=data)

print(f"Status: {{response.status_code}}")
print(f"Response: {{response.text[:200]}}...")

# Check if XSS payload is reflected in response
if payload in response.text:
    print("✅ XSS vulnerability confirmed!")
"""
        elif vulnerability_type == "Authentication Bypass":
            poc += f"""
# Authentication Bypass POC
url = "{self.base_url}{endpoint_path}"

# Test without authentication
response = requests.{method.lower()}(url)
print(f"No auth: {{response.status_code}}")

# Test with fake authentication
headers = {{"Authorization": "Bearer fake_token"}}
response = requests.{method.lower()}(url, headers=headers)
print(f"Fake auth: {{response.status_code}}")

if response.status_code == 200:
    print("✅ Authentication bypass vulnerability confirmed!")
"""
        elif vulnerability_type == "JWT Vulnerability":
            poc += f"""
# JWT Vulnerability POC
url = "{self.base_url}{endpoint_path}"

# Test with tampered JWT
tampered_jwt = "{payload}"
headers = {{"Authorization": f"Bearer {{tampered_jwt}}"}}

response = requests.{method.lower()}(url, headers=headers)
print(f"Tampered JWT: {{response.status_code}}")

if response.status_code == 200:
    print("✅ JWT vulnerability confirmed!")
"""
        elif vulnerability_type == "Missing Security Headers":
            poc += f"""
# Missing Security Headers POC
url = "{self.base_url}{endpoint_path}"

response = requests.{method.lower()}(url)
print(f"Status: {{response.status_code}}")
print("\\nSecurity Headers Check:")
print(f"X-Content-Type-Options: {{response.headers.get('X-Content-Type-Options', 'MISSING')}}")
print(f"X-Frame-Options: {{response.headers.get('X-Frame-Options', 'MISSING')}}")
print(f"X-XSS-Protection: {{response.headers.get('X-XSS-Protection', 'MISSING')}}")
print(f"Strict-Transport-Security: {{response.headers.get('Strict-Transport-Security', 'MISSING')}}")
print(f"Content-Security-Policy: {{response.headers.get('Content-Security-Policy', 'MISSING')}}")

missing_headers = [h for h in ["X-Content-Type-Options", "X-Frame-Options", "X-XSS-Protection", 
                               "Strict-Transport-Security", "Content-Security-Policy"] 
                if h not in response.headers]

if missing_headers:
    print(f"\\n❌ Missing security headers: {{', '.join(missing_headers)}}")
"""
        
        poc += f"""
if __name__ == "__main__":
    print("🔍 Running {vulnerability_type} vulnerability test...")
    print("\\n📋 Check the response for vulnerability indicators!")
"""
        
        return poc
    
    def _calculate_endpoint_risk_score(self, security_tests: List[SecurityTest]) -> float:
        """Calculate overall risk score for an endpoint based on security test results"""
        if not security_tests:
            return 0.0
        
        # Calculate weighted risk score based on vulnerability severity
        total_score = 0.0
        max_possible_score = 0.0
        
        for test in security_tests:
            if test.vulnerability_found:
                # Weight vulnerabilities by severity
                if test.severity == VulnerabilitySeverity.CRITICAL:
                    weight = 10.0
                elif test.severity == VulnerabilitySeverity.HIGH:
                    weight = 7.0
                elif test.severity == VulnerabilitySeverity.MEDIUM:
                    weight = 4.0
                elif test.severity == VulnerabilitySeverity.LOW:
                    weight = 2.0
                else:
                    weight = 0.0
                
                total_score += weight
                max_possible_score += 10.0  # Maximum score per test
        
        # Normalize to 0-10 scale
        if max_possible_score > 0:
            return min(10.0, (total_score / max_possible_score) * 10.0)
        else:
            return 0.0
    
    def _generate_endpoint_summary(self, endpoint_path: str, http_methods: List[str], 
                                  security_tests: List[SecurityTest]) -> Dict[str, Any]:
        """Generate summary for an endpoint based on security test results"""
        total_tests = len(security_tests)
        tests_passed = sum(1 for test in security_tests if not test.vulnerability_found)
        tests_failed = sum(1 for test in security_tests if test.vulnerability_found)
        
        # Count vulnerabilities by severity
        critical_vulnerabilities = sum(1 for test in security_tests 
                                     if test.vulnerability_found and test.severity == VulnerabilitySeverity.CRITICAL)
        high_vulnerabilities = sum(1 for test in security_tests 
                                 if test.vulnerability_found and test.severity == VulnerabilitySeverity.HIGH)
        medium_vulnerabilities = sum(1 for test in security_tests 
                                   if test.vulnerability_found and test.severity == VulnerabilitySeverity.MEDIUM)
        low_vulnerabilities = sum(1 for test in security_tests 
                                if test.vulnerability_found and test.severity == VulnerabilitySeverity.LOW)
        
        # Calculate overall risk score
        overall_risk_score = self._calculate_endpoint_risk_score(security_tests)
        
        # Generate recommendations
        recommendations = []
        if critical_vulnerabilities > 0:
            recommendations.append("Immediate action required for critical vulnerabilities")
        if high_vulnerabilities > 0:
            recommendations.append("High priority remediation needed")
        if medium_vulnerabilities > 0:
            recommendations.append("Medium priority fixes recommended")
        if low_vulnerabilities > 0:
            recommendations.append("Low priority improvements suggested")
        
        if not recommendations:
            recommendations.append("No immediate security concerns detected")
        
        return {
            "endpoint_path": endpoint_path,
            "http_methods": http_methods,
            "total_tests": total_tests,
            "tests_passed": tests_passed,
            "tests_failed": tests_failed,
            "vulnerabilities_found": tests_failed,
            "critical_vulnerabilities": critical_vulnerabilities,
            "high_vulnerabilities": high_vulnerabilities,
            "medium_vulnerabilities": medium_vulnerabilities,
            "low_vulnerabilities": low_vulnerabilities,
            "overall_risk_score": overall_risk_score,
            "security_tests": [test.__dict__ for test in security_tests],
            "summary": self._generate_summary_text(security_tests),
            "recommendations": recommendations,
            "test_timestamp": datetime.now().isoformat()
        }
    
    def _generate_summary_text(self, security_tests: List[SecurityTest]) -> str:
        """Generate human-readable summary text for security test results"""
        if not security_tests:
            return "No security tests performed"
        
        total_vulnerabilities = sum(1 for test in security_tests if test.vulnerability_found)
        
        if total_vulnerabilities == 0:
            return "All security tests passed. No vulnerabilities detected."
        
        # Count by severity
        critical = sum(1 for test in security_tests 
                      if test.vulnerability_found and test.severity == VulnerabilitySeverity.CRITICAL)
        high = sum(1 for test in security_tests 
                  if test.vulnerability_found and test.severity == VulnerabilitySeverity.HIGH)
        medium = sum(1 for test in security_tests 
                    if test.vulnerability_found and test.severity == VulnerabilitySeverity.MEDIUM)
        low = sum(1 for test in security_tests 
                 if test.vulnerability_found and test.severity == VulnerabilitySeverity.LOW)
        
        summary_parts = []
        if critical > 0:
            summary_parts.append(f"{critical} critical")
        if high > 0:
            summary_parts.append(f"{high} high")
        if medium > 0:
            summary_parts.append(f"{medium} medium")
        if low > 0:
            summary_parts.append(f"{low} low")
        
        severity_text = ", ".join(summary_parts)
        return f"Found {total_vulnerabilities} vulnerabilities: {severity_text} severity issues detected."
    
    def _generate_endpoint_recommendations(self, security_tests: List[SecurityTest]) -> List[str]:
        """Generate recommendations based on security test results"""
        recommendations = []
        
        for test in security_tests:
            if test.vulnerability_found and test.recommendations:
                recommendations.extend(test.recommendations)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_recommendations = []
        for rec in recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recommendations.append(rec)
        
        return unique_recommendations