#!/usr/bin/env python3
"""
Business Logic Vulnerability Testing Module

This module implements comprehensive business logic vulnerability testing
including workflow manipulation, state machine bypass, transaction integrity,
and business rule validation testing.
"""

import json
import time
import asyncio
import hashlib
import hmac
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import requests
import jwt
from datetime import datetime, timedelta


class BusinessLogicTestType(Enum):
    """Types of business logic tests"""
    WORKFLOW_MANIPULATION = "workflow_manipulation"
    STATE_MACHINE_BYPASS = "state_machine_bypass"
    TRANSACTION_INTEGRITY = "transaction_integrity"
    BUSINESS_RULE_BYPASS = "business_rule_bypass"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    AUTHORIZATION_ESCAPE = "authorization_escape"
    RATE_LIMIT_BYPASS = "rate_limit_bypass"
    SESSION_MANIPULATION = "session_manipulation"
    DATA_INTEGRITY = "data_integrity"
    CONCURRENT_OPERATIONS = "concurrent_operations"


@dataclass
class BusinessLogicTest:
    """Business logic test definition"""
    test_type: BusinessLogicTestType
    name: str
    description: str
    test_method: str
    payload: Dict[str, Any]
    expected_behavior: str
    vulnerability_indicators: List[str]
    severity: str
    category: str
    target_endpoints: List[str]
    prerequisites: List[str]


class BusinessLogicTester:
    """Comprehensive business logic vulnerability tester"""
    
    def __init__(self, base_url: str, session):
        self.base_url = base_url
        self.session = session
        self.test_results = []
        self.jwt_secrets = self._generate_common_jwt_secrets()
    
    def _generate_common_jwt_secrets(self) -> List[str]:
        """Generate common JWT secrets for brute force testing"""
        return [
            "secret", "password", "123456", "admin", "test", "key",
            "jwt_secret", "api_key", "token_secret", "auth_secret",
            "vampi_secret", "vulnerable", "insecure", "default",
            "changeme", "secretkey", "jwtkey", "apisecret"
        ]
    
    async def test_workflow_manipulation(self, endpoint: str, method: str) -> Dict[str, Any]:
        """Test workflow manipulation vulnerabilities"""
        results = []
        
        # Test 1: Multi-step process bypass
        workflow_tests = [
            {
                "name": "Multi-Step Registration Bypass",
                "payload": {
                    "step": "3",
                    "completed_steps": ["1", "2", "3"],
                    "skip_verification": "true",
                    "force_complete": "true"
                },
                "expected_behavior": "Skips required verification steps"
            },
            {
                "name": "State Machine Bypass",
                "payload": {
                    "current_state": "completed",
                    "next_state": "admin",
                    "skip_validation": "true",
                    "force_state": "admin"
                },
                "expected_behavior": "Bypasses state machine controls"
            },
            {
                "name": "Workflow Step Skipping",
                "payload": {
                    "completed_steps": ["1", "2", "3", "4"],
                    "current_step": "5",
                    "skip_to_final": "true",
                    "bypass_intermediate": "true"
                },
                "expected_behavior": "Skips to final step without validation"
            }
        ]
        
        for test in workflow_tests:
            result = await self._execute_business_logic_test(
                endpoint, method, test, BusinessLogicTestType.WORKFLOW_MANIPULATION
            )
            results.append(result)
        
        return {
            "endpoint": endpoint,
            "method": method,
            "test_type": "workflow_manipulation",
            "results": results,
            "total_tests": len(results),
            "vulnerabilities_found": sum(1 for r in results if r.get("vulnerability_found", False))
        }
    
    async def test_authentication_bypass(self, endpoint: str, method: str) -> Dict[str, Any]:
        """Test authentication bypass vulnerabilities"""
        results = []
        
        # Test 1: JWT Algorithm Confusion
        jwt_algorithm_confusion = {
            "name": "JWT Algorithm Confusion",
            "payload": {
                "Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0."
            },
            "expected_behavior": "Bypasses JWT validation using 'none' algorithm"
        }
        
        result = await self._execute_business_logic_test(
            endpoint, method, jwt_algorithm_confusion, BusinessLogicTestType.AUTHENTICATION_BYPASS
        )
        results.append(result)
        
        # Test 2: JWT Secret Brute Force
        for secret in self.jwt_secrets[:5]:  # Test first 5 secrets
            try:
                # Create JWT with common secret
                payload = {
                    "sub": "admin",
                    "role": "admin",
                    "exp": int((datetime.now() + timedelta(days=1)).timestamp())
                }
                token = jwt.encode(payload, secret, algorithm="HS256")
                
                jwt_brute_force = {
                    "name": f"JWT Secret Brute Force - {secret}",
                    "payload": {
                        "Authorization": f"Bearer {token}"
                    },
                    "expected_behavior": f"Bypasses JWT validation using secret: {secret}"
                }
                
                result = await self._execute_business_logic_test(
                    endpoint, method, jwt_brute_force, BusinessLogicTestType.AUTHENTICATION_BYPASS
                )
                results.append(result)
                
            except Exception as e:
                results.append({
                    "name": f"JWT Secret Brute Force - {secret}",
                    "error": str(e),
                    "vulnerability_found": False
                })
        
        # Test 3: Missing Authentication
        missing_auth = {
            "name": "Missing Authentication Test",
            "payload": {},
            "expected_behavior": "Accesses protected endpoint without authentication"
        }
        
        result = await self._execute_business_logic_test(
            endpoint, method, missing_auth, BusinessLogicTestType.AUTHENTICATION_BYPASS
        )
        results.append(result)
        
        # Test 4: Weak Authentication
        weak_auth = {
            "name": "Weak Authentication Test",
            "payload": {
                "Authorization": "Bearer invalid_token",
                "X-API-Key": "test",
                "X-Auth-Token": "weak_token"
            },
            "expected_behavior": "Bypasses authentication with weak tokens"
        }
        
        result = await self._execute_business_logic_test(
            endpoint, method, weak_auth, BusinessLogicTestType.AUTHENTICATION_BYPASS
        )
        results.append(result)
        
        return {
            "endpoint": endpoint,
            "method": method,
            "test_type": "authentication_bypass",
            "results": results,
            "total_tests": len(results),
            "vulnerabilities_found": sum(1 for r in results if r.get("vulnerability_found", False))
        }
    
    async def test_authorization_escape(self, endpoint: str, method: str) -> Dict[str, Any]:
        """Test authorization escape vulnerabilities"""
        results = []
        
        # Test 1: Role Escalation via Parameter Pollution
        role_escalation_tests = [
            {
                "name": "Role Escalation via Parameter Pollution",
                "payload": {
                    "role": "user",
                    "role": "admin",
                    "is_admin": "true",
                    "permissions": "all"
                },
                "expected_behavior": "Gains admin privileges through parameter pollution"
            },
            {
                "name": "IDOR via User ID Manipulation",
                "payload": {
                    "user_id": "1",
                    "target_user_id": "2",
                    "admin_override": "true"
                },
                "expected_behavior": "Accesses unauthorized user data"
            },
            {
                "name": "Privilege Escalation via Header Manipulation",
                "payload": {
                    "X-User-Role": "admin",
                    "X-Admin-Override": "true",
                    "X-Privilege-Level": "superuser"
                },
                "expected_behavior": "Escalates privileges through header manipulation"
            }
        ]
        
        for test in role_escalation_tests:
            result = await self._execute_business_logic_test(
                endpoint, method, test, BusinessLogicTestType.AUTHORIZATION_ESCAPE
            )
            results.append(result)
        
        return {
            "endpoint": endpoint,
            "method": method,
            "test_type": "authorization_escape",
            "results": results,
            "total_tests": len(results),
            "vulnerabilities_found": sum(1 for r in results if r.get("vulnerability_found", False))
        }
    
    async def test_rate_limit_bypass(self, endpoint: str, method: str) -> Dict[str, Any]:
        """Test rate limiting bypass vulnerabilities"""
        results = []
        
        # Test 1: Header Manipulation
        header_manipulation_tests = [
            {
                "name": "Rate Limit Bypass via X-Forwarded-For",
                "payload": {
                    "X-Forwarded-For": "127.0.0.1, 192.168.1.1, 10.0.0.1"
                },
                "expected_behavior": "Bypasses rate limiting using multiple IPs"
            },
            {
                "name": "Rate Limit Bypass via X-Real-IP",
                "payload": {
                    "X-Real-IP": "192.168.1.1",
                    "X-Client-IP": "10.0.0.1",
                    "X-Forwarded-For": "127.0.0.1"
                },
                "expected_behavior": "Bypasses rate limiting using conflicting IP headers"
            },
            {
                "name": "Rate Limit Bypass via User-Agent",
                "payload": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                },
                "expected_behavior": "Bypasses rate limiting using different User-Agent"
            }
        ]
        
        for test in header_manipulation_tests:
            result = await self._execute_business_logic_test(
                endpoint, method, test, BusinessLogicTestType.RATE_LIMIT_BYPASS
            )
            results.append(result)
        
        # Test 2: Concurrent Requests
        concurrent_test = await self._test_concurrent_rate_limit_bypass(endpoint, method)
        results.append(concurrent_test)
        
        return {
            "endpoint": endpoint,
            "method": method,
            "test_type": "rate_limit_bypass",
            "results": results,
            "total_tests": len(results),
            "vulnerabilities_found": sum(1 for r in results if r.get("vulnerability_found", False))
        }
    
    async def test_session_manipulation(self, endpoint: str, method: str) -> Dict[str, Any]:
        """Test session manipulation vulnerabilities"""
        results = []
        
        # Test 1: Session Fixation
        session_fixation_tests = [
            {
                "name": "Session Fixation Attack",
                "payload": {
                    "session_id": "fixed_session_123",
                    "force_session": "true",
                    "bypass_session_validation": "true"
                },
                "expected_behavior": "Hijacks user session through session fixation"
            },
            {
                "name": "Session Hijacking via Session ID",
                "payload": {
                    "session_id": "admin_session_456",
                    "user_id": "1",
                    "admin_override": "true"
                },
                "expected_behavior": "Hijacks admin session"
            },
            {
                "name": "Session Timeout Bypass",
                "payload": {
                    "session_id": "expired_session_789",
                    "extend_session": "true",
                    "bypass_timeout": "true"
                },
                "expected_behavior": "Bypasses session timeout"
            }
        ]
        
        for test in session_fixation_tests:
            result = await self._execute_business_logic_test(
                endpoint, method, test, BusinessLogicTestType.SESSION_MANIPULATION
            )
            results.append(result)
        
        return {
            "endpoint": endpoint,
            "method": method,
            "test_type": "session_manipulation",
            "results": results,
            "total_tests": len(results),
            "vulnerabilities_found": sum(1 for r in results if r.get("vulnerability_found", False))
        }
    
    async def test_data_integrity(self, endpoint: str, method: str) -> Dict[str, Any]:
        """Test data integrity vulnerabilities"""
        results = []
        
        # Test 1: Data Validation Bypass
        validation_bypass_tests = [
            {
                "name": "Password Policy Bypass",
                "payload": {
                    "password": "123456",
                    "password_confirmation": "123456",
                    "bypass_validation": "true",
                    "skip_policy_check": "true"
                },
                "expected_behavior": "Accepts weak password despite policy"
            },
            {
                "name": "Email Validation Bypass",
                "payload": {
                    "email": "invalid-email",
                    "bypass_email_validation": "true",
                    "skip_format_check": "true"
                },
                "expected_behavior": "Accepts invalid email format"
            },
            {
                "name": "Input Length Bypass",
                "payload": {
                    "username": "a" * 1000,
                    "bypass_length_check": "true",
                    "skip_size_validation": "true"
                },
                "expected_behavior": "Accepts input exceeding length limits"
            }
        ]
        
        for test in validation_bypass_tests:
            result = await self._execute_business_logic_test(
                endpoint, method, test, BusinessLogicTestType.DATA_INTEGRITY
            )
            results.append(result)
        
        return {
            "endpoint": endpoint,
            "method": method,
            "test_type": "data_integrity",
            "results": results,
            "total_tests": len(results),
            "vulnerabilities_found": sum(1 for r in results if r.get("vulnerability_found", False))
        }
    
    async def test_transaction_integrity(self, endpoint: str, method: str) -> Dict[str, Any]:
        """Test transaction integrity vulnerabilities"""
        results = []
        
        # Test 1: Transaction Rollback Bypass
        transaction_tests = [
            {
                "name": "Transaction Rollback Bypass",
                "payload": {
                    "transaction_id": "123",
                    "force_commit": "true",
                    "bypass_rollback": "true",
                    "skip_validation": "true"
                },
                "expected_behavior": "Commits transaction despite errors"
            },
            {
                "name": "Double Spending Attack",
                "payload": {
                    "amount": "100",
                    "duplicate_transaction": "true",
                    "bypass_double_spend_check": "true"
                },
                "expected_behavior": "Allows double spending"
            },
            {
                "name": "Transaction Replay Attack",
                "payload": {
                    "transaction_id": "replay_123",
                    "replay_transaction": "true",
                    "bypass_replay_protection": "true"
                },
                "expected_behavior": "Allows transaction replay"
            }
        ]
        
        for test in transaction_tests:
            result = await self._execute_business_logic_test(
                endpoint, method, test, BusinessLogicTestType.TRANSACTION_INTEGRITY
            )
            results.append(result)
        
        return {
            "endpoint": endpoint,
            "method": method,
            "test_type": "transaction_integrity",
            "results": results,
            "total_tests": len(results),
            "vulnerabilities_found": sum(1 for r in results if r.get("vulnerability_found", False))
        }
    
    async def _execute_business_logic_test(self, endpoint: str, method: str, 
                                         test: Dict[str, Any], test_type: BusinessLogicTestType) -> Dict[str, Any]:
        """Execute a business logic test"""
        try:
            url = f"{self.base_url}{endpoint}"
            
            # Prepare request based on method
            if method.upper() == "GET":
                response = self.session.get(url, params=test["payload"], timeout=30)
            elif method.upper() == "POST":
                response = self.session.post(url, json=test["payload"], timeout=30)
            elif method.upper() == "PUT":
                response = self.session.put(url, json=test["payload"], timeout=30)
            elif method.upper() == "DELETE":
                response = self.session.delete(url, json=test["payload"], timeout=30)
            else:
                response = self.session.request(method, url, json=test["payload"], timeout=30)
            
            # Analyze response for vulnerability indicators
            vulnerability_found = self._analyze_business_logic_response(response, test, test_type)
            
            return {
                "test_name": test["name"],
                "test_type": test_type.value,
                "payload": test["payload"],
                "expected_behavior": test["expected_behavior"],
                "status_code": response.status_code,
                "response_length": len(response.text),
                "response_headers": dict(response.headers),
                "vulnerability_found": vulnerability_found,
                "vulnerability_indicators": self._get_vulnerability_indicators(response, test_type),
                "severity": self._determine_severity(test_type, vulnerability_found),
                "category": test_type.value.replace("_", " ").title()
            }
            
        except Exception as e:
            return {
                "test_name": test["name"],
                "test_type": test_type.value,
                "error": str(e),
                "vulnerability_found": False,
                "severity": "Info",
                "category": test_type.value.replace("_", " ").title()
            }
    
    async def _test_concurrent_rate_limit_bypass(self, endpoint: str, method: str) -> Dict[str, Any]:
        """Test concurrent rate limit bypass"""
        try:
            url = f"{self.base_url}{endpoint}"
            
            # Create concurrent requests
            tasks = []
            for i in range(10):  # 10 concurrent requests
                if method.upper() == "GET":
                    task = self._make_concurrent_request(self.session.get, url, {})
                elif method.upper() == "POST":
                    task = self._make_concurrent_request(self.session.post, url, {})
                else:
                    task = self._make_concurrent_request(self.session.request, url, {}, method)
                tasks.append(task)
            
            # Execute concurrent requests
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Analyze for rate limit bypass
            valid_responses = [r for r in responses if hasattr(r, 'status_code')]
            successful_requests = len([r for r in valid_responses if r.status_code == 200])
            
            # Rate limit bypass if more than 5 requests succeed
            vulnerability_found = successful_requests > 5
            
            return {
                "test_name": "Concurrent Rate Limit Bypass",
                "test_type": BusinessLogicTestType.RATE_LIMIT_BYPASS.value,
                "concurrent_requests": 10,
                "successful_requests": successful_requests,
                "vulnerability_found": vulnerability_found,
                "severity": "High" if vulnerability_found else "Info",
                "category": "Rate Limit Bypass"
            }
            
        except Exception as e:
            return {
                "test_name": "Concurrent Rate Limit Bypass",
                "test_type": BusinessLogicTestType.RATE_LIMIT_BYPASS.value,
                "error": str(e),
                "vulnerability_found": False,
                "severity": "Info",
                "category": "Rate Limit Bypass"
            }
    
    async def _make_concurrent_request(self, request_func, url, payload, method=None):
        """Make a concurrent request"""
        try:
            if method:
                return request_func(method, url, json=payload, timeout=30)
            elif request_func == self.session.get:
                return request_func(url, params=payload, timeout=30)
            else:
                return request_func(url, json=payload, timeout=30)
        except Exception as e:
            return e
    
    def _analyze_business_logic_response(self, response, test: Dict[str, Any], 
                                       test_type: BusinessLogicTestType) -> bool:
        """Analyze response for business logic vulnerability indicators"""
        if response.status_code == 200:
            response_text = response.text.lower()
            
            # Check for success indicators that shouldn't be present
            success_indicators = [
                "success", "completed", "verified", "approved", "authenticated",
                "authorized", "admin", "privileged", "access granted", "login successful"
            ]
            
            # Check for error indicators that suggest vulnerability
            error_indicators = [
                "error", "failed", "unauthorized", "forbidden", "invalid",
                "denied", "rejected", "blocked"
            ]
            
            # For authentication bypass, look for success without proper auth
            if test_type == BusinessLogicTestType.AUTHENTICATION_BYPASS:
                return any(indicator in response_text for indicator in success_indicators)
            
            # For authorization escape, look for admin/privileged access
            elif test_type == BusinessLogicTestType.AUTHORIZATION_ESCAPE:
                admin_indicators = ["admin", "privileged", "superuser", "root", "elevated"]
                return any(indicator in response_text for indicator in admin_indicators)
            
            # For rate limit bypass, check if request succeeded
            elif test_type == BusinessLogicTestType.RATE_LIMIT_BYPASS:
                return response.status_code == 200
            
            # For other tests, look for unexpected success
            else:
                return any(indicator in response_text for indicator in success_indicators)
        
        return False
    
    def _get_vulnerability_indicators(self, response, test_type: BusinessLogicTestType) -> List[str]:
        """Get specific vulnerability indicators from response"""
        indicators = []
        response_text = response.text.lower()
        
        if test_type == BusinessLogicTestType.AUTHENTICATION_BYPASS:
            if "authenticated" in response_text:
                indicators.append("Authentication bypass successful")
            if "admin" in response_text:
                indicators.append("Admin access gained")
            if "token" in response_text and "valid" in response_text:
                indicators.append("Token validation bypassed")
        
        elif test_type == BusinessLogicTestType.AUTHORIZATION_ESCAPE:
            if "admin" in response_text:
                indicators.append("Admin privileges gained")
            if "privileged" in response_text:
                indicators.append("Privileged access obtained")
            if "unauthorized" not in response_text:
                indicators.append("Authorization bypassed")
        
        elif test_type == BusinessLogicTestType.RATE_LIMIT_BYPASS:
            if response.status_code == 200:
                indicators.append("Rate limiting bypassed")
            if "limit" not in response_text.lower():
                indicators.append("No rate limit enforcement detected")
        
        return indicators
    
    def _determine_severity(self, test_type: BusinessLogicTestType, vulnerability_found: bool) -> str:
        """Determine severity based on test type and result"""
        if not vulnerability_found:
            return "Info"
        
        severity_map = {
            BusinessLogicTestType.AUTHENTICATION_BYPASS: "Critical",
            BusinessLogicTestType.AUTHORIZATION_ESCAPE: "Critical",
            BusinessLogicTestType.WORKFLOW_MANIPULATION: "High",
            BusinessLogicTestType.TRANSACTION_INTEGRITY: "High",
            BusinessLogicTestType.SESSION_MANIPULATION: "High",
            BusinessLogicTestType.RATE_LIMIT_BYPASS: "Medium",
            BusinessLogicTestType.DATA_INTEGRITY: "Medium",
            BusinessLogicTestType.STATE_MACHINE_BYPASS: "High",
            BusinessLogicTestType.BUSINESS_RULE_BYPASS: "Medium",
            BusinessLogicTestType.CONCURRENT_OPERATIONS: "Medium"
        }
        
        return severity_map.get(test_type, "Medium")
    
    async def run_comprehensive_business_logic_tests(self, endpoint: str, method: str) -> Dict[str, Any]:
        """Run all business logic tests for an endpoint"""
        all_results = {}
        
        # Run all test types
        test_functions = [
            ("workflow_manipulation", self.test_workflow_manipulation),
            ("authentication_bypass", self.test_authentication_bypass),
            ("authorization_escape", self.test_authorization_escape),
            ("rate_limit_bypass", self.test_rate_limit_bypass),
            ("session_manipulation", self.test_session_manipulation),
            ("data_integrity", self.test_data_integrity),
            ("transaction_integrity", self.test_transaction_integrity)
        ]
        
        for test_name, test_func in test_functions:
            try:
                result = await test_func(endpoint, method)
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
            "test_type": "comprehensive_business_logic",
            "results": all_results,
            "total_tests": total_tests,
            "total_vulnerabilities": total_vulnerabilities,
            "vulnerability_rate": (total_vulnerabilities / total_tests * 100) if total_tests > 0 else 0
        }