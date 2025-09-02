#!/usr/bin/env python3
"""
Race Condition and Concurrent Operation Testing Module

This module implements comprehensive race condition testing including
concurrent user operations, resource contention, and timing-based
vulnerabilities.
"""

import json
import time
import asyncio
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import requests


class RaceConditionTestType(Enum):
    """Types of race condition tests"""
    CONCURRENT_USER_CREATION = "concurrent_user_creation"
    CONCURRENT_PASSWORD_RESET = "concurrent_password_reset"
    CONCURRENT_BOOK_CREATION = "concurrent_book_creation"
    CONCURRENT_AUTHENTICATION = "concurrent_authentication"
    CONCURRENT_DATA_MODIFICATION = "concurrent_data_modification"
    RESOURCE_CONTENTION = "resource_contention"
    TIMING_ATTACK = "timing_attack"
    CONCURRENT_SESSION_MANAGEMENT = "concurrent_session_management"


@dataclass
class RaceConditionTest:
    """Race condition test definition"""
    test_type: RaceConditionTestType
    name: str
    description: str
    test_method: str
    payload: Dict[str, Any]
    concurrent_requests: int
    expected_behavior: str
    vulnerability_indicators: List[str]
    severity: str
    category: str
    target_endpoints: List[str]
    prerequisites: List[str]


class RaceConditionTester:
    """Tester for race condition and concurrent operation vulnerabilities"""
    
    def __init__(self, base_url: str, session):
        self.base_url = base_url
        self.session = session
        self.race_condition_patterns = self._initialize_race_condition_patterns()
    
    def _initialize_race_condition_patterns(self) -> List[RaceConditionTest]:
        """Initialize race condition vulnerability patterns"""
        patterns = []
        
        # Concurrent user creation patterns
        concurrent_user_patterns = [
            RaceConditionTest(
                test_type=RaceConditionTestType.CONCURRENT_USER_CREATION,
                name="Concurrent User Registration with Same Email",
                description="Attempt to create multiple users with the same email address simultaneously",
                test_method="POST",
                payload={
                    "username": "testuser",
                    "email": "test@example.com",
                    "password": "password123",
                    "confirm_password": "password123"
                },
                concurrent_requests=5,
                expected_behavior="May create duplicate users or bypass validation",
                vulnerability_indicators=["duplicate user", "email already exists", "user created", "validation bypassed"],
                severity="Medium",
                category="Concurrent User Creation",
                target_endpoints=["/users/v1/register"],
                prerequisites=["User registration", "Concurrent request handling", "Email validation"]
            ),
            
            RaceConditionTest(
                test_type=RaceConditionTestType.CONCURRENT_USER_CREATION,
                name="Concurrent User Registration with Same Username",
                description="Attempt to create multiple users with the same username simultaneously",
                test_method="POST",
                payload={
                    "username": "admin",
                    "email": "admin@example.com",
                    "password": "password123",
                    "confirm_password": "password123"
                },
                concurrent_requests=5,
                expected_behavior="May create duplicate usernames or bypass validation",
                vulnerability_indicators=["duplicate username", "username already exists", "user created", "validation bypassed"],
                severity="Medium",
                category="Concurrent User Creation",
                target_endpoints=["/users/v1/register"],
                prerequisites=["User registration", "Concurrent request handling", "Username validation"]
            ),
            
            RaceConditionTest(
                test_type=RaceConditionTestType.CONCURRENT_USER_CREATION,
                name="Concurrent Admin User Creation",
                description="Attempt to create multiple admin users simultaneously",
                test_method="POST",
                payload={
                    "username": "admin",
                    "email": "admin@example.com",
                    "password": "admin123",
                    "confirm_password": "admin123",
                    "role": "admin"
                },
                concurrent_requests=3,
                expected_behavior="May create multiple admin users",
                vulnerability_indicators=["admin user created", "multiple admins", "privilege escalation"],
                severity="High",
                category="Concurrent User Creation",
                target_endpoints=["/users/v1/register"],
                prerequisites=["User registration", "Admin role assignment", "Concurrent request handling"]
            )
        ]
        
        # Concurrent password reset patterns
        concurrent_password_patterns = [
            RaceConditionTest(
                test_type=RaceConditionTestType.CONCURRENT_PASSWORD_RESET,
                name="Concurrent Password Reset Requests",
                description="Request multiple password resets for the same user simultaneously",
                test_method="POST",
                payload={
                    "email": "admin@example.com",
                    "action": "reset_password"
                },
                concurrent_requests=10,
                expected_behavior="May bypass rate limiting or create multiple reset tokens",
                vulnerability_indicators=["multiple reset tokens", "rate limit bypassed", "reset email sent"],
                severity="Medium",
                category="Concurrent Password Reset",
                target_endpoints=["/users/v1/password/reset"],
                prerequisites=["Password reset functionality", "Rate limiting", "Email sending"]
            ),
            
            RaceConditionTest(
                test_type=RaceConditionTestType.CONCURRENT_PASSWORD_RESET,
                name="Concurrent Password Reset Token Usage",
                description="Use the same password reset token multiple times simultaneously",
                test_method="POST",
                payload={
                    "token": "reset_token_123",
                    "new_password": "newpassword123",
                    "confirm_password": "newpassword123"
                },
                concurrent_requests=5,
                expected_behavior="May allow multiple password changes with same token",
                vulnerability_indicators=["password changed", "token reused", "multiple changes"],
                severity="High",
                category="Concurrent Password Reset",
                target_endpoints=["/users/v1/password/reset/confirm"],
                prerequisites=["Password reset token validation", "Token usage tracking"]
            )
        ]
        
        # Concurrent book creation patterns
        concurrent_book_patterns = [
            RaceConditionTest(
                test_type=RaceConditionTestType.CONCURRENT_BOOK_CREATION,
                name="Concurrent Book Creation with Same ISBN",
                description="Attempt to create multiple books with the same ISBN simultaneously",
                test_method="POST",
                payload={
                    "title": "Test Book",
                    "author": "Test Author",
                    "isbn": "1234567890",
                    "description": "Test description"
                },
                concurrent_requests=5,
                expected_behavior="May create duplicate books or bypass validation",
                vulnerability_indicators=["duplicate book", "isbn already exists", "book created", "validation bypassed"],
                severity="Low",
                category="Concurrent Book Creation",
                target_endpoints=["/books/v1"],
                prerequisites=["Book creation", "ISBN validation", "Concurrent request handling"]
            ),
            
            RaceConditionTest(
                test_type=RaceConditionTestType.CONCURRENT_BOOK_CREATION,
                name="Concurrent Book Creation with Same Title",
                description="Attempt to create multiple books with the same title simultaneously",
                test_method="POST",
                payload={
                    "title": "Duplicate Title",
                    "author": "Test Author",
                    "isbn": "1234567890",
                    "description": "Test description"
                },
                concurrent_requests=5,
                expected_behavior="May create duplicate books or bypass validation",
                vulnerability_indicators=["duplicate book", "title already exists", "book created", "validation bypassed"],
                severity="Low",
                category="Concurrent Book Creation",
                target_endpoints=["/books/v1"],
                prerequisites=["Book creation", "Title validation", "Concurrent request handling"]
            )
        ]
        
        # Concurrent authentication patterns
        concurrent_auth_patterns = [
            RaceConditionTest(
                test_type=RaceConditionTestType.CONCURRENT_AUTHENTICATION,
                name="Concurrent Login Attempts",
                description="Attempt multiple login attempts for the same user simultaneously",
                test_method="POST",
                payload={
                    "username": "admin",
                    "password": "admin123"
                },
                concurrent_requests=10,
                expected_behavior="May bypass rate limiting or create multiple sessions",
                vulnerability_indicators=["multiple sessions", "rate limit bypassed", "login successful"],
                severity="Medium",
                category="Concurrent Authentication",
                target_endpoints=["/users/v1/login"],
                prerequisites=["User authentication", "Rate limiting", "Session management"]
            ),
            
            RaceConditionTest(
                test_type=RaceConditionTestType.CONCURRENT_AUTHENTICATION,
                name="Concurrent Session Creation",
                description="Create multiple sessions for the same user simultaneously",
                test_method="POST",
                payload={
                    "username": "admin",
                    "password": "admin123",
                    "create_session": "true"
                },
                concurrent_requests=5,
                expected_behavior="May create multiple sessions for the same user",
                vulnerability_indicators=["multiple sessions", "session created", "concurrent sessions"],
                severity="Medium",
                category="Concurrent Authentication",
                target_endpoints=["/users/v1/login"],
                prerequisites=["Session management", "Concurrent request handling"]
            )
        ]
        
        # Concurrent data modification patterns
        concurrent_data_patterns = [
            RaceConditionTest(
                test_type=RaceConditionTestType.CONCURRENT_DATA_MODIFICATION,
                name="Concurrent User Profile Updates",
                description="Update the same user profile multiple times simultaneously",
                test_method="PUT",
                payload={
                    "user_id": "1",
                    "email": "newemail@example.com",
                    "profile_data": {"name": "New Name", "bio": "New Bio"}
                },
                concurrent_requests=5,
                expected_behavior="May cause data corruption or inconsistent state",
                vulnerability_indicators=["data corruption", "inconsistent state", "update successful"],
                severity="Medium",
                category="Concurrent Data Modification",
                target_endpoints=["/users/v1/{user_id}"],
                prerequisites=["User profile updates", "Data validation", "Concurrent request handling"]
            ),
            
            RaceConditionTest(
                test_type=RaceConditionTestType.CONCURRENT_DATA_MODIFICATION,
                name="Concurrent Book Updates",
                description="Update the same book multiple times simultaneously",
                test_method="PUT",
                payload={
                    "book_id": "1",
                    "title": "Updated Title",
                    "author": "Updated Author",
                    "description": "Updated description"
                },
                concurrent_requests=5,
                expected_behavior="May cause data corruption or inconsistent state",
                vulnerability_indicators=["data corruption", "inconsistent state", "update successful"],
                severity="Low",
                category="Concurrent Data Modification",
                target_endpoints=["/books/v1/{book_id}"],
                prerequisites=["Book updates", "Data validation", "Concurrent request handling"]
            )
        ]
        
        # Resource contention patterns
        resource_contention_patterns = [
            RaceConditionTest(
                test_type=RaceConditionTestType.RESOURCE_CONTENTION,
                name="Database Connection Pool Exhaustion",
                description="Exhaust database connection pool with concurrent requests",
                test_method="GET",
                payload={},
                concurrent_requests=50,
                expected_behavior="May exhaust database connections and cause service degradation",
                vulnerability_indicators=["connection pool exhausted", "service degradation", "timeout"],
                severity="Medium",
                category="Resource Contention",
                target_endpoints=["/books/v1", "/users/v1"],
                prerequisites=["Database connection pooling", "Concurrent request handling"]
            ),
            
            RaceConditionTest(
                test_type=RaceConditionTestType.RESOURCE_CONTENTION,
                name="Memory Exhaustion Attack",
                description="Exhaust server memory with large concurrent requests",
                test_method="POST",
                payload={
                    "large_data": "x" * 10000,  # 10KB of data
                    "repeat_data": True
                },
                concurrent_requests=20,
                expected_behavior="May exhaust server memory and cause service degradation",
                vulnerability_indicators=["memory exhausted", "service degradation", "out of memory"],
                severity="Medium",
                category="Resource Contention",
                target_endpoints=["/books/v1", "/users/v1"],
                prerequisites=["Memory management", "Concurrent request handling"]
            )
        ]
        
        # Timing attack patterns
        timing_attack_patterns = [
            RaceConditionTest(
                test_type=RaceConditionTestType.TIMING_ATTACK,
                name="Username Enumeration Timing Attack",
                description="Use timing differences to enumerate valid usernames",
                test_method="POST",
                payload={
                    "username": "admin",
                    "password": "wrongpassword"
                },
                concurrent_requests=1,
                expected_behavior="May reveal valid usernames through timing differences",
                vulnerability_indicators=["timing difference", "username enumeration", "response time variation"],
                severity="Low",
                category="Timing Attack",
                target_endpoints=["/users/v1/login"],
                prerequisites=["Username validation", "Timing-based authentication"]
            ),
            
            RaceConditionTest(
                test_type=RaceConditionTestType.TIMING_ATTACK,
                name="Password Brute Force Timing Attack",
                description="Use timing differences to brute force passwords",
                test_method="POST",
                payload={
                    "username": "admin",
                    "password": "password123"
                },
                concurrent_requests=1,
                expected_behavior="May reveal password through timing differences",
                vulnerability_indicators=["timing difference", "password enumeration", "response time variation"],
                severity="Medium",
                category="Timing Attack",
                target_endpoints=["/users/v1/login"],
                prerequisites=["Password validation", "Timing-based authentication"]
            )
        ]
        
        # Concurrent session management patterns
        concurrent_session_patterns = [
            RaceConditionTest(
                test_type=RaceConditionTestType.CONCURRENT_SESSION_MANAGEMENT,
                name="Concurrent Session Invalidation",
                description="Invalidate the same session multiple times simultaneously",
                test_method="POST",
                payload={
                    "session_id": "session_123",
                    "action": "invalidate"
                },
                concurrent_requests=5,
                expected_behavior="May cause session management issues",
                vulnerability_indicators=["session management issue", "concurrent invalidation", "session state corrupted"],
                severity="Medium",
                category="Concurrent Session Management",
                target_endpoints=["/users/v1/logout", "/users/v1/session/invalidate"],
                prerequisites=["Session management", "Concurrent request handling"]
            ),
            
            RaceConditionTest(
                test_type=RaceConditionTestType.CONCURRENT_SESSION_MANAGEMENT,
                name="Concurrent Session Refresh",
                description="Refresh the same session multiple times simultaneously",
                test_method="POST",
                payload={
                    "session_id": "session_123",
                    "action": "refresh"
                },
                concurrent_requests=5,
                expected_behavior="May cause session management issues",
                vulnerability_indicators=["session management issue", "concurrent refresh", "session state corrupted"],
                severity="Low",
                category="Concurrent Session Management",
                target_endpoints=["/users/v1/session/refresh"],
                prerequisites=["Session management", "Concurrent request handling"]
            )
        ]
        
        # Combine all patterns
        patterns.extend(concurrent_user_patterns)
        patterns.extend(concurrent_password_patterns)
        patterns.extend(concurrent_book_patterns)
        patterns.extend(concurrent_auth_patterns)
        patterns.extend(concurrent_data_patterns)
        patterns.extend(resource_contention_patterns)
        patterns.extend(timing_attack_patterns)
        patterns.extend(concurrent_session_patterns)
        
        return patterns
    
    async def test_concurrent_user_creation(self, endpoint: str, method: str) -> Dict[str, Any]:
        """Test concurrent user creation vulnerabilities"""
        results = []
        concurrent_user_tests = [p for p in self.race_condition_patterns if p.test_type == RaceConditionTestType.CONCURRENT_USER_CREATION]
        
        for test in concurrent_user_tests:
            if any(target in endpoint for target in test.target_endpoints):
                result = await self._execute_concurrent_test(endpoint, method, test)
                results.append(result)
        
        return {
            "endpoint": endpoint,
            "method": method,
            "test_type": "concurrent_user_creation",
            "results": results,
            "total_tests": len(results),
            "vulnerabilities_found": sum(1 for r in results if r.get("vulnerability_found", False))
        }
    
    async def test_concurrent_password_reset(self, endpoint: str, method: str) -> Dict[str, Any]:
        """Test concurrent password reset vulnerabilities"""
        results = []
        concurrent_password_tests = [p for p in self.race_condition_patterns if p.test_type == RaceConditionTestType.CONCURRENT_PASSWORD_RESET]
        
        for test in concurrent_password_tests:
            if any(target in endpoint for target in test.target_endpoints):
                result = await self._execute_concurrent_test(endpoint, method, test)
                results.append(result)
        
        return {
            "endpoint": endpoint,
            "method": method,
            "test_type": "concurrent_password_reset",
            "results": results,
            "total_tests": len(results),
            "vulnerabilities_found": sum(1 for r in results if r.get("vulnerability_found", False))
        }
    
    async def test_concurrent_book_creation(self, endpoint: str, method: str) -> Dict[str, Any]:
        """Test concurrent book creation vulnerabilities"""
        results = []
        concurrent_book_tests = [p for p in self.race_condition_patterns if p.test_type == RaceConditionTestType.CONCURRENT_BOOK_CREATION]
        
        for test in concurrent_book_tests:
            if any(target in endpoint for target in test.target_endpoints):
                result = await self._execute_concurrent_test(endpoint, method, test)
                results.append(result)
        
        return {
            "endpoint": endpoint,
            "method": method,
            "test_type": "concurrent_book_creation",
            "results": results,
            "total_tests": len(results),
            "vulnerabilities_found": sum(1 for r in results if r.get("vulnerability_found", False))
        }
    
    async def test_concurrent_authentication(self, endpoint: str, method: str) -> Dict[str, Any]:
        """Test concurrent authentication vulnerabilities"""
        results = []
        concurrent_auth_tests = [p for p in self.race_condition_patterns if p.test_type == RaceConditionTestType.CONCURRENT_AUTHENTICATION]
        
        for test in concurrent_auth_tests:
            if any(target in endpoint for target in test.target_endpoints):
                result = await self._execute_concurrent_test(endpoint, method, test)
                results.append(result)
        
        return {
            "endpoint": endpoint,
            "method": method,
            "test_type": "concurrent_authentication",
            "results": results,
            "total_tests": len(results),
            "vulnerabilities_found": sum(1 for r in results if r.get("vulnerability_found", False))
        }
    
    async def test_concurrent_data_modification(self, endpoint: str, method: str) -> Dict[str, Any]:
        """Test concurrent data modification vulnerabilities"""
        results = []
        concurrent_data_tests = [p for p in self.race_condition_patterns if p.test_type == RaceConditionTestType.CONCURRENT_DATA_MODIFICATION]
        
        for test in concurrent_data_tests:
            if any(target in endpoint for target in test.target_endpoints):
                result = await self._execute_concurrent_test(endpoint, method, test)
                results.append(result)
        
        return {
            "endpoint": endpoint,
            "method": method,
            "test_type": "concurrent_data_modification",
            "results": results,
            "total_tests": len(results),
            "vulnerabilities_found": sum(1 for r in results if r.get("vulnerability_found", False))
        }
    
    async def test_resource_contention(self, endpoint: str, method: str) -> Dict[str, Any]:
        """Test resource contention vulnerabilities"""
        results = []
        resource_contention_tests = [p for p in self.race_condition_patterns if p.test_type == RaceConditionTestType.RESOURCE_CONTENTION]
        
        for test in resource_contention_tests:
            if any(target in endpoint for target in test.target_endpoints):
                result = await self._execute_concurrent_test(endpoint, method, test)
                results.append(result)
        
        return {
            "endpoint": endpoint,
            "method": method,
            "test_type": "resource_contention",
            "results": results,
            "total_tests": len(results),
            "vulnerabilities_found": sum(1 for r in results if r.get("vulnerability_found", False))
        }
    
    async def test_timing_attack(self, endpoint: str, method: str) -> Dict[str, Any]:
        """Test timing attack vulnerabilities"""
        results = []
        timing_attack_tests = [p for p in self.race_condition_patterns if p.test_type == RaceConditionTestType.TIMING_ATTACK]
        
        for test in timing_attack_tests:
            if any(target in endpoint for target in test.target_endpoints):
                result = await self._execute_timing_attack_test(endpoint, method, test)
                results.append(result)
        
        return {
            "endpoint": endpoint,
            "method": method,
            "test_type": "timing_attack",
            "results": results,
            "total_tests": len(results),
            "vulnerabilities_found": sum(1 for r in results if r.get("vulnerability_found", False))
        }
    
    async def test_concurrent_session_management(self, endpoint: str, method: str) -> Dict[str, Any]:
        """Test concurrent session management vulnerabilities"""
        results = []
        concurrent_session_tests = [p for p in self.race_condition_patterns if p.test_type == RaceConditionTestType.CONCURRENT_SESSION_MANAGEMENT]
        
        for test in concurrent_session_tests:
            if any(target in endpoint for target in test.target_endpoints):
                result = await self._execute_concurrent_test(endpoint, method, test)
                results.append(result)
        
        return {
            "endpoint": endpoint,
            "method": method,
            "test_type": "concurrent_session_management",
            "results": results,
            "total_tests": len(results),
            "vulnerabilities_found": sum(1 for r in results if r.get("vulnerability_found", False))
        }
    
    async def _execute_concurrent_test(self, endpoint: str, method: str, test: RaceConditionTest) -> Dict[str, Any]:
        """Execute a concurrent test"""
        try:
            url = f"{self.base_url}{endpoint}"
            
            # Create concurrent requests
            tasks = []
            for i in range(test.concurrent_requests):
                if method.upper() == "GET":
                    task = self._make_concurrent_request(self.session.get, url, test.payload)
                elif method.upper() == "POST":
                    task = self._make_concurrent_request(self.session.post, url, test.payload)
                elif method.upper() == "PUT":
                    task = self._make_concurrent_request(self.session.put, url, test.payload)
                else:
                    task = self._make_concurrent_request(self.session.request, url, test.payload, method)
                tasks.append(task)
            
            # Execute concurrent requests
            start_time = time.time()
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            end_time = time.time()
            
            # Analyze responses for race condition indicators
            vulnerability_found = self._analyze_concurrent_responses(responses, test)
            
            return {
                "test_name": test.name,
                "test_type": test.test_type.value,
                "payload": test.payload,
                "expected_behavior": test.expected_behavior,
                "concurrent_requests": test.concurrent_requests,
                "responses_received": len([r for r in responses if not isinstance(r, Exception)]),
                "execution_time": end_time - start_time,
                "vulnerability_found": vulnerability_found,
                "vulnerability_indicators": self._get_race_condition_indicators(responses, test),
                "severity": test.severity,
                "category": test.category,
                "response_codes": [r.status_code if hasattr(r, 'status_code') else 'error' for r in responses],
                "response_times": [r.elapsed.total_seconds() if hasattr(r, 'elapsed') else 0 for r in responses]
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
    
    async def _execute_timing_attack_test(self, endpoint: str, method: str, test: RaceConditionTest) -> Dict[str, Any]:
        """Execute a timing attack test"""
        try:
            url = f"{self.base_url}{endpoint}"
            
            # Execute multiple requests to measure timing
            response_times = []
            for i in range(10):  # 10 requests for timing analysis
                start_time = time.time()
                if method.upper() == "GET":
                    response = self.session.get(url, params=test.payload, timeout=30)
                elif method.upper() == "POST":
                    response = self.session.post(url, json=test.payload, timeout=30)
                else:
                    response = self.session.request(method, url, json=test.payload, timeout=30)
                end_time = time.time()
                response_times.append(end_time - start_time)
            
            # Analyze timing variations
            avg_time = sum(response_times) / len(response_times)
            max_time = max(response_times)
            min_time = min(response_times)
            time_variance = max_time - min_time
            
            # Check for timing attack indicators
            vulnerability_found = time_variance > 0.1  # 100ms variance threshold
            
            return {
                "test_name": test.name,
                "test_type": test.test_type.value,
                "payload": test.payload,
                "expected_behavior": test.expected_behavior,
                "requests_sent": 10,
                "average_response_time": avg_time,
                "max_response_time": max_time,
                "min_response_time": min_time,
                "time_variance": time_variance,
                "vulnerability_found": vulnerability_found,
                "vulnerability_indicators": ["Timing attack detected"] if vulnerability_found else [],
                "severity": test.severity,
                "category": test.category,
                "response_times": response_times
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
    
    def _analyze_concurrent_responses(self, responses, test: RaceConditionTest) -> bool:
        """Analyze responses for race condition indicators"""
        valid_responses = [r for r in responses if hasattr(r, 'status_code')]
        
        if len(valid_responses) < 2:
            return False
        
        # Check for race condition indicators
        status_codes = [r.status_code for r in valid_responses]
        response_lengths = [len(r.text) for r in valid_responses]
        response_times = [r.elapsed.total_seconds() if hasattr(r, 'elapsed') else 0 for r in valid_responses]
        
        # Race condition indicators:
        # 1. Multiple successful responses when only one should succeed
        # 2. Inconsistent response lengths
        # 3. Different status codes for identical requests
        # 4. Significant timing variations
        
        multiple_success = status_codes.count(200) > 1
        inconsistent_lengths = len(set(response_lengths)) > 1
        inconsistent_codes = len(set(status_codes)) > 1
        
        # Check for timing variations
        if len(response_times) > 1:
            max_time = max(response_times)
            min_time = min(response_times)
            time_variance = max_time - min_time
            significant_timing_variation = time_variance > 0.5  # 500ms variance
        else:
            significant_timing_variation = False
        
        # Check for specific vulnerability indicators in response content
        content_indicators = []
        for response in valid_responses:
            response_text = response.text.lower()
            for indicator in test.vulnerability_indicators:
                if indicator.lower() in response_text:
                    content_indicators.append(True)
        
        content_vulnerability = len(content_indicators) > 0
        
        return multiple_success or inconsistent_lengths or inconsistent_codes or significant_timing_variation or content_vulnerability
    
    def _get_race_condition_indicators(self, responses, test: RaceConditionTest) -> List[str]:
        """Get specific race condition indicators from responses"""
        indicators = []
        valid_responses = [r for r in responses if hasattr(r, 'status_code')]
        
        if not valid_responses:
            return indicators
        
        # Check response codes
        status_codes = [r.status_code for r in valid_responses]
        if len(set(status_codes)) > 1:
            indicators.append("Inconsistent response codes")
        
        # Check response lengths
        response_lengths = [len(r.text) for r in valid_responses]
        if len(set(response_lengths)) > 1:
            indicators.append("Inconsistent response lengths")
        
        # Check for multiple successful responses
        successful_responses = len([r for r in valid_responses if r.status_code == 200])
        if successful_responses > 1:
            indicators.append("Multiple successful responses")
        
        # Check response content for specific indicators
        for response in valid_responses:
            response_text = response.text.lower()
            for indicator in test.vulnerability_indicators:
                if indicator.lower() in response_text:
                    indicators.append(f"Content indicator: {indicator}")
        
        # Check for timing variations
        response_times = [r.elapsed.total_seconds() if hasattr(r, 'elapsed') else 0 for r in valid_responses]
        if len(response_times) > 1:
            max_time = max(response_times)
            min_time = min(response_times)
            time_variance = max_time - min_time
            if time_variance > 0.5:
                indicators.append("Significant timing variation")
        
        return indicators
    
    async def run_comprehensive_race_condition_tests(self, endpoint: str, method: str) -> Dict[str, Any]:
        """Run all race condition tests for an endpoint"""
        all_results = {}
        
        # Run all test types
        test_functions = [
            ("concurrent_user_creation", self.test_concurrent_user_creation),
            ("concurrent_password_reset", self.test_concurrent_password_reset),
            ("concurrent_book_creation", self.test_concurrent_book_creation),
            ("concurrent_authentication", self.test_concurrent_authentication),
            ("concurrent_data_modification", self.test_concurrent_data_modification),
            ("resource_contention", self.test_resource_contention),
            ("timing_attack", self.test_timing_attack),
            ("concurrent_session_management", self.test_concurrent_session_management)
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
            "test_type": "comprehensive_race_condition_testing",
            "results": all_results,
            "total_tests": total_tests,
            "total_vulnerabilities": total_vulnerabilities,
            "vulnerability_rate": (total_vulnerabilities / total_tests * 100) if total_tests > 0 else 0
        }