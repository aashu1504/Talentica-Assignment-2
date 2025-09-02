#!/usr/bin/env python3
"""
Workflow State Manipulation Testing Module

This module implements comprehensive workflow state manipulation testing
including state machine bypass, multi-step process manipulation, and
workflow integrity validation.
"""

import json
import time
import asyncio
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import requests


class WorkflowTestType(Enum):
    """Types of workflow tests"""
    STATE_MACHINE_BYPASS = "state_machine_bypass"
    MULTI_STEP_BYPASS = "multi_step_bypass"
    WORKFLOW_INTEGRITY = "workflow_integrity"
    STATE_MANIPULATION = "state_manipulation"
    PROCESS_SKIPPING = "process_skipping"
    TRANSACTION_BYPASS = "transaction_bypass"
    WORKFLOW_REPLAY = "workflow_replay"
    CONCURRENT_WORKFLOW = "concurrent_workflow"


@dataclass
class WorkflowTest:
    """Workflow test definition"""
    test_type: WorkflowTestType
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


class WorkflowTester:
    """Tester for workflow state manipulation vulnerabilities"""
    
    def __init__(self, base_url: str, session):
        self.base_url = base_url
        self.session = session
        self.workflow_patterns = self._initialize_workflow_patterns()
        self.workflow_states = self._initialize_workflow_states()
    
    def _initialize_workflow_states(self) -> Dict[str, List[str]]:
        """Initialize common workflow states for VAmPI"""
        return {
            "user_registration": [
                "initial", "email_verification", "profile_setup", "completed"
            ],
            "user_authentication": [
                "login_attempt", "password_verification", "token_generation", "authenticated"
            ],
            "password_reset": [
                "request_initiated", "email_sent", "token_verified", "password_changed", "completed"
            ],
            "book_management": [
                "creation_requested", "validation", "creation_confirmed", "published"
            ],
            "admin_operations": [
                "request_received", "authorization_check", "operation_executed", "completed"
            ]
        }
    
    def _initialize_workflow_patterns(self) -> List[WorkflowTest]:
        """Initialize workflow manipulation patterns"""
        patterns = []
        
        # State machine bypass patterns
        state_machine_patterns = [
            WorkflowTest(
                test_type=WorkflowTestType.STATE_MACHINE_BYPASS,
                name="Direct State Transition Bypass",
                description="Bypass state machine by directly setting final state",
                test_method="POST",
                payload={
                    "current_state": "initial",
                    "target_state": "completed",
                    "bypass_validation": "true",
                    "force_transition": "true"
                },
                expected_behavior="Skips intermediate states and goes directly to final state",
                vulnerability_indicators=["completed", "success", "state bypassed"],
                severity="High",
                category="State Machine Bypass",
                target_endpoints=["/users/v1/register", "/users/v1/verify"],
                prerequisites=["State machine implementation", "State validation vulnerability"]
            ),
            
            WorkflowTest(
                test_type=WorkflowTestType.STATE_MACHINE_BYPASS,
                name="State Validation Bypass",
                description="Bypass state validation by manipulating state parameters",
                test_method="POST",
                payload={
                    "state": "completed",
                    "validation_required": "false",
                    "skip_state_check": "true",
                    "admin_override": "true"
                },
                expected_behavior="Bypasses state validation checks",
                vulnerability_indicators=["validation bypassed", "state accepted", "admin override"],
                severity="High",
                category="State Machine Bypass",
                target_endpoints=["/users/v1/register", "/users/v1/verify"],
                prerequisites=["State validation", "Validation bypass vulnerability"]
            ),
            
            WorkflowTest(
                test_type=WorkflowTestType.STATE_MACHINE_BYPASS,
                name="Invalid State Transition",
                description="Attempt invalid state transitions",
                test_method="POST",
                payload={
                    "from_state": "initial",
                    "to_state": "admin",
                    "transition_type": "privilege_escalation",
                    "bypass_restrictions": "true"
                },
                expected_behavior="Allows invalid state transitions",
                vulnerability_indicators=["admin", "privilege", "escalation", "invalid transition"],
                severity="Critical",
                category="State Machine Bypass",
                target_endpoints=["/users/v1/register", "/users/v1/verify"],
                prerequisites=["State machine", "Transition validation vulnerability"]
            )
        ]
        
        # Multi-step process bypass patterns
        multi_step_patterns = [
            WorkflowTest(
                test_type=WorkflowTestType.MULTI_STEP_BYPASS,
                name="Multi-Step Registration Bypass",
                description="Bypass multi-step registration process",
                test_method="POST",
                payload={
                    "step": "3",
                    "completed_steps": ["1", "2", "3"],
                    "skip_verification": "true",
                    "force_complete": "true",
                    "bypass_intermediate": "true"
                },
                expected_behavior="Skips required verification steps in registration",
                vulnerability_indicators=["registration completed", "verification skipped", "process bypassed"],
                severity="High",
                category="Multi-Step Process Bypass",
                target_endpoints=["/users/v1/register"],
                prerequisites=["Multi-step registration", "Step validation vulnerability"]
            ),
            
            WorkflowTest(
                test_type=WorkflowTestType.MULTI_STEP_BYPASS,
                name="Password Reset Process Bypass",
                description="Bypass password reset verification steps",
                test_method="POST",
                payload={
                    "reset_step": "4",
                    "completed_steps": ["1", "2", "3", "4"],
                    "skip_email_verification": "true",
                    "skip_token_validation": "true",
                    "force_password_change": "true"
                },
                expected_behavior="Bypasses email verification and token validation",
                vulnerability_indicators=["password reset completed", "verification skipped", "token bypassed"],
                severity="High",
                category="Multi-Step Process Bypass",
                target_endpoints=["/users/v1/password/reset"],
                prerequisites=["Password reset process", "Step validation vulnerability"]
            ),
            
            WorkflowTest(
                test_type=WorkflowTestType.MULTI_STEP_BYPASS,
                name="Book Creation Process Bypass",
                description="Bypass book creation validation steps",
                test_method="POST",
                payload={
                    "creation_step": "4",
                    "completed_steps": ["1", "2", "3", "4"],
                    "skip_validation": "true",
                    "skip_approval": "true",
                    "force_publish": "true"
                },
                expected_behavior="Bypasses book validation and approval steps",
                vulnerability_indicators=["book published", "validation skipped", "approval bypassed"],
                severity="Medium",
                category="Multi-Step Process Bypass",
                target_endpoints=["/books/v1"],
                prerequisites=["Book creation process", "Step validation vulnerability"]
            )
        ]
        
        # Workflow integrity patterns
        integrity_patterns = [
            WorkflowTest(
                test_type=WorkflowTestType.WORKFLOW_INTEGRITY,
                name="Workflow State Consistency Check",
                description="Test workflow state consistency validation",
                test_method="POST",
                payload={
                    "workflow_id": "123",
                    "current_state": "completed",
                    "previous_state": "initial",
                    "consistency_check": "false",
                    "bypass_integrity": "true"
                },
                expected_behavior="Bypasses workflow integrity checks",
                vulnerability_indicators=["integrity bypassed", "consistency check failed", "state inconsistent"],
                severity="Medium",
                category="Workflow Integrity",
                target_endpoints=["/users/v1/register", "/users/v1/verify"],
                prerequisites=["Workflow integrity checks", "Integrity validation vulnerability"]
            ),
            
            WorkflowTest(
                test_type=WorkflowTestType.WORKFLOW_INTEGRITY,
                name="Workflow History Manipulation",
                description="Manipulate workflow execution history",
                test_method="POST",
                payload={
                    "workflow_id": "123",
                    "history": ["step1", "step2", "step3", "completed"],
                    "manipulate_history": "true",
                    "fake_completion": "true"
                },
                expected_behavior="Allows manipulation of workflow history",
                vulnerability_indicators=["history manipulated", "fake completion", "workflow tampered"],
                severity="High",
                category="Workflow Integrity",
                target_endpoints=["/users/v1/register", "/users/v1/verify"],
                prerequisites=["Workflow history tracking", "History validation vulnerability"]
            )
        ]
        
        # State manipulation patterns
        state_manipulation_patterns = [
            WorkflowTest(
                test_type=WorkflowTestType.STATE_MANIPULATION,
                name="State Parameter Injection",
                description="Inject malicious parameters into state management",
                test_method="POST",
                payload={
                    "state": "completed",
                    "state_data": {"admin": "true", "privileges": "all", "bypass": "true"},
                    "inject_parameters": "true",
                    "malicious_state": "true"
                },
                expected_behavior="Injects malicious parameters into state",
                vulnerability_indicators=["admin privileges", "malicious state", "parameter injection"],
                severity="High",
                category="State Manipulation",
                target_endpoints=["/users/v1/register", "/users/v1/verify"],
                prerequisites=["State parameter handling", "Parameter injection vulnerability"]
            ),
            
            WorkflowTest(
                test_type=WorkflowTestType.STATE_MANIPULATION,
                name="State Context Manipulation",
                description="Manipulate workflow context and environment",
                test_method="POST",
                payload={
                    "context": {"user_role": "admin", "permissions": "all", "environment": "production"},
                    "manipulate_context": "true",
                    "context_override": "true"
                },
                expected_behavior="Manipulates workflow context",
                vulnerability_indicators=["context manipulated", "role escalated", "permissions changed"],
                severity="High",
                category="State Manipulation",
                target_endpoints=["/users/v1/register", "/users/v1/verify"],
                prerequisites=["Context management", "Context validation vulnerability"]
            )
        ]
        
        # Process skipping patterns
        process_skipping_patterns = [
            WorkflowTest(
                test_type=WorkflowTestType.PROCESS_SKIPPING,
                name="Critical Process Skipping",
                description="Skip critical security processes",
                test_method="POST",
                payload={
                    "skip_security_checks": "true",
                    "skip_authentication": "true",
                    "skip_authorization": "true",
                    "skip_validation": "true"
                },
                expected_behavior="Skips critical security processes",
                vulnerability_indicators=["security checks skipped", "authentication bypassed", "authorization bypassed"],
                severity="Critical",
                category="Process Skipping",
                target_endpoints=["/users/v1/register", "/users/v1/verify"],
                prerequisites=["Security process validation", "Process skipping vulnerability"]
            ),
            
            WorkflowTest(
                test_type=WorkflowTestType.PROCESS_SKIPPING,
                name="Business Logic Process Skipping",
                description="Skip business logic validation processes",
                test_method="POST",
                payload={
                    "skip_business_validation": "true",
                    "skip_policy_checks": "true",
                    "skip_compliance_checks": "true",
                    "force_approval": "true"
                },
                expected_behavior="Skips business logic validation",
                vulnerability_indicators=["business validation skipped", "policy checks bypassed", "compliance bypassed"],
                severity="High",
                category="Process Skipping",
                target_endpoints=["/users/v1/register", "/books/v1"],
                prerequisites=["Business logic validation", "Process skipping vulnerability"]
            )
        ]
        
        # Transaction bypass patterns
        transaction_bypass_patterns = [
            WorkflowTest(
                test_type=WorkflowTestType.TRANSACTION_BYPASS,
                name="Transaction Rollback Bypass",
                description="Bypass transaction rollback mechanisms",
                test_method="POST",
                payload={
                    "transaction_id": "123",
                    "force_commit": "true",
                    "bypass_rollback": "true",
                    "skip_validation": "true"
                },
                expected_behavior="Commits transaction despite errors",
                vulnerability_indicators=["transaction committed", "rollback bypassed", "validation skipped"],
                severity="High",
                category="Transaction Bypass",
                target_endpoints=["/users/v1/register", "/books/v1"],
                prerequisites=["Transaction management", "Rollback bypass vulnerability"]
            ),
            
            WorkflowTest(
                test_type=WorkflowTestType.TRANSACTION_BYPASS,
                name="Transaction Isolation Bypass",
                description="Bypass transaction isolation mechanisms",
                test_method="POST",
                payload={
                    "transaction_id": "123",
                    "isolation_level": "none",
                    "bypass_isolation": "true",
                    "concurrent_access": "true"
                },
                expected_behavior="Bypasses transaction isolation",
                vulnerability_indicators=["isolation bypassed", "concurrent access", "transaction conflict"],
                severity="High",
                category="Transaction Bypass",
                target_endpoints=["/users/v1/register", "/books/v1"],
                prerequisites=["Transaction isolation", "Isolation bypass vulnerability"]
            )
        ]
        
        # Workflow replay patterns
        workflow_replay_patterns = [
            WorkflowTest(
                test_type=WorkflowTestType.WORKFLOW_REPLAY,
                name="Workflow Replay Attack",
                description="Replay completed workflow steps",
                test_method="POST",
                payload={
                    "workflow_id": "123",
                    "replay_steps": ["step1", "step2", "step3", "completed"],
                    "replay_attack": "true",
                    "bypass_replay_protection": "true"
                },
                expected_behavior="Allows workflow replay",
                vulnerability_indicators=["workflow replayed", "replay attack", "protection bypassed"],
                severity="Medium",
                category="Workflow Replay",
                target_endpoints=["/users/v1/register", "/users/v1/verify"],
                prerequisites=["Workflow replay protection", "Replay protection vulnerability"]
            ),
            
            WorkflowTest(
                test_type=WorkflowTestType.WORKFLOW_REPLAY,
                name="Step Replay Attack",
                description="Replay individual workflow steps",
                test_method="POST",
                payload={
                    "step_id": "456",
                    "replay_step": "true",
                    "bypass_step_protection": "true",
                    "duplicate_execution": "true"
                },
                expected_behavior="Allows step replay",
                vulnerability_indicators=["step replayed", "duplicate execution", "step protection bypassed"],
                severity="Medium",
                category="Workflow Replay",
                target_endpoints=["/users/v1/register", "/users/v1/verify"],
                prerequisites=["Step replay protection", "Step protection vulnerability"]
            )
        ]
        
        # Concurrent workflow patterns
        concurrent_workflow_patterns = [
            WorkflowTest(
                test_type=WorkflowTestType.CONCURRENT_WORKFLOW,
                name="Concurrent Workflow Execution",
                description="Execute multiple workflows concurrently",
                test_method="POST",
                payload={
                    "concurrent_workflows": ["workflow1", "workflow2", "workflow3"],
                    "parallel_execution": "true",
                    "bypass_concurrency_control": "true"
                },
                expected_behavior="Allows concurrent workflow execution",
                vulnerability_indicators=["concurrent execution", "parallel workflows", "concurrency bypassed"],
                severity="Medium",
                category="Concurrent Workflow",
                target_endpoints=["/users/v1/register", "/books/v1"],
                prerequisites=["Concurrency control", "Concurrency control vulnerability"]
            ),
            
            WorkflowTest(
                test_type=WorkflowTestType.CONCURRENT_WORKFLOW,
                name="Race Condition in Workflow",
                description="Exploit race conditions in workflow execution",
                test_method="POST",
                payload={
                    "race_condition": "true",
                    "concurrent_requests": "true",
                    "bypass_race_protection": "true"
                },
                expected_behavior="Exploits race conditions",
                vulnerability_indicators=["race condition", "concurrent requests", "race protection bypassed"],
                severity="High",
                category="Concurrent Workflow",
                target_endpoints=["/users/v1/register", "/books/v1"],
                prerequisites=["Race condition vulnerability", "Concurrent request handling"]
            )
        ]
        
        # Combine all patterns
        patterns.extend(state_machine_patterns)
        patterns.extend(multi_step_patterns)
        patterns.extend(integrity_patterns)
        patterns.extend(state_manipulation_patterns)
        patterns.extend(process_skipping_patterns)
        patterns.extend(transaction_bypass_patterns)
        patterns.extend(workflow_replay_patterns)
        patterns.extend(concurrent_workflow_patterns)
        
        return patterns
    
    async def test_state_machine_bypass(self, endpoint: str, method: str) -> Dict[str, Any]:
        """Test state machine bypass vulnerabilities"""
        results = []
        state_machine_tests = [p for p in self.workflow_patterns if p.test_type == WorkflowTestType.STATE_MACHINE_BYPASS]
        
        for test in state_machine_tests:
            if any(target in endpoint for target in test.target_endpoints):
                result = await self._execute_workflow_test(endpoint, method, test)
                results.append(result)
        
        return {
            "endpoint": endpoint,
            "method": method,
            "test_type": "state_machine_bypass",
            "results": results,
            "total_tests": len(results),
            "vulnerabilities_found": sum(1 for r in results if r.get("vulnerability_found", False))
        }
    
    async def test_multi_step_bypass(self, endpoint: str, method: str) -> Dict[str, Any]:
        """Test multi-step process bypass vulnerabilities"""
        results = []
        multi_step_tests = [p for p in self.workflow_patterns if p.test_type == WorkflowTestType.MULTI_STEP_BYPASS]
        
        for test in multi_step_tests:
            if any(target in endpoint for target in test.target_endpoints):
                result = await self._execute_workflow_test(endpoint, method, test)
                results.append(result)
        
        return {
            "endpoint": endpoint,
            "method": method,
            "test_type": "multi_step_bypass",
            "results": results,
            "total_tests": len(results),
            "vulnerabilities_found": sum(1 for r in results if r.get("vulnerability_found", False))
        }
    
    async def test_workflow_integrity(self, endpoint: str, method: str) -> Dict[str, Any]:
        """Test workflow integrity vulnerabilities"""
        results = []
        integrity_tests = [p for p in self.workflow_patterns if p.test_type == WorkflowTestType.WORKFLOW_INTEGRITY]
        
        for test in integrity_tests:
            if any(target in endpoint for target in test.target_endpoints):
                result = await self._execute_workflow_test(endpoint, method, test)
                results.append(result)
        
        return {
            "endpoint": endpoint,
            "method": method,
            "test_type": "workflow_integrity",
            "results": results,
            "total_tests": len(results),
            "vulnerabilities_found": sum(1 for r in results if r.get("vulnerability_found", False))
        }
    
    async def test_state_manipulation(self, endpoint: str, method: str) -> Dict[str, Any]:
        """Test state manipulation vulnerabilities"""
        results = []
        state_manipulation_tests = [p for p in self.workflow_patterns if p.test_type == WorkflowTestType.STATE_MANIPULATION]
        
        for test in state_manipulation_tests:
            if any(target in endpoint for target in test.target_endpoints):
                result = await self._execute_workflow_test(endpoint, method, test)
                results.append(result)
        
        return {
            "endpoint": endpoint,
            "method": method,
            "test_type": "state_manipulation",
            "results": results,
            "total_tests": len(results),
            "vulnerabilities_found": sum(1 for r in results if r.get("vulnerability_found", False))
        }
    
    async def test_process_skipping(self, endpoint: str, method: str) -> Dict[str, Any]:
        """Test process skipping vulnerabilities"""
        results = []
        process_skipping_tests = [p for p in self.workflow_patterns if p.test_type == WorkflowTestType.PROCESS_SKIPPING]
        
        for test in process_skipping_tests:
            if any(target in endpoint for target in test.target_endpoints):
                result = await self._execute_workflow_test(endpoint, method, test)
                results.append(result)
        
        return {
            "endpoint": endpoint,
            "method": method,
            "test_type": "process_skipping",
            "results": results,
            "total_tests": len(results),
            "vulnerabilities_found": sum(1 for r in results if r.get("vulnerability_found", False))
        }
    
    async def test_transaction_bypass(self, endpoint: str, method: str) -> Dict[str, Any]:
        """Test transaction bypass vulnerabilities"""
        results = []
        transaction_bypass_tests = [p for p in self.workflow_patterns if p.test_type == WorkflowTestType.TRANSACTION_BYPASS]
        
        for test in transaction_bypass_tests:
            if any(target in endpoint for target in test.target_endpoints):
                result = await self._execute_workflow_test(endpoint, method, test)
                results.append(result)
        
        return {
            "endpoint": endpoint,
            "method": method,
            "test_type": "transaction_bypass",
            "results": results,
            "total_tests": len(results),
            "vulnerabilities_found": sum(1 for r in results if r.get("vulnerability_found", False))
        }
    
    async def test_workflow_replay(self, endpoint: str, method: str) -> Dict[str, Any]:
        """Test workflow replay vulnerabilities"""
        results = []
        workflow_replay_tests = [p for p in self.workflow_patterns if p.test_type == WorkflowTestType.WORKFLOW_REPLAY]
        
        for test in workflow_replay_tests:
            if any(target in endpoint for target in test.target_endpoints):
                result = await self._execute_workflow_test(endpoint, method, test)
                results.append(result)
        
        return {
            "endpoint": endpoint,
            "method": method,
            "test_type": "workflow_replay",
            "results": results,
            "total_tests": len(results),
            "vulnerabilities_found": sum(1 for r in results if r.get("vulnerability_found", False))
        }
    
    async def test_concurrent_workflow(self, endpoint: str, method: str) -> Dict[str, Any]:
        """Test concurrent workflow vulnerabilities"""
        results = []
        concurrent_workflow_tests = [p for p in self.workflow_patterns if p.test_type == WorkflowTestType.CONCURRENT_WORKFLOW]
        
        for test in concurrent_workflow_tests:
            if any(target in endpoint for target in test.target_endpoints):
                result = await self._execute_concurrent_workflow_test(endpoint, method, test)
                results.append(result)
        
        return {
            "endpoint": endpoint,
            "method": method,
            "test_type": "concurrent_workflow",
            "results": results,
            "total_tests": len(results),
            "vulnerabilities_found": sum(1 for r in results if r.get("vulnerability_found", False))
        }
    
    async def _execute_workflow_test(self, endpoint: str, method: str, test: WorkflowTest) -> Dict[str, Any]:
        """Execute a workflow test"""
        try:
            url = f"{self.base_url}{endpoint}"
            
            # Prepare request based on method
            if method.upper() == "GET":
                response = self.session.get(url, params=test.payload, timeout=30)
            elif method.upper() == "POST":
                response = self.session.post(url, json=test.payload, timeout=30)
            elif method.upper() == "PUT":
                response = self.session.put(url, json=test.payload, timeout=30)
            else:
                response = self.session.request(method, url, json=test.payload, timeout=30)
            
            # Analyze response for vulnerability indicators
            vulnerability_found = self._analyze_workflow_response(response, test)
            
            return {
                "test_name": test.name,
                "test_type": test.test_type.value,
                "payload": test.payload,
                "expected_behavior": test.expected_behavior,
                "status_code": response.status_code,
                "response_length": len(response.text),
                "response_time": response.elapsed.total_seconds(),
                "vulnerability_found": vulnerability_found,
                "vulnerability_indicators": self._get_workflow_vulnerability_indicators(response, test),
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
    
    async def _execute_concurrent_workflow_test(self, endpoint: str, method: str, test: WorkflowTest) -> Dict[str, Any]:
        """Execute a concurrent workflow test"""
        try:
            url = f"{self.base_url}{endpoint}"
            
            # Create concurrent requests
            tasks = []
            for i in range(5):  # 5 concurrent requests
                if method.upper() == "GET":
                    task = self._make_concurrent_request(self.session.get, url, test.payload)
                elif method.upper() == "POST":
                    task = self._make_concurrent_request(self.session.post, url, test.payload)
                else:
                    task = self._make_concurrent_request(self.session.request, url, test.payload, method)
                tasks.append(task)
            
            # Execute concurrent requests
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Analyze responses for concurrent workflow vulnerabilities
            vulnerability_found = self._analyze_concurrent_workflow_responses(responses, test)
            
            return {
                "test_name": test.name,
                "test_type": test.test_type.value,
                "payload": test.payload,
                "expected_behavior": test.expected_behavior,
                "concurrent_requests": 5,
                "responses_received": len([r for r in responses if not isinstance(r, Exception)]),
                "vulnerability_found": vulnerability_found,
                "vulnerability_indicators": ["Concurrent workflow vulnerability detected"] if vulnerability_found else [],
                "severity": test.severity,
                "category": test.category,
                "response_codes": [r.status_code if hasattr(r, 'status_code') else 'error' for r in responses]
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
    
    def _analyze_workflow_response(self, response, test: WorkflowTest) -> bool:
        """Analyze response for workflow vulnerability indicators"""
        if response.status_code == 200:
            response_text = response.text.lower()
            
            # Check for specific vulnerability indicators
            for indicator in test.vulnerability_indicators:
                if indicator.lower() in response_text:
                    return True
            
            # Check for workflow-specific success indicators
            workflow_success_indicators = [
                "completed", "success", "bypassed", "skipped", "admin", "privilege",
                "escalated", "manipulated", "replayed", "concurrent"
            ]
            
            return any(indicator in response_text for indicator in workflow_success_indicators)
        
        return False
    
    def _analyze_concurrent_workflow_responses(self, responses, test: WorkflowTest) -> bool:
        """Analyze responses for concurrent workflow vulnerabilities"""
        valid_responses = [r for r in responses if hasattr(r, 'status_code')]
        
        if len(valid_responses) < 2:
            return False
        
        # Check for concurrent workflow indicators
        status_codes = [r.status_code for r in valid_responses]
        response_lengths = [len(r.text) for r in valid_responses]
        
        # Concurrent workflow vulnerability indicators:
        # 1. Multiple successful responses when only one should succeed
        # 2. Inconsistent response lengths
        # 3. Different status codes for identical requests
        # 4. Race condition indicators
        
        multiple_success = status_codes.count(200) > 1
        inconsistent_lengths = len(set(response_lengths)) > 1
        inconsistent_codes = len(set(status_codes)) > 1
        
        # Check for race condition indicators in response content
        race_condition_indicators = []
        for response in valid_responses:
            response_text = response.text.lower()
            if any(indicator in response_text for indicator in ["race", "concurrent", "conflict", "duplicate"]):
                race_condition_indicators.append(True)
        
        race_condition_detected = len(race_condition_indicators) > 0
        
        return multiple_success or inconsistent_lengths or inconsistent_codes or race_condition_detected
    
    def _get_workflow_vulnerability_indicators(self, response, test: WorkflowTest) -> List[str]:
        """Get specific workflow vulnerability indicators from response"""
        indicators = []
        response_text = response.text.lower()
        
        if test.test_type == WorkflowTestType.STATE_MACHINE_BYPASS:
            if "state bypassed" in response_text:
                indicators.append("State machine bypassed")
            if "admin" in response_text:
                indicators.append("Admin privileges gained")
            if "privilege" in response_text:
                indicators.append("Privilege escalation detected")
        
        elif test.test_type == WorkflowTestType.MULTI_STEP_BYPASS:
            if "verification skipped" in response_text:
                indicators.append("Verification steps skipped")
            if "process bypassed" in response_text:
                indicators.append("Multi-step process bypassed")
            if "completed" in response_text:
                indicators.append("Process completed without proper validation")
        
        elif test.test_type == WorkflowTestType.WORKFLOW_INTEGRITY:
            if "integrity bypassed" in response_text:
                indicators.append("Workflow integrity bypassed")
            if "history manipulated" in response_text:
                indicators.append("Workflow history manipulated")
            if "consistency check failed" in response_text:
                indicators.append("Workflow consistency check failed")
        
        elif test.test_type == WorkflowTestType.STATE_MANIPULATION:
            if "state manipulated" in response_text:
                indicators.append("Workflow state manipulated")
            if "context manipulated" in response_text:
                indicators.append("Workflow context manipulated")
            if "parameter injection" in response_text:
                indicators.append("State parameter injection detected")
        
        elif test.test_type == WorkflowTestType.PROCESS_SKIPPING:
            if "security checks skipped" in response_text:
                indicators.append("Security checks skipped")
            if "validation skipped" in response_text:
                indicators.append("Validation processes skipped")
            if "authentication bypassed" in response_text:
                indicators.append("Authentication bypassed")
        
        elif test.test_type == WorkflowTestType.TRANSACTION_BYPASS:
            if "transaction committed" in response_text:
                indicators.append("Transaction committed despite errors")
            if "rollback bypassed" in response_text:
                indicators.append("Transaction rollback bypassed")
            if "isolation bypassed" in response_text:
                indicators.append("Transaction isolation bypassed")
        
        elif test.test_type == WorkflowTestType.WORKFLOW_REPLAY:
            if "workflow replayed" in response_text:
                indicators.append("Workflow replay attack successful")
            if "step replayed" in response_text:
                indicators.append("Workflow step replayed")
            if "replay protection bypassed" in response_text:
                indicators.append("Replay protection bypassed")
        
        elif test.test_type == WorkflowTestType.CONCURRENT_WORKFLOW:
            if "concurrent execution" in response_text:
                indicators.append("Concurrent workflow execution detected")
            if "race condition" in response_text:
                indicators.append("Race condition detected")
            if "parallel workflows" in response_text:
                indicators.append("Parallel workflow execution detected")
        
        return indicators
    
    async def run_comprehensive_workflow_tests(self, endpoint: str, method: str) -> Dict[str, Any]:
        """Run all workflow tests for an endpoint"""
        all_results = {}
        
        # Run all test types
        test_functions = [
            ("state_machine_bypass", self.test_state_machine_bypass),
            ("multi_step_bypass", self.test_multi_step_bypass),
            ("workflow_integrity", self.test_workflow_integrity),
            ("state_manipulation", self.test_state_manipulation),
            ("process_skipping", self.test_process_skipping),
            ("transaction_bypass", self.test_transaction_bypass),
            ("workflow_replay", self.test_workflow_replay),
            ("concurrent_workflow", self.test_concurrent_workflow)
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
            "test_type": "comprehensive_workflow_testing",
            "results": all_results,
            "total_tests": total_tests,
            "total_vulnerabilities": total_vulnerabilities,
            "vulnerability_rate": (total_vulnerabilities / total_tests * 100) if total_tests > 0 else 0
        }