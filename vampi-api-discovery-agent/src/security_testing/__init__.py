#!/usr/bin/env python3
"""
Security Testing Module for VAmPI API Discovery Agent

This module provides comprehensive OWASP API security testing capabilities
including injection testing, authentication analysis, authorization testing,
and security misconfiguration detection.
"""

from .models import (
    SecurityTest, EndpointSecurityReport, SecurityAssessmentReport,
    SecurityTestSuite, SecurityTestResult, CVSSMetrics,
    OWASPCategory, VulnerabilitySeverity, AttackVector, AttackComplexity,
    PrivilegesRequired, UserInteraction, Scope, Impact
)

from .engine import SecurityTestingEngine
from .agent import SecurityTestingAgent, SecurityTestingTool

__version__ = "1.0.0"
__author__ = "VAmPI Security Testing Team"

__all__ = [
    # Models
    "SecurityTest",
    "EndpointSecurityReport", 
    "SecurityAssessmentReport",
    "SecurityTestSuite",
    "SecurityTestResult",
    "CVSSMetrics",
    "OWASPCategory",
    "VulnerabilitySeverity",
    "AttackVector",
    "AttackComplexity",
    "PrivilegesRequired",
    "UserInteraction",
    "Scope",
    "Impact",
    
    # Engine
    "SecurityTestingEngine",
    
    # Agent
    "SecurityTestingAgent",
    "SecurityTestingTool"
] 