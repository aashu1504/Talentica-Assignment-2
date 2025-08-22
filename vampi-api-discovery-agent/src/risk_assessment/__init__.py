"""
Risk Assessment Package

This package provides a pluggable architecture for risk assessment modules.
Each module can implement custom risk assessment strategies and be loaded at runtime.
"""

from .base import BaseRiskAssessor
from .factory import RiskAssessorFactory
from .modules import (
    UserManagementRiskAssessor,
    DataExposureRiskAssessor,
    AuthenticationRiskAssessor,
    AdminAccessRiskAssessor,
    FileOperationsRiskAssessor,
    DatabaseOperationsRiskAssessor
)

__all__ = [
    'BaseRiskAssessor',
    'RiskAssessorFactory',
    'UserManagementRiskAssessor',
    'DataExposureRiskAssessor',
    'AuthenticationRiskAssessor',
    'AdminAccessRiskAssessor',
    'FileOperationsRiskAssessor',
    'DatabaseOperationsRiskAssessor'
] 