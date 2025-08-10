#!/usr/bin/env python3
"""
VAmPI API Discovery Agent - Discovery Engine Tests

This file contains unit tests for the VAmPI discovery engine functionality.
Tests cover endpoint discovery, authentication detection, and risk assessment.

DO NOT EDIT THIS HEADER
"""

import unittest
from unittest.mock import Mock, patch, AsyncMock
import asyncio
from typing import List, Dict, Any

# Import the modules to test
from src.discovery import VAmPIDiscoveryEngine
from src.models import DiscoveryConfig, EndpointMetadata, RiskLevel


class TestVAmPIDiscoveryEngine(unittest.TestCase):
    """Test cases for VAmPIDiscoveryEngine class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = DiscoveryConfig(
            vampi_url="http://localhost:5000",
            timeout=30,
            rate_limit_delay=1.0,
            max_retries=3,
            user_agent="VAmPI-Discovery-Agent/1.0"
        )
        self.engine = VAmPIDiscoveryEngine(self.config)
    
    def test_engine_initialization(self):
        """Test that the discovery engine initializes correctly."""
        self.assertEqual(self.engine.config.vampi_url, "http://localhost:5000")
        self.assertEqual(self.engine.config.timeout, 30)
        self.assertEqual(len(self.engine.common_paths), 20)  # Should have 20 common paths
        self.assertEqual(len(self.engine.http_methods), 7)   # Should have 7 HTTP methods
    
    def test_risk_assessment_patterns(self):
        """Test risk assessment pattern matching."""
        path = "/users/v1/register"
        method = "POST"
        auth_required = False
        
        risk_level, reasons = self.engine._assess_risk_level(path, method, auth_required)
        
        # Registration endpoint without auth should be high risk
        self.assertIn(risk_level, [RiskLevel.HIGH, RiskLevel.CRITICAL])
        self.assertGreater(len(reasons), 0)
    
    def test_authentication_detection(self):
        """Test authentication mechanism detection."""
        # Mock response for testing
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.headers = {"WWW-Authenticate": "Bearer"}
        
        auth_type, required = self.engine._detect_authentication_type(
            mock_response, "/api/v1/users"
        )
        
        self.assertTrue(required)
        # Add more specific assertions based on your models
    
    @patch('httpx.AsyncClient')
    async def test_endpoint_discovery(self, mock_client):
        """Test endpoint discovery process."""
        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{"users": []}'
        mock_response.headers = {"Content-Type": "application/json"}
        
        mock_client.return_value.get.return_value = mock_response
        
        # Test discovery (this would need proper async test setup)
        pass
    
    def test_parameter_extraction(self):
        """Test parameter extraction from endpoint paths."""
        path = "/users/{id}/books/{book_id}"
        mock_response = Mock()
        mock_response.status_code = 200
        
        params = self.engine._extract_parameters(path, mock_response)
        
        # Should extract path parameters
        self.assertIn("id", [p.name for p in params.path_parameters])
        self.assertIn("book_id", [p.name for p in params.path_parameters])


class TestDiscoveryIntegration(unittest.TestCase):
    """Integration tests for discovery functionality."""
    
    def test_config_loading(self):
        """Test that configuration loads correctly from environment."""
        # This would test actual config loading
        pass
    
    def test_output_generation(self):
        """Test that discovery results are properly formatted."""
        # This would test the output format
        pass


if __name__ == "__main__":
    # Run tests
    unittest.main() 