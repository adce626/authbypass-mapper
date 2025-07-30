#!/usr/bin/env python3
"""
Unit tests for AuthBypass Mapper components.
Tests the core functionality of response analysis and AI analysis.
"""

import unittest
import json
from unittest.mock import Mock, patch, MagicMock
from response_analyzer import ResponseAnalyzer
from ai_analyzer import AIAnalyzer
from bypass_generator import BypassGenerator
from har_parser import HARParser, BurpParser


class TestResponseAnalyzer(unittest.TestCase):
    """Test the response analyzer component."""
    
    def setUp(self):
        self.analyzer = ResponseAnalyzer()
    
    def test_status_code_bypass_detection(self):
        """Test detection of authentication bypass via status code changes."""
        original = {
            'status_code': 401,
            'content': 'Unauthorized',
            'headers': {},
            'is_redirect': False,
            'content_length': 12
        }
        
        modified = {
            'status_code': 200,
            'content': 'Welcome to admin panel',
            'headers': {},
            'is_redirect': False,
            'content_length': 22
        }
        
        result = self.analyzer.analyze_responses(original, modified)
        
        self.assertTrue(result['status_code_change'])
        self.assertTrue(result['significant_change'])
        self.assertGreater(result['confidence_score'], 0.7)
        self.assertIn('Authentication/Authorization bypass', str(result['bypass_indicators']))
    
    def test_redirect_bypass_detection(self):
        """Test detection of redirect bypass."""
        original = {
            'status_code': 302,
            'content': '',
            'headers': {'Location': '/login'},
            'is_redirect': True,
            'content_length': 0
        }
        
        modified = {
            'status_code': 200,
            'content': '<h1>Dashboard</h1><p>Welcome admin!</p>',
            'headers': {},
            'is_redirect': False,
            'content_length': 40
        }
        
        result = self.analyzer.analyze_responses(original, modified)
        
        self.assertTrue(result['status_code_change'])
        self.assertTrue(result['redirect_change'])
        self.assertTrue(result['content_change'])
        self.assertGreater(result['confidence_score'], 0.6)
    
    def test_json_response_analysis(self):
        """Test analysis of JSON responses for privilege escalation."""
        original = {
            'status_code': 200,
            'content': '{"role": "user", "access": "limited"}',
            'headers': {'Content-Type': 'application/json'},
            'is_redirect': False,
            'content_length': 35
        }
        
        modified = {
            'status_code': 200,
            'content': '{"role": "admin", "access": "full", "user_id": 123}',
            'headers': {'Content-Type': 'application/json'},
            'is_redirect': False,
            'content_length': 50
        }
        
        result = self.analyzer.analyze_responses(original, modified)
        
        self.assertTrue(result['content_change'])
        self.assertTrue(result['significant_change'])
        self.assertIn('role', str(result['bypass_indicators']).lower())
    
    def test_no_significant_change(self):
        """Test that similar responses don't trigger false positives."""
        original = {
            'status_code': 200,
            'content': 'Hello World',
            'headers': {},
            'is_redirect': False,
            'content_length': 11
        }
        
        modified = {
            'status_code': 200,
            'content': 'Hello World!',
            'headers': {},
            'is_redirect': False,
            'content_length': 12
        }
        
        result = self.analyzer.analyze_responses(original, modified)
        
        self.assertFalse(result['status_code_change'])
        self.assertLess(result['confidence_score'], 0.3)
        self.assertEqual(len(result['bypass_indicators']), 0)


class TestBypassGenerator(unittest.TestCase):
    """Test the bypass attack generator."""
    
    def setUp(self):
        self.generator = BypassGenerator()
    
    def test_jwt_attack_generation(self):
        """Test JWT token manipulation attacks."""
        request = {
            'url': 'https://api.example.com/user/profile',
            'method': 'GET',
            'headers': {
                'Authorization': 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.test.signature'
            },
            'cookies': {},
            'post_data': None,
            'auth_indicators': {
                'has_jwt_token': True,
                'has_auth_header': True,
                'auth_headers': ['Authorization']
            }
        }
        
        attacks = self.generator.generate_attacks(request)
        
        # Should generate multiple JWT attacks
        jwt_attacks = [a for a in attacks if 'jwt' in a['attack_type']]
        self.assertGreater(len(jwt_attacks), 0)
        
        # Check for specific JWT manipulations
        attack_types = [a['attack_type'] for a in attacks]
        self.assertIn('jwt_null', attack_types)
        self.assertIn('jwt_empty', attack_types)
        self.assertIn('jwt_invalid_signature', attack_types)
    
    def test_session_cookie_attacks(self):
        """Test session cookie manipulation."""
        request = {
            'url': 'https://app.example.com/dashboard',
            'method': 'GET',
            'headers': {'Cookie': 'sessionid=abc123; other=value'},
            'cookies': {'sessionid': 'abc123', 'other': 'value'},
            'post_data': None,
            'auth_indicators': {
                'has_session_cookie': True,
                'session_cookies': ['sessionid']
            }
        }
        
        attacks = self.generator.generate_attacks(request)
        
        # Should generate session manipulation attacks
        session_attacks = [a for a in attacks if 'session' in a['attack_type']]
        self.assertGreater(len(session_attacks), 0)
        
        # Check that session cookie is modified
        for attack in session_attacks:
            if attack['attack_type'] == 'remove_session_cookie':
                self.assertNotIn('sessionid', attack['modified']['cookies'])
    
    def test_role_escalation_attacks(self):
        """Test role escalation in POST data."""
        request = {
            'url': 'https://api.example.com/user/update',
            'method': 'POST',
            'headers': {'Content-Type': 'application/json'},
            'cookies': {},
            'post_data': {'user_id': 123, 'role': 'user', 'permissions': 'read'},
            'auth_indicators': {'has_auth_header': True}
        }
        
        attacks = self.generator.generate_attacks(request)
        
        # Should generate role escalation attacks
        role_attacks = [a for a in attacks if 'role_escalation' in a['attack_type']]
        self.assertGreater(len(role_attacks), 0)
        
        # Check that role is escalated
        for attack in role_attacks:
            if attack['attack_type'] == 'role_escalation':
                modified_role = attack['modified']['post_data']['role']
                self.assertNotEqual(modified_role, 'user')


class TestHARParser(unittest.TestCase):
    """Test HAR file parsing."""
    
    def setUp(self):
        self.parser = HARParser()
    
    def test_auth_indicator_detection(self):
        """Test detection of authentication indicators."""
        headers = {
            'Authorization': 'Bearer jwt_token_here',
            'Content-Type': 'application/json'
        }
        cookies = {'sessionid': 'session_value'}
        post_data = {'token': 'api_token'}
        
        indicators = self.parser._detect_auth_indicators(headers, cookies, post_data)
        
        self.assertTrue(indicators['has_auth_header'])
        self.assertTrue(indicators['has_jwt_token'])
        self.assertTrue(indicators['has_session_cookie'])
        self.assertIn('Authorization', indicators['auth_headers'])
        self.assertIn('sessionid', indicators['session_cookies'])


class TestAIAnalyzer(unittest.TestCase):
    """Test AI analysis component."""
    
    def setUp(self):
        # Mock the OpenAI client to avoid API calls during tests
        with patch.dict('os.environ', {'OPENAI_API_KEY': 'test_key'}):
            self.analyzer = AIAnalyzer()
    
    @patch('ai_analyzer.OpenAI')
    def test_bypass_analysis_success(self, mock_openai):
        """Test successful bypass analysis."""
        # Mock OpenAI response
        mock_response = Mock()
        mock_response.choices = [Mock()]
        mock_response.choices[0].message.content = json.dumps({
            'bypass_detected': True,
            'severity': 'Critical',
            'confidence': 0.9,
            'explanation': 'Status code changed from 401 to 200, indicating bypass',
            'evidence': ['401 -> 200 status change', 'Admin content in response'],
            'false_positive_likelihood': 'Low',
            'recommendations': ['Verify manually', 'Test with different accounts'],
            'attack_effectiveness': 'High'
        })
        
        mock_openai.return_value.chat.completions.create.return_value = mock_response
        
        attack_request = {
            'attack_type': 'remove_auth_header',
            'description': 'Removed Authorization header'
        }
        
        original_response = {
            'status_code': 401,
            'content': 'Unauthorized'
        }
        
        modified_response = {
            'status_code': 200,
            'content': 'Welcome to admin dashboard'
        }
        
        diff_analysis = {
            'status_code_change': True,
            'confidence_score': 0.8,
            'bypass_indicators': ['Status change 401->200']
        }
        
        result = self.analyzer.analyze_bypass_attempt(
            attack_request, original_response, modified_response, diff_analysis
        )
        
        self.assertTrue(result['bypass_detected'])
        self.assertEqual(result['severity'], 'Critical')
        self.assertGreater(result['confidence'], 0.8)
        self.assertEqual(result['ai_model'], 'gpt-4o')
    
    def test_content_sanitization(self):
        """Test PII removal from content."""
        content = "Email: john.doe@example.com Phone: 555-123-4567 SSN: 123-45-6789"
        sanitized = self.analyzer._sanitize_content(content)
        
        self.assertNotIn('john.doe@example.com', sanitized)
        self.assertNotIn('555-123-4567', sanitized)
        self.assertNotIn('123-45-6789', sanitized)
        self.assertIn('[EMAIL]', sanitized)
        self.assertIn('[PHONE]', sanitized)
        self.assertIn('[SSN]', sanitized)


if __name__ == '__main__':
    # Run all tests
    unittest.main(verbosity=2)