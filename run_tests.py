#!/usr/bin/env python3
"""
Test runner for AuthBypass Mapper with comprehensive testing and validation.
"""

import os
import sys
import unittest
import tempfile
import json
from pathlib import Path

# Add current directory to path
sys.path.insert(0, '.')

def create_sample_har_file():
    """Create a sample HAR file for testing."""
    sample_har = {
        "log": {
            "version": "1.2",
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://api.example.com/user/profile",
                        "headers": [
                            {"name": "Authorization", "value": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.test.signature"},
                            {"name": "Content-Type", "value": "application/json"}
                        ],
                        "cookies": [
                            {"name": "sessionid", "value": "abc123def456"}
                        ],
                        "queryString": [],
                        "postData": {
                            "mimeType": "application/json",
                            "text": '{"user_id": 123, "role": "user"}'
                        }
                    }
                },
                {
                    "request": {
                        "method": "POST",
                        "url": "https://app.example.com/admin/settings",
                        "headers": [
                            {"name": "Cookie", "value": "sessionid=xyz789; admin=true"},
                            {"name": "X-CSRF-Token", "value": "csrf_token_value"}
                        ],
                        "cookies": [
                            {"name": "sessionid", "value": "xyz789"},
                            {"name": "admin", "value": "true"}
                        ],
                        "queryString": [],
                        "postData": {
                            "mimeType": "application/x-www-form-urlencoded",
                            "text": "action=update&user_role=admin&permissions=all"
                        }
                    }
                }
            ]
        }
    }
    
    temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.har', delete=False)
    json.dump(sample_har, temp_file, indent=2)
    temp_file.close()
    
    return temp_file.name

def create_sample_burp_file():
    """Create a sample Burp Suite XML file for testing."""
    sample_xml = '''<?xml version="1.0" encoding="UTF-8"?>
<issues>
    <item>
        <url>https://app.example.com/api/sensitive</url>
        <method>GET</method>
        <request>R0VUIC9hcGkvc2Vuc2l0aXZlIEhUVFAvMS4xDQpIb3N0OiBhcHAuZXhhbXBsZS5jb20NCkF1dGhvcml6YXRpb246IEJlYXJlciB0ZXN0X3Rva2VuDQpDb250ZW50LVR5cGU6IGFwcGxpY2F0aW9uL2pzb24NCg0K</request>
    </item>
</issues>'''
    
    temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False)
    temp_file.write(sample_xml)
    temp_file.close()
    
    return temp_file.name

def run_integration_tests():
    """Run integration tests with sample files."""
    print("🧪 Running Integration Tests...")
    
    # Create sample files
    har_file = create_sample_har_file()
    xml_file = create_sample_burp_file()
    
    try:
        from har_parser import HARParser, BurpParser
        from bypass_generator import BypassGenerator
        from response_analyzer import ResponseAnalyzer
        
        # Test HAR parsing
        print("  ✓ Testing HAR parsing...")
        har_parser = HARParser()
        har_requests = har_parser.parse(har_file)
        assert len(har_requests) > 0, "HAR parsing failed"
        assert har_requests[0]['auth_indicators']['has_jwt_token'], "JWT detection failed"
        
        # Test Burp parsing
        print("  ✓ Testing Burp XML parsing...")
        burp_parser = BurpParser()
        burp_requests = burp_parser.parse(xml_file)
        assert len(burp_requests) > 0, "Burp parsing failed"
        
        # Test attack generation
        print("  ✓ Testing attack generation...")
        bypass_gen = BypassGenerator()
        attacks = bypass_gen.generate_attacks(har_requests[0])
        assert len(attacks) > 0, "Attack generation failed"
        
        # Test response analysis
        print("  ✓ Testing response analysis...")
        analyzer = ResponseAnalyzer()
        
        # Simulate bypass scenario
        original_response = {
            'status_code': 401,
            'content': 'Unauthorized',
            'headers': {},
            'is_redirect': False,
            'content_length': 12
        }
        
        modified_response = {
            'status_code': 200,
            'content': '{"user_id": 123, "role": "admin", "access": "granted"}',
            'headers': {'Content-Type': 'application/json'},
            'is_redirect': False,
            'content_length': 52
        }
        
        analysis = analyzer.analyze_responses(original_response, modified_response)
        assert analysis['significant_change'], "Bypass detection failed"
        assert analysis['confidence_score'] > 0.5, "Confidence scoring failed"
        
        print("  ✅ All integration tests passed!")
        
    except Exception as e:
        print(f"  ❌ Integration test failed: {e}")
        return False
    finally:
        # Cleanup
        os.unlink(har_file)
        os.unlink(xml_file)
    
    return True

def test_advanced_features():
    """Test advanced features like multipart handling."""
    print("🔧 Testing Advanced Features...")
    
    try:
        from advanced_request_handler import AdvancedRequestHandler
        
        handler = AdvancedRequestHandler()
        
        # Test multipart parsing
        multipart_request = {
            'headers': {
                'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW'
            },
            'post_data': '''------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="token"

auth_token_value
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="test.txt"
Content-Type: text/plain

test file content
------WebKitFormBoundary7MA4YWxkTrZu0gW--'''
        }
        
        parsed = handler.parse_multipart_request(multipart_request)
        assert 'multipart_data' in parsed, "Multipart parsing failed"
        assert len(parsed['multipart_data']) == 2, "Multipart field count incorrect"
        
        # Test SPA pattern detection
        spa_request = {
            'headers': {
                'Authorization': 'Bearer jwt_token_here',
                'X-CSRF-Token': 'csrf_value',
                'X-API-Key': 'api_key_value'
            },
            'cookies': {'sessionid': 'session_value'},
            'post_data': '{"refresh_token": "refresh_value"}'
        }
        
        spa_patterns = handler.detect_spa_auth_patterns(spa_request)
        assert spa_patterns['has_bearer_token'], "Bearer token detection failed"
        assert spa_patterns['has_csrf_token'], "CSRF token detection failed"
        assert spa_patterns['has_api_key'], "API key detection failed"
        
        print("  ✅ Advanced features working correctly!")
        
    except Exception as e:
        print(f"  ❌ Advanced features test failed: {e}")
        return False
    
    return True

def validate_ai_integration():
    """Validate AI integration without making actual API calls."""
    print("🤖 Validating AI Integration...")
    
    try:
        # Check if OpenAI API key is available
        import os
        api_key = os.getenv('OPENAI_API_KEY')
        if not api_key:
            print("  ⚠️  OpenAI API key not found - AI features will not work")
            return False
        
        from ai_analyzer import AIAnalyzer
        
        # Initialize analyzer (this tests key validation)
        analyzer = AIAnalyzer()
        assert analyzer.client is not None, "AI analyzer initialization failed"
        
        # Test content sanitization
        test_content = "Email: test@example.com Phone: 555-1234 SSN: 123-45-6789"
        sanitized = analyzer._sanitize_content(test_content)
        assert '[EMAIL]' in sanitized, "Email sanitization failed"
        assert '[PHONE]' in sanitized, "Phone sanitization failed"
        assert '[SSN]' in sanitized, "SSN sanitization failed"
        
        print("  ✅ AI integration validated!")
        
    except Exception as e:
        print(f"  ❌ AI integration validation failed: {e}")
        return False
    
    return True

def run_unit_tests():
    """Run the unit test suite."""
    print("🧪 Running Unit Tests...")
    
    try:
        # Import and run tests
        from test_authbypass import TestResponseAnalyzer, TestBypassGenerator, TestHARParser
        
        test_loader = unittest.TestLoader()
        test_suite = unittest.TestSuite()
        
        # Add test classes
        test_suite.addTests(test_loader.loadTestsFromTestCase(TestResponseAnalyzer))
        test_suite.addTests(test_loader.loadTestsFromTestCase(TestBypassGenerator))
        test_suite.addTests(test_loader.loadTestsFromTestCase(TestHARParser))
        
        # Run tests
        runner = unittest.TextTestRunner(verbosity=0, stream=open(os.devnull, 'w'))
        result = runner.run(test_suite)
        
        if result.wasSuccessful():
            print(f"  ✅ All {result.testsRun} unit tests passed!")
            return True
        else:
            print(f"  ❌ {len(result.failures)} failures, {len(result.errors)} errors")
            for test, traceback in result.failures + result.errors:
                print(f"    Failed: {test}")
            return False
            
    except Exception as e:
        print(f"  ❌ Unit tests failed to run: {e}")
        return False

def validate_cli_interface():
    """Validate CLI interface functionality."""
    print("💻 Validating CLI Interface...")
    
    try:
        import subprocess
        result = subprocess.run(['python', 'main.py', '--help'], 
                              capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0 and 'AuthBypass Mapper' in result.stdout:
            print("  ✅ CLI interface working correctly!")
            return True
        else:
            print(f"  ❌ CLI interface failed: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"  ❌ CLI validation failed: {e}")
        return False

def main():
    """Main test runner."""
    print("🚀 AuthBypass Mapper - Comprehensive Test Suite")
    print("=" * 50)
    
    test_results = []
    
    # Run all tests
    test_results.append(("Unit Tests", run_unit_tests()))
    test_results.append(("Integration Tests", run_integration_tests()))
    test_results.append(("Advanced Features", test_advanced_features()))
    test_results.append(("AI Integration", validate_ai_integration()))
    test_results.append(("CLI Interface", validate_cli_interface()))
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 TEST SUMMARY")
    print("=" * 50)
    
    passed = 0
    total = len(test_results)
    
    for test_name, result in test_results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name:20} {status}")
        if result:
            passed += 1
    
    print("-" * 50)
    print(f"Total: {passed}/{total} test suites passed")
    
    if passed == total:
        print("\n🎉 All tests passed! AuthBypass Mapper is ready for use.")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test suite(s) failed. Please review the issues above.")
        return 1

if __name__ == '__main__':
    sys.exit(main())