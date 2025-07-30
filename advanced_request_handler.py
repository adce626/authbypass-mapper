"""
Advanced request handler for complex authentication scenarios.
Supports multipart forms, file uploads, multi-step auth, and SPA token handling.
"""

import json
import re
import base64
import mimetypes
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import parse_qs, urlencode
import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder


class AdvancedRequestHandler:
    """Handles complex request scenarios including multipart forms and multi-step auth."""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False  # Disable SSL verification for testing
        
    def parse_multipart_request(self, request_data: Dict) -> Dict:
        """Parse and understand multipart/form-data requests."""
        headers = request_data.get('headers', {})
        post_data = request_data.get('post_data', '')
        
        content_type = headers.get('Content-Type', '').lower()
        
        if 'multipart/form-data' not in content_type:
            return request_data
        
        # Extract boundary from content type
        boundary_match = re.search(r'boundary=([^;]+)', content_type)
        if not boundary_match:
            return request_data
        
        boundary = boundary_match.group(1).strip('"')
        
        # Parse multipart data
        multipart_data = self._parse_multipart_body(post_data, boundary)
        
        # Enhanced request data with parsed multipart info
        enhanced_request = request_data.copy()
        enhanced_request['multipart_data'] = multipart_data
        enhanced_request['form_fields'] = {
            field['name']: field['value'] 
            for field in multipart_data 
            if field['type'] == 'field'
        }
        enhanced_request['file_uploads'] = [
            field for field in multipart_data 
            if field['type'] == 'file'
        ]
        
        return enhanced_request
    
    def _parse_multipart_body(self, body: str, boundary: str) -> List[Dict]:
        """Parse multipart body content."""
        parts = []
        
        # Split by boundary
        boundary_pattern = f'--{boundary}'
        sections = body.split(boundary_pattern)
        
        for section in sections[1:-1]:  # Skip first empty and last closing sections
            section = section.strip()
            if not section:
                continue
                
            # Split headers from content
            header_end = section.find('\r\n\r\n')
            if header_end == -1:
                header_end = section.find('\n\n')
            
            if header_end == -1:
                continue
                
            headers_text = section[:header_end]
            content = section[header_end:].strip('\r\n ')
            
            # Parse headers
            headers = {}
            for line in headers_text.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
            
            # Extract field information
            content_disposition = headers.get('Content-Disposition', '')
            name_match = re.search(r'name="([^"]*)"', content_disposition)
            filename_match = re.search(r'filename="([^"]*)"', content_disposition)
            
            field_info = {
                'headers': headers,
                'content': content,
                'name': name_match.group(1) if name_match else '',
                'type': 'file' if filename_match else 'field',
            }
            
            if filename_match:
                field_info['filename'] = filename_match.group(1)
                field_info['content_type'] = headers.get('Content-Type', 'application/octet-stream')
            else:
                field_info['value'] = content
            
            parts.append(field_info)
        
        return parts
    
    def generate_multipart_bypass_attacks(self, request_data: Dict) -> List[Dict]:
        """Generate bypass attacks for multipart requests."""
        attacks = []
        
        multipart_data = request_data.get('multipart_data', [])
        if not multipart_data:
            return attacks
        
        # Attack 1: Remove authentication tokens from form fields
        for field in multipart_data:
            if field['type'] == 'field':
                field_name = field['name'].lower()
                if any(auth_term in field_name for auth_term in ['token', 'auth', 'session', 'csrf']):
                    modified_request = self._create_multipart_attack(
                        request_data, 'remove_auth_field', 
                        f"Removed authentication field: {field['name']}", 
                        remove_field=field['name']
                    )
                    attacks.append(modified_request)
        
        # Attack 2: Modify file upload parameters
        for field in multipart_data:
            if field['type'] == 'file':
                # Try bypassing file type restrictions
                modified_request = self._create_multipart_attack(
                    request_data, 'file_type_bypass',
                    f"Modified file type for: {field['name']}",
                    modify_file_field=field['name']
                )
                attacks.append(modified_request)
        
        # Attack 3: Add malicious fields
        modified_request = self._create_multipart_attack(
            request_data, 'privilege_injection',
            "Added privilege escalation fields",
            add_fields={'role': 'admin', 'is_admin': 'true', 'permission': 'all'}
        )
        attacks.append(modified_request)
        
        return attacks
    
    def _create_multipart_attack(self, original_request: Dict, attack_type: str, 
                                description: str, **modifications) -> Dict:
        """Create a modified multipart request for bypass testing."""
        multipart_data = original_request.get('multipart_data', []).copy()
        
        # Apply modifications
        if 'remove_field' in modifications:
            multipart_data = [
                field for field in multipart_data 
                if field['name'] != modifications['remove_field']
            ]
        
        if 'modify_file_field' in modifications:
            for field in multipart_data:
                if field['name'] == modifications['modify_file_field'] and field['type'] == 'file':
                    # Change file extension to try bypass
                    if 'filename' in field:
                        name, ext = field['filename'].rsplit('.', 1) if '.' in field['filename'] else (field['filename'], '')
                        field['filename'] = f"{name}.txt"  # Try common bypass
                        field['content_type'] = 'text/plain'
        
        if 'add_fields' in modifications:
            for name, value in modifications['add_fields'].items():
                multipart_data.append({
                    'type': 'field',
                    'name': name,
                    'value': str(value),
                    'headers': {'Content-Disposition': f'form-data; name="{name}"'}
                })
        
        # Rebuild the request
        modified_request = original_request.copy()
        modified_request['multipart_data'] = multipart_data
        modified_request['post_data'] = self._rebuild_multipart_body(multipart_data, original_request)
        
        return {
            'original': original_request,
            'modified': modified_request,
            'attack_type': attack_type,
            'description': description
        }
    
    def _rebuild_multipart_body(self, multipart_data: List[Dict], original_request: Dict) -> str:
        """Rebuild multipart body from parsed data."""
        # Create new multipart encoder
        fields = {}
        
        for field in multipart_data:
            if field['type'] == 'field':
                fields[field['name']] = field['value']
            elif field['type'] == 'file':
                # For files, we'll use a simple text representation
                # In a real scenario, you'd handle actual file content
                filename = field.get('filename', 'file.txt')
                content_type = field.get('content_type', 'text/plain')
                content = field.get('content', 'test content')
                fields[field['name']] = (filename, content, content_type)
        
        if fields:
            encoder = MultipartEncoder(fields=fields)
            return encoder.to_string()
        
        return original_request.get('post_data', '')
    
    def detect_spa_auth_patterns(self, request_data: Dict) -> Dict:
        """Detect Single Page Application authentication patterns."""
        patterns = {
            'has_bearer_token': False,
            'has_refresh_token': False,
            'has_csrf_token': False,
            'has_api_key': False,
            'uses_cookies': False,
            'auth_mechanisms': []
        }
        
        headers = request_data.get('headers', {})
        cookies = request_data.get('cookies', {})
        post_data = request_data.get('post_data', '')
        
        # Check for bearer tokens
        auth_header = headers.get('Authorization', '')
        if 'bearer' in auth_header.lower():
            patterns['has_bearer_token'] = True
            patterns['auth_mechanisms'].append('bearer_token')
        
        # Check for API keys
        for header_name, header_value in headers.items():
            if 'api' in header_name.lower() or 'key' in header_name.lower():
                patterns['has_api_key'] = True
                patterns['auth_mechanisms'].append('api_key')
                break
        
        # Check for CSRF tokens
        csrf_headers = ['x-csrf-token', 'x-xsrf-token', 'csrf-token']
        for csrf_header in csrf_headers:
            if csrf_header in [h.lower() for h in headers.keys()]:
                patterns['has_csrf_token'] = True
                patterns['auth_mechanisms'].append('csrf_token')
                break
        
        # Check POST data for tokens
        if isinstance(post_data, dict):
            post_str = json.dumps(post_data).lower()
        else:
            post_str = str(post_data).lower()
        
        token_keywords = ['refresh_token', 'access_token', 'csrf', 'xsrf']
        for keyword in token_keywords:
            if keyword in post_str:
                if 'refresh' in keyword:
                    patterns['has_refresh_token'] = True
                    patterns['auth_mechanisms'].append('refresh_token')
                elif 'csrf' in keyword or 'xsrf' in keyword:
                    patterns['has_csrf_token'] = True
                    patterns['auth_mechanisms'].append('csrf_token')
        
        # Check for session cookies
        if cookies:
            patterns['uses_cookies'] = True
            patterns['auth_mechanisms'].append('session_cookies')
        
        return patterns
    
    def generate_spa_bypass_attacks(self, request_data: Dict) -> List[Dict]:
        """Generate SPA-specific bypass attacks."""
        attacks = []
        spa_patterns = self.detect_spa_auth_patterns(request_data)
        
        if not spa_patterns['auth_mechanisms']:
            return attacks
        
        # Attack 1: Remove CSRF tokens
        if spa_patterns['has_csrf_token']:
            attacks.extend(self._generate_csrf_bypass_attacks(request_data))
        
        # Attack 2: Bearer token manipulation
        if spa_patterns['has_bearer_token']:
            attacks.extend(self._generate_bearer_token_attacks(request_data))
        
        # Attack 3: API key manipulation
        if spa_patterns['has_api_key']:
            attacks.extend(self._generate_api_key_attacks(request_data))
        
        return attacks
    
    def _generate_csrf_bypass_attacks(self, request_data: Dict) -> List[Dict]:
        """Generate CSRF token bypass attacks."""
        attacks = []
        headers = request_data.get('headers', {})
        
        # Remove CSRF headers
        csrf_headers = ['x-csrf-token', 'x-xsrf-token', 'csrf-token']
        for csrf_header in csrf_headers:
            for actual_header in headers.keys():
                if actual_header.lower() == csrf_header:
                    modified_request = request_data.copy()
                    modified_headers = headers.copy()
                    del modified_headers[actual_header]
                    modified_request['headers'] = modified_headers
                    
                    attacks.append({
                        'original': request_data,
                        'modified': modified_request,
                        'attack_type': 'csrf_bypass',
                        'description': f'Removed CSRF header: {actual_header}'
                    })
        
        return attacks
    
    def _generate_bearer_token_attacks(self, request_data: Dict) -> List[Dict]:
        """Generate bearer token bypass attacks."""
        attacks = []
        headers = request_data.get('headers', {})
        
        auth_header = headers.get('Authorization', '')
        if 'bearer' in auth_header.lower():
            # Attack 1: Remove bearer token
            modified_request = request_data.copy()
            modified_headers = headers.copy()
            del modified_headers['Authorization']
            modified_request['headers'] = modified_headers
            
            attacks.append({
                'original': request_data,
                'modified': modified_request,
                'attack_type': 'bearer_removal',
                'description': 'Removed Bearer token'
            })
            
            # Attack 2: Malformed bearer token
            modified_request = request_data.copy()
            modified_headers = headers.copy()
            modified_headers['Authorization'] = 'Bearer invalid_token'
            modified_request['headers'] = modified_headers
            
            attacks.append({
                'original': request_data,
                'modified': modified_request,
                'attack_type': 'bearer_invalid',
                'description': 'Set invalid Bearer token'
            })
        
        return attacks
    
    def _generate_api_key_attacks(self, request_data: Dict) -> List[Dict]:
        """Generate API key bypass attacks."""
        attacks = []
        headers = request_data.get('headers', {})
        
        # Find API key headers
        api_headers = []
        for header_name in headers.keys():
            if 'api' in header_name.lower() or 'key' in header_name.lower():
                api_headers.append(header_name)
        
        for api_header in api_headers:
            # Remove API key
            modified_request = request_data.copy()
            modified_headers = headers.copy()
            del modified_headers[api_header]
            modified_request['headers'] = modified_headers
            
            attacks.append({
                'original': request_data,
                'modified': modified_request,
                'attack_type': 'api_key_removal',
                'description': f'Removed API key header: {api_header}'
            })
            
            # Invalid API key
            modified_request = request_data.copy()
            modified_headers = headers.copy()
            modified_headers[api_header] = 'invalid_api_key'
            modified_request['headers'] = modified_headers
            
            attacks.append({
                'original': request_data,
                'modified': modified_request,
                'attack_type': 'api_key_invalid',
                'description': f'Set invalid API key in header: {api_header}'
            })
        
        return attacks
    
    def simulate_multi_step_auth(self, request_sequence: List[Dict]) -> List[Dict]:
        """Simulate multi-step authentication bypass scenarios."""
        if len(request_sequence) < 2:
            return []
        
        bypass_scenarios = []
        
        # Scenario 1: Skip intermediate steps
        for i in range(1, len(request_sequence) - 1):
            scenario = {
                'type': 'skip_step',
                'description': f'Skip authentication step {i+1}',
                'modified_sequence': request_sequence[:i] + request_sequence[i+1:],
                'skipped_step': i
            }
            bypass_scenarios.append(scenario)
        
        # Scenario 2: Reorder steps
        if len(request_sequence) >= 3:
            reordered = [request_sequence[0], request_sequence[2], request_sequence[1]]
            if len(request_sequence) > 3:
                reordered.extend(request_sequence[3:])
            
            scenario = {
                'type': 'reorder_steps',
                'description': 'Reorder authentication steps',
                'modified_sequence': reordered,
                'changes': 'Swapped steps 2 and 3'
            }
            bypass_scenarios.append(scenario)
        
        # Scenario 3: Repeat successful step
        last_request = request_sequence[-1]
        repeated_sequence = request_sequence + [last_request]
        
        scenario = {
            'type': 'repeat_final_step',
            'description': 'Repeat final authentication step',
            'modified_sequence': repeated_sequence,
            'changes': 'Added duplicate final request'
        }
        bypass_scenarios.append(scenario)
        
        return bypass_scenarios
    
    def analyze_javascript_auth_context(self, html_content: str) -> Dict:
        """Analyze HTML content for JavaScript-based authentication patterns."""
        patterns = {
            'has_spa_framework': False,
            'framework_type': None,
            'has_local_storage_auth': False,
            'has_session_storage_auth': False,
            'auth_endpoints': [],
            'token_patterns': []
        }
        
        # Check for SPA frameworks
        spa_frameworks = {
            'react': ['react', 'jsx', 'createelement'],
            'angular': ['angular', 'ng-', '@angular'],
            'vue': ['vue', 'v-', 'vuejs'],
            'ember': ['ember', 'emberjs']
        }
        
        content_lower = html_content.lower()
        
        for framework, indicators in spa_frameworks.items():
            if any(indicator in content_lower for indicator in indicators):
                patterns['has_spa_framework'] = True
                patterns['framework_type'] = framework
                break
        
        # Check for local/session storage usage
        storage_patterns = [
            'localstorage.setitem',
            'sessionstorage.setitem',
            'localstorage.getitem',
            'sessionstorage.getitem'
        ]
        
        for pattern in storage_patterns:
            if pattern in content_lower:
                if 'local' in pattern:
                    patterns['has_local_storage_auth'] = True
                else:
                    patterns['has_session_storage_auth'] = True
        
        # Extract potential API endpoints
        api_patterns = [
            r'/api/[^\s"\']+',
            r'/v\d+/[^\s"\']+',
            r'https?://[^\s"\']+/api/[^\s"\']+',
        ]
        
        for pattern in api_patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            patterns['auth_endpoints'].extend(matches)
        
        # Look for token patterns in JavaScript
        token_patterns = [
            r'token["\']?\s*[:=]\s*["\'][^"\']+["\']',
            r'bearer["\']?\s*[:=]\s*["\'][^"\']+["\']',
            r'authorization["\']?\s*[:=]\s*["\'][^"\']+["\']',
        ]
        
        for pattern in token_patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            patterns['token_patterns'].extend(matches)
        
        return patterns