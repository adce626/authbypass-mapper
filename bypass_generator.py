"""
Authentication bypass attack generator.
Creates various attack vectors by modifying original requests.
"""

import copy
import json
import re
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


class BypassGenerator:
    """Generates authentication bypass attack vectors."""
    
    def generate_attacks(self, original_request: Dict) -> List[Dict]:
        """
        Generate various authentication bypass attacks for a given request.
        
        Args:
            original_request: The original HTTP request
            
        Returns:
            List of attack request variants
        """
        attacks = []
        
        # Only generate attacks for requests with authentication indicators
        auth_indicators = original_request.get('auth_indicators', {})
        if not any([
            auth_indicators.get('has_auth_header'),
            auth_indicators.get('has_session_cookie'),
            auth_indicators.get('has_jwt_token'),
            auth_indicators.get('has_api_key')
        ]):
            return attacks
        
        # Attack 1: Remove Authorization header
        if auth_indicators.get('has_auth_header'):
            for auth_header in auth_indicators.get('auth_headers', []):
                attacks.append(self._remove_auth_header(original_request, auth_header))
        
        # Attack 2: Modify JWT tokens
        if auth_indicators.get('has_jwt_token'):
            attacks.extend(self._jwt_manipulation_attacks(original_request))
        
        # Attack 3: Remove session cookies
        if auth_indicators.get('has_session_cookie'):
            for session_cookie in auth_indicators.get('session_cookies', []):
                attacks.append(self._remove_session_cookie(original_request, session_cookie))
        
        # Attack 4: Modify session cookies (swap with different values)
        if auth_indicators.get('has_session_cookie'):
            attacks.extend(self._session_manipulation_attacks(original_request))
        
        # Attack 5: Role/privilege escalation in request body
        attacks.extend(self._role_escalation_attacks(original_request))
        
        # Attack 6: HTTP header manipulation
        attacks.extend(self._header_manipulation_attacks(original_request))
        
        # Attack 7: HTTP method tampering
        attacks.extend(self._method_tampering_attacks(original_request))
        
        # Attack 8: Path traversal and endpoint manipulation
        attacks.extend(self._path_manipulation_attacks(original_request))
        
        return attacks
    
    def _remove_auth_header(self, original_request: Dict, header_name: str) -> Dict:
        """Remove authentication header from request."""
        modified_request = copy.deepcopy(original_request)
        modified_request['headers'].pop(header_name, None)
        
        return {
            'original': original_request,
            'modified': modified_request,
            'attack_type': 'remove_auth_header',
            'description': f'Removed authentication header: {header_name}'
        }
    
    def _jwt_manipulation_attacks(self, original_request: Dict) -> List[Dict]:
        """Generate JWT token manipulation attacks."""
        attacks = []
        
        for header_name, header_value in original_request.get('headers', {}).items():
            if any(keyword in header_value.lower() for keyword in ['bearer', 'jwt']):
                # Attack 1: Set JWT to null
                modified_request = copy.deepcopy(original_request)
                modified_request['headers'][header_name] = 'Bearer null'
                attacks.append({
                    'original': original_request,
                    'modified': modified_request,
                    'attack_type': 'jwt_null',
                    'description': f'Set JWT token to null in header: {header_name}'
                })
                
                # Attack 2: Set JWT to empty string
                modified_request = copy.deepcopy(original_request)
                modified_request['headers'][header_name] = 'Bearer '
                attacks.append({
                    'original': original_request,
                    'modified': modified_request,
                    'attack_type': 'jwt_empty',
                    'description': f'Set JWT token to empty in header: {header_name}'
                })
                
                # Attack 3: Use invalid JWT signature
                modified_request = copy.deepcopy(original_request)
                if 'Bearer ' in header_value:
                    token = header_value.replace('Bearer ', '')
                    # Simple signature manipulation - change last character
                    if '.' in token:
                        parts = token.split('.')
                        if len(parts) >= 3:
                            parts[-1] = parts[-1][:-1] + 'X' if parts[-1] else 'X'
                            modified_token = '.'.join(parts)
                            modified_request['headers'][header_name] = f'Bearer {modified_token}'
                            attacks.append({
                                'original': original_request,
                                'modified': modified_request,
                                'attack_type': 'jwt_invalid_signature',
                                'description': f'Modified JWT signature in header: {header_name}'
                            })
        
        return attacks
    
    def _remove_session_cookie(self, original_request: Dict, cookie_name: str) -> Dict:
        """Remove session cookie from request."""
        modified_request = copy.deepcopy(original_request)
        modified_request['cookies'].pop(cookie_name, None)
        
        # Also update Cookie header if it exists
        if 'Cookie' in modified_request['headers']:
            cookie_header = modified_request['headers']['Cookie']
            # Remove the specific cookie from the header
            cookie_pairs = [pair.strip() for pair in cookie_header.split(';')]
            filtered_pairs = [pair for pair in cookie_pairs if not pair.startswith(f'{cookie_name}=')]
            modified_request['headers']['Cookie'] = '; '.join(filtered_pairs)
        
        return {
            'original': original_request,
            'modified': modified_request,
            'attack_type': 'remove_session_cookie',
            'description': f'Removed session cookie: {cookie_name}'
        }
    
    def _session_manipulation_attacks(self, original_request: Dict) -> List[Dict]:
        """Generate session manipulation attacks."""
        attacks = []
        
        for cookie_name in original_request.get('auth_indicators', {}).get('session_cookies', []):
            original_value = original_request.get('cookies', {}).get(cookie_name, '')
            
            # Attack 1: Use a different session ID (simple increment/decrement)
            if original_value.isdigit():
                new_value = str(int(original_value) + 1)
            else:
                # Simple character modification
                new_value = original_value[:-1] + 'X' if original_value else 'modified_session'
            
            modified_request = copy.deepcopy(original_request)
            modified_request['cookies'][cookie_name] = new_value
            
            # Update Cookie header
            if 'Cookie' in modified_request['headers']:
                cookie_header = modified_request['headers']['Cookie']
                cookie_header = re.sub(
                    f'{cookie_name}=[^;]*', 
                    f'{cookie_name}={new_value}', 
                    cookie_header
                )
                modified_request['headers']['Cookie'] = cookie_header
            
            attacks.append({
                'original': original_request,
                'modified': modified_request,
                'attack_type': 'session_manipulation',
                'description': f'Modified session cookie {cookie_name}: {original_value} -> {new_value}'
            })
        
        return attacks
    
    def _role_escalation_attacks(self, original_request: Dict) -> List[Dict]:
        """Generate role/privilege escalation attacks."""
        attacks = []
        
        # Check POST data for role-related parameters
        post_data = original_request.get('post_data')
        if post_data:
            role_keywords = ['role', 'user_type', 'permission', 'level', 'admin', 'privilege']
            
            if isinstance(post_data, dict):
                for key, value in post_data.items():
                    key_lower = key.lower()
                    if any(keyword in key_lower for keyword in role_keywords):
                        # Try to escalate to admin
                        modified_request = copy.deepcopy(original_request)
                        
                        if 'user' in str(value).lower():
                            modified_request['post_data'][key] = str(value).replace('user', 'admin')
                        elif str(value).isdigit():
                            # Assume higher number = higher privilege
                            modified_request['post_data'][key] = str(int(value) + 1)
                        else:
                            modified_request['post_data'][key] = 'admin'
                        
                        attacks.append({
                            'original': original_request,
                            'modified': modified_request,
                            'attack_type': 'role_escalation',
                            'description': f'Modified role parameter {key}: {value} -> {modified_request["post_data"][key]}'
                        })
            
            elif isinstance(post_data, str):
                # Try to find and modify role-related parameters in string data
                for keyword in role_keywords:
                    if keyword in post_data.lower():
                        modified_request = copy.deepcopy(original_request)
                        # Simple string replacement
                        modified_data = post_data.replace('user', 'admin').replace('User', 'Admin')
                        if modified_data != post_data:
                            modified_request['post_data'] = modified_data
                            attacks.append({
                                'original': original_request,
                                'modified': modified_request,
                                'attack_type': 'role_escalation_string',
                                'description': f'Modified role in POST data: user -> admin'
                            })
                        break
        
        return attacks
    
    def _header_manipulation_attacks(self, original_request: Dict) -> List[Dict]:
        """Generate header manipulation attacks."""
        attacks = []
        
        # Attack 1: Add X-Forwarded-For header to bypass IP restrictions
        modified_request = copy.deepcopy(original_request)
        modified_request['headers']['X-Forwarded-For'] = '127.0.0.1'
        attacks.append({
            'original': original_request,
            'modified': modified_request,
            'attack_type': 'x_forwarded_for',
            'description': 'Added X-Forwarded-For: 127.0.0.1 to bypass IP restrictions'
        })
        
        # Attack 2: Add X-Real-IP header
        modified_request = copy.deepcopy(original_request)
        modified_request['headers']['X-Real-IP'] = '127.0.0.1'
        attacks.append({
            'original': original_request,
            'modified': modified_request,
            'attack_type': 'x_real_ip',
            'description': 'Added X-Real-IP: 127.0.0.1 to bypass IP restrictions'
        })
        
        # Attack 3: Add X-Originating-IP header
        modified_request = copy.deepcopy(original_request)
        modified_request['headers']['X-Originating-IP'] = '127.0.0.1'
        attacks.append({
            'original': original_request,
            'modified': modified_request,
            'attack_type': 'x_originating_ip',
            'description': 'Added X-Originating-IP: 127.0.0.1 to bypass IP restrictions'
        })
        
        # Attack 4: Modify User-Agent to admin/bot
        if 'User-Agent' in original_request.get('headers', {}):
            modified_request = copy.deepcopy(original_request)
            modified_request['headers']['User-Agent'] = 'AdminBot/1.0'
            attacks.append({
                'original': original_request,
                'modified': modified_request,
                'attack_type': 'admin_user_agent',
                'description': 'Changed User-Agent to AdminBot/1.0'
            })
        
        return attacks
    
    def _method_tampering_attacks(self, original_request: Dict) -> List[Dict]:
        """Generate HTTP method tampering attacks."""
        attacks = []
        
        original_method = original_request.get('method', 'GET')
        
        # Try different HTTP methods
        test_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
        
        for method in test_methods:
            if method != original_method:
                modified_request = copy.deepcopy(original_request)
                modified_request['method'] = method
                
                # For GET requests, move POST data to query parameters
                if method == 'GET' and original_request.get('post_data'):
                    post_data = original_request['post_data']
                    if isinstance(post_data, dict):
                        # Add to query parameters
                        parsed_url = urlparse(original_request['url'])
                        query_params = parse_qs(parsed_url.query)
                        query_params.update(post_data)
                        new_query = urlencode(query_params, doseq=True)
                        modified_request['url'] = urlunparse(parsed_url._replace(query=new_query))
                        modified_request['post_data'] = None
                
                attacks.append({
                    'original': original_request,
                    'modified': modified_request,
                    'attack_type': 'method_tampering',
                    'description': f'Changed HTTP method from {original_method} to {method}'
                })
        
        return attacks
    
    def _path_manipulation_attacks(self, original_request: Dict) -> List[Dict]:
        """Generate path manipulation attacks."""
        attacks = []
        
        url = original_request.get('url', '')
        if not url:
            return attacks
        
        parsed_url = urlparse(url)
        original_path = parsed_url.path
        
        # Attack 1: Add ../ path traversal
        if original_path and not original_path.endswith('/'):
            modified_path = original_path + '/../admin'
            modified_url = urlunparse(parsed_url._replace(path=modified_path))
            
            modified_request = copy.deepcopy(original_request)
            modified_request['url'] = modified_url
            
            attacks.append({
                'original': original_request,
                'modified': modified_request,
                'attack_type': 'path_traversal',
                'description': f'Added path traversal: {original_path} -> {modified_path}'
            })
        
        # Attack 2: Try /admin endpoint
        if '/admin' not in original_path.lower():
            admin_path = '/admin' + original_path
            modified_url = urlunparse(parsed_url._replace(path=admin_path))
            
            modified_request = copy.deepcopy(original_request)
            modified_request['url'] = modified_url
            
            attacks.append({
                'original': original_request,
                'modified': modified_request,
                'attack_type': 'admin_path',
                'description': f'Modified path to admin endpoint: {original_path} -> {admin_path}'
            })
        
        return attacks
