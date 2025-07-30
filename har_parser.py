"""
HAR and Burp Suite XML file parsers for extracting HTTP requests.
"""

import json
import xml.etree.ElementTree as ET
import base64
from urllib.parse import urlparse, parse_qs, unquote
from typing import List, Dict, Optional


class HARParser:
    """Parser for HAR (HTTP Archive) files."""
    
    def parse(self, file_path: str, target_domain: Optional[str] = None) -> List[Dict]:
        """
        Parse HAR file and extract HTTP requests.
        
        Args:
            file_path: Path to the HAR file
            target_domain: Optional domain filter
            
        Returns:
            List of parsed HTTP requests
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                har_data = json.load(f)
        except Exception as e:
            raise Exception(f"Failed to parse HAR file: {e}")
        
        requests = []
        entries = har_data.get('log', {}).get('entries', [])
        
        for entry in entries:
            request_data = entry.get('request', {})
            
            # Filter by domain if specified
            if target_domain:
                url = request_data.get('url', '')
                parsed_url = urlparse(url)
                if target_domain.lower() not in parsed_url.netloc.lower():
                    continue
            
            # Extract request details
            parsed_request = self._extract_request_details(request_data)
            if parsed_request:
                requests.append(parsed_request)
        
        return requests
    
    def _extract_request_details(self, request_data: Dict) -> Optional[Dict]:
        """Extract and normalize request details from HAR entry."""
        try:
            url = request_data.get('url', '')
            method = request_data.get('method', 'GET')
            
            # Skip non-interesting methods or URLs
            if method in ['OPTIONS', 'HEAD'] or not url:
                return None
            
            # Extract headers
            headers = {}
            for header in request_data.get('headers', []):
                headers[header['name']] = header['value']
            
            # Extract cookies
            cookies = {}
            for cookie in request_data.get('cookies', []):
                cookies[cookie['name']] = cookie['value']
            
            # Extract query parameters
            query_params = {}
            for param in request_data.get('queryString', []):
                query_params[param['name']] = param['value']
            
            # Extract POST data
            post_data = None
            if 'postData' in request_data:
                post_data_info = request_data['postData']
                if post_data_info.get('mimeType') == 'application/json':
                    try:
                        post_data = json.loads(post_data_info.get('text', ''))
                    except:
                        post_data = post_data_info.get('text', '')
                else:
                    post_data = post_data_info.get('text', '')
            
            # Check for authentication indicators
            auth_indicators = self._detect_auth_indicators(headers, cookies, post_data)
            
            return {
                'url': url,
                'method': method,
                'headers': headers,
                'cookies': cookies,
                'query_params': query_params,
                'post_data': post_data,
                'auth_indicators': auth_indicators
            }
            
        except Exception as e:
            print(f"Warning: Failed to parse request entry: {e}")
            return None
    
    def _detect_auth_indicators(self, headers: Dict, cookies: Dict, post_data) -> Dict:
        """Detect authentication-related indicators in the request."""
        indicators = {
            'has_auth_header': False,
            'has_jwt_token': False,
            'has_session_cookie': False,
            'has_api_key': False,
            'auth_headers': [],
            'session_cookies': [],
            'potential_tokens': []
        }
        
        # Check headers for authentication
        auth_headers = ['authorization', 'x-auth-token', 'x-api-key', 'x-access-token']
        for header_name, header_value in headers.items():
            header_lower = header_name.lower()
            
            if header_lower in auth_headers:
                indicators['has_auth_header'] = True
                indicators['auth_headers'].append(header_name)
                
                if 'bearer' in header_value.lower() or 'jwt' in header_value.lower():
                    indicators['has_jwt_token'] = True
                    indicators['potential_tokens'].append(header_value)
                
                if 'api' in header_lower or 'key' in header_lower:
                    indicators['has_api_key'] = True
        
        # Check cookies for sessions
        session_cookie_names = ['sessionid', 'session', 'jsessionid', 'phpsessid', 'auth']
        for cookie_name, cookie_value in cookies.items():
            cookie_lower = cookie_name.lower()
            
            for session_name in session_cookie_names:
                if session_name in cookie_lower:
                    indicators['has_session_cookie'] = True
                    indicators['session_cookies'].append(cookie_name)
                    break
        
        # Check POST data for tokens
        if post_data and isinstance(post_data, (str, dict)):
            post_str = json.dumps(post_data) if isinstance(post_data, dict) else str(post_data)
            token_keywords = ['token', 'jwt', 'bearer', 'auth', 'session']
            
            for keyword in token_keywords:
                if keyword in post_str.lower():
                    indicators['potential_tokens'].append(f"POST data contains '{keyword}'")
        
        return indicators


class BurpParser:
    """Parser for Burp Suite XML export files."""
    
    def parse(self, file_path: str, target_domain: Optional[str] = None) -> List[Dict]:
        """
        Parse Burp Suite XML file and extract HTTP requests.
        
        Args:
            file_path: Path to the XML file
            target_domain: Optional domain filter
            
        Returns:
            List of parsed HTTP requests
        """
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
        except Exception as e:
            raise Exception(f"Failed to parse Burp XML file: {e}")
        
        requests = []
        
        # Handle different Burp export formats
        items = root.findall('.//item') or root.findall('.//request')
        
        for item in items:
            try:
                parsed_request = self._extract_burp_request(item, target_domain)
                if parsed_request:
                    requests.append(parsed_request)
            except Exception as e:
                print(f"Warning: Failed to parse Burp item: {e}")
                continue
        
        return requests
    
    def _extract_burp_request(self, item, target_domain: Optional[str]) -> Optional[Dict]:
        """Extract request details from Burp XML item."""
        try:
            # Extract basic info
            url = item.find('url')
            url = url.text if url is not None else ''
            
            method = item.find('method')
            method = method.text if method is not None else 'GET'
            
            # Filter by domain if specified
            if target_domain and url:
                parsed_url = urlparse(url)
                if target_domain.lower() not in parsed_url.netloc.lower():
                    return None
            
            # Extract request data (base64 encoded in Burp)
            request_elem = item.find('request')
            if request_elem is not None and request_elem.text:
                try:
                    request_raw = base64.b64decode(request_elem.text).decode('utf-8', errors='ignore')
                    return self._parse_raw_http_request(request_raw, url, method)
                except Exception as e:
                    print(f"Warning: Failed to decode Burp request: {e}")
                    return None
            
            # Fallback: construct basic request from available info
            return {
                'url': url,
                'method': method,
                'headers': {},
                'cookies': {},
                'query_params': {},
                'post_data': None,
                'auth_indicators': {'has_auth_header': False, 'has_jwt_token': False, 
                                  'has_session_cookie': False, 'has_api_key': False,
                                  'auth_headers': [], 'session_cookies': [], 'potential_tokens': []}
            }
            
        except Exception as e:
            print(f"Warning: Failed to extract Burp request: {e}")
            return None
    
    def _parse_raw_http_request(self, raw_request: str, url: str, method: str) -> Dict:
        """Parse raw HTTP request text."""
        lines = raw_request.split('\r\n')
        if not lines:
            lines = raw_request.split('\n')
        
        headers = {}
        cookies = {}
        post_data = None
        
        # Parse headers (skip first line which is the request line)
        header_section = True
        body_lines = []
        
        for i, line in enumerate(lines[1:], 1):
            if header_section:
                if line.strip() == '':
                    header_section = False
                    continue
                
                if ':' in line:
                    header_name, header_value = line.split(':', 1)
                    header_name = header_name.strip()
                    header_value = header_value.strip()
                    headers[header_name] = header_value
                    
                    # Extract cookies from Cookie header
                    if header_name.lower() == 'cookie':
                        for cookie_pair in header_value.split(';'):
                            if '=' in cookie_pair:
                                cookie_name, cookie_value = cookie_pair.split('=', 1)
                                cookies[cookie_name.strip()] = cookie_value.strip()
            else:
                body_lines.append(line)
        
        # Parse POST data
        if body_lines and method.upper() in ['POST', 'PUT', 'PATCH']:
            post_data = '\r\n'.join(body_lines)
            try:
                # Try to parse as JSON
                post_data = json.loads(post_data)
            except:
                # Keep as string if not valid JSON
                pass
        
        # Extract query parameters from URL
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        # Flatten single-value lists
        query_params = {k: v[0] if len(v) == 1 else v for k, v in query_params.items()}
        
        # Detect authentication indicators
        auth_indicators = self._detect_auth_indicators_burp(headers, cookies, post_data)
        
        return {
            'url': url,
            'method': method,
            'headers': headers,
            'cookies': cookies,
            'query_params': query_params,
            'post_data': post_data,
            'auth_indicators': auth_indicators
        }
    
    def _detect_auth_indicators_burp(self, headers: Dict, cookies: Dict, post_data) -> Dict:
        """Detect authentication indicators in Burp request."""
        # Reuse the same logic as HAR parser
        har_parser = HARParser()
        return har_parser._detect_auth_indicators(headers, cookies, post_data)
