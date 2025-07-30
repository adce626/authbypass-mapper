"""
HTTP request sender with response capture and error handling.
"""

import requests
import time
from typing import Dict, Optional
from urllib3.exceptions import InsecureRequestWarning
from requests.exceptions import RequestException, Timeout, ConnectionError


# Disable SSL warnings for testing
import urllib3
urllib3.disable_warnings(InsecureRequestWarning)


class RequestSender:
    """Handles sending HTTP requests and capturing responses."""
    
    def __init__(self, timeout: int = 10, max_retries: int = 2):
        """
        Initialize the request sender.
        
        Args:
            timeout: Request timeout in seconds
            max_retries: Maximum number of retries for failed requests
        """
        self.timeout = timeout
        self.max_retries = max_retries
        
        # Create session with default settings
        self.session = requests.Session()
        self.session.verify = False  # Disable SSL verification for testing
        
        # Set default headers
        self.session.headers.update({
            'User-Agent': 'AuthBypass-Mapper/1.0',
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
    
    def send_request(self, request_data: Dict) -> Dict:
        """
        Send HTTP request and capture response.
        
        Args:
            request_data: Dictionary containing request information
            
        Returns:
            Dictionary containing response information
        """
        url = request_data.get('url', '')
        method = request_data.get('method', 'GET').upper()
        headers = request_data.get('headers', {})
        cookies = request_data.get('cookies', {})
        post_data = request_data.get('post_data')
        
        if not url:
            return self._create_error_response("No URL provided")
        
        # Prepare request parameters
        request_kwargs = {
            'method': method,
            'url': url,
            'headers': headers,
            'cookies': cookies,
            'timeout': self.timeout,
            'allow_redirects': False,  # Don't follow redirects to analyze them
            'verify': False  # Disable SSL verification
        }
        
        # Add request body if present
        if post_data is not None:
            if isinstance(post_data, dict):
                # Check content type to determine how to send data
                content_type = headers.get('Content-Type', '').lower()
                if 'application/json' in content_type:
                    import json
                    request_kwargs['json'] = post_data
                else:
                    request_kwargs['data'] = post_data
            else:
                request_kwargs['data'] = post_data
        
        # Send request with retries
        for attempt in range(self.max_retries + 1):
            try:
                start_time = time.time()
                response = self.session.request(**request_kwargs)
                end_time = time.time()
                
                return self._create_response_dict(response, end_time - start_time)
                
            except Timeout:
                if attempt < self.max_retries:
                    time.sleep(1)  # Wait before retry
                    continue
                return self._create_error_response(f"Request timeout after {self.timeout} seconds")
                
            except ConnectionError as e:
                if attempt < self.max_retries:
                    time.sleep(1)  # Wait before retry
                    continue
                return self._create_error_response(f"Connection error: {str(e)}")
                
            except RequestException as e:
                if attempt < self.max_retries:
                    time.sleep(1)  # Wait before retry
                    continue
                return self._create_error_response(f"Request error: {str(e)}")
                
            except Exception as e:
                return self._create_error_response(f"Unexpected error: {str(e)}")
        
        return self._create_error_response("Max retries exceeded")
    
    def _create_response_dict(self, response: requests.Response, response_time: float) -> Dict:
        """Create standardized response dictionary."""
        try:
            # Try to get response text
            try:
                response_text = response.text
            except Exception:
                response_text = "[Error reading response text]"
            
            # Get response headers
            response_headers = dict(response.headers)
            
            # Get cookies
            response_cookies = {}
            for cookie in response.cookies:
                response_cookies[cookie.name] = cookie.value
            
            return {
                'status_code': response.status_code,
                'reason': response.reason,
                'headers': response_headers,
                'cookies': response_cookies,
                'content': response_text,
                'content_length': len(response_text),
                'response_time': response_time,
                'url': response.url,
                'history': [r.status_code for r in response.history],
                'is_redirect': len(response.history) > 0 or response.status_code in [301, 302, 303, 307, 308],
                'error': None
            }
            
        except Exception as e:
            return self._create_error_response(f"Error processing response: {str(e)}")
    
    def _create_error_response(self, error_message: str) -> Dict:
        """Create error response dictionary."""
        return {
            'status_code': None,
            'reason': None,
            'headers': {},
            'cookies': {},
            'content': '',
            'content_length': 0,
            'response_time': 0,
            'url': None,
            'history': [],
            'is_redirect': False,
            'error': error_message
        }
    
    def close(self):
        """Close the session."""
        if self.session:
            self.session.close()
