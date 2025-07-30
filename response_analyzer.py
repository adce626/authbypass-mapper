"""
Response analyzer for comparing original and modified responses.
"""

import difflib
import re
import json
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse


class ResponseAnalyzer:
    """Analyzes and compares HTTP responses to detect potential bypasses."""
    
    def analyze_responses(self, original: Dict, modified: Dict) -> Dict:
        """
        Compare original and modified responses to detect significant changes.
        
        Args:
            original: Original response data
            modified: Modified response data
            
        Returns:
            Analysis results dictionary
        """
        if original.get('error') or modified.get('error'):
            return {
                'significant_change': False,
                'error': f"Request error - Original: {original.get('error', 'None')}, Modified: {modified.get('error', 'None')}",
                'status_code_change': False,
                'content_change': False,
                'redirect_change': False,
                'header_changes': {},
                'confidence_score': 0.0
            }
        
        analysis = {
            'significant_change': False,
            'status_code_change': False,
            'content_change': False,
            'redirect_change': False,
            'content_length_change': False,
            'header_changes': {},
            'content_diff': {},
            'confidence_score': 0.0,
            'bypass_indicators': []
        }
        
        # Analyze status code changes
        analysis.update(self._analyze_status_codes(original, modified))
        
        # Analyze content changes
        analysis.update(self._analyze_content_changes(original, modified))
        
        # Analyze redirect behavior
        analysis.update(self._analyze_redirects(original, modified))
        
        # Analyze headers
        analysis['header_changes'] = self._analyze_headers(original, modified)
        
        # Calculate overall confidence score
        analysis['confidence_score'] = self._calculate_confidence_score(analysis)
        
        # Determine if there's a significant change
        analysis['significant_change'] = self._is_significant_change(analysis)
        
        return analysis
    
    def _analyze_status_codes(self, original: Dict, modified: Dict) -> Dict:
        """Analyze status code differences."""
        orig_status = original.get('status_code')
        mod_status = modified.get('status_code')
        
        status_change = orig_status != mod_status
        bypass_indicators = []
        
        if status_change:
            # Check for common bypass patterns
            if orig_status in [401, 403] and mod_status == 200:
                bypass_indicators.append(f"Authentication/Authorization bypass: {orig_status} -> 200")
            elif orig_status == 302 and mod_status == 200:
                bypass_indicators.append("Redirect bypass: 302 -> 200 (direct access)")
            elif orig_status == 404 and mod_status == 200:
                bypass_indicators.append("Hidden endpoint discovered: 404 -> 200")
            elif orig_status in [500, 502, 503] and mod_status == 200:
                bypass_indicators.append(f"Error bypass: {orig_status} -> 200")
        
        return {
            'status_code_change': status_change,
            'original_status': orig_status,
            'modified_status': mod_status,
            'bypass_indicators': bypass_indicators
        }
    
    def _analyze_content_changes(self, original: Dict, modified: Dict) -> Dict:
        """Analyze content differences between responses."""
        orig_content = original.get('content', '')
        mod_content = modified.get('content', '')
        orig_length = original.get('content_length', 0)
        mod_length = modified.get('content_length', 0)
        
        content_change = orig_content != mod_content
        length_change = abs(orig_length - mod_length) > 10  # Ignore minor differences
        
        content_diff = {}
        bypass_indicators = []
        
        if content_change:
            # Calculate similarity ratio
            similarity = difflib.SequenceMatcher(None, orig_content, mod_content).ratio()
            content_diff['similarity_ratio'] = similarity
            
            # Look for bypass indicators in content
            bypass_indicators.extend(self._detect_content_bypass_indicators(orig_content, mod_content))
            
            # Analyze JSON responses
            if self._is_json_response(original) or self._is_json_response(modified):
                json_analysis = self._analyze_json_responses(orig_content, mod_content)
                content_diff.update(json_analysis)
                bypass_indicators.extend(json_analysis.get('bypass_indicators', []))
            
            # Analyze HTML responses
            if self._is_html_response(original) or self._is_html_response(modified):
                html_analysis = self._analyze_html_responses(orig_content, mod_content)
                content_diff.update(html_analysis)
                bypass_indicators.extend(html_analysis.get('bypass_indicators', []))
        
        return {
            'content_change': content_change,
            'content_length_change': length_change,
            'content_diff': content_diff,
            'original_length': orig_length,
            'modified_length': mod_length,
            'bypass_indicators': bypass_indicators
        }
    
    def _analyze_redirects(self, original: Dict, modified: Dict) -> Dict:
        """Analyze redirect behavior changes."""
        orig_redirect = original.get('is_redirect', False)
        mod_redirect = modified.get('is_redirect', False)
        
        redirect_change = orig_redirect != mod_redirect
        bypass_indicators = []
        
        if redirect_change:
            orig_location = original.get('headers', {}).get('Location', '')
            mod_location = modified.get('headers', {}).get('Location', '')
            
            if orig_redirect and not mod_redirect:
                bypass_indicators.append("Redirect bypassed - no longer redirecting")
            elif not orig_redirect and mod_redirect:
                bypass_indicators.append("New redirect introduced")
            elif orig_location != mod_location:
                bypass_indicators.append(f"Redirect destination changed: {orig_location} -> {mod_location}")
        
        return {
            'redirect_change': redirect_change,
            'bypass_indicators': bypass_indicators
        }
    
    def _analyze_headers(self, original: Dict, modified: Dict) -> Dict:
        """Analyze header differences."""
        orig_headers = original.get('headers', {})
        mod_headers = modified.get('headers', {})
        
        header_changes = {
            'added': {},
            'removed': {},
            'changed': {}
        }
        
        # Find added headers
        for header, value in mod_headers.items():
            if header not in orig_headers:
                header_changes['added'][header] = value
        
        # Find removed headers
        for header, value in orig_headers.items():
            if header not in mod_headers:
                header_changes['removed'][header] = value
        
        # Find changed headers
        for header in orig_headers:
            if header in mod_headers and orig_headers[header] != mod_headers[header]:
                header_changes['changed'][header] = {
                    'original': orig_headers[header],
                    'modified': mod_headers[header]
                }
        
        return header_changes
    
    def _detect_content_bypass_indicators(self, original: str, modified: str) -> List[str]:
        """Detect bypass indicators in content changes."""
        indicators = []
        
        # Keywords that might indicate successful access
        success_keywords = [
            'welcome', 'dashboard', 'admin', 'profile', 'settings',
            'logout', 'account', 'user_id', 'username', 'email',
            'token', 'session', 'authenticated', 'authorized'
        ]
        
        # Check if modified response contains success indicators not in original
        orig_lower = original.lower()
        mod_lower = modified.lower()
        
        for keyword in success_keywords:
            if keyword not in orig_lower and keyword in mod_lower:
                indicators.append(f"Success keyword '{keyword}' appeared in modified response")
        
        # Check for error messages disappearing
        error_keywords = ['error', 'unauthorized', 'forbidden', 'access denied', 'invalid']
        for keyword in error_keywords:
            if keyword in orig_lower and keyword not in mod_lower:
                indicators.append(f"Error keyword '{keyword}' disappeared from modified response")
        
        # Check for significant content increase (might indicate access to protected content)
        if len(modified) > len(original) * 1.5:
            indicators.append("Significant content increase (possible access to protected data)")
        
        return indicators
    
    def _analyze_json_responses(self, orig_content: str, mod_content: str) -> Dict:
        """Analyze JSON response differences."""
        analysis = {'bypass_indicators': []}
        
        try:
            orig_json = json.loads(orig_content)
            mod_json = json.loads(mod_content)
            
            # Check for privilege-related changes
            privilege_keys = ['role', 'admin', 'permissions', 'user_type', 'level', 'access']
            
            for key in privilege_keys:
                orig_val = self._get_nested_value(orig_json, key)
                mod_val = self._get_nested_value(mod_json, key)
                
                if orig_val != mod_val:
                    analysis['bypass_indicators'].append(
                        f"Privilege field '{key}' changed: {orig_val} -> {mod_val}"
                    )
            
            # Check for user data appearing
            user_keys = ['user_id', 'username', 'email', 'phone', 'address']
            for key in user_keys:
                if not self._get_nested_value(orig_json, key) and self._get_nested_value(mod_json, key):
                    analysis['bypass_indicators'].append(f"User data '{key}' appeared in response")
            
        except json.JSONDecodeError:
            pass
        
        return analysis
    
    def _analyze_html_responses(self, orig_content: str, mod_content: str) -> Dict:
        """Analyze HTML response differences."""
        analysis = {'bypass_indicators': []}
        
        # Look for form elements appearing/disappearing
        orig_forms = len(re.findall(r'<form[^>]*>', orig_content, re.IGNORECASE))
        mod_forms = len(re.findall(r'<form[^>]*>', mod_content, re.IGNORECASE))
        
        if mod_forms > orig_forms:
            analysis['bypass_indicators'].append("New forms appeared (possible admin interface)")
        
        # Look for admin-related elements
        admin_patterns = [
            r'admin', r'dashboard', r'control\s*panel', r'management',
            r'settings', r'configuration', r'users?\s+list'
        ]
        
        for pattern in admin_patterns:
            orig_matches = len(re.findall(pattern, orig_content, re.IGNORECASE))
            mod_matches = len(re.findall(pattern, mod_content, re.IGNORECASE))
            
            if mod_matches > orig_matches:
                analysis['bypass_indicators'].append(f"Admin-related content appeared: {pattern}")
        
        return analysis
    
    def _get_nested_value(self, data: Dict, key: str) -> Any:
        """Get value from nested dictionary by key (case-insensitive)."""
        if not isinstance(data, dict):
            return None
        
        # Direct match
        for k, v in data.items():
            if k.lower() == key.lower():
                return v
        
        # Search in nested dictionaries
        for k, v in data.items():
            if isinstance(v, dict):
                result = self._get_nested_value(v, key)
                if result is not None:
                    return result
        
        return None
    
    def _is_json_response(self, response: Dict) -> bool:
        """Check if response is JSON."""
        content_type = response.get('headers', {}).get('Content-Type', '').lower()
        return 'application/json' in content_type
    
    def _is_html_response(self, response: Dict) -> bool:
        """Check if response is HTML."""
        content_type = response.get('headers', {}).get('Content-Type', '').lower()
        return 'text/html' in content_type
    
    def _calculate_confidence_score(self, analysis: Dict) -> float:
        """Calculate confidence score for potential bypass."""
        score = 0.0
        
        # Status code changes
        if analysis.get('status_code_change'):
            orig_status = analysis.get('original_status')
            mod_status = analysis.get('modified_status')
            
            if orig_status in [401, 403] and mod_status == 200:
                score += 0.8  # High confidence for auth bypass
            elif orig_status == 302 and mod_status == 200:
                score += 0.7  # Good confidence for redirect bypass
            elif orig_status == 404 and mod_status == 200:
                score += 0.6  # Medium confidence for endpoint discovery
            else:
                score += 0.3  # Low confidence for other status changes
        
        # Content changes
        if analysis.get('content_change'):
            similarity = analysis.get('content_diff', {}).get('similarity_ratio', 1.0)
            if similarity < 0.5:  # Significant content change
                score += 0.4
            elif similarity < 0.8:
                score += 0.2
        
        # Bypass indicators
        indicator_count = len(analysis.get('bypass_indicators', []))
        score += min(indicator_count * 0.1, 0.3)  # Cap at 0.3
        
        return min(score, 1.0)  # Cap at 1.0
    
    def _is_significant_change(self, analysis: Dict) -> bool:
        """Determine if the changes are significant enough to warrant investigation."""
        return (
            analysis.get('confidence_score', 0) > 0.3 or
            analysis.get('status_code_change', False) or
            len(analysis.get('bypass_indicators', [])) > 0
        )
