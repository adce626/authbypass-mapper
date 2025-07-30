"""
Session Context Simulation for AuthBypass Mapper.
Handles login flows and session state management for realistic testing.
"""

import json
import re
import time
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse
import requests
from request_sender import RequestSender


class SessionManager:
    """Manages session context and login flows for authentication testing."""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.session_tokens = {}
        self.cookies = {}
        self.headers = {}
        self.login_config = None
        
    def load_login_config(self, config_path: str = "login_config.json") -> bool:
        """Load login configuration from JSON file."""
        try:
            with open(config_path, 'r') as f:
                self.login_config = json.load(f)
            return True
        except FileNotFoundError:
            return False
        except Exception as e:
            print(f"Error loading login config: {e}")
            return False
    
    def create_default_login_config(self) -> Dict:
        """Create a default login configuration template."""
        return {
            "login_flows": [
                {
                    "name": "standard_login",
                    "description": "Standard username/password login",
                    "steps": [
                        {
                            "step": 1,
                            "type": "POST",
                            "url": "https://example.com/api/login",
                            "headers": {
                                "Content-Type": "application/json"
                            },
                            "data": {
                                "username": "{{USERNAME}}",
                                "password": "{{PASSWORD}}"
                            },
                            "extract_tokens": [
                                {
                                    "name": "access_token",
                                    "from": "response_json",
                                    "path": "token"
                                },
                                {
                                    "name": "session_id",
                                    "from": "cookie",
                                    "path": "sessionid"
                                }
                            ]
                        }
                    ]
                },
                {
                    "name": "multi_step_oauth",
                    "description": "Multi-step OAuth flow",
                    "steps": [
                        {
                            "step": 1,
                            "type": "GET",
                            "url": "https://example.com/oauth/authorize",
                            "extract_tokens": [
                                {
                                    "name": "csrf_token",
                                    "from": "response_html",
                                    "regex": "csrf_token.*?value=[\"']([^\"']+)[\"']"
                                }
                            ]
                        },
                        {
                            "step": 2,
                            "type": "POST",
                            "url": "https://example.com/oauth/token",
                            "headers": {
                                "Content-Type": "application/x-www-form-urlencoded"
                            },
                            "data": {
                                "grant_type": "authorization_code",
                                "code": "{{AUTH_CODE}}",
                                "csrf_token": "{{csrf_token}}"
                            },
                            "extract_tokens": [
                                {
                                    "name": "access_token",
                                    "from": "response_json",
                                    "path": "access_token"
                                },
                                {
                                    "name": "refresh_token",
                                    "from": "response_json",
                                    "path": "refresh_token"
                                }
                            ]
                        }
                    ]
                }
            ],
            "credentials": {
                "USERNAME": "test_user",
                "PASSWORD": "test_password",
                "AUTH_CODE": "test_auth_code"
            }
        }
    
    def save_default_config(self, config_path: str = "login_config.json"):
        """Save default configuration to file."""
        config = self.create_default_login_config()
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        print(f"Default login configuration saved to {config_path}")
    
    def execute_login_flow(self, flow_name: str) -> Dict:
        """Execute a complete login flow and capture session state."""
        if not self.login_config:
            return {"error": "No login configuration loaded"}
        
        # Find the specified flow
        flow = None
        for f in self.login_config.get("login_flows", []):
            if f["name"] == flow_name:
                flow = f
                break
        
        if not flow:
            return {"error": f"Login flow '{flow_name}' not found"}
        
        results = {
            "flow_name": flow_name,
            "steps_executed": [],
            "extracted_tokens": {},
            "final_session_state": {},
            "success": False
        }
        
        try:
            for step in flow["steps"]:
                step_result = self._execute_login_step(step)
                results["steps_executed"].append(step_result)
                
                # Extract tokens from this step
                if step_result["success"] and "extract_tokens" in step:
                    extracted = self._extract_tokens(
                        step["extract_tokens"], 
                        step_result["response"]
                    )
                    results["extracted_tokens"].update(extracted)
                    
                    # Update session state with new tokens
                    self._update_session_state(extracted)
            
            # Capture final session state
            results["final_session_state"] = {
                "cookies": dict(self.session.cookies),
                "headers": self.headers.copy(),
                "tokens": self.session_tokens.copy()
            }
            
            results["success"] = len(results["extracted_tokens"]) > 0
            
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    def _execute_login_step(self, step: Dict) -> Dict:
        """Execute a single step in the login flow."""
        try:
            url = step["url"]
            method = step.get("type", "GET").upper()
            headers = step.get("headers", {})
            data = step.get("data", {})
            
            # Replace placeholders in data
            data = self._replace_placeholders(data)
            
            # Merge with session headers
            final_headers = {**self.headers, **headers}
            
            # Execute request
            if method == "GET":
                response = self.session.get(url, headers=final_headers)
            elif method == "POST":
                content_type = final_headers.get("Content-Type", "").lower()
                if "application/json" in content_type:
                    response = self.session.post(url, json=data, headers=final_headers)
                else:
                    response = self.session.post(url, data=data, headers=final_headers)
            else:
                response = self.session.request(method, url, json=data, headers=final_headers)
            
            return {
                "step": step.get("step", 0),
                "success": True,
                "status_code": response.status_code,
                "response": {
                    "text": response.text,
                    "json": self._safe_json_parse(response.text),
                    "headers": dict(response.headers),
                    "cookies": dict(response.cookies)
                }
            }
            
        except Exception as e:
            return {
                "step": step.get("step", 0),
                "success": False,
                "error": str(e),
                "response": None
            }
    
    def _extract_tokens(self, token_configs: List[Dict], response: Dict) -> Dict:
        """Extract tokens from response based on configuration."""
        extracted = {}
        
        for config in token_configs:
            token_name = config["name"]
            source = config["from"]
            
            try:
                if source == "response_json" and response["json"]:
                    path = config["path"]
                    value = self._get_nested_value(response["json"], path)
                    if value:
                        extracted[token_name] = value
                
                elif source == "cookie":
                    cookie_name = config["path"]
                    if cookie_name in response["cookies"]:
                        extracted[token_name] = response["cookies"][cookie_name]
                
                elif source == "response_html":
                    regex_pattern = config["regex"]
                    match = re.search(regex_pattern, response["text"], re.IGNORECASE)
                    if match:
                        extracted[token_name] = match.group(1)
                
                elif source == "header":
                    header_name = config["path"]
                    if header_name in response["headers"]:
                        extracted[token_name] = response["headers"][header_name]
                        
            except Exception as e:
                print(f"Error extracting token {token_name}: {e}")
        
        return extracted
    
    def _update_session_state(self, tokens: Dict):
        """Update session state with extracted tokens."""
        self.session_tokens.update(tokens)
        
        # Automatically set common headers based on token names
        for token_name, token_value in tokens.items():
            if "access_token" in token_name.lower() or "bearer" in token_name.lower():
                self.headers["Authorization"] = f"Bearer {token_value}"
            elif "csrf" in token_name.lower():
                self.headers["X-CSRF-Token"] = token_value
            elif "api_key" in token_name.lower():
                self.headers["X-API-Key"] = token_value
    
    def _replace_placeholders(self, data: Any) -> Any:
        """Replace placeholders in data with actual values."""
        if isinstance(data, dict):
            result = {}
            for key, value in data.items():
                result[key] = self._replace_placeholders(value)
            return result
        elif isinstance(data, list):
            return [self._replace_placeholders(item) for item in data]
        elif isinstance(data, str):
            # Replace credentials
            for cred_name, cred_value in self.login_config.get("credentials", {}).items():
                data = data.replace(f"{{{{{cred_name}}}}}", cred_value)
            
            # Replace extracted tokens
            for token_name, token_value in self.session_tokens.items():
                data = data.replace(f"{{{{{token_name}}}}}", str(token_value))
            
            return data
        else:
            return data
    
    def _get_nested_value(self, data: Dict, path: str) -> Any:
        """Get nested value from dictionary using dot notation."""
        keys = path.split('.')
        current = data
        
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None
        
        return current
    
    def _safe_json_parse(self, text: str) -> Optional[Dict]:
        """Safely parse JSON response."""
        try:
            return json.loads(text)
        except:
            return None
    
    def apply_session_to_request(self, request_data: Dict) -> Dict:
        """Apply current session state to a request."""
        enhanced_request = request_data.copy()
        
        # Merge headers
        current_headers = enhanced_request.get("headers", {})
        current_headers.update(self.headers)
        enhanced_request["headers"] = current_headers
        
        # Merge cookies
        current_cookies = enhanced_request.get("cookies", {})
        current_cookies.update(dict(self.session.cookies))
        enhanced_request["cookies"] = current_cookies
        
        # Add session tokens to request data if applicable
        if "post_data" in enhanced_request and isinstance(enhanced_request["post_data"], dict):
            # Don't automatically add tokens to POST data to avoid breaking requests
            pass
        
        return enhanced_request
    
    def get_session_summary(self) -> Dict:
        """Get summary of current session state."""
        return {
            "active_tokens": list(self.session_tokens.keys()),
            "session_cookies": list(self.session.cookies.keys()),
            "custom_headers": list(self.headers.keys()),
            "session_valid": len(self.session_tokens) > 0 or len(self.session.cookies) > 0
        }
    
    def reset_session(self):
        """Reset session state."""
        self.session.cookies.clear()
        self.session_tokens.clear()
        self.headers.clear()
        print("Session state reset")
    
    def simulate_session_bypass_attacks(self, request_data: Dict) -> List[Dict]:
        """Generate session-specific bypass attacks."""
        attacks = []
        
        if not self.session_tokens and not self.session.cookies:
            return attacks
        
        # Attack 1: Remove all session context
        no_session_request = request_data.copy()
        no_session_request["headers"] = {
            k: v for k, v in no_session_request.get("headers", {}).items()
            if "authorization" not in k.lower() and "csrf" not in k.lower()
        }
        no_session_request["cookies"] = {}
        
        attacks.append({
            "original": self.apply_session_to_request(request_data),
            "modified": no_session_request,
            "attack_type": "complete_session_removal",
            "description": "Removed all session context (tokens, cookies, auth headers)"
        })
        
        # Attack 2: Use expired/invalid session tokens
        invalid_session_request = self.apply_session_to_request(request_data)
        if "Authorization" in invalid_session_request.get("headers", {}):
            invalid_session_request["headers"]["Authorization"] = "Bearer invalid_expired_token"
        
        attacks.append({
            "original": self.apply_session_to_request(request_data),
            "modified": invalid_session_request,
            "attack_type": "invalid_session_token",
            "description": "Used invalid/expired session token"
        })
        
        # Attack 3: Session fixation attempt
        if self.session.cookies:
            fixed_session_request = self.apply_session_to_request(request_data)
            # Modify session ID slightly
            for cookie_name in fixed_session_request.get("cookies", {}):
                if "session" in cookie_name.lower():
                    original_value = fixed_session_request["cookies"][cookie_name]
                    fixed_session_request["cookies"][cookie_name] = original_value + "_fixed"
                    break
            
            attacks.append({
                "original": self.apply_session_to_request(request_data),
                "modified": fixed_session_request,
                "attack_type": "session_fixation",
                "description": "Modified session ID for fixation attack"
            })
        
        return attacks