"""
AI-Driven Smart Fuzzing Engine for AuthBypass Mapper.
Uses GPT to suggest intelligent follow-up attacks based on response analysis.
"""

import json
import re
import os
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, urljoin
from openai import OpenAI


class SmartAIFuzzer:
    """AI-powered intelligent attack suggestion engine."""
    
    def __init__(self):
        """Initialize the smart fuzzer with OpenAI client."""
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY environment variable is required")
        
        self.client = OpenAI(api_key=api_key)
        self.discovered_patterns = {}
        self.attack_history = []
    
    def analyze_and_suggest_attacks(self, test_result: Dict, original_request: Dict) -> Dict:
        """Analyze test result and suggest intelligent follow-up attacks."""
        
        # Extract key information from the test result
        analysis_context = self._extract_analysis_context(test_result, original_request)
        
        # Generate AI suggestions
        ai_suggestions = self._get_ai_attack_suggestions(analysis_context)
        
        # Generate specific attack requests
        suggested_attacks = self._generate_suggested_attacks(ai_suggestions, original_request)
        
        # Update pattern database
        self._update_pattern_database(test_result, ai_suggestions)
        
        return {
            "context": analysis_context,
            "ai_suggestions": ai_suggestions,
            "generated_attacks": suggested_attacks,
            "patterns_discovered": self._get_relevant_patterns(analysis_context)
        }
    
    def _extract_analysis_context(self, test_result: Dict, original_request: Dict) -> Dict:
        """Extract relevant context for AI analysis."""
        context = {
            "attack_type": test_result.get("attack_type", "unknown"),
            "attack_description": test_result.get("description", ""),
            "success_indicators": [],
            "response_analysis": {},
            "endpoint_info": {},
            "discovered_data": {}
        }
        
        # Extract response information
        original_response = test_result.get("original_response", {})
        modified_response = test_result.get("modified_response", {})
        
        context["response_analysis"] = {
            "status_change": f"{original_response.get('status_code')} → {modified_response.get('status_code')}",
            "content_change": len(modified_response.get("content", "")) != len(original_response.get("content", "")),
            "significant_change": test_result.get("diff_analysis", {}).get("significant_change", False),
            "bypass_indicators": test_result.get("diff_analysis", {}).get("bypass_indicators", [])
        }
        
        # Extract endpoint information
        url = original_request.get("url", "")
        parsed_url = urlparse(url)
        context["endpoint_info"] = {
            "base_url": f"{parsed_url.scheme}://{parsed_url.netloc}",
            "path": parsed_url.path,
            "method": original_request.get("method", "GET"),
            "has_parameters": bool(parsed_url.query),
            "is_api_endpoint": "/api/" in parsed_url.path.lower(),
            "path_segments": [seg for seg in parsed_url.path.split("/") if seg]
        }
        
        # Extract discovered data from responses
        context["discovered_data"] = self._extract_discovered_data(
            original_response.get("content", ""),
            modified_response.get("content", "")
        )
        
        # Determine success indicators
        if context["response_analysis"]["significant_change"]:
            context["success_indicators"].extend([
                "Response modification detected",
                "Potential bypass identified"
            ])
            
            if test_result.get("ai_analysis", {}).get("bypass_detected"):
                context["success_indicators"].append("AI confirmed bypass")
        
        return context
    
    def _extract_discovered_data(self, original_content: str, modified_content: str) -> Dict:
        """Extract interesting data from response content."""
        discovered = {
            "user_ids": set(),
            "roles": set(),
            "endpoints": set(),
            "tokens": set(),
            "parameters": set(),
            "file_paths": set()
        }
        
        # Combine both responses for analysis
        combined_content = original_content + " " + modified_content
        
        # Extract user IDs
        user_id_patterns = [
            r'"user_id":\s*(\d+)',
            r'"userId":\s*(\d+)',
            r'"id":\s*(\d+)',
            r'user[_-]?id["\']?\s*[:=]\s*["\']?(\d+)',
        ]
        
        for pattern in user_id_patterns:
            matches = re.findall(pattern, combined_content, re.IGNORECASE)
            discovered["user_ids"].update(matches)
        
        # Extract roles
        role_patterns = [
            r'"role":\s*"([^"]+)"',
            r'"user_role":\s*"([^"]+)"',
            r'"permission":\s*"([^"]+)"',
            r'role["\']?\s*[:=]\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in role_patterns:
            matches = re.findall(pattern, combined_content, re.IGNORECASE)
            discovered["roles"].update(matches)
        
        # Extract API endpoints
        endpoint_patterns = [
            r'"/api/[^"\s]+',
            r'"/v\d+/[^"\s]+',
            r'"/(admin|user|auth|login|dashboard)/[^"\s]*'
        ]
        
        for pattern in endpoint_patterns:
            matches = re.findall(pattern, combined_content, re.IGNORECASE)
            discovered["endpoints"].update(matches)
        
        # Extract tokens
        token_patterns = [
            r'"token":\s*"([^"]+)"',
            r'"access_token":\s*"([^"]+)"',
            r'"session_id":\s*"([^"]+)"',
            r'token["\']?\s*[:=]\s*["\']([^"\']{20,})["\']'
        ]
        
        for pattern in token_patterns:
            matches = re.findall(pattern, combined_content, re.IGNORECASE)
            discovered["tokens"].update(matches)
        
        # Convert sets to lists for JSON serialization
        return {k: list(v) for k, v in discovered.items()}
    
    def _get_ai_attack_suggestions(self, context: Dict) -> Dict:
        """Get AI-powered attack suggestions based on context."""
        try:
            prompt = self._create_attack_suggestion_prompt(context)
            
            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {
                        "role": "system",
                        "content": self._get_fuzzing_system_prompt()
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                response_format={"type": "json_object"},
                temperature=0.3,  # Slightly higher for creative attack suggestions
                max_tokens=1500
            )
            
            content = response.choices[0].message.content
            if content is None:
                raise ValueError("Empty response from OpenAI")
            
            ai_suggestions = json.loads(content)
            return ai_suggestions
            
        except Exception as e:
            return {
                "error": f"AI suggestion generation failed: {str(e)}",
                "suggested_attacks": [],
                "priority_targets": [],
                "attack_vectors": []
            }
    
    def _create_attack_suggestion_prompt(self, context: Dict) -> str:
        """Create prompt for AI attack suggestions."""
        return f"""
        Analyze this authentication bypass test result and suggest intelligent follow-up attacks:

        **Test Context:**
        - Attack Type: {context['attack_type']}
        - Description: {context['attack_description']}
        - Success Indicators: {', '.join(context['success_indicators'])}

        **Response Analysis:**
        - Status Change: {context['response_analysis']['status_change']}
        - Content Changed: {context['response_analysis']['content_change']}
        - Significant Change: {context['response_analysis']['significant_change']}
        - Bypass Indicators: {', '.join(context['response_analysis']['bypass_indicators'])}

        **Target Endpoint:**
        - Base URL: {context['endpoint_info']['base_url']}
        - Path: {context['endpoint_info']['path']}
        - Method: {context['endpoint_info']['method']}
        - Is API: {context['endpoint_info']['is_api_endpoint']}
        - Path Segments: {' -> '.join(context['endpoint_info']['path_segments'])}

        **Discovered Data:**
        - User IDs: {', '.join(context['discovered_data']['user_ids'][:5])}
        - Roles: {', '.join(context['discovered_data']['roles'])}
        - Endpoints: {', '.join(context['discovered_data']['endpoints'][:5])}
        - Tokens Found: {len(context['discovered_data']['tokens'])} tokens

        Based on this analysis, suggest specific follow-up attacks that could exploit the discovered information.
        Focus on practical, high-impact attacks that build on what was discovered.
        """
    
    def _get_fuzzing_system_prompt(self) -> str:
        """Get system prompt for AI fuzzing suggestions."""
        return """You are an expert penetration tester and vulnerability researcher specializing in authentication bypass attacks. Your task is to analyze test results and suggest intelligent follow-up attacks.

        Respond with JSON containing:
        - suggested_attacks: array of specific attack objects with type, description, and target
        - priority_targets: array of high-value endpoints/parameters to test next
        - attack_vectors: array of attack techniques to try based on discovered data
        - escalation_paths: array of privilege escalation opportunities
        - idor_opportunities: array of potential IDOR/BOLA targets based on discovered IDs

        For each suggested attack, include:
        - attack_type: brief identifier
        - description: what the attack does
        - target: specific endpoint or parameter to target
        - payload_suggestions: specific payloads or modifications to try
        - expected_outcome: what success would look like
        - risk_level: High/Medium/Low

        Focus on:
        1. Using discovered user IDs for IDOR testing
        2. Exploiting discovered roles for privilege escalation
        3. Testing discovered endpoints with bypass techniques
        4. Token manipulation based on found tokens
        5. Path traversal and endpoint discovery

        Be specific and actionable in your suggestions."""
    
    def _generate_suggested_attacks(self, ai_suggestions: Dict, original_request: Dict) -> List[Dict]:
        """Generate actual attack requests based on AI suggestions."""
        generated_attacks = []
        
        if "error" in ai_suggestions:
            return generated_attacks
        
        try:
            # Process suggested attacks
            for attack in ai_suggestions.get("suggested_attacks", []):
                attack_requests = self._create_attack_from_suggestion(attack, original_request)
                generated_attacks.extend(attack_requests)
            
            # Process IDOR opportunities
            for idor in ai_suggestions.get("idor_opportunities", []):
                idor_attacks = self._create_idor_attacks(idor, original_request)
                generated_attacks.extend(idor_attacks)
            
            # Process priority targets
            for target in ai_suggestions.get("priority_targets", []):
                target_attacks = self._create_target_attacks(target, original_request)
                generated_attacks.extend(target_attacks)
                
        except Exception as e:
            print(f"Error generating attacks from AI suggestions: {e}")
        
        return generated_attacks
    
    def _create_attack_from_suggestion(self, attack_suggestion: Dict, original_request: Dict) -> List[Dict]:
        """Create specific attack requests from AI suggestion."""
        attacks = []
        
        attack_type = attack_suggestion.get("attack_type", "ai_suggested")
        description = attack_suggestion.get("description", "AI-suggested attack")
        target = attack_suggestion.get("target", "")
        payloads = attack_suggestion.get("payload_suggestions", [])
        
        # Generate attacks based on target type
        if "endpoint" in target.lower():
            # Endpoint-based attacks
            attacks.extend(self._create_endpoint_attacks(attack_suggestion, original_request))
        elif "parameter" in target.lower():
            # Parameter-based attacks
            attacks.extend(self._create_parameter_attacks(attack_suggestion, original_request))
        elif "header" in target.lower():
            # Header-based attacks
            attacks.extend(self._create_header_attacks(attack_suggestion, original_request))
        
        return attacks
    
    def _create_idor_attacks(self, idor_suggestion: Dict, original_request: Dict) -> List[Dict]:
        """Create IDOR attacks based on AI suggestions."""
        attacks = []
        
        # Extract user IDs from discovered data
        discovered_ids = idor_suggestion.get("user_ids", [])
        target_parameter = idor_suggestion.get("parameter", "user_id")
        
        for user_id in discovered_ids[:5]:  # Limit to first 5 IDs
            # Test with different user ID
            modified_request = original_request.copy()
            
            # Modify in POST data
            if "post_data" in modified_request and isinstance(modified_request["post_data"], dict):
                if target_parameter in modified_request["post_data"]:
                    modified_request["post_data"][target_parameter] = user_id
                else:
                    modified_request["post_data"][target_parameter] = user_id
            
            # Modify in URL path
            url = modified_request.get("url", "")
            if "/users/" in url or "/user/" in url:
                # Replace user ID in URL
                url_parts = url.split("/")
                for i, part in enumerate(url_parts):
                    if part.isdigit():
                        url_parts[i] = str(user_id)
                        break
                modified_request["url"] = "/".join(url_parts)
            
            attacks.append({
                "original": original_request,
                "modified": modified_request,
                "attack_type": "ai_idor_test",
                "description": f"IDOR test with user ID: {user_id} (AI suggested)",
                "ai_generated": True,
                "expected_outcome": idor_suggestion.get("expected_outcome", "Access to other user's data")
            })
        
        return attacks
    
    def _create_endpoint_attacks(self, attack_suggestion: Dict, original_request: Dict) -> List[Dict]:
        """Create endpoint-based attacks."""
        attacks = []
        
        base_url = original_request.get("url", "")
        parsed_url = urlparse(base_url)
        base = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        # Suggested endpoints to test
        suggested_endpoints = attack_suggestion.get("payload_suggestions", [])
        
        for endpoint in suggested_endpoints:
            if endpoint.startswith("/"):
                new_url = base + endpoint
            else:
                new_url = urljoin(base_url, endpoint)
            
            modified_request = original_request.copy()
            modified_request["url"] = new_url
            
            attacks.append({
                "original": original_request,
                "modified": modified_request,
                "attack_type": "ai_endpoint_test",
                "description": f"Test AI-suggested endpoint: {endpoint}",
                "ai_generated": True,
                "expected_outcome": attack_suggestion.get("expected_outcome", "Access to sensitive endpoint")
            })
        
        return attacks
    
    def _create_parameter_attacks(self, attack_suggestion: Dict, original_request: Dict) -> List[Dict]:
        """Create parameter-based attacks."""
        attacks = []
        
        target_param = attack_suggestion.get("target", "").replace("parameter ", "")
        payloads = attack_suggestion.get("payload_suggestions", [])
        
        for payload in payloads:
            modified_request = original_request.copy()
            
            # Add/modify parameter in POST data
            if "post_data" in modified_request:
                if isinstance(modified_request["post_data"], dict):
                    modified_request["post_data"][target_param] = payload
                elif isinstance(modified_request["post_data"], str):
                    # Add as URL-encoded parameter
                    separator = "&" if modified_request["post_data"] else ""
                    modified_request["post_data"] += f"{separator}{target_param}={payload}"
            else:
                modified_request["post_data"] = {target_param: payload}
            
            attacks.append({
                "original": original_request,
                "modified": modified_request,
                "attack_type": "ai_parameter_test",
                "description": f"Test parameter {target_param} with AI-suggested payload: {payload}",
                "ai_generated": True,
                "expected_outcome": attack_suggestion.get("expected_outcome", "Parameter manipulation success")
            })
        
        return attacks
    
    def _create_header_attacks(self, attack_suggestion: Dict, original_request: Dict) -> List[Dict]:
        """Create header-based attacks."""
        attacks = []
        
        target_header = attack_suggestion.get("target", "").replace("header ", "")
        payloads = attack_suggestion.get("payload_suggestions", [])
        
        for payload in payloads:
            modified_request = original_request.copy()
            headers = modified_request.get("headers", {}).copy()
            headers[target_header] = payload
            modified_request["headers"] = headers
            
            attacks.append({
                "original": original_request,
                "modified": modified_request,
                "attack_type": "ai_header_test",
                "description": f"Test header {target_header} with AI-suggested value: {payload}",
                "ai_generated": True,
                "expected_outcome": attack_suggestion.get("expected_outcome", "Header manipulation success")
            })
        
        return attacks
    
    def _create_target_attacks(self, target: Dict, original_request: Dict) -> List[Dict]:
        """Create attacks for priority targets."""
        attacks = []
        
        target_type = target.get("type", "endpoint")
        target_value = target.get("value", "")
        reasoning = target.get("reasoning", "")
        
        if target_type == "endpoint":
            modified_request = original_request.copy()
            parsed_url = urlparse(original_request.get("url", ""))
            base = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            if target_value.startswith("/"):
                modified_request["url"] = base + target_value
            else:
                modified_request["url"] = urljoin(original_request.get("url", ""), target_value)
            
            attacks.append({
                "original": original_request,
                "modified": modified_request,
                "attack_type": "ai_priority_target",
                "description": f"AI-identified priority target: {target_value} ({reasoning})",
                "ai_generated": True,
                "expected_outcome": target.get("expected_outcome", "Access to high-value target")
            })
        
        return attacks
    
    def _update_pattern_database(self, test_result: Dict, ai_suggestions: Dict):
        """Update discovered patterns database."""
        attack_type = test_result.get("attack_type", "unknown")
        
        if attack_type not in self.discovered_patterns:
            self.discovered_patterns[attack_type] = {
                "successful_count": 0,
                "total_attempts": 0,
                "common_indicators": [],
                "effective_techniques": []
            }
        
        pattern = self.discovered_patterns[attack_type]
        pattern["total_attempts"] += 1
        
        if test_result.get("diff_analysis", {}).get("significant_change"):
            pattern["successful_count"] += 1
            
            # Add successful techniques
            if ai_suggestions.get("attack_vectors"):
                pattern["effective_techniques"].extend(ai_suggestions["attack_vectors"])
        
        # Store in attack history
        self.attack_history.append({
            "timestamp": self._get_current_timestamp(),
            "attack_type": attack_type,
            "success": test_result.get("diff_analysis", {}).get("significant_change", False),
            "ai_suggestions_count": len(ai_suggestions.get("suggested_attacks", []))
        })
    
    def _get_relevant_patterns(self, context: Dict) -> Dict:
        """Get relevant patterns for current context."""
        attack_type = context.get("attack_type", "unknown")
        
        if attack_type in self.discovered_patterns:
            pattern = self.discovered_patterns[attack_type]
            return {
                "success_rate": pattern["successful_count"] / max(pattern["total_attempts"], 1),
                "total_attempts": pattern["total_attempts"],
                "effective_techniques": list(set(pattern["effective_techniques"]))
            }
        
        return {"success_rate": 0.0, "total_attempts": 0, "effective_techniques": []}
    
    def _get_current_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def get_learning_summary(self) -> Dict:
        """Get summary of learned patterns and effectiveness."""
        return {
            "total_attacks_analyzed": len(self.attack_history),
            "discovered_patterns": {
                attack_type: {
                    "success_rate": pattern["successful_count"] / max(pattern["total_attempts"], 1),
                    "attempts": pattern["total_attempts"]
                }
                for attack_type, pattern in self.discovered_patterns.items()
            },
            "most_effective_attacks": self._get_most_effective_attacks(),
            "recent_activity": self.attack_history[-10:]  # Last 10 attacks
        }
    
    def _get_most_effective_attacks(self) -> List[Dict]:
        """Get most effective attack types based on success rate."""
        effective_attacks = []
        
        for attack_type, pattern in self.discovered_patterns.items():
            if pattern["total_attempts"] >= 3:  # Only consider attacks tried at least 3 times
                success_rate = pattern["successful_count"] / pattern["total_attempts"]
                effective_attacks.append({
                    "attack_type": attack_type,
                    "success_rate": success_rate,
                    "attempts": pattern["total_attempts"],
                    "successes": pattern["successful_count"]
                })
        
        # Sort by success rate
        effective_attacks.sort(key=lambda x: x["success_rate"], reverse=True)
        return effective_attacks[:5]  # Top 5