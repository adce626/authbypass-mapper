"""
AI-powered response analyzer using OpenAI GPT-4o for intelligent bypass detection.
"""

import json
import os
from typing import Dict, List, Optional

# the newest OpenAI model is "gpt-4o" which was released May 13, 2024.
# do not change this unless explicitly requested by the user
from openai import OpenAI


class AIAnalyzer:
    """AI-powered analyzer for authentication bypass detection."""
    
    def __init__(self):
        """Initialize the AI analyzer with OpenAI client."""
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY environment variable is required")
        
        self.client = OpenAI(api_key=api_key)
        
    def analyze_bypass_attempt(self, attack_request: Dict, original_response: Dict, 
                             modified_response: Dict, diff_analysis: Dict) -> Dict:
        """
        Use AI to analyze a potential authentication bypass attempt.
        
        Args:
            attack_request: The attack request details
            original_response: Original response data
            modified_response: Modified response data
            diff_analysis: Response difference analysis
            
        Returns:
            AI analysis results
        """
        try:
            # Prepare data for AI analysis
            analysis_data = self._prepare_analysis_data(
                attack_request, original_response, modified_response, diff_analysis
            )
            
            # Create AI prompt
            prompt = self._create_analysis_prompt(analysis_data)
            
            # Call OpenAI API
            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {
                        "role": "system",
                        "content": self._get_system_prompt()
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                response_format={"type": "json_object"},
                temperature=0.1,  # Low temperature for consistent analysis
                max_tokens=1000
            )
            
            # Parse AI response
            content = response.choices[0].message.content
            if content is None:
                raise ValueError("Empty response from OpenAI")
            ai_result = json.loads(content)
            
            # Validate and enhance the response
            return self._process_ai_response(ai_result, diff_analysis)
            
        except Exception as e:
            return {
                'error': f"AI analysis failed: {str(e)}",
                'severity': 'Unknown',
                'confidence': 0.0,
                'bypass_detected': False,
                'explanation': 'AI analysis could not be completed',
                'recommendations': ['Manual review required due to AI analysis failure']
            }
    
    def _prepare_analysis_data(self, attack_request: Dict, original_response: Dict, 
                              modified_response: Dict, diff_analysis: Dict) -> Dict:
        """Prepare data for AI analysis, removing sensitive information."""
        
        # Sanitize response content (limit size and remove potential PII)
        orig_content = self._sanitize_content(original_response.get('content', ''))
        mod_content = self._sanitize_content(modified_response.get('content', ''))
        
        return {
            'attack_type': attack_request.get('attack_type', 'unknown'),
            'attack_description': attack_request.get('description', ''),
            'original_status': original_response.get('status_code'),
            'modified_status': modified_response.get('status_code'),
            'status_changed': diff_analysis.get('status_code_change', False),
            'content_changed': diff_analysis.get('content_change', False),
            'redirect_changed': diff_analysis.get('redirect_change', False),
            'original_content_sample': orig_content[:1000],  # Limit content size
            'modified_content_sample': mod_content[:1000],
            'bypass_indicators': diff_analysis.get('bypass_indicators', []),
            'confidence_score': diff_analysis.get('confidence_score', 0.0),
            'content_similarity': diff_analysis.get('content_diff', {}).get('similarity_ratio', 1.0),
            'original_redirect': original_response.get('is_redirect', False),
            'modified_redirect': modified_response.get('is_redirect', False)
        }
    
    def _sanitize_content(self, content: str) -> str:
        """Sanitize content to remove potential PII and reduce size."""
        if not content:
            return ""
        
        # Remove potential email addresses
        import re
        content = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL]', content)
        
        # Remove potential phone numbers
        content = re.sub(r'\b\d{3}-\d{3}-\d{4}\b', '[PHONE]', content)
        content = re.sub(r'\b\(\d{3}\)\s*\d{3}-\d{4}\b', '[PHONE]', content)
        content = re.sub(r'\b\d{3}\s*\d{3}\s*\d{4}\b', '[PHONE]', content)
        
        # Remove potential SSNs
        content = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[SSN]', content)
        
        # Remove potential credit card numbers
        content = re.sub(r'\b\d{4}\s*\d{4}\s*\d{4}\s*\d{4}\b', '[CARD]', content)
        
        return content
    
    def _get_system_prompt(self) -> str:
        """Get the system prompt for AI analysis."""
        return """You are a cybersecurity expert specializing in authentication bypass vulnerabilities. 
        Your task is to analyze HTTP request/response pairs to determine if an authentication bypass 
        vulnerability exists.

        You should analyze:
        1. Status code changes (especially 401/403 -> 200, 302 -> 200)
        2. Content changes that indicate access to protected resources
        3. Redirect behavior changes
        4. Presence of authentication bypass indicators

        Respond with JSON containing:
        - bypass_detected: boolean (true if bypass detected)
        - severity: string ("Critical", "High", "Medium", "Low", "Info")
        - confidence: float (0.0 to 1.0, your confidence in the finding)
        - explanation: string (detailed explanation of your analysis)
        - evidence: array of strings (specific evidence supporting your conclusion)
        - false_positive_likelihood: string ("Low", "Medium", "High")
        - recommendations: array of strings (manual verification steps)
        - attack_effectiveness: string (assessment of the attack's effectiveness)

        Be conservative in your analysis - it's better to flag potential issues for manual review 
        than to miss real vulnerabilities. However, also consider false positive likelihood."""
    
    def _create_analysis_prompt(self, data: Dict) -> str:
        """Create the analysis prompt for AI."""
        return f"""
        Analyze this potential authentication bypass attempt:

        **Attack Details:**
        - Attack Type: {data['attack_type']}
        - Description: {data['attack_description']}

        **Response Analysis:**
        - Original Status: {data['original_status']}
        - Modified Status: {data['modified_status']}
        - Status Changed: {data['status_changed']}
        - Content Changed: {data['content_changed']}
        - Content Similarity: {data['content_similarity']:.2f}
        - Redirect Changed: {data['redirect_changed']}
        - System Confidence Score: {data['confidence_score']:.2f}

        **Bypass Indicators Found:**
        {json.dumps(data['bypass_indicators'], indent=2)}

        **Content Samples:**
        Original Response (first 1000 chars):
        ```
        {data['original_content_sample']}
        ```

        Modified Response (first 1000 chars):
        ```
        {data['modified_content_sample']}
        ```

        **Additional Context:**
        - Original had redirect: {data['original_redirect']}
        - Modified has redirect: {data['modified_redirect']}

        Please provide a comprehensive analysis in the specified JSON format.
        """
    
    def _process_ai_response(self, ai_result: Dict, diff_analysis: Dict) -> Dict:
        """Process and validate AI response."""
        
        # Ensure required fields exist with defaults
        processed_result = {
            'bypass_detected': ai_result.get('bypass_detected', False),
            'severity': ai_result.get('severity', 'Info'),
            'confidence': float(ai_result.get('confidence', 0.0)),
            'explanation': ai_result.get('explanation', 'No explanation provided'),
            'evidence': ai_result.get('evidence', []),
            'false_positive_likelihood': ai_result.get('false_positive_likelihood', 'Medium'),
            'recommendations': ai_result.get('recommendations', []),
            'attack_effectiveness': ai_result.get('attack_effectiveness', 'Unknown'),
            'ai_model': 'gpt-4o',
            'analysis_timestamp': self._get_current_timestamp()
        }
        
        # Validate severity levels
        valid_severities = ['Critical', 'High', 'Medium', 'Low', 'Info']
        if processed_result['severity'] not in valid_severities:
            processed_result['severity'] = 'Info'
        
        # Ensure confidence is between 0 and 1
        processed_result['confidence'] = max(0.0, min(1.0, processed_result['confidence']))
        
        # Add system-level insights
        processed_result = self._add_system_insights(processed_result, diff_analysis)
        
        # Generate follow-up suggestions based on attack type and findings
        processed_result['follow_up_tests'] = self._generate_followup_tests(
            processed_result, diff_analysis
        )
        
        return processed_result
    
    def _add_system_insights(self, ai_result: Dict, diff_analysis: Dict) -> Dict:
        """Add system-level insights to complement AI analysis."""
        
        insights = []
        
        # Add confidence correlation insight
        system_confidence = diff_analysis.get('confidence_score', 0.0)
        ai_confidence = ai_result.get('confidence', 0.0)
        
        if abs(system_confidence - ai_confidence) > 0.3:
            if system_confidence > ai_confidence:
                insights.append("System detected more indicators than AI analysis suggests - consider manual review")
            else:
                insights.append("AI analysis shows higher confidence than system metrics - verify findings")
        
        # Add technical insights based on bypass indicators
        bypass_indicators = diff_analysis.get('bypass_indicators', [])
        if bypass_indicators:
            insights.append(f"System detected {len(bypass_indicators)} bypass indicators")
        
        # Add status code insights
        if diff_analysis.get('status_code_change'):
            orig_status = diff_analysis.get('original_status')
            mod_status = diff_analysis.get('modified_status')
            if orig_status in [401, 403] and mod_status == 200:
                insights.append("Strong indication of authentication bypass based on status code change")
        
        ai_result['system_insights'] = insights
        return ai_result
    
    def _generate_followup_tests(self, ai_result: Dict, diff_analysis: Dict) -> List[str]:
        """Generate follow-up test suggestions based on the analysis."""
        
        followup_tests = []
        
        if ai_result.get('bypass_detected'):
            followup_tests.extend([
                "Manually verify access to the endpoint using the same attack vector",
                "Test with different user accounts to confirm IDOR/privilege escalation",
                "Try accessing other protected endpoints using the same technique"
            ])
            
            # Specific suggestions based on attack type
            attack_type = diff_analysis.get('attack_type', '')
            
            if 'jwt' in attack_type.lower():
                followup_tests.extend([
                    "Test with completely invalid JWT tokens",
                    "Try JWT algorithms confusion attacks (RS256 to HS256)",
                    "Test JWT token replay attacks"
                ])
            
            if 'session' in attack_type.lower():
                followup_tests.extend([
                    "Test session fixation attacks",
                    "Try accessing endpoints with expired sessions",
                    "Test concurrent sessions with same credentials"
                ])
            
            if 'header' in attack_type.lower():
                followup_tests.extend([
                    "Test other IP spoofing headers (X-Client-IP, X-Cluster-Client-IP)",
                    "Try combination of multiple bypass headers",
                    "Test with localhost variations (127.0.0.1, ::1, localhost)"
                ])
        
        # Always suggest these for any detected changes
        if diff_analysis.get('significant_change'):
            followup_tests.extend([
                "Document the exact request/response for reporting",
                "Test the same technique on other similar endpoints",
                "Verify the finding is reproducible"
            ])
        
        return followup_tests
    
    def _get_current_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def analyze_batch_responses(self, attack_results: List[Dict]) -> Dict:
        """
        Analyze multiple attack results to identify patterns and prioritize findings.
        
        Args:
            attack_results: List of attack result dictionaries
            
        Returns:
            Batch analysis summary
        """
        if not attack_results:
            return {'error': 'No attack results provided'}
        
        try:
            # Prepare batch analysis data
            batch_data = {
                'total_attacks': len(attack_results),
                'successful_bypasses': 0,
                'critical_findings': 0,
                'high_findings': 0,
                'attack_types': {},
                'common_patterns': []
            }
            
            # Analyze each result
            for result in attack_results:
                ai_analysis = result.get('ai_analysis', {})
                
                if ai_analysis.get('bypass_detected'):
                    batch_data['successful_bypasses'] += 1
                
                severity = ai_analysis.get('severity', 'Info')
                if severity == 'Critical':
                    batch_data['critical_findings'] += 1
                elif severity == 'High':
                    batch_data['high_findings'] += 1
                
                # Track attack types
                attack_type = result.get('attack_type', 'unknown')
                batch_data['attack_types'][attack_type] = batch_data['attack_types'].get(attack_type, 0) + 1
            
            # Use AI to identify patterns across all results
            if batch_data['successful_bypasses'] > 0:
                pattern_analysis = self._analyze_attack_patterns(attack_results)
                batch_data.update(pattern_analysis)
            
            return batch_data
            
        except Exception as e:
            return {'error': f"Batch analysis failed: {str(e)}"}
    
    def _analyze_attack_patterns(self, attack_results: List[Dict]) -> Dict:
        """Use AI to analyze patterns across multiple successful attacks."""
        
        successful_attacks = [
            result for result in attack_results 
            if result.get('ai_analysis', {}).get('bypass_detected')
        ]
        
        if not successful_attacks:
            return {}
        
        try:
            # Create summary for AI analysis
            attack_summary = []
            for attack in successful_attacks[:5]:  # Analyze top 5 to avoid token limits
                attack_summary.append({
                    'type': attack.get('attack_type'),
                    'description': attack.get('description'),
                    'severity': attack.get('ai_analysis', {}).get('severity'),
                    'evidence': attack.get('ai_analysis', {}).get('evidence', [])[:3]  # Top 3 evidence
                })
            
            prompt = f"""
            Analyze these successful authentication bypass attacks and identify common patterns:
            
            {json.dumps(attack_summary, indent=2)}
            
            Respond with JSON containing:
            - common_attack_vectors: array of strings (most effective attack types)
            - vulnerability_patterns: array of strings (common vulnerabilities found)
            - risk_assessment: string (overall risk level based on findings)
            - remediation_priority: array of strings (prioritized fix recommendations)
            """
            
            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity analyst specializing in vulnerability pattern analysis. Provide actionable insights about authentication bypass vulnerabilities."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                response_format={"type": "json_object"},
                temperature=0.2,
                max_tokens=800
            )
            
            content = response.choices[0].message.content
            if content is None:
                raise ValueError("Empty pattern analysis response from OpenAI")
            pattern_result = json.loads(content)
            return pattern_result
            
        except Exception as e:
            return {'pattern_analysis_error': f"Pattern analysis failed: {str(e)}"}
