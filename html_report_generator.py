"""
HTML Report Generator for AuthBypass Mapper.
Creates professional, visual reports for security testing results.
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any
from pathlib import Path


class HTMLReportGenerator:
    """Generates professional HTML reports for bypass testing results."""
    
    def __init__(self):
        self.template_dir = Path("templates")
        self.template_dir.mkdir(exist_ok=True)
    
    def generate_report(self, results: Dict, output_path: str = None) -> str:
        """Generate comprehensive HTML report from test results."""
        
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"output/authbypass_report_{timestamp}.html"
        
        # Prepare data for template
        report_data = self._prepare_report_data(results)
        
        # Generate HTML content
        html_content = self._create_html_report(report_data)
        
        # Save report
        output_file = Path(output_path)
        output_file.parent.mkdir(exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return str(output_file)
    
    def _prepare_report_data(self, results: Dict) -> Dict:
        """Prepare and organize data for the HTML report."""
        
        scan_info = results.get('scan_info', {})
        tests = results.get('tests', [])
        
        # Calculate summary statistics
        total_tests = len(tests)
        significant_findings = sum(1 for test in tests if test.get('significant_change', False))
        critical_findings = sum(1 for test in tests 
                              if test.get('ai_analysis', {}).get('severity') == 'Critical')
        high_findings = sum(1 for test in tests 
                          if test.get('ai_analysis', {}).get('severity') == 'High')
        medium_findings = sum(1 for test in tests 
                            if test.get('ai_analysis', {}).get('severity') == 'Medium')
        
        # Categorize findings by severity
        findings_by_severity = {
            'Critical': [test for test in tests if test.get('ai_analysis', {}).get('severity') == 'Critical'],
            'High': [test for test in tests if test.get('ai_analysis', {}).get('severity') == 'High'],
            'Medium': [test for test in tests if test.get('ai_analysis', {}).get('severity') == 'Medium'],
            'Low': [test for test in tests if test.get('ai_analysis', {}).get('severity') == 'Low'],
            'Info': [test for test in tests if test.get('ai_analysis', {}).get('severity') == 'Info']
        }
        
        # Categorize by attack type
        attack_types = {}
        for test in tests:
            attack_type = test.get('attack_type', 'unknown')
            if attack_type not in attack_types:
                attack_types[attack_type] = []
            attack_types[attack_type].append(test)
        
        # Generate executive summary
        exec_summary = self._generate_executive_summary(
            total_tests, significant_findings, critical_findings, high_findings
        )
        
        return {
            'scan_info': scan_info,
            'executive_summary': exec_summary,
            'statistics': {
                'total_tests': total_tests,
                'significant_findings': significant_findings,
                'critical_findings': critical_findings,
                'high_findings': high_findings,
                'medium_findings': medium_findings,
                'success_rate': round((significant_findings / total_tests) * 100, 1) if total_tests > 0 else 0
            },
            'findings_by_severity': findings_by_severity,
            'attack_types': attack_types,
            'detailed_findings': tests,
            'generation_time': datetime.now().isoformat(),
        }
    
    def _generate_executive_summary(self, total: int, significant: int, critical: int, high: int) -> str:
        """Generate executive summary text."""
        
        if critical > 0:
            risk_level = "CRITICAL"
            summary = f"Critical security vulnerabilities detected. Immediate action required."
        elif high > 0:
            risk_level = "HIGH"
            summary = f"High-risk authentication bypass vulnerabilities identified."
        elif significant > 0:
            risk_level = "MEDIUM"
            summary = f"Potential authentication weaknesses detected requiring investigation."
        else:
            risk_level = "LOW"
            summary = f"No significant authentication bypass vulnerabilities detected."
        
        return f"""
        <strong>Risk Level: {risk_level}</strong><br>
        {summary}<br><br>
        
        Out of {total} authentication bypass tests performed, {significant} showed significant changes 
        indicating potential vulnerabilities. {critical} critical and {high} high-severity issues 
        were identified that require immediate attention.
        """
    
    def _create_html_report(self, data: Dict) -> str:
        """Create the complete HTML report."""
        
        html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AuthBypass Mapper - Security Assessment Report</title>
    <style>
        {self._get_report_css()}
    </style>
</head>
<body>
    <div class="container">
        {self._create_header(data)}
        {self._create_executive_summary(data)}
        {self._create_statistics_section(data)}
        {self._create_findings_overview(data)}
        {self._create_detailed_findings(data)}
        {self._create_recommendations_section(data)}
        {self._create_footer(data)}
    </div>
    
    <script>
        {self._get_report_javascript()}
    </script>
</body>
</html>
        """
        
        return html_template
    
    def _get_report_css(self) -> str:
        """Get CSS styles for the report."""
        return """
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            min-height: 100vh;
        }
        
        .header {
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
        }
        
        .header .subtitle {
            font-size: 1.2rem;
            opacity: 0.9;
        }
        
        .section {
            padding: 40px;
            border-bottom: 1px solid #e0e0e0;
        }
        
        .section h2 {
            color: #2c3e50;
            margin-bottom: 20px;
            font-size: 1.8rem;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        
        .exec-summary {
            background: #f8f9fa;
            padding: 30px;
            border-left: 4px solid #3498db;
            margin: 20px 0;
            border-radius: 5px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
            border-left: 4px solid #3498db;
        }
        
        .stat-card.critical {
            border-left-color: #e74c3c;
        }
        
        .stat-card.high {
            border-left-color: #f39c12;
        }
        
        .stat-card.medium {
            border-left-color: #f1c40f;
        }
        
        .stat-number {
            font-size: 2.5rem;
            font-weight: bold;
            color: #2c3e50;
        }
        
        .stat-card.critical .stat-number {
            color: #e74c3c;
        }
        
        .stat-card.high .stat-number {
            color: #f39c12;
        }
        
        .stat-card.medium .stat-number {
            color: #f1c40f;
        }
        
        .stat-label {
            color: #7f8c8d;
            font-size: 0.9rem;
            margin-top: 5px;
        }
        
        .findings-table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        
        .findings-table th,
        .findings-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e0e0e0;
        }
        
        .findings-table th {
            background: #f8f9fa;
            font-weight: 600;
            color: #2c3e50;
        }
        
        .severity-badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .severity-critical {
            background: #ffe6e6;
            color: #e74c3c;
        }
        
        .severity-high {
            background: #fff3e0;
            color: #f39c12;
        }
        
        .severity-medium {
            background: #fffbf0;
            color: #f1c40f;
        }
        
        .severity-low {
            background: #e8f5e8;
            color: #27ae60;
        }
        
        .severity-info {
            background: #e3f2fd;
            color: #3498db;
        }
        
        .finding-details {
            background: #f8f9fa;
            border: 1px solid #e0e0e0;
            border-radius: 5px;
            margin: 10px 0;
            overflow: hidden;
        }
        
        .finding-header {
            background: #2c3e50;
            color: white;
            padding: 15px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .finding-content {
            padding: 20px;
            display: none;
        }
        
        .finding-content.show {
            display: block;
        }
        
        .code-block {
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            overflow-x: auto;
            margin: 10px 0;
        }
        
        .recommendation {
            background: #e8f5e8;
            border-left: 4px solid #27ae60;
            padding: 15px;
            margin: 10px 0;
            border-radius: 0 5px 5px 0;
        }
        
        .footer {
            background: #2c3e50;
            color: white;
            padding: 20px;
            text-align: center;
            font-size: 0.9rem;
        }
        
        .toggle-icon {
            transition: transform 0.3s ease;
        }
        
        .toggle-icon.rotated {
            transform: rotate(180deg);
        }
        
        @media (max-width: 768px) {
            .container {
                margin: 0;
            }
            
            .section {
                padding: 20px;
            }
            
            .stats-grid {
                grid-template-columns: 1fr;
            }
        }
        """
    
    def _create_header(self, data: Dict) -> str:
        """Create report header."""
        scan_info = data['scan_info']
        timestamp = datetime.fromisoformat(scan_info.get('timestamp', ''))
        formatted_time = timestamp.strftime("%B %d, %Y at %I:%M %p")
        
        return f"""
        <div class="header">
            <h1>🛡️ AuthBypass Mapper</h1>
            <div class="subtitle">Authentication Bypass Security Assessment Report</div>
            <div style="margin-top: 20px; font-size: 1rem; opacity: 0.8;">
                Generated on {formatted_time}
            </div>
        </div>
        """
    
    def _create_executive_summary(self, data: Dict) -> str:
        """Create executive summary section."""
        return f"""
        <div class="section">
            <h2>Executive Summary</h2>
            <div class="exec-summary">
                {data['executive_summary']}
            </div>
        </div>
        """
    
    def _create_statistics_section(self, data: Dict) -> str:
        """Create statistics overview section."""
        stats = data['statistics']
        
        return f"""
        <div class="section">
            <h2>Assessment Statistics</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{stats['total_tests']}</div>
                    <div class="stat-label">Total Tests</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{stats['significant_findings']}</div>
                    <div class="stat-label">Significant Findings</div>
                </div>
                <div class="stat-card critical">
                    <div class="stat-number">{stats['critical_findings']}</div>
                    <div class="stat-label">Critical Issues</div>
                </div>
                <div class="stat-card high">
                    <div class="stat-number">{stats['high_findings']}</div>
                    <div class="stat-label">High Risk</div>
                </div>
                <div class="stat-card medium">
                    <div class="stat-number">{stats['medium_findings']}</div>
                    <div class="stat-label">Medium Risk</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{stats['success_rate']}%</div>
                    <div class="stat-label">Success Rate</div>
                </div>
            </div>
        </div>
        """
    
    def _create_findings_overview(self, data: Dict) -> str:
        """Create findings overview table."""
        findings_by_severity = data['findings_by_severity']
        
        table_rows = ""
        for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            findings = findings_by_severity.get(severity, [])
            if findings:
                for finding in findings:
                    ai_analysis = finding.get('ai_analysis', {})
                    confidence = round(ai_analysis.get('confidence', 0) * 100)
                    
                    table_rows += f"""
                    <tr>
                        <td>{finding.get('test_id', 'N/A')}</td>
                        <td>{finding.get('attack_type', 'Unknown')}</td>
                        <td><span class="severity-badge severity-{severity.lower()}">{severity}</span></td>
                        <td>{confidence}%</td>
                        <td>{'✅' if ai_analysis.get('bypass_detected', False) else '❌'}</td>
                        <td>{finding.get('original_status', 'N/A')} → {finding.get('modified_status', 'N/A')}</td>
                    </tr>
                    """
        
        return f"""
        <div class="section">
            <h2>Findings Overview</h2>
            <table class="findings-table">
                <thead>
                    <tr>
                        <th>Test ID</th>
                        <th>Attack Type</th>
                        <th>Severity</th>
                        <th>Confidence</th>
                        <th>Bypass Detected</th>
                        <th>Status Change</th>
                    </tr>
                </thead>
                <tbody>
                    {table_rows}
                </tbody>
            </table>
        </div>
        """
    
    def _create_detailed_findings(self, data: Dict) -> str:
        """Create detailed findings section."""
        significant_findings = [
            test for test in data['detailed_findings'] 
            if test.get('significant_change', False)
        ]
        
        findings_html = ""
        for i, finding in enumerate(significant_findings):
            findings_html += self._create_finding_detail(finding, i)
        
        return f"""
        <div class="section">
            <h2>Detailed Findings</h2>
            <div class="findings-details">
                {findings_html}
            </div>
        </div>
        """
    
    def _create_finding_detail(self, finding: Dict, index: int) -> str:
        """Create detailed view for a single finding."""
        ai_analysis = finding.get('ai_analysis', {})
        severity = ai_analysis.get('severity', 'Info')
        confidence = round(ai_analysis.get('confidence', 0) * 100)
        
        # Request details
        original_request = finding.get('original_request', {})
        modified_request = finding.get('modified_request', {})
        
        # Response details
        original_response = finding.get('original_response', {})
        modified_response = finding.get('modified_response', {})
        
        # AI analysis details
        explanation = ai_analysis.get('explanation', 'No explanation available')
        evidence = ai_analysis.get('evidence', [])
        recommendations = ai_analysis.get('recommendations', [])
        
        evidence_html = ""
        if evidence:
            evidence_html = "<ul>" + "".join([f"<li>{item}</li>" for item in evidence]) + "</ul>"
        
        recommendations_html = ""
        if recommendations:
            recommendations_html = "<ul>" + "".join([f"<li>{item}</li>" for item in recommendations]) + "</ul>"
        
        return f"""
        <div class="finding-details">
            <div class="finding-header" onclick="toggleFinding({index})">
                <div>
                    <strong>Test #{finding.get('test_id', 'N/A')}: {finding.get('attack_type', 'Unknown')}</strong>
                    <span class="severity-badge severity-{severity.lower()}" style="margin-left: 10px;">{severity}</span>
                </div>
                <div class="toggle-icon" id="toggle-{index}">▼</div>
            </div>
            <div class="finding-content" id="content-{index}">
                <div style="margin-bottom: 20px;">
                    <strong>Description:</strong> {finding.get('description', 'No description available')}
                </div>
                
                <div style="margin-bottom: 20px;">
                    <strong>AI Analysis (Confidence: {confidence}%):</strong><br>
                    {explanation}
                </div>
                
                {f'<div style="margin-bottom: 20px;"><strong>Evidence:</strong>{evidence_html}</div>' if evidence else ''}
                
                <div style="margin-bottom: 20px;">
                    <strong>Response Comparison:</strong><br>
                    Original Status: {original_response.get('status_code', 'N/A')}<br>
                    Modified Status: {modified_response.get('status_code', 'N/A')}<br>
                    Content Length Change: {original_response.get('content_length', 0)} → {modified_response.get('content_length', 0)} bytes
                </div>
                
                <div style="margin-bottom: 20px;">
                    <strong>Modified Request:</strong>
                    <div class="code-block">
{modified_request.get('method', 'GET')} {modified_request.get('url', 'N/A')}
Headers: {json.dumps(modified_request.get('headers', {}), indent=2)}
                    </div>
                </div>
                
                {f'<div class="recommendation"><strong>Recommendations:</strong>{recommendations_html}</div>' if recommendations else ''}
            </div>
        </div>
        """
    
    def _create_recommendations_section(self, data: Dict) -> str:
        """Create recommendations section."""
        critical_count = data['statistics']['critical_findings']
        high_count = data['statistics']['high_findings']
        
        recommendations = []
        
        if critical_count > 0:
            recommendations.append("🚨 <strong>IMMEDIATE ACTION REQUIRED:</strong> Critical authentication bypass vulnerabilities detected. Review and fix immediately.")
        
        if high_count > 0:
            recommendations.append("⚠️ <strong>HIGH PRIORITY:</strong> High-risk vulnerabilities require prompt attention and remediation.")
        
        recommendations.extend([
            "🔍 <strong>Manual Verification:</strong> Manually verify all reported findings to confirm exploitability.",
            "🛡️ <strong>Access Controls:</strong> Review and strengthen authentication and authorization mechanisms.",
            "📝 <strong>Code Review:</strong> Conduct thorough code review of authentication-related functions.",
            "🧪 <strong>Regular Testing:</strong> Implement regular security testing as part of your development lifecycle.",
            "📚 <strong>Developer Training:</strong> Ensure development team is trained on secure authentication practices."
        ])
        
        recommendations_html = ""
        for rec in recommendations:
            recommendations_html += f'<div class="recommendation">{rec}</div>'
        
        return f"""
        <div class="section">
            <h2>Recommendations</h2>
            {recommendations_html}
        </div>
        """
    
    def _create_footer(self, data: Dict) -> str:
        """Create report footer."""
        return f"""
        <div class="footer">
            <div>Report generated by AuthBypass Mapper on {data['generation_time']}</div>
            <div style="margin-top: 10px; font-size: 0.8rem; opacity: 0.8;">
                This report contains {data['statistics']['total_tests']} test results with AI-powered analysis
            </div>
        </div>
        """
    
    def _get_report_javascript(self) -> str:
        """Get JavaScript for interactive report features."""
        return """
        function toggleFinding(index) {
            const content = document.getElementById('content-' + index);
            const toggle = document.getElementById('toggle-' + index);
            
            if (content.classList.contains('show')) {
                content.classList.remove('show');
                toggle.classList.remove('rotated');
            } else {
                content.classList.add('show');
                toggle.classList.add('rotated');
            }
        }
        
        // Auto-expand critical and high severity findings
        document.addEventListener('DOMContentLoaded', function() {
            const criticalFindings = document.querySelectorAll('.severity-critical, .severity-high');
            criticalFindings.forEach(function(badge) {
                const findingHeader = badge.closest('.finding-header');
                if (findingHeader) {
                    const index = findingHeader.getAttribute('onclick').match(/\\d+/)[0];
                    toggleFinding(parseInt(index));
                }
            });
        });
        """