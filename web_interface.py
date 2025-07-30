#!/usr/bin/env python3
"""
Web interface for AuthBypass Mapper.
Simple Flask-based GUI for easier tool usage.
"""

import os
import json
import tempfile
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename

from main import (
    HARParser, BurpParser, BypassGenerator, RequestSender, ResponseAnalyzer, AIAnalyzer,
    save_results, setup_output_directory
)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()

ALLOWED_EXTENSIONS = {'har', 'xml'}


def allowed_file(filename):
    """Check if file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/')
def index():
    """Main interface page."""
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload and start analysis."""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'Invalid file type. Use .har or .xml files'}), 400
        
        # Save uploaded file
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{timestamp}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Get analysis parameters
        target_domain = request.form.get('target_domain', '').strip()
        max_requests = int(request.form.get('max_requests', 20))
        skip_ai = request.form.get('skip_ai') == 'true'
        
        # Start analysis
        session_id = f"session_{timestamp}"
        result = analyze_file(filepath, target_domain, max_requests, skip_ai, session_id)
        
        # Clean up uploaded file
        os.unlink(filepath)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500


def analyze_file(file_path, target_domain, max_requests, skip_ai, session_id):
    """Analyze uploaded file and return results."""
    try:
        # Parse input file
        if file_path.endswith('.har'):
            parser = HARParser()
            requests_data = parser.parse(file_path, target_domain=target_domain or None)
        elif file_path.endswith('.xml'):
            parser = BurpParser()
            requests_data = parser.parse(file_path, target_domain=target_domain or None)
        else:
            raise ValueError("Unsupported file format")
        
        if not requests_data:
            return {'error': 'No requests found in the input file'}
        
        # Limit requests
        requests_data = requests_data[:max_requests]
        
        # Generate bypass attacks
        bypass_gen = BypassGenerator()
        attack_requests = []
        
        for original_request in requests_data:
            attacks = bypass_gen.generate_attacks(original_request)
            attack_requests.extend(attacks)
        
        if not attack_requests:
            return {'error': 'No authentication-related requests found'}
        
        # Send requests and analyze
        sender = RequestSender()
        results = {
            'session_id': session_id,
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'total_original_requests': len(requests_data),
                'total_attack_requests': len(attack_requests),
                'target_domain': target_domain,
                'ai_analysis_enabled': not skip_ai
            },
            'tests': []
        }
        
        for i, attack_request in enumerate(attack_requests):
            # Send original request
            original_response = sender.send_request(attack_request['original'])
            
            # Send modified request
            modified_response = sender.send_request(attack_request['modified'])
            
            # Analyze response differences
            analyzer = ResponseAnalyzer()
            diff_analysis = analyzer.analyze_responses(original_response, modified_response)
            
            test_result = {
                'test_id': i + 1,
                'attack_type': attack_request['attack_type'],
                'description': attack_request['description'],
                'original_status': original_response.get('status_code'),
                'modified_status': modified_response.get('status_code'),
                'significant_change': diff_analysis.get('significant_change', False),
                'confidence_score': diff_analysis.get('confidence_score', 0.0),
                'bypass_indicators': diff_analysis.get('bypass_indicators', []),
                'diff_analysis': diff_analysis
            }
            
            # AI Analysis (if enabled)
            if not skip_ai and diff_analysis.get('significant_change', False):
                try:
                    ai_analyzer = AIAnalyzer()
                    ai_analysis = ai_analyzer.analyze_bypass_attempt(
                        attack_request, original_response, modified_response, diff_analysis
                    )
                    test_result['ai_analysis'] = ai_analysis
                except Exception as e:
                    test_result['ai_analysis'] = {
                        'error': f'AI analysis failed: {str(e)}',
                        'severity': 'Unknown'
                    }
            
            results['tests'].append(test_result)
        
        # Save results to file
        output_dir = setup_output_directory()
        output_file = save_results(results, output_dir)
        results['output_file'] = str(output_file)
        
        # Generate summary
        total_tests = len(results['tests'])
        significant_findings = sum(1 for test in results['tests'] if test.get('significant_change'))
        critical_findings = sum(1 for test in results['tests'] 
                              if test.get('ai_analysis', {}).get('severity') == 'Critical')
        high_findings = sum(1 for test in results['tests'] 
                          if test.get('ai_analysis', {}).get('severity') == 'High')
        
        results['summary'] = {
            'total_tests': total_tests,
            'significant_findings': significant_findings,
            'critical_findings': critical_findings,
            'high_findings': high_findings,
            'success_rate': round((significant_findings / total_tests) * 100, 1) if total_tests > 0 else 0
        }
        
        return results
        
    except Exception as e:
        return {'error': f'Analysis failed: {str(e)}'}


@app.route('/results/<session_id>')
def get_results(session_id):
    """Get detailed results for a session."""
    # In a real implementation, you'd store results in a database
    # For now, return a placeholder
    return jsonify({'message': f'Results for session {session_id}'})


@app.route('/download/<filename>')
def download_file(filename):
    """Download result file."""
    try:
        output_dir = Path("output")
        file_path = output_dir / filename
        if file_path.exists():
            return send_file(file_path, as_attachment=True)
        else:
            return jsonify({'error': 'File not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/health')
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'version': '1.0.0',
        'timestamp': datetime.now().isoformat()
    })


if __name__ == '__main__':
    # Create templates directory if it doesn't exist
    templates_dir = Path("templates")
    templates_dir.mkdir(exist_ok=True)
    
    # Start the web server
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)