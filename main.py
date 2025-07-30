#!/usr/bin/env python3
"""
AuthBypass Mapper - A specialized tool for detecting authentication bypass vulnerabilities
using AI-powered response analysis.

This tool parses HAR/Burp Suite files, generates bypass attack requests,
and uses GPT-4o to analyze responses for potential vulnerabilities.
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

from har_parser import HARParser, BurpParser
from bypass_generator import BypassGenerator
from request_sender import RequestSender
from response_analyzer import ResponseAnalyzer
from ai_analyzer import AIAnalyzer


def setup_output_directory():
    """Create output directory if it doesn't exist."""
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)
    return output_dir


def save_results(results, output_dir):
    """Save results to JSON file with timestamp."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = output_dir / f"authbypass_results_{timestamp}.json"
    
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    return output_file


def print_summary(results):
    """Print a summary of the scan results."""
    total_requests = len(results.get('tests', []))
    critical_findings = sum(1 for test in results.get('tests', []) 
                          if test.get('ai_analysis', {}).get('severity') == 'Critical')
    high_findings = sum(1 for test in results.get('tests', []) 
                       if test.get('ai_analysis', {}).get('severity') == 'High')
    medium_findings = sum(1 for test in results.get('tests', []) 
                         if test.get('ai_analysis', {}).get('severity') == 'Medium')
    
    print("\n" + "="*60)
    print("AUTHBYPASS MAPPER - SCAN SUMMARY")
    print("="*60)
    print(f"Total requests tested: {total_requests}")
    print(f"Critical findings: {critical_findings}")
    print(f"High findings: {high_findings}")
    print(f"Medium findings: {medium_findings}")
    
    if critical_findings > 0 or high_findings > 0:
        print("\n🚨 POTENTIAL VULNERABILITIES DETECTED!")
        print("Review the detailed results for manual verification.")
    
    print("="*60)


def main():
    parser = argparse.ArgumentParser(
        description="AuthBypass Mapper - Automated authentication bypass detection tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py -f traffic.har
  python main.py -f burp_export.xml --max-requests 50
  python main.py -f traffic.har --target-domain example.com
        """
    )
    
    parser.add_argument(
        '-f', '--file',
        required=True,
        help='HAR file (.har) or Burp Suite export (.xml) to analyze'
    )
    
    parser.add_argument(
        '--target-domain',
        help='Filter requests to specific domain (optional)'
    )
    
    parser.add_argument(
        '--max-requests',
        type=int,
        default=20,
        help='Maximum number of requests to test (default: 20)'
    )
    
    parser.add_argument(
        '--skip-ai',
        action='store_true',
        help='Skip AI analysis (faster but less intelligent detection)'
    )
    
    parser.add_argument(
        '--output-dir',
        default='output',
        help='Output directory for results (default: output)'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    # Validate input file
    if not os.path.exists(args.file):
        print(f"Error: File '{args.file}' not found.")
        sys.exit(1)
    
    # Setup output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)
    
    print("🧠 AuthBypass Mapper - Starting Analysis")
    print("="*50)
    
    try:
        # Step 1: Parse input file
        print("1️⃣ Parsing input file...")
        if args.file.endswith('.har'):
            parser = HARParser()
            requests = parser.parse(args.file, target_domain=args.target_domain)
        elif args.file.endswith('.xml'):
            parser = BurpParser()
            requests = parser.parse(args.file, target_domain=args.target_domain)
        else:
            print("Error: Unsupported file format. Use .har or .xml files.")
            sys.exit(1)
        
        if not requests:
            print("No requests found in the input file.")
            sys.exit(1)
        
        # Limit requests if specified
        requests = requests[:args.max_requests]
        print(f"Found {len(requests)} requests to analyze")
        
        # Step 2: Generate bypass attacks
        print("2️⃣ Generating bypass attack variants...")
        bypass_gen = BypassGenerator()
        attack_requests = []
        
        for original_request in requests:
            attacks = bypass_gen.generate_attacks(original_request)
            attack_requests.extend(attacks)
        
        print(f"Generated {len(attack_requests)} attack variants")
        
        # Step 3: Send requests and capture responses
        print("3️⃣ Sending requests and capturing responses...")
        sender = RequestSender()
        results = {
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'input_file': args.file,
                'total_original_requests': len(requests),
                'total_attack_requests': len(attack_requests),
                'target_domain': args.target_domain
            },
            'tests': []
        }
        
        for i, attack_request in enumerate(attack_requests, 1):
            if args.verbose:
                print(f"  Testing {i}/{len(attack_requests)}: {attack_request['attack_type']}")
            
            # Send original request
            original_response = sender.send_request(attack_request['original'])
            
            # Send modified request
            modified_response = sender.send_request(attack_request['modified'])
            
            # Step 4: Analyze response differences
            analyzer = ResponseAnalyzer()
            diff_analysis = analyzer.analyze_responses(original_response, modified_response)
            
            test_result = {
                'test_id': i,
                'attack_type': attack_request['attack_type'],
                'description': attack_request['description'],
                'original_request': attack_request['original'],
                'modified_request': attack_request['modified'],
                'original_response': original_response,
                'modified_response': modified_response,
                'diff_analysis': diff_analysis
            }
            
            # Step 5: AI Analysis (if not skipped)
            if not args.skip_ai and diff_analysis.get('significant_change', False):
                print(f"  🤖 Running AI analysis for test {i}...")
                ai_analyzer = AIAnalyzer()
                ai_analysis = ai_analyzer.analyze_bypass_attempt(
                    attack_request, original_response, modified_response, diff_analysis
                )
                test_result['ai_analysis'] = ai_analysis
                
                if ai_analysis.get('severity') in ['Critical', 'High']:
                    print(f"    ⚠️  Potential {ai_analysis['severity']} finding detected!")
            
            results['tests'].append(test_result)
        
        # Save results
        output_file = save_results(results, output_dir)
        print(f"\n✅ Results saved to: {output_file}")
        
        # Print summary
        print_summary(results)
        
    except KeyboardInterrupt:
        print("\n\n⚠️ Scan interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error during analysis: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
