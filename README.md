# 🛡️ AuthBypass Mapper

**Advanced AI-Powered Authentication Bypass Detection Tool**

AuthBypass Mapper is a specialized cybersecurity tool that automatically detects authentication bypass vulnerabilities, privilege escalation issues, and IDOR/BOLA vulnerabilities using traditional HTTP request manipulation combined with AI-powered response analysis.

## 🚀 Key Features

### ✅ **Session Context Simulation**
- Multi-step authentication flow support
- Automatic token extraction and session management  
- Login flow simulation with JSON configuration
- Session-aware bypass testing

### 🤖 **AI-Driven Smart Fuzzing**
- GPT-4o powered intelligent attack suggestions
- Automatic follow-up attack generation based on findings
- Pattern learning and attack effectiveness tracking
- Context-aware vulnerability hunting

### 📊 **Professional HTML Reports**
- Beautiful, interactive HTML reports with visual analysis
- Executive summaries with risk assessments
- Detailed finding breakdowns with evidence
- Expandable sections for technical details
- Professional presentation for stakeholders

### 🔧 **Advanced Request Handling**
- Multipart form-data and file upload support
- Single Page Application (SPA) authentication patterns
- JavaScript-based auth context analysis
- Complex POST request manipulation

### 🧪 **Comprehensive Testing Framework**
- Complete unit test suite with mock-based AI testing
- Integration testing with sample data validation
- Test coverage for all core components
- Automated quality assurance

## 📖 Quick Start

### Basic Usage
```bash
# Simple scan with HAR file
python main.py -f traffic.har

# Scan with domain filtering and AI analysis
python main.py -f burp_export.xml --target-domain example.com --max-requests 50

# Generate HTML report
python main.py -f traffic.har --html-report

# Enable smart fuzzing for follow-up attacks
python main.py -f traffic.har --smart-fuzzing --html-report
```

### Session Simulation
```bash
# Create login configuration template
python main.py --create-login-config

# Edit login_config.json with your credentials and endpoints

# Run with session simulation
python main.py -f traffic.har --login-flow standard_login --smart-fuzzing
```

## 🛠️ Attack Types

The tool generates and tests multiple authentication bypass vectors:

1. **Authorization Header Removal** - Tests access without auth headers
2. **JWT Token Manipulation** - Invalid signatures, null tokens, empty tokens
3. **Session Cookie Attacks** - Cookie removal and manipulation
4. **Role/Privilege Escalation** - Parameter modification for privilege escalation
5. **HTTP Header Manipulation** - IP spoofing and bypass headers
6. **HTTP Method Tampering** - Method override attacks
7. **Path Manipulation** - Path traversal and endpoint discovery
8. **Session Context Attacks** - Multi-step auth bypass scenarios
9. **SPA-Specific Attacks** - CSRF, bearer token, and API key attacks
10. **AI-Suggested Attacks** - Intelligent follow-up attacks based on findings

## 📊 Output Formats

### JSON Results
Detailed technical results with:
- Attack request/response pairs
- Differential analysis results
- AI-powered vulnerability assessments
- Confidence scores and evidence

### HTML Reports
Professional presentation with:
- Executive summary and risk assessment
- Visual statistics and charts
- Detailed findings with expandable sections
- Actionable recommendations
- Print-ready format for reporting

## 🔧 Configuration

### Login Configuration (`login_config.json`)
```json
{
  "login_flows": [
    {
      "name": "standard_login",
      "description": "Standard username/password login",
      "steps": [
        {
          "step": 1,
          "type": "POST",
          "url": "https://example.com/api/login",
          "data": {
            "username": "{{USERNAME}}",
            "password": "{{PASSWORD}}"
          },
          "extract_tokens": [
            {
              "name": "access_token",
              "from": "response_json", 
              "path": "token"
            }
          ]
        }
      ]
    }
  ],
  "credentials": {
    "USERNAME": "test_user",
    "PASSWORD": "test_password"
  }
}
```

## 🧪 Testing

Run the comprehensive test suite:
```bash
python run_tests.py
```

This validates:
- Unit tests for all components
- Integration testing with sample data  
- AI integration verification
- CLI interface validation
- Advanced feature testing

## 📋 Requirements

- Python 3.11+
- OpenAI API Key (for AI analysis)
- Required packages: `flask`, `openai`, `requests`, `requests-toolbelt`

## 🔒 Security Considerations

- PII sanitization in AI analysis
- No credentials stored in plain text
- SSL verification disabled for testing environments only
- Comprehensive error handling to prevent information leakage

## 📈 Smart Fuzzing Features

The AI-powered smart fuzzing engine provides:

- **Intelligent Attack Suggestions**: Based on response analysis and discovered data
- **IDOR Opportunity Detection**: Automatic user ID enumeration testing
- **Endpoint Discovery**: API endpoint suggestion based on patterns
- **Parameter Fuzzing**: Smart parameter manipulation suggestions
- **Pattern Learning**: Attack effectiveness tracking over time
- **Context-Aware Testing**: Attacks tailored to discovered application context

## 🎯 Use Cases

- **Bug Bounty Research**: Systematic authentication bypass testing
- **Penetration Testing**: Comprehensive auth vulnerability assessment
- **Security Audits**: Professional reporting for compliance
- **Red Team Operations**: Advanced attack scenario simulation
- **Developer Testing**: Secure coding verification

## 📚 Advanced Examples

### Multi-Step OAuth Testing
```bash
# Test complex OAuth flows with session simulation
python main.py -f oauth_traffic.har --login-flow multi_step_oauth --smart-fuzzing --html-report
```

### SPA Application Testing
```bash  
# Test Single Page Applications with advanced request handling
python main.py -f spa_traffic.har --smart-fuzzing --target-domain app.example.com
```

### Comprehensive Assessment
```bash
# Full assessment with all features enabled
python main.py -f full_traffic.har --login-flow standard_login --smart-fuzzing --html-report --verbose --max-requests 100
```

---

**AuthBypass Mapper** - Professional-grade authentication security testing with AI-powered intelligence.