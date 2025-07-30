# AuthBypass Mapper

## Overview

AuthBypass Mapper is a specialized cybersecurity tool designed to automatically detect authentication bypass vulnerabilities, privilege escalation issues, and IDOR/BOLA vulnerabilities. The tool combines traditional HTTP request manipulation with AI-powered response analysis using OpenAI's GPT-4o model to identify potential security weaknesses in web applications.

## User Preferences

Preferred communication style: Simple, everyday language.

## Recent Changes (July 30, 2025)

✅ **STRATEGIC FEATURE IMPLEMENTATION - Professional Tool Enhancement**

**Session Context Simulation (`session_manager.py`)**
- Multi-step authentication flow support with JSON configuration
- Automatic token extraction and session management 
- Login flow simulation for realistic testing scenarios
- Session-aware bypass attack generation

**AI-Driven Smart Fuzzing Engine (`smart_ai_fuzzer.py`)**
- GPT-4o powered intelligent follow-up attack suggestions
- Context-aware vulnerability hunting based on response analysis
- Pattern learning and attack effectiveness tracking over time
- Automatic IDOR opportunity detection with user ID enumeration

**Professional HTML Report Generation (`html_report_generator.py`)**
- Executive summary with risk level assessment
- Interactive findings with expandable technical details
- Visual statistics and professional presentation
- Print-ready format for stakeholder reporting

**Advanced Request Handling (`advanced_request_handler.py`)**
- Complete multipart form-data and file upload support
- SPA authentication pattern detection and bypass testing
- JavaScript-based auth context analysis
- Multi-step authentication bypass simulation

**Enhanced CLI Interface**
- `--login-flow` for session simulation with config files
- `--smart-fuzzing` for AI-powered attack generation
- `--html-report` for professional report output
- `--create-login-config` for easy setup

**Comprehensive Testing Framework**
- Complete test runner with integration validation
- Mock-based AI testing to avoid API costs during development
- Sample data generators for HAR and Burp file testing
- Quality assurance across all components

## System Architecture

### Core Architecture Pattern
The application follows a modular pipeline architecture where each component handles a specific stage of the vulnerability detection process:

1. **Input Processing**: HAR/Burp Suite file parsing
2. **Attack Generation**: Request modification for bypass testing
3. **Request Execution**: HTTP request sending and response capture
4. **Response Analysis**: Differential analysis between original and modified responses
5. **AI Analysis**: GPT-4o powered intelligent vulnerability assessment

### Technology Stack
- **Language**: Python 3
- **AI Integration**: OpenAI GPT-4o API
- **HTTP Client**: requests library with custom session management
- **File Formats**: HAR (HTTP Archive) and Burp Suite XML parsing
- **Output**: JSON-based results with timestamped files

## Key Components

### 1. HAR Parser (`har_parser.py`)
**Purpose**: Extracts HTTP requests from HAR files and Burp Suite XML exports
**Key Features**:
- Supports both HAR and Burp Suite formats
- Domain filtering capabilities
- Request detail extraction and normalization

### 2. Bypass Generator (`bypass_generator.py`)
**Purpose**: Creates authentication bypass attack vectors by modifying original requests
**Attack Types**:
- Authorization header removal
- JWT token manipulation
- Session cookie removal
- Parameter modification
- Header injection

### 3. Request Sender (`request_sender.py`)
**Purpose**: Handles HTTP request execution with proper error handling and retry logic
**Features**:
- Session management with SSL verification disabled for testing
- Configurable timeouts and retry mechanisms
- Comprehensive error handling

### 4. Response Analyzer (`response_analyzer.py`)
**Purpose**: Performs differential analysis between original and modified responses
**Analysis Types**:
- Status code changes
- Content differences
- Redirect behavior changes
- Header modifications
- Content length variations

### 5. AI Analyzer (`ai_analyzer.py`)
**Purpose**: Uses OpenAI GPT-4o to provide intelligent vulnerability assessment
**Capabilities**:
- Context-aware response analysis
- Severity classification
- Bypass detection with confidence scoring
- Recommendation generation

### 6. Main Controller (`main.py`)
**Purpose**: Orchestrates the entire vulnerability detection pipeline
**Features**:
- Command-line interface
- Output directory management
- Results compilation and reporting
- Summary generation

## Data Flow

1. **Input Stage**: HAR/Burp files are parsed to extract legitimate HTTP requests
2. **Authentication Detection**: Requests are analyzed for authentication indicators (tokens, headers, cookies)
3. **Attack Generation**: Multiple bypass variants are created for each authenticated request
4. **Execution Stage**: Both original and modified requests are sent to target servers
5. **Comparison**: Responses are compared using differential analysis techniques
6. **AI Assessment**: GPT-4o analyzes response differences to determine potential vulnerabilities
7. **Output**: Results are compiled into timestamped JSON reports with severity classifications

## External Dependencies

### Required APIs
- **OpenAI API**: GPT-4o model access for intelligent response analysis
- **Target Web Applications**: HTTP endpoints being tested for vulnerabilities

### Python Libraries
- `requests`: HTTP client for sending requests
- `openai`: OpenAI API client
- `json`: Data serialization
- `xml.etree.ElementTree`: XML parsing for Burp Suite files
- `urllib3`: URL handling and SSL warning suppression

### Environment Variables
- `OPENAI_API_KEY`: Required for AI analysis functionality

## Deployment Strategy

### Local Development
The tool is designed to run as a standalone Python application with minimal setup requirements:

1. Install required dependencies
2. Set OpenAI API key as environment variable
3. Run via command line with HAR/Burp files as input

### Key Design Decisions

**Modular Architecture**: Each component is isolated with clear interfaces, allowing for easy testing and maintenance of individual pipeline stages.

**AI Integration Choice**: GPT-4o was selected for its advanced reasoning capabilities in understanding HTTP response contexts and identifying subtle bypass indicators that traditional rule-based systems might miss.

**File Format Support**: Both HAR and Burp Suite XML formats are supported to accommodate different workflow preferences and toolchains used by security researchers.

**Error Handling Strategy**: Comprehensive error handling ensures the tool continues operation even when individual requests fail, maximizing the coverage of vulnerability testing.

**Output Format**: JSON output with timestamps provides machine-readable results that can be integrated into larger security testing pipelines or imported into other tools.

The architecture prioritizes reliability, extensibility, and accuracy in vulnerability detection while maintaining simplicity in deployment and usage.