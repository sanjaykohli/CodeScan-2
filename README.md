# CodeScan-2 - Advanced Security Code Analyzer

CodeScan-2 is a comprehensive security analysis tool that scans both individual code snippets and entire GitHub repositories for security vulnerabilities. It provides detailed reports with vulnerability locations, severity levels, and remediation guidance.

## Features

- **Direct Code Analysis**: Paste code directly for instant security evaluation
- **GitHub Repository Scanning**: Analyze entire repositories for security issues
- **Detailed Vulnerability Reports**:
  - File paths and line numbers
  - Code snippets with context
  - Severity classification (Critical, High, Medium, Low)
  - Remediation recommendations
- **Security Score**: Overall security rating for your codebase
- **Educational Content**: Learn about common security vulnerabilities

## How It Works

### 1. Direct Code Analysis
- Users paste code into the text area on the homepage
- The code is sent to the `/api/evaluate` endpoint
- The server runs a series of regex-based security checks
- Returns a security score and a list of vulnerabilities

### 2. GitHub Repository Analysis
- Users provide a GitHub repository URL
- The application uses the GitHub API to fetch repository contents
- All code files (JavaScript, TypeScript, Python, Java, C++, Go, Ruby, PHP) are analyzed
- Results are aggregated into a comprehensive security report

### 3. Security Checks
The system uses 20+ security checks including:
- SQL Injection
- Cross-Site Scripting (XSS)
- Remote Code Execution
- Sensitive Data Exposure
- Path Traversal
- Insecure Deserialization
- Weak Cryptography
- Prototype Pollution
- Command Injection
- Regular Expression DoS (ReDoS)

## Setup Instructions

1. **Clone the repository**:
   ```bash
   git clone https://github.com/sanjaykohli/CodeScan-2.git
   cd CodeScan-2
   ```

2. **Install dependencies**:
   ```bash
   npm install
   ```

3. **Create a `.env.local` file in the root directory and add your GitHub Personal Access Token**:
   ```env
   GITHUB_TOKEN=your_github_personal_access_token_here
   ```
   **Note**: To create a GitHub token, go to your GitHub account Settings > Developer Settings > Personal Access Tokens. Generate a new token with `repo` scope.

4. **Run the development server**:
   ```bash
   npm run dev
   ```

5. **Access the application**: Open your browser and navigate to:
   ```
   http://localhost:3000
   ```

## Usage

### Direct Code Analysis
1. Navigate to the homepage
2. Paste your code in the text area
3. Click "Check Security"
4. View the security report

### GitHub Repository Analysis
1. Go to the GitHub tab
2. Enter a GitHub repository URL (e.g., `https://github.com/facebook/react`)
3. Click "Scan Repository"
4. View the comprehensive security report

## Architecture Overview

```
Frontend (Next.js)
├── User Interface
├── GitHub Integration
└── Results Display

Backend (Next.js API Routes)
├── /api/evaluate - Direct code analysis
└── /api/github - Repository analysis

Security Engine
├── Regex-based pattern matching
├── Context-aware analysis
├── Severity scoring
└── Vulnerability classification
```

## Contributing

We welcome contributions to improve CodeScan-2! Here's how you can help:

1. **Add new security checks**:
   - Modify `lib/securityAnalysis.ts`
   - Add new regex patterns to the `securityChecks` array

2. **Improve UI/UX**:
   - Enhance vulnerability cards
   - Add code syntax highlighting
   - Improve mobile responsiveness

3. **Enhance analysis capabilities**:
   - Add AST-based analysis
   - Integrate with linters (ESLint, Bandit, etc.)
   - Add language-specific parsers

4. **Fix bugs and improve documentation**