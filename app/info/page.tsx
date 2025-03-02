"use client";
import { useState } from "react";
import {
  ShieldAlert,
  AlertTriangle,
  Lock,
  Code2,
  Database,
  Globe,
  Key,
  FileWarning,
  X
} from "lucide-react";
import Navbar from "../components/Navbar";

interface SecurityParameter {
  title: string;
  description: string;
  icon: React.ComponentType<any>;
  severity: string;
  riskLevel: string;
  impact: string;
  commonExamples: string[];
  simpleExplanation: string;
  whatCanHappen: string[];
  howToFix: string[];
}

const securityParameters: SecurityParameter[] = [
  {
    title: "Remote Code Execution",
    description: "Prevents hackers from running harmful code on your system",
    icon: Code2,
    severity: "Critical",
    riskLevel: "High",
    impact: "Complete system compromise",
    commonExamples: [
      "eval('user_input')",
      "exec(user_command)",
      "new Function(code_string)"
    ],
    simpleExplanation: "This is like accidentally giving a stranger the keys to your house. They could do anything inside your system, like steal data or break things.",
    whatCanHappen: [
      "Attackers can run any code they want on your server",
      "They could steal sensitive data",
      "They might use your system to attack others"
    ],
    howToFix: [
      "Never use eval() or similar functions",
      "Don't run code from user input",
      "Use safe alternatives like JSON.parse()",
      "Keep a whitelist of allowed operations"
    ]
  },
  {
    title: "SQL Injection",
    description: "Stops attackers from manipulating your database",
    icon: Database,
    severity: "Critical",
    riskLevel: "High",
    impact: "Database breach and data theft",
    commonExamples: [
      "query = 'SELECT * FROM users WHERE id = ' + userInput",
      "db.query(DELETE FROM table WHERE id = ${id})"
    ],
    simpleExplanation: "Think of this like someone changing your shopping list while you're not looking. They could add things you don't want or delete important items.",
    whatCanHappen: [
      "Attackers can read all your database data",
      "They might delete or change important information",
      "They could bypass login systems"
    ],
    howToFix: [
      "Use prepared statements",
      "Never put user input directly in queries",
      "Use an ORM (Object-Relational Mapping) library",
      "Validate all user inputs"
    ]
  },
  {
    title: "Cross-Site Scripting (XSS)",
    description: "Prevents malicious scripts in your web pages",
    icon: Globe,
    severity: "High",
    riskLevel: "High",
    impact: "User session hijacking",
    commonExamples: [
      "element.innerHTML = userInput",
      "document.write(data)",
      "<div dangerouslySetInnerHTML={...}>"
    ],
    simpleExplanation: "This is like someone putting a fake sign in a store that tricks customers into giving away their credit card details.",
    whatCanHappen: [
      "Attackers can steal user login sessions",
      "They might impersonate users",
      "They could steal sensitive browser data"
    ],
    howToFix: [
      "Use textContent instead of innerHTML",
      "Sanitize all user input",
      "Enable Content Security Policy (CSP)",
      "Use modern framework safety features"
    ]
  },
  {
    title: "Sensitive Data Exposure",
    description: "Protects passwords and private information",
    icon: Lock,
    severity: "Critical",
    riskLevel: "High",
    impact: "Credential theft",
    commonExamples: [
      "const API_KEY = 'abc123'",
      "password = 'secret123'",
      "private_key = 'ssh-rsa...'"
    ],
    simpleExplanation: "This is like accidentally posting your house key on social media. Anyone could copy it and get in.",
    whatCanHappen: [
      "Passwords could be stolen",
      "API keys might be compromised",
      "Private data could be exposed"
    ],
    howToFix: [
      "Use environment variables",
      "Never commit secrets to code",
      "Use secure credential storage",
      "Encrypt sensitive data"
    ]
  },
  {
    title: "Weak Cryptography",
    description: "Ensures strong encryption for data protection",
    icon: Key,
    severity: "High",
    riskLevel: "High",
    impact: "Data protection failure",
    commonExamples: [
      "md5(password)",
      "crypto.createHash('sha1')",
      "DES encryption"
    ],
    simpleExplanation: "This is like using a simple lock that anyone can pick, instead of a strong modern lock.",
    whatCanHappen: [
      "Encrypted data could be decrypted",
      "Passwords might be cracked",
      "Secure communications could be compromised"
    ],
    howToFix: [
      "Use SHA-256 or better for hashing",
      "Use AES-256 for encryption",
      "Keep crypto libraries updated",
      "Follow modern security standards"
    ]
  },
  {
    title: "Debug Information Leaks",
    description: "Removes development traces from production",
    icon: AlertTriangle,
    severity: "Low",
    riskLevel: "Medium",
    impact: "Information disclosure",
    commonExamples: [
      "console.log(sensitiveData)",
      "print(error_details)",
      "alert(debug_info)"
    ],
    simpleExplanation: "This is like accidentally leaving your notes about the building's security where visitors can see them.",
    whatCanHappen: [
      "System details might be exposed",
      "Error messages could reveal vulnerabilities",
      "Attackers gain insights into your system"
    ],
    howToFix: [
      "Remove all console.log statements",
      "Use proper error handling",
      "Implement secure logging",
      "Configure production environments correctly"
    ]
  },
  {
    title: "Path Traversal",
    description: "Prevents unauthorized file access",
    icon: FileWarning,
    severity: "High",
    riskLevel: "High",
    impact: "Unauthorized file access",
    commonExamples: [
      "readFile('../../../etc/passwd')",
      "import('../../config.js')",
      "require('../sensitive/data')"
    ],
    simpleExplanation: "This is like someone using maintenance corridors to access restricted areas of a building.",
    whatCanHappen: [
      "Sensitive files could be accessed",
      "System configuration might be exposed",
      "Private data could be stolen"
    ],
    howToFix: [
      "Validate all file paths",
      "Use path normalization",
      "Implement proper access controls",
      "Keep files in allowed directories only"
    ]
  },
  {
    title: "Insecure Deserialization",
    description: "Prevents unsafe data processing",
    icon: ShieldAlert,
    severity: "High",
    riskLevel: "High",
    impact: "Remote code execution",
    commonExamples: [
      "JSON.parse(untrusted_data)",
      "eval('(' + data + ')')",
      "deserialize(user_input)"
    ],
    simpleExplanation: "This is like accepting a package without checking what's inside - it could contain something harmful.",
    whatCanHappen: [
      "Attackers could run malicious code",
      "System could be compromised",
      "Data might be manipulated"
    ],
    howToFix: [
      "Validate data before parsing",
      "Use safe parsing methods",
      "Implement input sanitization",
      "Avoid eval() completely"
    ]
  }
];

const Info = () => {
  const [selectedVulnerability, setSelectedVulnerability] = useState<SecurityParameter | null>(null);

  return (
    <div className="page-container">
      <Navbar />
      <div className="content-wrapper">
        <div className="info-card">
          <h1 className="page-title">
            <ShieldAlert className="title-icon" /> Security Vulnerability Guide
          </h1>
          <p className="info-description">
            Learn about common security vulnerabilities and how to protect your code from them.
          </p>
          <div className="vulnerability-grid">
            {securityParameters.map((param) => (
              <div
                key={param.title}
                className="vulnerability-card"
                onClick={() => setSelectedVulnerability(param)}
              >
                <div className="vulnerability-card-header">
                  <param.icon className="vuln-icon" />
                  <div className="vuln-header-content">
                    <h3 className="vuln-title">{param.title}</h3>
                    <span className={`severity-badge ${param.severity.toLowerCase()}`}>
                      {param.severity} Risk
                    </span>
                  </div>
                </div>
                <p className="vuln-description">{param.description}</p>
              </div>
            ))}
          </div>
        </div>
      </div>

      {selectedVulnerability && (
        <div className="modal-overlay" onClick={() => setSelectedVulnerability(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div className="modal-title-group">
                <selectedVulnerability.icon className="modal-icon" />
                <h2 className="modal-title">{selectedVulnerability.title}</h2>
              </div>
              <button
                className="close-button"
                onClick={() => setSelectedVulnerability(null)}
              >
                <X />
              </button>
            </div>

            <div className="modal-body">
              <div className="info-section">
                <span className={`severity-badge ${selectedVulnerability.severity.toLowerCase()}`}>
                  {selectedVulnerability.severity} Risk Level
                </span>
                <p className="simple-explanation">
                  {selectedVulnerability.simpleExplanation}
                </p>
              </div>

              <div className="info-section">
                <h3>What Can Happen?</h3>
                <ul className="impact-list">
                  {selectedVulnerability.whatCanHappen.map((impact: string, index: number) => (
                    <li key={index}>{impact}</li>
                  ))}
                </ul>
              </div>

              <div className="info-section">
                <h3>Common Examples</h3>
                <div className="code-examples">
                  {selectedVulnerability.commonExamples.map((example: string, index: number) => (
                    <code key={index} className="code-block">{example}</code>
                  ))}
                </div>
              </div>

              <div className="info-section">
                <h3>How to Fix</h3>
                <ul className="fix-list">
                  {selectedVulnerability.howToFix.map((fix: string, index: number) => (
                    <li key={index}>{fix}</li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Info;