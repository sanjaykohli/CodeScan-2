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
  X,
  Terminal,
  Shield,
  Cookie,
  RefreshCw,
  Clock,
  Server,
  Eye,
  Wifi,
  Zap,
  Bug,
  Package,
  Users
} from "lucide-react";
import Navbar from "../components/Navbar";
import { LucideIcon } from "lucide-react";

interface SecurityParameter {
  title: string;
  description: string;
  icon: LucideIcon;
  severity: string;
  riskLevel: string;
  impact: string;
  commonExamples: string[];
  simpleExplanation: string;
  whatCanHappen: string[];
  howToFix: string[];
}

const securityParameters: SecurityParameter[] = [
  // CRITICAL VULNERABILITIES
  {
    title: "Remote Code Execution",
    description: "Prevents hackers from running harmful code on your system",
    icon: Code2,
    severity: "Critical",
    riskLevel: "Critical",
    impact: "Complete system compromise",
    commonExamples: [
      "eval('user_input')",
      "setTimeout(userCode, 1000)",
      "new Function(code_string)"
    ],
    simpleExplanation: "This is like accidentally giving a stranger the keys to your house. They could do anything inside your system, like steal data or break things.",
    whatCanHappen: [
      "Attackers can run any code they want on your server",
      "They could steal sensitive data",
      "They might use your system to attack others",
      "Complete system takeover is possible"
    ],
    howToFix: [
      "Never use eval() or similar functions with user input",
      "Don't run code from user input",
      "Use safe alternatives like JSON.parse()",
      "Keep a whitelist of allowed operations"
    ]
  },
  {
    title: "Command Injection",
    description: "Stops attackers from running system commands",
    icon: Terminal,
    severity: "Critical",
    riskLevel: "Critical",
    impact: "System command execution",
    commonExamples: [
      "exec('rm -rf ' + userInput)",
      "spawn('cat', userFile)",
      "child_process.exec(command + userInput)"
    ],
    simpleExplanation: "This is like letting someone type commands directly into your computer's command line - they could delete files or install malware.",
    whatCanHappen: [
      "Attackers can execute any system command",
      "Files could be deleted or modified",
      "Malware could be installed",
      "System could be completely compromised"
    ],
    howToFix: [
      "Use command arguments array instead of string concatenation",
      "Never pass unsanitized user input to system commands",
      "Use safe alternatives to shell commands",
      "Implement strict input validation"
    ]
  },
  {
    title: "Prototype Pollution",
    description: "Prevents modification of JavaScript object prototypes",
    icon: Shield,
    severity: "Critical",
    riskLevel: "Critical",
    impact: "Application-wide code execution",
    commonExamples: [
      "Object.assign(target, userInput)",
      "obj.__proto__ = maliciousObj",
      "constructor.prototype.isAdmin = true"
    ],
    simpleExplanation: "This is like someone changing the basic rules of how your entire application works, affecting every part of your code.",
    whatCanHappen: [
      "Attackers can modify how all objects behave",
      "Security checks might be bypassed",
      "Application logic could be corrupted",
      "Privilege escalation is possible"
    ],
    howToFix: [
      "Use Object.freeze() on prototypes",
      "Use Object.create(null) for safe objects",
      "Validate all object properties",
      "Avoid dynamic property assignment"
    ]
  },

  // HIGH VULNERABILITIES
  {
    title: "SQL Injection",
    description: "Stops attackers from manipulating your database",
    icon: Database,
    severity: "High",
    riskLevel: "High",
    impact: "Database breach and data theft",
    commonExamples: [
      "query = 'SELECT * FROM users WHERE id = ' + userInput",
      "db.query(`DELETE FROM table WHERE id = ${id}`)",
      "sql = 'UPDATE users SET name = ' + userName"
    ],
    simpleExplanation: "Think of this like someone changing your shopping list while you're not looking. They could add things you don't want or delete important items.",
    whatCanHappen: [
      "Attackers can read all your database data",
      "They might delete or change important information",
      "They could bypass login systems",
      "Sensitive data could be exposed"
    ],
    howToFix: [
      "Use prepared statements or parameterized queries",
      "Never put user input directly in queries",
      "Use an ORM (Object-Relational Mapping) library",
      "Validate and sanitize all user inputs"
    ]
  },
  {
    title: "NoSQL Injection",
    description: "Protects NoSQL databases from malicious queries",
    icon: Database,
    severity: "High",
    riskLevel: "High",
    impact: "Database manipulation and data theft",
    commonExamples: [
      "db.find({name: userInput})",
      "collection.update({id: ${userId}})",
      "Model.aggregate([{$match: userQuery}])"
    ],
    simpleExplanation: "Similar to SQL injection, but for modern NoSQL databases like MongoDB. Attackers can manipulate your database queries.",
    whatCanHappen: [
      "Unauthorized access to database records",
      "Data manipulation or deletion",
      "Bypass of authentication mechanisms",
      "Exposure of sensitive information"
    ],
    howToFix: [
      "Use parameterized values in queries",
      "Validate input types and structures",
      "Use ORM sanitization features",
      "Implement proper input validation"
    ]
  },
  {
    title: "Sensitive Data Exposure",
    description: "Protects passwords and private information",
    icon: Lock,
    severity: "High",
    riskLevel: "High",
    impact: "Credential theft and privacy breach",
    commonExamples: [
      "const API_KEY = 'abc123'",
      "password = 'secret123'",
      "private_key = 'ssh-rsa...'"
    ],
    simpleExplanation: "This is like accidentally posting your house key on social media. Anyone could copy it and get in.",
    whatCanHappen: [
      "Passwords could be stolen",
      "API keys might be compromised",
      "Private data could be exposed",
      "Account takeover is possible"
    ],
    howToFix: [
      "Use environment variables for secrets",
      "Never commit secrets to code repositories",
      "Use secure credential storage services",
      "Encrypt sensitive data at rest"
    ]
  },
  {
    title: "Cross-Site Scripting (XSS)",
    description: "Prevents malicious scripts in your web pages",
    icon: Globe,
    severity: "High",
    riskLevel: "High",
    impact: "User session hijacking and data theft",
    commonExamples: [
      "element.innerHTML = userInput",
      "document.write(data)",
      "<div dangerouslySetInnerHTML={{__html: userInput}}>"
    ],
    simpleExplanation: "This is like someone putting a fake sign in a store that tricks customers into giving away their credit card details.",
    whatCanHappen: [
      "Attackers can steal user login sessions",
      "They might impersonate users",
      "They could steal sensitive browser data",
      "Malicious scripts could be injected"
    ],
    howToFix: [
      "Use textContent instead of innerHTML",
      "Sanitize all user input with libraries like DOMPurify",
      "Enable Content Security Policy (CSP)",
      "Use modern framework safety features"
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
      "crypto.createCipher('des', key)"
    ],
    simpleExplanation: "This is like using a simple lock that anyone can pick, instead of a strong modern lock.",
    whatCanHappen: [
      "Encrypted data could be easily decrypted",
      "Passwords might be cracked quickly",
      "Secure communications could be compromised",
      "Sensitive data could be exposed"
    ],
    howToFix: [
      "Use SHA-256 or better for hashing",
      "Use AES-256 for encryption",
      "Keep cryptographic libraries updated",
      "Follow modern security standards"
    ]
  },
  {
    title: "Path Traversal",
    description: "Prevents unauthorized file access",
    icon: FileWarning,
    severity: "High",
    riskLevel: "High",
    impact: "Unauthorized file system access",
    commonExamples: [
      "fs.readFile('../../../etc/passwd')",
      "fs.writeFile(userPath + '/file.txt')",
      "require('../../config.js')"
    ],
    simpleExplanation: "This is like someone using maintenance corridors to access restricted areas of a building.",
    whatCanHappen: [
      "Sensitive files could be accessed",
      "System configuration might be exposed",
      "Private data could be stolen",
      "System files could be modified"
    ],
    howToFix: [
      "Validate and sanitize all file paths",
      "Use path.normalize() and path.resolve()",
      "Implement proper access controls",
      "Keep files in allowed directories only"
    ]
  },
  {
    title: "Regular Expression DoS",
    description: "Prevents regex patterns that cause performance issues",
    icon: Clock,
    severity: "High",
    riskLevel: "High",
    impact: "Service unavailability",
    commonExamples: [
      "/(a+)+$/",
      "/([a-zA-Z]+)*$/",
      "/(a|a)*$/"
    ],
    simpleExplanation: "This is like giving someone a puzzle so complex that they get stuck trying to solve it forever, blocking everything else.",
    whatCanHappen: [
      "Application could become unresponsive",
      "Server resources could be exhausted",
      "Service denial for legitimate users",
      "System performance degradation"
    ],
    howToFix: [
      "Avoid nested quantifiers in regex",
      "Use regex validators to check patterns",
      "Implement timeouts for regex operations",
      "Use simpler, more efficient patterns"
    ]
  },

  // MEDIUM VULNERABILITIES
  {
    title: "Insecure Deserialization",
    description: "Prevents unsafe data processing",
    icon: ShieldAlert,
    severity: "Medium",
    riskLevel: "Medium",
    impact: "Remote code execution risk",
    commonExamples: [
      "JSON.parse(untrustedData)",
      "eval('(' + data + ')')",
      "unserialize(userInput)"
    ],
    simpleExplanation: "This is like accepting a package without checking what's inside - it could contain something harmful.",
    whatCanHappen: [
      "Attackers could run malicious code",
      "System could be compromised",
      "Data might be manipulated",
      "Application state could be corrupted"
    ],
    howToFix: [
      "Validate data structure before parsing",
      "Use schema validation libraries",
      "Implement input sanitization",
      "Avoid eval() and similar functions"
    ]
  },
  {
    title: "Insecure Random Values",
    description: "Ensures cryptographically secure random generation",
    icon: Zap,
    severity: "Medium",
    riskLevel: "Medium",
    impact: "Predictable security tokens",
    commonExamples: [
      "Math.random()",
      "new Date().getTime()",
      "Math.floor(Math.random() * 1000)"
    ],
    simpleExplanation: "This is like using a broken lottery machine that always picks predictable numbers.",
    whatCanHappen: [
      "Security tokens could be guessed",
      "Session IDs might be predictable",
      "Encryption keys could be weak",
      "Authentication bypass is possible"
    ],
    howToFix: [
      "Use crypto.randomBytes() for secure random values",
      "Use Web Crypto API in browsers",
      "Implement proper entropy sources",
      "Never use Math.random() for security purposes"
    ]
  },
  {
    title: "CSRF Vulnerability",
    description: "Prevents cross-site request forgery attacks",
    icon: Wifi,
    severity: "Medium",
    riskLevel: "Medium",
    impact: "Unauthorized actions on behalf of users",
    commonExamples: [
      "fetch('/api/transfer', {method: 'POST'})",
      "axios.post('/delete-account')",
      "form.submit() without CSRF token"
    ],
    simpleExplanation: "This is like someone tricking you into signing a document while you're not paying attention.",
    whatCanHappen: [
      "Unauthorized actions performed as user",
      "Data could be modified without consent",
      "Account settings might be changed",
      "Financial transactions could be initiated"
    ],
    howToFix: [
      "Include CSRF tokens in all forms",
      "Use SameSite cookie attributes",
      "Implement proper CORS policies",
      "Validate referrer headers"
    ]
  },
  {
    title: "Server-Side Request Forgery",
    description: "Prevents unauthorized server-side requests",
    icon: Server,
    severity: "Medium",
    riskLevel: "Medium",
    impact: "Internal system access",
    commonExamples: [
      "fetch(userProvidedURL)",
      "axios.get(externalURL)",
      "http.request({url: userInput})"
    ],
    simpleExplanation: "This is like someone tricking your server into making phone calls to numbers they shouldn't call.",
    whatCanHappen: [
      "Internal services could be accessed",
      "Cloud metadata could be exposed",
      "Internal network could be scanned",
      "Sensitive internal data might leak"
    ],
    howToFix: [
      "Validate and sanitize all URLs",
      "Implement URL allowlists",
      "Use URL parsing libraries",
      "Restrict outbound network access"
    ]
  },
  {
    title: "Unvalidated Redirects",
    description: "Prevents malicious redirect attacks",
    icon: RefreshCw,
    severity: "Medium",
    riskLevel: "Medium",
    impact: "Phishing and credential theft",
    commonExamples: [
      "res.redirect(userInput)",
      "window.location = userURL",
      "location.href = redirectURL"
    ],
    simpleExplanation: "This is like someone changing the road signs to redirect you to the wrong destination.",
    whatCanHappen: [
      "Users could be redirected to malicious sites",
      "Phishing attacks might be successful",
      "Credentials could be stolen",
      "Brand reputation could be damaged"
    ],
    howToFix: [
      "Validate all redirect URLs against allowlist",
      "Use relative URLs when possible",
      "Implement redirect confirmation pages",
      "Never use user input directly in redirects"
    ]
  },
  {
    title: "JWT Insecure Usage",
    description: "Ensures secure JSON Web Token implementation",
    icon: Key,
    severity: "Medium",
    riskLevel: "Medium",
    impact: "Authentication bypass",
    commonExamples: [
      "jwt.sign(payload, '', {algorithm: 'none'})",
      "jwt.verify(token, publicKey, {algorithms: ['HS256']})",
      "jwt.decode(token) // without verification"
    ],
    simpleExplanation: "This is like using a security badge that anyone can easily copy or forge.",
    whatCanHappen: [
      "Authentication could be bypassed",
      "Tokens might be forged",
      "User sessions could be hijacked",
      "Privilege escalation is possible"
    ],
    howToFix: [
      "Use strong algorithms (RS256, ES256)",
      "Implement proper key rotation",
      "Set appropriate expiration times",
      "Always verify token signatures"
    ]
  },
  {
    title: "Privacy Data Logging",
    description: "Prevents logging of personal information",
    icon: Eye,
    severity: "Medium",
    riskLevel: "Medium",
    impact: "Privacy violation and data exposure",
    commonExamples: [
      "console.log(user.email)",
      "logger.info('Password: ' + password)",
      "print(user.creditCard)"
    ],
    simpleExplanation: "This is like accidentally writing down everyone's secrets in a public notebook.",
    whatCanHappen: [
      "Personal information could be exposed",
      "Privacy regulations might be violated",
      "User trust could be lost",
      "Legal liability could increase"
    ],
    howToFix: [
      "Never log personal or sensitive information",
      "Use data masking for logs",
      "Implement log sanitization",
      "Follow privacy regulations (GDPR, CCPA)"
    ]
  },

  // LOW VULNERABILITIES
  {
    title: "Debug Information Leaks",
    description: "Removes development traces from production",
    icon: Bug,
    severity: "Low",
    riskLevel: "Low",
    impact: "Information disclosure",
    commonExamples: [
      "console.log(sensitiveData)",
      "alert(debug_info)",
      "debugger; // left in production"
    ],
    simpleExplanation: "This is like accidentally leaving your notes about the building's security where visitors can see them.",
    whatCanHappen: [
      "System details might be exposed",
      "Error messages could reveal vulnerabilities",
      "Attackers gain insights into your system",
      "Performance could be impacted"
    ],
    howToFix: [
      "Remove all console.log statements before deployment",
      "Use proper error handling",
      "Implement secure logging practices",
      "Configure production environments correctly"
    ]
  },
  {
    title: "Insecure Cookie Configuration",
    description: "Ensures secure cookie settings",
    icon: Cookie,
    severity: "Low",
    riskLevel: "Low",
    impact: "Session hijacking risk",
    commonExamples: [
      "document.cookie = 'session=' + id",
      "res.cookie('auth', token)",
      "cookies.set('user', data)"
    ],
    simpleExplanation: "This is like putting a 'take me' sign on your lunchbox - anyone could grab it.",
    whatCanHappen: [
      "Cookies could be stolen over insecure connections",
      "Session hijacking might occur",
      "Cross-site attacks could succeed",
      "User privacy could be compromised"
    ],
    howToFix: [
      "Set Secure flag for HTTPS-only cookies",
      "Use HttpOnly to prevent JavaScript access",
      "Implement SameSite attribute",
      "Use cookie prefixes for added security"
    ]
  },
  {
    title: "Outdated Package Reference",
    description: "Identifies use of outdated or vulnerable libraries",
    icon: Package,
    severity: "Low",
    riskLevel: "Low",
    impact: "Known vulnerability exposure",
    commonExamples: [
      "jquery@1.x",
      "lodash@3.x",
      "moment@2.x"
    ],
    simpleExplanation: "This is like using old locks that everyone knows how to pick because the vulnerability has been publicized.",
    whatCanHappen: [
      "Known vulnerabilities could be exploited",
      "Security patches might be missing",
      "Compatibility issues could arise",
      "Performance might be suboptimal"
    ],
    howToFix: [
      "Update to latest stable versions",
      "Use dependency scanning tools",
      "Consider modern alternatives",
      "Implement regular update schedules"
    ]
  },
  {
    title: "Inefficient React Patterns",
    description: "Identifies performance issues in React components",
    icon: RefreshCw,
    severity: "Low",
    riskLevel: "Low",
    impact: "Performance degradation",
    commonExamples: [
      "useEffect(() => {}, [])",
      "useEffect(() => fetchData())",
      "componentDidUpdate() without checks"
    ],
    simpleExplanation: "This is like leaving all the lights on in your house - it wastes energy and can cause problems.",
    whatCanHappen: [
      "Application could become slow",
      "Unnecessary re-renders might occur",
      "Memory usage could increase",
      "User experience might degrade"
    ],
    howToFix: [
      "Add proper dependency arrays to useEffect",
      "Use React.memo for expensive components",
      "Implement proper state management",
      "Optimize component rendering"
    ]
  }
];

const Info = () => {
  const [selectedVulnerability, setSelectedVulnerability] = useState<SecurityParameter | null>(null);

  // Group vulnerabilities by severity
  const groupedVulnerabilities = {
    critical: securityParameters.filter(p => p.severity === 'Critical'),
    high: securityParameters.filter(p => p.severity === 'High'),
    medium: securityParameters.filter(p => p.severity === 'Medium'),
    low: securityParameters.filter(p => p.severity === 'Low')
  };

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
            We check for {securityParameters.length} different types of security issues.
          </p>
          
          {/* Summary Stats */}
          <div className="vulnerability-stats">
            <div className="stat-item critical">
              <span className="stat-number">{groupedVulnerabilities.critical.length}</span>
              <span className="stat-label">Critical</span>
            </div>
            <div className="stat-item high">
              <span className="stat-number">{groupedVulnerabilities.high.length}</span>
              <span className="stat-label">High</span>
            </div>
            <div className="stat-item medium">
              <span className="stat-number">{groupedVulnerabilities.medium.length}</span>
              <span className="stat-label">Medium</span>
            </div>
            <div className="stat-item low">
              <span className="stat-number">{groupedVulnerabilities.low.length}</span>
              <span className="stat-label">Low</span>
            </div>
          </div>

          {/* Critical Vulnerabilities */}
          <div className="vulnerability-section">
            <h2 className="section-title critical">
              <AlertTriangle className="section-icon" />
              Critical Vulnerabilities
            </h2>
            <div className="vulnerability-grid">
              {groupedVulnerabilities.critical.map((param) => (
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

          {/* High Vulnerabilities */}
          <div className="vulnerability-section">
            <h2 className="section-title high">
              <ShieldAlert className="section-icon" />
              High Vulnerabilities
            </h2>
            <div className="vulnerability-grid">
              {groupedVulnerabilities.high.map((param) => (
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

          {/* Medium Vulnerabilities */}
          <div className="vulnerability-section">
            <h2 className="section-title medium">
              <AlertTriangle className="section-icon" />
              Medium Vulnerabilities
            </h2>
            <div className="vulnerability-grid">
              {groupedVulnerabilities.medium.map((param) => (
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

          {/* Low Vulnerabilities */}
          <div className="vulnerability-section">
            <h2 className="section-title low">
              <Shield className="section-icon" />
              Low Vulnerabilities
            </h2>
            <div className="vulnerability-grid">
              {groupedVulnerabilities.low.map((param) => (
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
                  {selectedVulnerability.whatCanHappen.map((impact, index) => (
                    <li key={index}>{impact}</li>
                  ))}
                </ul>
              </div>

              <div className="info-section">
                <h3>Common Examples</h3>
                <div className="code-examples">
                  {selectedVulnerability.commonExamples.map((example, index) => (
                    <code key={index} className="code-block">{example}</code>
                  ))}
                </div>
              </div>

              <div className="info-section">
                <h3>How to Fix</h3>
                <ul className="fix-list">
                  {selectedVulnerability.howToFix.map((fix, index) => (
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