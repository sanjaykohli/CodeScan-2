import {
  SecurityCheck,
  VulnerabilityDetection,
  CodeBlock,
  SecurityAnalysisResult
} from "@/types";

const getLineContext = (lines: string[], lineIndex: number): string => {
  const contextLines = 2;
  const start = Math.max(0, lineIndex - contextLines);
  const end = Math.min(lines.length - 1, lineIndex + contextLines);
  
  let context = '';
  for (let i = start; i <= end; i++) {
    if (i === lineIndex) {
      context += `→ ${lines[i]}\n`;
    } else {
      context += `  ${lines[i]}\n`;
    }
  }
  return context.trim();
};

const isNotFalsePositive = (line: string, check: SecurityCheck): boolean => {
  if (!check.falsePositivePatterns) return true;
  return !check.falsePositivePatterns.some(pattern => pattern.test(line));
};

export const performSecurityAnalysis = (code: string, securityChecks: SecurityCheck[]): SecurityAnalysisResult => {
  const lines = code.split('\n');
  const vulnerabilities: Array<{
    check: SecurityCheck;
    detections: VulnerabilityDetection[];
  }> = [];
  
  let totalImpact = 0;
  let highestSeverity: 'low' | 'medium' | 'high' | 'critical' = 'low';
  const categoryBreakdown: Record<string, number> = {};
  const severityBreakdown: Record<string, number> = {};
  
  const severityMap: Record<string, number> = {
    'low': 1,
    'medium': 2,
    'high': 3,
    'critical': 4
  };

  // Process multiline code blocks
  const codeBlocks: CodeBlock[] = [];
  let currentBlock = '';
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    currentBlock += line + '\n';
    
    if (line.trim().endsWith(';') || line.trim().endsWith('}') || line.trim().endsWith('{')) {
      codeBlocks.push({
        content: currentBlock,
        startLine: i - currentBlock.split('\n').length + 2,
        endLine: i + 1
      });
      currentBlock = '';
    }
  }
  
  if (currentBlock.trim()) {
    codeBlocks.push({
      content: currentBlock,
      startLine: lines.length - currentBlock.split('\n').length + 1,
      endLine: lines.length
    });
  }

  // Run security checks
  securityChecks.forEach(check => {
    const lineDetections: VulnerabilityDetection[] = [];
    
    // Line-by-line analysis
    lines.forEach((line, index) => {
      if (line.trim().startsWith('//') || line.trim() === '') return;
      
      const matches = line.match(check.regex);
      if (matches && isNotFalsePositive(line, check)) {
        lineDetections.push({
          line: index + 1,
          lineContent: line.trim(),
          matchedPattern: matches[0],
          context: getLineContext(lines, index)
        });
      }
    });
    
    // Code block analysis
    codeBlocks.forEach(block => {
      const matches = block.content.match(check.regex);
      if (matches && !lineDetections.some(det => 
          det.line >= block.startLine && det.line <= block.endLine)) {
        if (isNotFalsePositive(block.content, check)) {
          lineDetections.push({
            line: block.startLine,
            lineContent: block.content.split('\n')[0].trim() + '...',
            matchedPattern: matches[0],
            context: block.content.trim()
          });
        }
      }
    });
    
    if (lineDetections.length > 0) {
      vulnerabilities.push({ 
        check, 
        detections: lineDetections 
      });
      
      totalImpact += check.impact * lineDetections.length;
      categoryBreakdown[check.category] = (categoryBreakdown[check.category] || 0) + lineDetections.length;
      severityBreakdown[check.severity] = (severityBreakdown[check.severity] || 0) + lineDetections.length;
      
      if (severityMap[check.severity] > severityMap[highestSeverity]) {
        highestSeverity = check.severity;
      }
    }
  });

  // Calculate score
  const maxPossibleImpact = securityChecks.reduce((sum, check) => sum + check.impact, 0) * 3;
  const securityScore = Math.max(0, Math.floor(100 - (totalImpact / maxPossibleImpact * 100)));

  // Generate report
  const report = vulnerabilities.flatMap(vuln => 
    vuln.detections.map(det => 
      `[${vuln.check.severity.toUpperCase()}] ${vuln.check.message} at Line ${det.line}: ${det.lineContent}\n   Matched: ${det.matchedPattern}\n   Remediation: ${vuln.check.remediation}`
    )
  );

  // Determine severity level
  let severityLevel: 'Low' | 'Medium' | 'High' | 'Critical' = 'Low';
  if (highestSeverity === 'critical' || securityScore < 40) severityLevel = 'Critical';
  else if (highestSeverity === 'high' || securityScore < 60) severityLevel = 'High';
  else if (highestSeverity === 'medium' || securityScore < 80) severityLevel = 'Medium';

  return {
    securityScore,
    report,
    severityLevel,
    totalViolations: report.length,
    impactScore: totalImpact,
    vulnerabilities,
    categoryBreakdown,
    severityBreakdown
  };
};

// Security checks definition
export const securityChecks: SecurityCheck[] = [
  // CRITICAL VULNERABILITIES
  {
    name: "Remote Code Execution",
    regex: /(?<!\w)(eval|exec|setTimeout|setInterval)\s*\(\s*(.*\$\{.*\}.*|.*\+.*|.*`.*`.*|.*\(\).*=>.*|['"].*['"].*\+.*['"].*['"])/i,
    message: "Remote Code Execution Vulnerability",
    severity: 'critical',
    category: 'security',
    impact: 25,
    remediation: "Avoid using eval, exec, or executing user-controlled input. Use safe alternatives like JSON.parse() for parsing.",
    falsePositivePatterns: [
      /\/\/.*eval/i,
      /['"`].*eval.*['"`]/i
    ]
  },
  {
    name: "Command Injection",
    regex: /(?<!\w)(child_process|spawn|exec|execSync|execFile|fork|spawnSync|execFileSync|os\.system|subprocess\.Popen|shell\.exec)\s*\(\s*(.*\$\{.*\}.*|.*\+.*|.*`.*`.*|.*['"].*['"].*\+.*)/i,
    message: "Command Injection Vulnerability",
    severity: 'critical',
    category: 'security',
    impact: 25,
    remediation: "Never pass unsanitized user input to system commands. Use command arguments array instead of shell string concatenation.",
  },
  {
    name: "Prototype Pollution",
    regex: /(?<!\w)(Object\.assign|Object\.setPrototypeOf|__proto__|constructor\.prototype|Object\.prototype)\s*(\[\s*['"`].*['"`]\s*\]|\.\s*['"`].*['"`])/i,
    message: "Prototype Pollution Vulnerability",
    severity: 'critical',
    category: 'security',
    impact: 22,
    remediation: "Use Object.freeze() or Object.create(null). Avoid setting properties on Object prototypes dynamically.",
  },
  
  // HIGH VULNERABILITIES
  {
    name: "SQL Injection",
    regex: /(?<!\w)(SELECT|INSERT|DELETE|UPDATE|DROP|UNION|ALTER|CREATE|TRUNCATE|GRANT|REVOKE)\s+(?:.*?)(?:(FROM|INTO|WHERE|VALUES|SET|TABLE)\s+)?(?:.*?)(`|\$\{|\$|'|\s*\+\s*.*['"]|\${.*})/i,
    message: "SQL Injection Vulnerability",
    severity: 'high',
    category: 'security',
    impact: 20,
    remediation: "Use parameterized queries, prepared statements, or ORM libraries. Never concatenate user input into SQL queries.",
  },
  {
    name: "NoSQL Injection",
    regex: /(?<!\w)(db|collection|Model)\.(?:find|findOne|update|updateOne|updateMany|replaceOne|deleteOne|deleteMany|aggregate)\s*\(\s*(?:\{.*\$\{.*\}.*\}|\{.*\+.*\}|\{.*`.*`.*\})/i,
    message: "NoSQL Injection Vulnerability",
    severity: 'high',
    category: 'security',
    impact: 18,
    remediation: "Use parameterized values or ORM sanitization. Avoid constructing query objects with string concatenation or template literals.",
  },
  {
    name: "Sensitive Data Exposure",
    regex: /(?<!\w)(password|passwd|secret|api[_-]?key|token|private[_-]?key|auth|bearer|jwt|ssh[_-]?key|encryption[_-]?key|credentials|cert|certificate|access[_-]?token)[\s]*[=:][\s]*['"`][^'"`]{5,}['"`]/i,
    message: "Sensitive Data Exposure",
    severity: 'high',
    category: 'security',
    impact: 18,
    remediation: "Use environment variables, secure vaults, or encryption. Never hardcode sensitive information.",
  },
  {
    name: "XSS Vulnerability",
    regex: /(?<!\w)(innerHTML|outerHTML|document\.write|document\.writeln|\$\(['"]*.*['"]*\)\.html\(|dangerouslySetInnerHTML|insertAdjacentHTML)\s*[=\(]\s*(?:.*\$\{.*\}.*|.*\+.*|.*`.*`.*)/i,
    message: "Cross-Site Scripting (XSS) Vulnerability",
    severity: 'high',
    category: 'security',
    impact: 18,
    remediation: "Use safe DOM manipulation methods. Sanitize user inputs with libraries like DOMPurify. Use React's JSX or framework-specific templating.",
  },
  {
    name: "Weak Cryptography",
    regex: /(?<!\w)(MD5|SHA1|DES|RC4|ECB|createHash\(['"](md5|sha1)['"]\)|crypto\.createCipher\(['"](des|rc4)['"]\)|crypto\.createCipheriv\(['"](des-ecb|rc4)['"]\))/i,
    message: "Weak Cryptographic Method",
    severity: 'high',
    category: 'security',
    impact: 16,
    remediation: "Use modern cryptographic algorithms like SHA-256, AES-GCM. Prefer built-in crypto libraries with strong defaults.",
  },
  {
    name: "Path Traversal",
    regex: /(?<!\w)(fs|path)\.(readFile|writeFile|appendFile|createReadStream|createWriteStream|unlink|readdir|mkdir|rmdir|copyFile|access|stat|readFileSync|writeFileSync)\s*\(\s*(?:.*\$\{.*\}.*|.*\+.*|.*`.*`.*|.*['"].*\.\.\/.*['"])/i,
    message: "Path Traversal Vulnerability",
    severity: 'high',
    category: 'security',
    impact: 17,
    remediation: "Validate and sanitize file paths. Use path.normalize() and check for directory traversal sequences. Use built-in path libraries.",
  },
  {
    name: "Regular Expression DoS",
    regex: /(?<!\w)new RegExp\(.*\+.*\)|(?<!\w)\/(\.\*|\\\w\*|\[.*\]\*|\.\+|\\\w\+|\[.*\]\+)\+(\?\=|\$|\/)/i,
    message: "Regular Expression Denial of Service (ReDoS)",
    severity: 'high',
    category: 'security',
    impact: 15,
    remediation: "Avoid nested quantifiers in regex patterns. Use regex validators and tools to check for ReDoS vulnerabilities.",
  },
  
  // MEDIUM VULNERABILITIES
  {
    name: "Insecure Deserialization",
    regex: /(?<!\w)(JSON\.parse\(|parse\()(?:.*\$\{.*\}.*|.*\+.*|.*`.*`.*|.*fetch\(.*\.then\(.*\)|.*axios\.get\(.*\.then\(.*\))/i,
    message: "Potential Insecure Deserialization",
    severity: 'medium',
    category: 'security',
    impact: 14,
    remediation: "Use safe parsing methods with schema validation. Validate and sanitize input before parsing. Consider using libraries like joi or yup.",
  },
  {
    name: "Insecure Random Values",
    regex: /(?<!\w)(Math\.random\(\)|new Date\(\)\.getTime\(\))/i,
    message: "Insecure Random Value Generation",
    severity: 'medium',
    category: 'security',
    impact: 12,
    remediation: "Use crypto.randomBytes() or Web Crypto API for cryptographically secure random values instead of Math.random().",
  },
  {
    name: "CSRF Vulnerability",
    regex: /(?<!\w)(fetch|axios|http|https|request)\s*\(\s*(?:.*\$\{.*\}.*|.*\+.*|.*`.*`.*)\s*[,)]\s*\{(?:(?!csrf|xsrf|token).)*\}/i,
    message: "Potential CSRF Vulnerability",
    severity: 'medium',
    category: 'security',
    impact: 13,
    remediation: "Include CSRF tokens in requests. Use SameSite cookies. Implement proper CORS policies.",
  },
  {
    name: "Server-Side Request Forgery",
    regex: /(?<!\w)(fetch|axios|http|https|request)\s*\(\s*(?:.*\$\{.*\}.*|.*\+.*|.*`.*`.*)\s*[,)]/i,
    message: "Potential Server-Side Request Forgery (SSRF)",
    severity: 'medium',
    category: 'security',
    impact: 14,
    remediation: "Validate and sanitize URLs. Implement an allowlist of approved domains. Use URL parsing libraries to check URL components.",
  },
  {
    name: "Unvalidated Redirects",
    regex: /(?<!\w)(res\.redirect|window\.location|location\.href|location\.replace|location\.assign|response\.sendRedirect)\s*\(\s*(?:.*\$\{.*\}.*|.*\+.*|.*`.*`.*)\s*\)/i,
    message: "Unvalidated Redirects and Forwards",
    severity: 'medium',
    category: 'security',
    impact: 12,
    remediation: "Validate all redirect URLs against an allowlist. Never use user input directly in redirects without validation.",
  },
  {
    name: "JWT Insecure Usage",
    regex: /(?<!\w)(jwt\.sign|signAsync|verify|decode)\s*\(\s*(?:.*\$\{.*\}.*|.*\+.*|.*`.*`.*|.*{.*algorithm\s*:\s*['"](?:none|HS256|HS384|HS512)['"].*})/i,
    message: "Insecure JWT Implementation",
    severity: 'medium',
    category: 'security',
    impact: 13,
    remediation: "Use strong algorithms (RS256, ES256). Implement proper key rotation and validation. Set appropriate expiration times.",
  },
  
  // LOW VULNERABILITIES
  {
    name: "Debug Statements",
    regex: /(?<!\w)(console\.(log|debug|info|warn|error)|print\s*\(|alert\(|debugger)/i,
    message: "Production Debug Statements",
    severity: 'low',
    category: 'performance',
    impact: 5,
    remediation: "Remove all console logs and debugging statements before production deployment.",
    falsePositivePatterns: [
      /\/\/.*console\.(log|debug|info|warn|error)/i,
      /['"`].*console\.(log|debug|info|warn|error).*['"`]/i
    ]
  },
  {
    name: "Insecure Cookie Configuration",
    regex: /(?<!\w)(document\.cookie|cookies\.set|res\.cookie|cookie\.serialize|new Cookie)\s*\(\s*(?:(?!secure|httpOnly|sameSite).)*\)/i,
    message: "Insecure Cookie Configuration",
    severity: 'low',
    category: 'security',
    impact: 8,
    remediation: "Set Secure, HttpOnly, and SameSite attributes on cookies. Use cookie prefixes for additional security.",
  },
  {
    name: "Outdated Package Reference",
    regex: /(?<!\w)(jquery|backbone|angularjs|moment|lodash)(?:\s*@\s*["']1\.[0-9]\.["']|["']1\.[0-9]\.["'])/i,
    message: "Reference to Outdated Package",
    severity: 'low',
    category: 'security',
    impact: 7,
    remediation: "Update to the latest version of the library. Consider using alternatives with active maintenance.",
  },
  {
    name: "Inefficient React Patterns",
    regex: /(?<!\w)(useEffect|componentDidMount|componentDidUpdate)\s*\(\s*\(\)\s*=>\s*\{(?:(?!dependencies|props).)*\}\s*(?:,\s*)?\)/i,
    message: "Inefficient React Pattern",
    severity: 'low',
    category: 'performance',
    impact: 6,
    remediation: "Add appropriate dependencies array to useEffect. Optimize component updates to prevent unnecessary renders.",
  },
  {
    name: "Privacy Data Logging",
    regex: /(?<!\w)(console\.(log|debug|info|warn|error)|print\s*\()\s*\(\s*(?:.*\.email.*|.*\.password.*|.*\.name.*|.*\.address.*|.*\.phone.*|.*\.credit.*|.*\.ssn.*)/i,
    message: "Logging Personal Information",
    severity: 'medium',
    category: 'privacy',
    impact: 10,
    remediation: "Never log personal or sensitive information. Use data masking or sanitization before logging.",
  }
];