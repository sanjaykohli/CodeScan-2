import { NextResponse } from "next/server";

interface SecurityCheck {
  name: string;
  regex: RegExp;
  message: string;
  severity: 'low' | 'medium' | 'high';
  category: 'code' | 'security' | 'performance';
  impact: number;
  remediation: string;
}

interface VulnerabilityDetection {
  line: number;
  lineContent: string;
  matchedPattern: string;
}

export async function POST(req: Request) {
  const body = await req.json();
  const { code } = body;

  if (!code) {
    return NextResponse.json({
      error: "Code is required for evaluation.",
      securityScore: 0,
      report: ["No code provided for analysis."]
    }, { status: 400 });
  }

  const securityChecks: SecurityCheck[] = [
    {
      name: "Remote Code Execution",
      regex: /eval|exec|Function\(|os\.system|subprocess\.Popen|child_process|shell\.exec/i,
      message: "Remote Code Execution Vulnerability",
      severity: 'high',
      category: 'security',
      impact: 20,
      remediation: "Avoid using eval, exec, or system commands. Use safe alternatives like JSON.parse() for parsing or specific library functions."
    },
    {
      name: "SQL Injection",
      regex: /(SELECT|INSERT|DELETE|UPDATE|DROP|UNION|ALTER).*(`|\$\{|\$|'|\s*\+\s*.*['"]|\${.*})/i,
      message: "SQL Injection Vulnerability",
      severity: 'high',
      category: 'security',
      impact: 18,
      remediation: "Use parameterized queries, prepared statements, or ORM libraries. Never concatenate user input directly into SQL queries."
    },
    {
      name: "Sensitive Data Exposure",
      regex: /(password|secret|api[_-]?key|token|private[_-]?key|auth|bearer|jwt|ssh[_-]?key)[\s]*[=:][\s]*['"`][^'"`]+['"`]/i,
      message: "Sensitive Data Exposure",
      severity: 'high',
      category: 'security',
      impact: 15,
      remediation: "Use environment variables, secure vaults, or encryption. Never hardcode sensitive information."
    },
    {
      name: "XSS Vulnerability",
      regex: /innerHTML|outerHTML|document\.write|\$\(['"]*.*['"]*\)\.html\(|dangerouslySetInnerHTML/i,
      message: "Cross-Site Scripting (XSS) Vulnerability",
      severity: 'high',
      category: 'security',
      impact: 16,
      remediation: "Use safe DOM manipulation methods. Sanitize and escape user inputs. Use libraries like DOMPurify for input sanitization."
    },
    {
      name: "Weak Cryptography",
      regex: /MD5|SHA1|DES|RC4|createHash\(['"](md5|sha1)['"]\)|crypto\.createCipher\(['"](des|rc4)['"]\)/i,
      message: "Weak Cryptographic Method",
      severity: 'high',
      category: 'security',
      impact: 14,
      remediation: "Use modern cryptographic algorithms like SHA-256, AES-256. Prefer built-in crypto libraries with strong defaults."
    },
    {
      name: "Insecure Deserialization",
      regex: /JSON\.parse\(|\beval\(|JSON\.stringify\(/i,
      message: "Potential Insecure Deserialization",
      severity: 'medium',
      category: 'security',
      impact: 12,
      remediation: "Use safe parsing methods. Validate and sanitize input before parsing. Avoid eval() completely."
    },
    {
      name: "Debug Statements",
      regex: /console\.(log|debug|info|warn|error)|print[\s]*\(|alert\(|debugger/i,
      message: "Production Debug Statements",
      severity: 'low',
      category: 'performance',
      impact: 5,
      remediation: "Remove all console logs and debugging statements before production deployment."
    },
    {
      name: "Path Traversal",
      regex: /\.\.\//,
      message: "Potential Path Traversal Vulnerability",
      severity: 'high',
      category: 'security',
      impact: 15,
      remediation: "Validate and sanitize file paths. Use built-in path libraries to prevent directory traversal."
    }
  ];

  const performSecurityAnalysis = (code: string) => {
    const lines = code.split('\n');
    const vulnerabilities: Array<{
      check: SecurityCheck;
      detections: VulnerabilityDetection[];
    }> = [];
    let totalImpact = 0;
    let highestSeverity = 'low';

    securityChecks.forEach(check => {
      const lineDetections: VulnerabilityDetection[] = lines.reduce((acc, line, index) => {
        const matches = line.match(check.regex);
        if (matches) {
          acc.push({
            line: index + 1,
            lineContent: line.trim(),
            matchedPattern: matches[0]
          });
        }
        return acc;
      }, [] as VulnerabilityDetection[]);

      if (lineDetections.length > 0) {
        vulnerabilities.push({ 
          check, 
          detections: lineDetections 
        });
        
        totalImpact += check.impact * lineDetections.length;

        if (
          (check.severity === 'high') ||
          (check.severity === 'medium' && highestSeverity !== 'high') ||
          (check.severity === 'low' && highestSeverity === 'low')
        ) {
          highestSeverity = check.severity;
        }
      }
    });

    const maxPossibleImpact = securityChecks.reduce((sum, check) => sum + check.impact, 0) * 5;
    const securityScore = Math.max(0, Math.floor(100 - (totalImpact / maxPossibleImpact * 100)));

    const report = vulnerabilities.flatMap(vuln => 
      vuln.detections.map(det => 
        `[${vuln.check.severity.toUpperCase()}] ${vuln.check.message} at Line ${det.line}: ${det.lineContent}\n   Remediation: ${vuln.check.remediation}`
      )
    );

    let severityLevel = 'Low';
    if (securityScore < 50) severityLevel = 'High';
    else if (securityScore < 75) severityLevel = 'Medium';

    return {
      securityScore,
      report,
      severityLevel,
      totalViolations: report.length,
      impactScore: totalImpact,
      vulnerabilities
    };
  };

  return NextResponse.json(performSecurityAnalysis(code), { status: 200 });
}