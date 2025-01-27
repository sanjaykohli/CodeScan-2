import { NextResponse } from "next/server";

interface SecurityCheck {
  name: string;
  regex: RegExp;
  message: string;
  severity: 'low' | 'medium' | 'high';
  category: 'code' | 'security' | 'performance';
  impact: number; // Impact score for each violation
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
      name: "Unsafe Functions",
      regex: /eval|exec|Function\(|os\.system|subprocess\.Popen|child_process|shell\.exec|dangerouslySetInnerHTML/i,
      message: "Critical: Unsafe function detected that could allow remote code execution. These functions are strictly prohibited in secure environments.",
      severity: 'high',
      category: 'security',
      impact: 15
    },
    {
      name: "SQL Injection Risk",
      regex: /(SELECT|INSERT|DELETE|UPDATE|DROP|UNION|ALTER).*(`|\$\{|\$|'|\s*\+\s*.*['"]|\${.*})/i,
      message: "Critical: SQL injection vulnerability detected. Use prepared statements and ORM libraries for database operations.",
      severity: 'high',
      category: 'security',
      impact: 15
    },
    {
      name: "Sensitive Data Exposure",
      regex: /(password|secret|api[_-]?key|token|private[_-]?key|auth|bearer|jwt|ssh[_-]?key)[\s]*[=:][\s]*['"`][^'"`]+['"`]/i,
      message: "Critical: Sensitive data exposed in plaintext. Use environment variables and secure vaults.",
      severity: 'high',
      category: 'security',
      impact: 12
    },
    {
      name: "Hardcoded Credentials",
      regex: /(credentials|config)[\s]*[=:][\s]*{[\s\S]*?(password|secret|key)[\s\S]*?}/i,
      message: "Critical: Hardcoded credentials detected. Use secure credential management systems.",
      severity: 'high',
      category: 'security',
      impact: 12
    },
    {
      name: "Debugging Statements",
      regex: /console\.(log|debug|info|warn|error)|print[\s]*\(|alert\(|debugger/i,
      message: "Warning: Debug statements found in production code. Remove all debugging before deployment.",
      severity: 'medium',
      category: 'performance',
      impact: 8
    },
    {
      name: "Insufficient Error Handling",
      regex: /catch[\s]*\(.*\)[\s]*{[\s]*}|catch[\s]*\(.*\)[\s]*{[\s]*console\.|catch[\s]*\(.*\)[\s]*{[\s]*return/i,
      message: "Warning: Empty or insufficient error handling detected. Implement proper error handling and logging.",
      severity: 'medium',
      category: 'code',
      impact: 8
    },
    {
      name: "Insecure Dependencies",
      regex: /import[\s]+.*?(requests|urllib|http|fs|crypto)[\s]+from|require\(['"](request|http|fs|crypto)['"]|import\s+{[\s\S]*?}\s+from\s+['"]express['"]|import\s+express\s+from\s+['"]express['"]/i,
      message: "Warning: Potentially vulnerable library usage detected. Ensure latest security patches are applied.",
      severity: 'medium',
      category: 'security',
      impact: 10
    },
    {
      name: "Weak Cryptography",
      regex: /MD5|SHA1|DES|RC4|createHash\(['"](md5|sha1)['"]\)|crypto\.createCipher\(['"](des|rc4)['"]\)/i,
      message: "Critical: Weak cryptographic methods detected. Use strong algorithms (SHA-256, AES) and proper key lengths.",
      severity: 'high',
      category: 'security',
      impact: 12
    },
    {
      name: "Insecure Random Values",
      regex: /Math\.random\(\)|new Random\(\)|random\.|rand\(/i,
      message: "Warning: Insecure random number generation. Use cryptographically secure methods.",
      severity: 'medium',
      category: 'security',
      impact: 8
    },
    {
      name: "Directory Traversal",
      regex: /\.\.\//,
      message: "Critical: Potential directory traversal vulnerability detected. Use path sanitization.",
      severity: 'high',
      category: 'security',
      impact: 10
    },
    {
      name: "XSS Vulnerabilities",
      regex: /innerHTML|outerHTML|document\.write|\$\(['"]*.*['"]*\)\.html\(|dangerouslySetInnerHTML/i,
      message: "Critical: Potential XSS vulnerability detected. Use safe DOM manipulation methods.",
      severity: 'high',
      category: 'security',
      impact: 12
    }
  ];

  const performSecurityAnalysis = (code: string) => {
    const report: string[] = [];
    let totalImpact = 0;
    let highestSeverity = 'low';
    
    // Calculate maximum possible impact
    const maxImpact = securityChecks.reduce((sum, check) => sum + check.impact, 0);

    securityChecks.forEach(check => {
      if (check.regex.test(code)) {
        report.push(`[${check.severity.toUpperCase()}] ${check.message}`);
        totalImpact += check.impact;

        if (
          (check.severity === 'high') ||
          (check.severity === 'medium' && highestSeverity !== 'high') ||
          (check.severity === 'low' && highestSeverity === 'low')
        ) {
          highestSeverity = check.severity;
        }
      }
    });

    // Calculate security score (more strict scoring)
    const securityScore = Math.max(0, Math.floor(100 - (totalImpact / maxImpact * 100)));

    // Adjust severity levels based on score
    let severityLevel = 'Low';
    if (securityScore < 70) severityLevel = 'High';
    else if (securityScore < 85) severityLevel = 'Medium';

    return {
      securityScore,
      report,
      severityLevel,
      totalViolations: report.length,
      impactScore: totalImpact
    };
  };

  return NextResponse.json(performSecurityAnalysis(code), { status: 200 });
}