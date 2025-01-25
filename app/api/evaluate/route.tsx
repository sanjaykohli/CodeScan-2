import { NextResponse } from "next/server";

interface SecurityCheck {
  name: string;
  regex: RegExp;
  message: string;
  severity: 'low' | 'medium' | 'high';
  category: 'code' | 'security' | 'performance';
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
      regex: /eval|exec|os\.system|subprocess\.Popen/,
      message: "Unsafe function detected that could allow remote code execution.",
      severity: 'high',
      category: 'security'
    },
    {
      name: "SQL Injection Risk",
      regex: /SELECT|INSERT|DELETE|UPDATE.*['"]\s*\+\s*.*['"]/,
      message: "Potential SQL injection vulnerability detected. Use parameterized queries.",
      severity: 'high',
      category: 'security'
    },
    {
      name: "Sensitive Data Exposure",
      regex: /(password|secret|api_key|token)\s*=\s*['"].*['"]/,
      message: "Sensitive data found in plain text. Use secure environment variables.",
      severity: 'high',
      category: 'security'
    },
    {
      name: "Hardcoded Credentials",
      regex: /credentials\s*=\s*{.*}/,
      message: "Hardcoded credentials found. Implement secure credential management.",
      severity: 'high',
      category: 'security'
    },
    {
      name: "Debugging Statements",
      regex: /console\.log|print\(/,
      message: "Production code contains debugging statements. Remove before deployment.",
      severity: 'low',
      category: 'performance'
    },
    {
      name: "Missing Error Handling",
      regex: /try\s*{.*}\s*catch\s*\(.*\)\s*{.*}/,
      message: "Potential lack of comprehensive error handling.",
      severity: 'medium',
      category: 'code'
    },
    {
      name: "Insecure Dependency",
      regex: /import\s+(requests|urllib)/,
      message: "Potentially vulnerable library detected. Ensure latest security updates.",
      severity: 'medium',
      category: 'security'
    },
    {
      name: "Weak Cryptography",
      regex: /MD5|SHA1/,
      message: "Weak cryptographic hash function detected. Use stronger alternatives.",
      severity: 'high',
      category: 'security'
    }
  ];

  const performSecurityAnalysis = (code: string) => {
    const report: string[] = [];
    const severityScores = { low: 1, medium: 3, high: 5 };
    let totalScore = 100;
    let highestSeverity = 'low';

    securityChecks.forEach(check => {
      if (check.regex.test(code)) {
        report.push(`[${check.severity.toUpperCase()}] ${check.message}`);
        totalScore -= severityScores[check.severity];
        
        // Track highest severity
        if (
          (check.severity === 'high') || 
          (check.severity === 'medium' && highestSeverity !== 'high') ||
          (check.severity === 'low' && highestSeverity === 'low')
        ) {
          highestSeverity = check.severity;
        }
      }
    });

    // Normalize score and ensure it's not negative
    const securityScore = Math.max(0, totalScore);

    return { 
      securityScore, 
      report, 
      severityLevel: highestSeverity === 'high' ? 'High' : 
                     highestSeverity === 'medium' ? 'Medium' : 'Low'
    };
  };

  return NextResponse.json(performSecurityAnalysis(code), { status: 200 });
}