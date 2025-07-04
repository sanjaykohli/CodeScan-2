export interface SecurityCheck {
  name: string;
  regex: RegExp;
  message: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  category: 'code' | 'security' | 'performance' | 'privacy';
  impact: number;
  remediation: string;
  falsePositivePatterns?: RegExp[];
}

export interface VulnerabilityDetection {
  line: number;
  lineContent: string;
  matchedPattern: string;
  context?: string;
}

export interface CodeBlock {
  content: string;
  startLine: number;
  endLine: number;
}

export interface SecurityAnalysisResult {
  securityScore: number;
  report: string[];
  severityLevel: 'Low' | 'Medium' | 'High' | 'Critical';
  totalViolations: number;
  impactScore: number;
  vulnerabilities: Array<{
    check: SecurityCheck;
    detections: VulnerabilityDetection[];
  }>;
  categoryBreakdown: Record<string, number>;
  severityBreakdown: Record<string, number>;
}

export interface VulnerabilityReportItem {
  filePath: string;
  line: number;
  codeSnippet: string;
  message: string;
  severity: string;
  remediation: string;
}