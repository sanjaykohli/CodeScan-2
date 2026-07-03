import { performSecurityAnalysis, securityChecks } from '../lib/securityAnalysis';

// Helper: run only the named check(s) so tests are isolated
function runCheck(code: string, checkName: string | string[]) {
  const names = Array.isArray(checkName) ? checkName : [checkName];
  const subset = securityChecks.filter(c => names.includes(c.name));
  return performSecurityAnalysis(code, subset);
}

// ─────────────────────────────────────────────────────────────────────────────
// Clean code
// ─────────────────────────────────────────────────────────────────────────────
describe('clean code', () => {
  it('returns score 100 and empty report for empty string', () => {
    const result = performSecurityAnalysis('', securityChecks);
    expect(result.securityScore).toBe(100);
    expect(result.report).toHaveLength(0);
    expect(result.severityLevel).toBe('Low');
  });

  it('returns score 100 and empty report for safe code', () => {
    const safe = `
      function add(a, b) {
        return a + b;
      }
      const result = add(1, 2);
    `;
    const result = performSecurityAnalysis(safe, securityChecks);
    expect(result.securityScore).toBe(100);
    expect(result.report).toHaveLength(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// CRITICAL: Remote Code Execution
// ─────────────────────────────────────────────────────────────────────────────
describe('Remote Code Execution', () => {
  it('detects eval with string concatenation', () => {
    const result = runCheck('eval("alert(" + userInput + ")")', 'Remote Code Execution');
    expect(result.report.length).toBeGreaterThan(0);
    expect(result.severityLevel).toBe('Critical');
  });

  it('detects eval with template literal', () => {
    const result = runCheck('eval(`exec(${cmd})`)', 'Remote Code Execution');
    expect(result.report.length).toBeGreaterThan(0);
  });

  it('does NOT flag eval in a comment', () => {
    const result = runCheck('// eval("dangerous")', 'Remote Code Execution');
    expect(result.report).toHaveLength(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// CRITICAL: Command Injection
// ─────────────────────────────────────────────────────────────────────────────
describe('Command Injection', () => {
  it('detects exec with template literal', () => {
    const result = runCheck('exec(`ls ${userInput}`)', 'Command Injection');
    expect(result.report.length).toBeGreaterThan(0);
    expect(result.severityLevel).toBe('Critical');
  });

  it('detects execSync with concatenation', () => {
    const result = runCheck('execSync("rm -rf " + path)', 'Command Injection');
    expect(result.report.length).toBeGreaterThan(0);
  });

  it('detects os.system with user input', () => {
    const result = runCheck('os.system("cmd " + userArg)', 'Command Injection');
    expect(result.report.length).toBeGreaterThan(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// CRITICAL: Prototype Pollution
// ─────────────────────────────────────────────────────────────────────────────
describe('Prototype Pollution', () => {
  it('detects __proto__ property access', () => {
    const result = runCheck('obj.__proto__["admin"] = true', 'Prototype Pollution');
    expect(result.report.length).toBeGreaterThan(0);
    expect(result.severityLevel).toBe('Critical');
  });

  it('detects Object.prototype dynamic assignment', () => {
    const result = runCheck('Object.prototype["polluted"] = 1', 'Prototype Pollution');
    expect(result.report.length).toBeGreaterThan(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// HIGH: SQL Injection
// ─────────────────────────────────────────────────────────────────────────────
describe('SQL Injection', () => {
  it('detects SELECT with template literal injection', () => {
    const result = runCheck(
      'db.query(`SELECT * FROM users WHERE id = ${userId}`)',
      'SQL Injection'
    );
    expect(result.report.length).toBeGreaterThan(0);
    expect(result.severityLevel).toBe('High');
  });

  it('detects DELETE with template literal', () => {
    const result = runCheck(
      'db.query(`DELETE FROM sessions WHERE token = ${tok}`)',
      'SQL Injection'
    );
    expect(result.report.length).toBeGreaterThan(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// HIGH: Sensitive Data Exposure
// ─────────────────────────────────────────────────────────────────────────────
describe('Sensitive Data Exposure', () => {
  it('detects hardcoded password', () => {
    const result = runCheck('const password = "hunter2"', 'Sensitive Data Exposure');
    expect(result.report.length).toBeGreaterThan(0);
    expect(result.severityLevel).toBe('High');
  });

  it('detects hardcoded API key', () => {
    const result = runCheck('const api_key = "sk-abc123def456"', 'Sensitive Data Exposure');
    expect(result.report.length).toBeGreaterThan(0);
  });

  it('detects hardcoded JWT secret', () => {
    const result = runCheck("const jwt = 'mysecretkey123'", 'Sensitive Data Exposure');
    expect(result.report.length).toBeGreaterThan(0);
  });

  it('does NOT flag environment variable reference', () => {
    // process.env.PASSWORD is not a string literal assignment with a value
    const result = runCheck('const token = process.env.GITHUB_TOKEN', 'Sensitive Data Exposure');
    expect(result.report).toHaveLength(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// HIGH: XSS
// ─────────────────────────────────────────────────────────────────────────────
describe('XSS Vulnerability', () => {
  it('detects innerHTML with concatenation', () => {
    const result = runCheck(
      'element.innerHTML = "<p>" + userInput + "</p>"',
      'XSS Vulnerability'
    );
    expect(result.report.length).toBeGreaterThan(0);
    expect(result.severityLevel).toBe('High');
  });

  it('detects dangerouslySetInnerHTML with template literal', () => {
    const result = runCheck(
      'dangerouslySetInnerHTML={{ __html: `<b>${userContent}</b>` }}',
      'XSS Vulnerability'
    );
    expect(result.report.length).toBeGreaterThan(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// HIGH: Weak Cryptography
// ─────────────────────────────────────────────────────────────────────────────
describe('Weak Cryptography', () => {
  it('detects MD5 usage', () => {
    const result = runCheck('const hash = createHash("md5").update(data).digest("hex")', 'Weak Cryptography');
    expect(result.report.length).toBeGreaterThan(0);
    expect(result.severityLevel).toBe('High');
  });

  it('detects SHA1 usage', () => {
    const result = runCheck('const h = SHA1(password)', 'Weak Cryptography');
    expect(result.report.length).toBeGreaterThan(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// HIGH: Path Traversal
// ─────────────────────────────────────────────────────────────────────────────
describe('Path Traversal', () => {
  it('detects readFile with concatenation', () => {
    const result = runCheck(
      'fs.readFile("/uploads/" + filename, "utf8", cb)',
      'Path Traversal'
    );
    expect(result.report.length).toBeGreaterThan(0);
    expect(result.severityLevel).toBe('High');
  });

  it('detects readFile with template literal', () => {
    const result = runCheck(
      'fs.readFileSync(`/var/data/${userPath}`)',
      'Path Traversal'
    );
    expect(result.report.length).toBeGreaterThan(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// MEDIUM: Insecure Random Values
// ─────────────────────────────────────────────────────────────────────────────
describe('Insecure Random Values', () => {
  it('detects Math.random() used as a security token', () => {
    const result = runCheck('const token = Math.random().toString(36)', 'Insecure Random Values');
    expect(result.report.length).toBeGreaterThan(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// MEDIUM: Unvalidated Redirects
// ─────────────────────────────────────────────────────────────────────────────
describe('Unvalidated Redirects', () => {
  it('detects res.redirect with user input', () => {
    const result = runCheck(
      'res.redirect(`/dashboard/${req.body.next}`)',
      'Unvalidated Redirects'
    );
    expect(result.report.length).toBeGreaterThan(0);
  });

  it('detects location.replace with concatenation', () => {
    const result = runCheck(
      'location.replace("/go?url=" + userUrl)',
      'Unvalidated Redirects'
    );
    expect(result.report.length).toBeGreaterThan(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// LOW: Debug Statements
// ─────────────────────────────────────────────────────────────────────────────
describe('Debug Statements', () => {
  it('detects console.log', () => {
    const result = runCheck('console.log("debug value:", x)', 'Debug Statements');
    expect(result.report.length).toBeGreaterThan(0);
  });

  it('detects debugger statement', () => {
    const result = runCheck('debugger', 'Debug Statements');
    expect(result.report.length).toBeGreaterThan(0);
  });

  it('does NOT flag a commented console.log', () => {
    const result = runCheck('// console.log("commented out")', 'Debug Statements');
    expect(result.report).toHaveLength(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// MEDIUM: Privacy Data Logging
// ─────────────────────────────────────────────────────────────────────────────
describe('Privacy Data Logging', () => {
  it('detects logging of email field', () => {
    const result = runCheck('console.log(user.email)', 'Privacy Data Logging');
    expect(result.report.length).toBeGreaterThan(0);
  });

  it('detects logging of password field', () => {
    const result = runCheck('console.log(req.body.password)', 'Privacy Data Logging');
    expect(result.report.length).toBeGreaterThan(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Score and severity level calculations
// ─────────────────────────────────────────────────────────────────────────────
describe('score and severity', () => {
  it('score is between 0 and 100', () => {
    const result = performSecurityAnalysis(
      'eval(userInput + "()"); const password = "abc123"',
      securityChecks
    );
    expect(result.securityScore).toBeGreaterThanOrEqual(0);
    expect(result.securityScore).toBeLessThanOrEqual(100);
  });

  it('multiple critical findings lower score below 100', () => {
    const code = [
      'eval("alert(" + x + ")")',
      'execSync("rm -rf " + path)',
      'Object.prototype["x"] = 1',
    ].join('\n');
    const result = performSecurityAnalysis(code, securityChecks);
    expect(result.securityScore).toBeLessThan(100);
    expect(result.severityLevel).toBe('Critical');
  });

  it('only low severity findings yield Low or Medium severity level', () => {
    const result = runCheck('console.log("debug")', 'Debug Statements');
    expect(['Low', 'Medium']).toContain(result.severityLevel);
  });

  it('report strings include severity, line number, and remediation', () => {
    const result = runCheck('const password = "secret123"', 'Sensitive Data Exposure');
    expect(result.report.length).toBeGreaterThan(0);
    const entry = result.report[0];
    expect(entry).toMatch(/\[HIGH\]/);
    expect(entry).toMatch(/Line \d+/);
    expect(entry).toMatch(/Remediation:/i);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// totalViolations and categoryBreakdown
// ─────────────────────────────────────────────────────────────────────────────
describe('metadata fields', () => {
  it('totalViolations equals report length', () => {
    const code = 'console.log("a"); console.log("b");';
    const result = runCheck(code, 'Debug Statements');
    expect(result.totalViolations).toBe(result.report.length);
  });

  it('categoryBreakdown sums to totalViolations', () => {
    const code = [
      'eval(x + "()")',
      'const password = "pw123"',
      'console.log("debug")',
    ].join('\n');
    const result = performSecurityAnalysis(code, securityChecks);
    const breakdownTotal = Object.values(result.categoryBreakdown ?? {}).reduce((a, b) => a + b, 0);
    expect(breakdownTotal).toBe(result.totalViolations);
  });
});
