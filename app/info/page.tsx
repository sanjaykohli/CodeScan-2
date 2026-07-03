"use client";
import { useState, useEffect, useCallback } from "react";
import {
  ShieldAlert, AlertTriangle, Lock, Code2, Database, Globe, Key,
  FileWarning, X, Terminal, Shield, Cookie, RefreshCw, Clock,
  Server, Eye, Wifi, Zap, Bug, Package
} from "lucide-react";
import Navbar from "../components/Navbar";
import { LucideIcon } from "lucide-react";

interface SecurityParameter {
  title: string;
  description: string;
  icon: LucideIcon;
  severity: "Critical" | "High" | "Medium" | "Low";
  impact: string;
  commonExamples: string[];
  simpleExplanation: string;
  whatCanHappen: string[];
  howToFix: string[];
}

const SEVERITY_CONFIG = {
  Critical: { color: "critical", label: "Critical" },
  High:     { color: "high",     label: "High" },
  Medium:   { color: "medium",   label: "Medium" },
  Low:      { color: "low",      label: "Low" },
} as const;

const securityParameters: SecurityParameter[] = [
  {
    title: "Remote Code Execution", description: "Prevents hackers from running arbitrary code on your system",
    icon: Code2, severity: "Critical", impact: "Complete system compromise",
    commonExamples: ["eval('user_input')", "setTimeout(userCode, 1000)", "new Function(code_string)"],
    simpleExplanation: "Like accidentally handing a stranger the keys to your server — they can run anything they want.",
    whatCanHappen: ["Attackers can execute arbitrary code on your server", "Sensitive data can be stolen or destroyed", "Your system can be used to attack others", "Complete system takeover is possible"],
    howToFix: ["Never pass user input to eval() or new Function()", "Use JSON.parse() instead of eval() for data", "Whitelist allowed operations strictly", "Sandbox untrusted code execution"]
  },
  {
    title: "Command Injection", description: "Stops attackers from executing system-level commands",
    icon: Terminal, severity: "Critical", impact: "System command execution",
    commonExamples: ["exec('rm -rf ' + userInput)", "spawn('cat', userFile)", "child_process.exec(cmd + userInput)"],
    simpleExplanation: "Like letting a visitor type commands directly into your computer's terminal.",
    whatCanHappen: ["Attackers can run any OS command", "Files can be deleted or exfiltrated", "Malware can be installed", "Full system compromise"],
    howToFix: ["Use command argument arrays, not strings", "Never concatenate user input into shell commands", "Validate all input against a strict allowlist", "Run processes with minimal privileges"]
  },
  {
    title: "Prototype Pollution", description: "Prevents modification of JavaScript's object prototype chain",
    icon: Shield, severity: "Critical", impact: "Application-wide behaviour corruption",
    commonExamples: ["Object.assign(target, userInput)", "obj.__proto__ = maliciousObj", "constructor.prototype.isAdmin = true"],
    simpleExplanation: "Like changing the fundamental rules of how your entire application works, affecting every object.",
    whatCanHappen: ["All objects in the app can be affected", "Security checks can be silently bypassed", "Application logic can be corrupted", "Privilege escalation becomes possible"],
    howToFix: ["Freeze prototypes with Object.freeze()", "Use Object.create(null) for safe data containers", "Validate all incoming object keys", "Avoid dynamic property assignment from user data"]
  },
  {
    title: "SQL Injection", description: "Prevents attackers from manipulating database queries",
    icon: Database, severity: "High", impact: "Database breach and data theft",
    commonExamples: ["'SELECT * FROM users WHERE id = ' + id", "db.query(`DELETE FROM t WHERE id = ${id}`)", "'UPDATE users SET name = ' + name"],
    simpleExplanation: "Like someone altering your shopping list while you aren't watching — they can add, remove, or read anything.",
    whatCanHappen: ["All database records can be read", "Data can be deleted or modified", "Authentication can be bypassed", "Entire database can be dumped"],
    howToFix: ["Use parameterized queries or prepared statements", "Never interpolate user input into SQL strings", "Use an ORM with built-in sanitization", "Validate and type-check all inputs"]
  },
  {
    title: "NoSQL Injection", description: "Protects NoSQL databases from malicious query manipulation",
    icon: Database, severity: "High", impact: "Database manipulation and data theft",
    commonExamples: ["db.find({name: userInput})", "collection.update({id: `${userId}`})", "Model.aggregate([{$match: userQuery}])"],
    simpleExplanation: "The same risk as SQL injection, but targeting modern NoSQL databases like MongoDB.",
    whatCanHappen: ["Unauthorised access to records", "Data can be modified or deleted", "Authentication mechanisms bypassed", "Sensitive information exposed"],
    howToFix: ["Use typed parameterized values in queries", "Validate input types and structures", "Use ORM sanitization features", "Reject unexpected query operators ($where, $gt, etc.)"]
  },
  {
    title: "Sensitive Data Exposure", description: "Detects hardcoded passwords, tokens, and private keys",
    icon: Lock, severity: "High", impact: "Credential theft and privacy breach",
    commonExamples: ["const API_KEY = 'abc123'", "password = 'secret123'", "private_key = 'ssh-rsa...'"],
    simpleExplanation: "Like posting your house key on social media — anyone who sees your code gets access.",
    whatCanHappen: ["API keys and tokens can be stolen", "Accounts can be taken over", "Private services can be accessed", "Secrets committed to repos are permanently exposed"],
    howToFix: ["Use environment variables (.env.local)", "Never commit secrets to version control", "Use secret managers (Vault, AWS Secrets Manager)", "Rotate any key that has been exposed"]
  },
  {
    title: "Cross-Site Scripting (XSS)", description: "Prevents malicious scripts from being injected into your pages",
    icon: Globe, severity: "High", impact: "User session hijacking and data theft",
    commonExamples: ["element.innerHTML = userInput", "document.write(data)", "<div dangerouslySetInnerHTML={{__html: input}}>"],
    simpleExplanation: "Like a fake sign in a store that tricks customers into handing over their credit card details.",
    whatCanHappen: ["User login sessions can be stolen", "Attackers can impersonate users", "Browser-stored data can be exfiltrated", "Malicious scripts run in victims' browsers"],
    howToFix: ["Use textContent instead of innerHTML", "Sanitize with DOMPurify before rendering HTML", "Enable a strict Content Security Policy", "Use framework-provided safe rendering (React JSX)"]
  },
  {
    title: "Weak Cryptography", description: "Flags outdated algorithms that provide inadequate protection",
    icon: Key, severity: "High", impact: "Data protection failure",
    commonExamples: ["md5(password)", "crypto.createHash('sha1')", "crypto.createCipher('des', key)"],
    simpleExplanation: "Like using a cheap padlock that can be picked in seconds — the lock exists, but provides no real security.",
    whatCanHappen: ["Hashed passwords can be cracked quickly", "Encrypted data can be decrypted", "Secure communications can be intercepted", "Compliance requirements violated"],
    howToFix: ["Use SHA-256 or SHA-3 for hashing", "Use AES-256-GCM for encryption", "Use bcrypt/argon2 for password storage", "Keep cryptographic libraries updated"]
  },
  {
    title: "Path Traversal", description: "Prevents attackers from escaping your intended file directory",
    icon: FileWarning, severity: "High", impact: "Unauthorized file system access",
    commonExamples: ["fs.readFile('../../../etc/passwd')", "fs.writeFile(userPath + '/file.txt')", "require('../../config.js')"],
    simpleExplanation: "Like someone using maintenance corridors to access restricted areas they were never meant to enter.",
    whatCanHappen: ["System config files can be read", "Private files can be stolen", "Sensitive credentials can be exposed", "Application source code can be leaked"],
    howToFix: ["Use path.resolve() and verify the result stays within your allowed root", "Validate all file paths against an allowlist", "Reject paths containing '..' sequences", "Run file operations with least-privilege accounts"]
  },
  {
    title: "Regular Expression DoS", description: "Detects catastrophically backtracking regex patterns",
    icon: Clock, severity: "High", impact: "Service unavailability",
    commonExamples: ["/(a+)+$/", "/([a-zA-Z]+)*$/", "/(a|a)*$/"],
    simpleExplanation: "Like a puzzle so complex that solving it takes forever, freezing everything else.",
    whatCanHappen: ["One request can stall the entire server", "CPU resources can be exhausted", "Legitimate users get denied service", "Application becomes unresponsive under load"],
    howToFix: ["Avoid nested quantifiers (e.g. (a+)+)", "Use a regex validator/linter before deploying", "Set timeouts on regex operations", "Use simpler, linear-time patterns"]
  },
  {
    title: "Insecure Deserialization", description: "Flags unsafe parsing of untrusted data",
    icon: ShieldAlert, severity: "Medium", impact: "Remote code execution risk",
    commonExamples: ["JSON.parse(untrustedData)", "eval('(' + data + ')')", "unserialize(userInput)"],
    simpleExplanation: "Like accepting a parcel without scanning it — the contents could be dangerous.",
    whatCanHappen: ["Malicious code can be embedded in data", "Application state can be corrupted", "Authentication can be bypassed", "Server can be fully compromised"],
    howToFix: ["Validate data schema before parsing (joi, zod, yup)", "Sanitize and type-check all external data", "Never pass deserialized data to code execution functions", "Use allowlists for expected data shapes"]
  },
  {
    title: "Insecure Random Values", description: "Ensures cryptographically secure random number generation",
    icon: Zap, severity: "Medium", impact: "Predictable security tokens",
    commonExamples: ["Math.random()", "new Date().getTime()", "Math.floor(Math.random() * 1000)"],
    simpleExplanation: "Like a broken lottery machine that always picks the same predictable numbers.",
    whatCanHappen: ["Security tokens can be guessed", "Session IDs can be predicted", "Password reset links can be brute-forced", "Authentication can be bypassed"],
    howToFix: ["Use crypto.randomBytes() in Node.js", "Use window.crypto.getRandomValues() in browsers", "Never use Math.random() for security-sensitive values", "Use UUID v4 for session identifiers"]
  },
  {
    title: "CSRF Vulnerability", description: "Prevents cross-site request forgery attacks",
    icon: Wifi, severity: "Medium", impact: "Unauthorized actions on behalf of users",
    commonExamples: ["fetch('/api/transfer', {method: 'POST'})", "axios.post('/delete-account')", "form submit without CSRF token"],
    simpleExplanation: "Like someone tricking you into signing a document while you're distracted.",
    whatCanHappen: ["Actions performed without user consent", "Account settings silently changed", "Funds or data can be transferred", "Users can be logged out or locked out"],
    howToFix: ["Include CSRF tokens in all state-changing requests", "Use SameSite=Strict cookie attribute", "Implement proper CORS policies", "Validate the Origin and Referer headers"]
  },
  {
    title: "Server-Side Request Forgery", description: "Prevents your server from making unauthorized outbound requests",
    icon: Server, severity: "Medium", impact: "Internal network and metadata access",
    commonExamples: ["fetch(userProvidedURL)", "axios.get(externalURL)", "http.request({url: userInput})"],
    simpleExplanation: "Like tricking a receptionist into making phone calls to restricted internal extensions.",
    whatCanHappen: ["Internal services can be probed", "Cloud provider metadata (AWS keys) can be stolen", "Internal network topology can be mapped", "Sensitive internal data can leak"],
    howToFix: ["Validate and parse all URLs before fetching", "Maintain a strict allowlist of permitted domains", "Block requests to private IP ranges (169.254.x.x, 10.x.x.x)", "Use an outbound proxy with filtering"]
  },
  {
    title: "Unvalidated Redirects", description: "Prevents phishing via open redirect vulnerabilities",
    icon: RefreshCw, severity: "Medium", impact: "Phishing and credential theft",
    commonExamples: ["res.redirect(req.query.next)", "window.location = userURL", "location.href = redirectURL"],
    simpleExplanation: "Like someone swapping the road signs so you end up at the wrong destination.",
    whatCanHappen: ["Users redirected to malicious phishing sites", "Credentials stolen via fake login pages", "Brand reputation damaged", "OAuth tokens intercepted"],
    howToFix: ["Validate redirect URLs against a strict allowlist", "Use relative paths where possible", "Show a confirmation page for external redirects", "Never use raw user input as a redirect target"]
  },
  {
    title: "JWT Insecure Usage", description: "Flags weak JWT signing algorithms and missing verification",
    icon: Key, severity: "Medium", impact: "Authentication bypass",
    commonExamples: ["jwt.sign(payload, '', {algorithm: 'none'})", "jwt.decode(token) // no verification", "jwt.verify with weak HS256 secret"],
    simpleExplanation: "Like using a security badge that anyone can photocopy and forge.",
    whatCanHappen: ["Authentication can be completely bypassed", "Tokens can be forged to impersonate any user", "Admin privileges can be self-granted", "Sessions can never truly expire"],
    howToFix: ["Use RS256 or ES256 (asymmetric algorithms)", "Always call jwt.verify(), never just jwt.decode()", "Set short expiration times and rotate keys", "Reject tokens with algorithm 'none'"]
  },
  {
    title: "Privacy Data Logging", description: "Prevents personal information from appearing in log files",
    icon: Eye, severity: "Medium", impact: "Privacy violation and data exposure",
    commonExamples: ["console.log(user.email)", "logger.info('Password: ' + password)", "print(user.creditCard)"],
    simpleExplanation: "Like accidentally writing everyone's secrets in a publicly accessible notebook.",
    whatCanHappen: ["PII exposed in log aggregation platforms", "GDPR/CCPA compliance violations", "User trust eroded", "Legal liability increased"],
    howToFix: ["Mask or omit sensitive fields before logging", "Use structured logging with field-level filtering", "Audit your log outputs regularly", "Follow data minimization principles"]
  },
  {
    title: "Debug Information Leaks", description: "Removes development artifacts before production deployment",
    icon: Bug, severity: "Low", impact: "Information disclosure",
    commonExamples: ["console.log(sensitiveData)", "alert(debug_info)", "debugger; // left in production"],
    simpleExplanation: "Like leaving your security blueprint where visitors can see it.",
    whatCanHappen: ["System internals revealed to attackers", "Error messages disclose stack traces", "Attack surface becomes easier to map", "Performance impacted in production"],
    howToFix: ["Strip all console.log statements before deploying", "Use a linter rule to catch debug code", "Implement structured error handling", "Configure production error pages without stack traces"]
  },
  {
    title: "Insecure Cookie Configuration", description: "Ensures cookies have the correct security attributes set",
    icon: Cookie, severity: "Low", impact: "Session hijacking risk",
    commonExamples: ["document.cookie = 'session=' + id", "res.cookie('auth', token)", "cookies.set('user', data)"],
    simpleExplanation: "Like leaving a 'take me' label on your lunchbox — anyone who walks past can grab it.",
    whatCanHappen: ["Cookies stolen over non-HTTPS connections", "JavaScript can read session cookies (XSS amplification)", "Cross-site attacks more likely to succeed", "User sessions hijacked"],
    howToFix: ["Set the Secure flag (HTTPS-only transmission)", "Set HttpOnly to block JavaScript access", "Set SameSite=Strict or Lax", "Use the __Host- or __Secure- cookie prefixes"]
  },
  {
    title: "Outdated Package Reference", description: "Identifies known-vulnerable library versions in source code",
    icon: Package, severity: "Low", impact: "Known vulnerability exposure",
    commonExamples: ["jquery@1.x", "lodash@3.x", "moment@2.x"],
    simpleExplanation: "Like using an old lock model with a published break-in technique.",
    whatCanHappen: ["Known CVEs can be exploited", "Security patches from newer versions are missing", "Compatibility issues can emerge", "Dependency audits flag the project"],
    howToFix: ["Run npm audit / yarn audit regularly", "Update to the latest stable versions", "Use Dependabot or Renovate for automated updates", "Consider replacing unmaintained libraries"]
  },
  {
    title: "Inefficient React Patterns", description: "Detects missing dependency arrays and unnecessary re-renders",
    icon: RefreshCw, severity: "Low", impact: "Performance degradation",
    commonExamples: ["useEffect(() => {}, [])", "useEffect(() => fetchData())", "componentDidUpdate() without condition checks"],
    simpleExplanation: "Like leaving all the lights on in every room — wasteful and eventually problematic.",
    whatCanHappen: ["Application slows down under load", "Unnecessary API calls are made", "Memory usage climbs over time", "User experience degrades"],
    howToFix: ["Always provide a dependency array to useEffect", "Wrap expensive computations in useMemo", "Use React.memo for pure child components", "Profile with React DevTools before optimizing"]
  },
];

const SEVERITY_ORDER: Array<"Critical" | "High" | "Medium" | "Low"> = ["Critical", "High", "Medium", "Low"];

const Info = () => {
  const [selected, setSelected] = useState<SecurityParameter | null>(null);

  const closeModal = useCallback(() => setSelected(null), []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") closeModal(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [closeModal]);

  const grouped = SEVERITY_ORDER.reduce((acc, sev) => {
    acc[sev] = securityParameters.filter(p => p.severity === sev);
    return acc;
  }, {} as Record<string, SecurityParameter[]>);

  const counts = SEVERITY_ORDER.map(s => ({ label: s, n: grouped[s].length, color: SEVERITY_CONFIG[s].color }));

  return (
    <div className="page-container">
      <Navbar />
      <div className="content-wrapper">

        {/* Header */}
        <div className="info-header">
          <h1 className="page-title">
            <ShieldAlert className="title-icon" /> Security Checks
          </h1>
          <p className="info-description">
            {securityParameters.length} checks across four severity levels. Click any card for details, examples, and remediation steps.
          </p>
          <div className="vuln-stats-row">
            {counts.map(({ label, n, color }) => (
              <div key={label} className={`vuln-stat-chip ${color}`}>
                <span className="vuln-stat-num">{n}</span>
                <span className="vuln-stat-label">{label}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Sections by severity */}
        {SEVERITY_ORDER.map((severity) => (
          <section key={severity} className="vuln-section">
            <div className={`section-heading ${SEVERITY_CONFIG[severity].color}`}>
              {severity === "Critical" && <AlertTriangle size={16} />}
              {severity === "High"     && <ShieldAlert size={16} />}
              {severity === "Medium"   && <AlertTriangle size={16} />}
              {severity === "Low"      && <Shield size={16} />}
              {severity}
            </div>
            <div className="vuln-grid">
              {grouped[severity].map((param) => (
                <button
                  key={param.title}
                  className="vuln-card"
                  onClick={() => setSelected(param)}
                  type="button"
                >
                  <div className="vuln-card-top">
                    <div className={`vuln-icon-wrap ${SEVERITY_CONFIG[severity].color}`}>
                      <param.icon size={18} />
                    </div>
                    <span className={`severity-pill ${SEVERITY_CONFIG[severity].color}`}>
                      {severity}
                    </span>
                  </div>
                  <h3 className="vuln-card-title">{param.title}</h3>
                  <p className="vuln-card-desc">{param.description}</p>
                  <span className="vuln-card-link">View details →</span>
                </button>
              ))}
            </div>
          </section>
        ))}
      </div>

      {/* Modal */}
      {selected && (
        <div className="modal-overlay" onClick={closeModal}>
          <div className="modal-box" onClick={(e) => e.stopPropagation()}>
            <div className="modal-top">
              <div className="modal-title-row">
                <div className={`vuln-icon-wrap ${SEVERITY_CONFIG[selected.severity].color}`}>
                  <selected.icon size={18} />
                </div>
                <div>
                  <h2 className="modal-title">{selected.title}</h2>
                  <span className={`severity-pill ${SEVERITY_CONFIG[selected.severity].color}`}>
                    {selected.severity} Risk
                  </span>
                </div>
              </div>
              <button className="modal-close" onClick={closeModal} aria-label="Close">
                <X size={20} />
              </button>
            </div>

            <div className="modal-body">
              <p className="modal-explanation">{selected.simpleExplanation}</p>

              <div className="modal-section">
                <h4 className="modal-section-title">What can happen</h4>
                <ul className="modal-list">
                  {selected.whatCanHappen.map((item, i) => (
                    <li key={i}>{item}</li>
                  ))}
                </ul>
              </div>

              <div className="modal-section">
                <h4 className="modal-section-title">Common patterns</h4>
                <div className="modal-code-list">
                  {selected.commonExamples.map((ex, i) => (
                    <code key={i} className="modal-code">{ex}</code>
                  ))}
                </div>
              </div>

              <div className="modal-section">
                <h4 className="modal-section-title">How to fix</h4>
                <ul className="modal-list fix-list">
                  {selected.howToFix.map((fix, i) => (
                    <li key={i}>{fix}</li>
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
