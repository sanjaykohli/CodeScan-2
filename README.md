# CodeScan

A static security analysis tool for code snippets and GitHub repositories. Instant vulnerability detection, security scoring, and remediation guidance — no AI API key required.

> Built with the assistance of [Claude Sonnet 4.5](https://www.anthropic.com/claude) by Anthropic.

---

## Features

### Code Analyzer (`/`)
- Paste any code snippet and get an instant security report
- Line-level findings with the matched pattern highlighted
- Security score from 0–100
- Risk level: **Critical / High / Medium / Low**
- Remediation guidance for every finding

### GitHub Repository Scanner (`/github`)
- Scan any public GitHub repository by URL
- Fetches the full file tree in a single API call (Git Trees API)
- Downloads and analyses files in parallel batches
- **Score blending**: 60% average score + 40% worst-file score — so one critical file isn't buried by a large clean codebase
- Click **Files Scanned** to browse every file that was analysed
- Severity derived from both the numeric score and the highest-severity finding

### Security Checks (`/info`)
21 checks across 4 severity levels:

| Severity | Checks |
|---|---|
| 🔴 Critical | Remote Code Execution, Command Injection, Prototype Pollution |
| 🟠 High | SQL Injection, NoSQL Injection, XSS, Weak Cryptography, Path Traversal, Sensitive Data Exposure, ReDoS |
| 🟡 Medium | Insecure Deserialization, Insecure Random Values, CSRF, SSRF, Unvalidated Redirects, JWT Insecure Usage, Privacy Data Logging |
| 🟢 Low | Debug Statements, Insecure Cookie Config, Outdated Package References, Inefficient React Patterns |

Click any check card to see a plain-English explanation, common code examples, and a step-by-step fix guide.

### Technical highlights
- **No AI dependency** — pure regex-based static analysis, runs entirely server-side
- **Rate limiting** — 30 req/min on code scans, 10 req/min on repo scans (per IP)
- **Input validation** — 200 KB code limit, 500 KB per-file limit for GitHub scans
- **SSRF protection** — owner/repo names validated against `[A-Za-z0-9_.-]+`
- **Responsive design** — works on mobile, tablet, and desktop

---

## Local Setup

### Prerequisites

| Requirement | Version |
|---|---|
| Node.js | 18+ |
| npm | 9+ |
| GitHub Personal Access Token | Only for `/github` scanner |

### 1 — Clone the repository

```bash
git clone https://github.com/sanjaykohli/CodeScan-2.git
cd CodeScan-2
```

### 2 — Install dependencies

```bash
npm install
```

### 3 — Configure environment variables

```bash
cp .env.example .env.local
```

Open `.env.local` and paste your GitHub token:

```
GITHUB_TOKEN=ghp_your_token_here
```

**How to get a GitHub token:**
1. Go to [github.com/settings/tokens](https://github.com/settings/tokens)
2. Click **Generate new token (classic)**
3. Name it `codescan-local`
4. Check the `repo` scope (read-only access is enough for public repos)
5. Click **Generate token** and copy the result

> The code analyzer (`/`) works without a token. Only the GitHub scanner (`/github`) requires one.

### 4 — Start the development server

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

### 5 — (Optional) Run the test suite

```bash
npm test
```

36 unit tests covering every security check — positive detection, false-positive suppression, score calculation, and metadata fields.

---

## Project Structure

```
app/
  page.tsx              # Code analyzer UI
  github/page.tsx       # GitHub scanner UI
  info/page.tsx         # Security checks reference
  layout.tsx            # Root HTML layout
  globals.css           # All styles (custom CSS, no Tailwind required)
  api/
    evaluate/route.ts   # POST /api/evaluate — code analysis
    github/route.ts     # POST /api/github   — repo scan
  components/
    Navbar.tsx          # Top navigation with active-state highlighting
    VulnerabilityCard.tsx
    FileListModal.tsx
lib/
  securityAnalysis.ts   # Core engine + all 21 security checks
  rateLimit.ts          # In-memory sliding-window rate limiter
types.d.ts              # Shared TypeScript interfaces
__tests__/
  securityAnalysis.test.ts
public/
  favicon.svg
```

---

## Contributing

Contributions are welcome. Please open an issue first to discuss what you'd like to change.

### Adding a new security check

All checks live in `lib/securityAnalysis.ts` in the `securityChecks` array:

```ts
{
  name: "Check Name",
  regex: /your-pattern/i,
  message: "Human-readable description",
  severity: 'critical' | 'high' | 'medium' | 'low',
  category: 'security' | 'performance' | 'best-practices',
  impact: 10,            // higher = worse; affects score calculation
  remediation: "How to fix it.",
  falsePositivePatterns: [/pattern-to-suppress/]  // optional
}
```

Add a corresponding test in `__tests__/securityAnalysis.test.ts`, then run `npm test` to verify.

---

## Limitations

- **Static analysis only** — regex-based; dynamic bugs (race conditions, logic flaws) are not detected
- **Public repositories only** — private repos need a token with the appropriate scope
- **False positives** — some patterns may flag code inside comments or strings; common cases are suppressed
- **In-memory rate limiting** — resets on server restart; replace with Redis (`@upstash/ratelimit`) for production

---

## Tech Stack

- [Next.js 15](https://nextjs.org/) (App Router, Turbopack)
- [TypeScript 5](https://www.typescriptlang.org/)
- [React 19](https://react.dev/)
- [@octokit/rest](https://github.com/octokit/rest.js) — GitHub API
- [lucide-react](https://lucide.dev/) — icons
- [Jest](https://jestjs.io/) + [ts-jest](https://kulshekhar.github.io/ts-jest/) — testing

---

## License

MIT — see [LICENSE](LICENSE).

---

*Built with the assistance of [Claude Sonnet 4.5](https://www.anthropic.com/claude) by Anthropic.*
