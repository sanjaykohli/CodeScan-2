"use client";
import { useState } from "react";
import { ShieldCheck, AlertTriangle, Code as CodeIcon, FileWarning, CheckCircle2, Zap } from "lucide-react";
import Navbar from "./components/Navbar";
import type { CodeScanResult } from "@/types";

export default function Home() {
  const [code, setCode] = useState<string>("");
  const [result, setResult] = useState<CodeScanResult | null>(null);
  const [loading, setLoading] = useState<boolean>(false);

  const handleCheck = async () => {
    if (!code.trim()) return;
    setLoading(true);
    setResult(null);
    try {
      const response = await fetch("/api/evaluate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code }),
      });
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || "Error evaluating the code");
      }
      const data: CodeScanResult = await response.json();
      setResult(data);
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Failed to analyze code. Please try again.";
      setResult({ securityScore: 0, report: [message], severityLevel: "High" });
    } finally {
      setLoading(false);
    }
  };

  const scoreColor =
    result && result.securityScore >= 80
      ? "score-low"
      : result && result.securityScore >= 50
      ? "score-medium"
      : "score-high";

  return (
    <div className="page-container">
      <Navbar />
      <div className="content-wrapper">

        {/* Hero */}
        <div className="hero">
          <div className="hero-badge">
            <Zap size={13} />
            Static Analysis · No AI Required
          </div>
          <h1 className="hero-title">Analyze your code for<br />security vulnerabilities</h1>
          <p className="hero-sub">Paste any snippet and get an instant security score, line-level findings, and remediation guidance.</p>
        </div>

        {/* Scanner */}
        <div className="scanner-card">
          <textarea
            className="code-textarea"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder="// Paste your code here…&#10;// Supports JS, TS, Python, Java, Go, PHP, and more"
            rows={12}
          />
          <div className="scanner-footer">
            <span className="char-count">{code.length.toLocaleString()} chars</span>
            <button onClick={handleCheck} disabled={loading || !code.trim()} className="scan-btn">
              {loading ? (
                <>
                  <div className="spinner" />
                  Analyzing…
                </>
              ) : (
                <>
                  <ShieldCheck size={16} />
                  Check Security
                </>
              )}
            </button>
          </div>
        </div>

        {/* Results */}
        {result && (
          <div className="results-card">
            <div className="results-header">
              <h3 className="results-title">
                <FileWarning size={18} className="results-icon" />
                Security Analysis
              </h3>
              <div className="score-block">
                <span className={`score-value ${scoreColor}`}>{result.securityScore.toFixed(0)}%</span>
                <span className={`risk-label ${result.severityLevel.toLowerCase()}-risk`}>
                  {result.severityLevel} Risk
                </span>
              </div>
            </div>

            <div className="score-bar-wrap">
              <div
                className={`score-bar-fill ${scoreColor}`}
                style={{ width: `${result.securityScore}%` }}
              />
            </div>

            <div className="issues-container">
              {result.report.length === 0 ? (
                <div className="no-issues">
                  <CheckCircle2 size={32} className="success-icon" />
                  <p>No vulnerabilities detected</p>
                  <p className="subtext">Your code looks clean — keep following security best practices.</p>
                </div>
              ) : (
                <ul className="issues-list">
                  {result.report.map((issue, index) => (
                    <li key={index} className="issue-item">
                      <AlertTriangle size={16} className="issue-icon" />
                      <pre className="issue-details">{issue}</pre>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
