"use client";
import { useState } from "react";
import { Github, ShieldCheck, AlertTriangle, FileWarning, Code, FileText } from "lucide-react";
import Navbar from "../components/Navbar";
import VulnerabilityCard from "../components/VulnerabilityCard";
import FileListModal from "../components/FileListModal";
import type { GitHubScanResult } from "@/types";

export default function GitHubPage() {
  const [repoUrl, setRepoUrl] = useState<string>("");
  const [result, setResult] = useState<GitHubScanResult | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [showFileList, setShowFileList] = useState<boolean>(false);

  const isValidGitHubUrl = (url: string) => {
    return url.startsWith("https://github.com/") && url.split("/").length >= 5;
  };

  const handleCheck = async () => {
    if (!isValidGitHubUrl(repoUrl)) {
      setError("Please enter a valid GitHub repository URL (https://github.com/owner/repo)");
      return;
    }

    setLoading(true);
    setResult(null);
    setError(null);

    try {
      const response = await fetch("/api/github", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repoUrl }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || "Error analyzing repository");
      }

      const data: GitHubScanResult = await response.json();
      setResult(data);
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Failed to analyze repository";
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="page-container">
      <Navbar />
      <div className="content-wrapper">
        <div className="github-checker-card">
          <h1 className="page-title">
            <Github className="title-icon" /> GitHub Repository Security Scan
          </h1>

          <div className="input-group">
            <input
              type="url"
              className="repo-input"
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
              placeholder="https://github.com/username/repository"
              disabled={loading}
              onKeyDown={(e) => e.key === "Enter" && !loading && handleCheck()}
            />
            <button
              onClick={handleCheck}
              disabled={loading}
              className="check-security-btn"
            >
              {loading ? (
                <div className="flex items-center">
                  <div className="spinner mr-2"></div>
                  <span>Scanning...</span>
                </div>
              ) : (
                <>
                  Scan Repository
                  <ShieldCheck className="btn-icon" />
                </>
              )}
            </button>
          </div>

          {loading && (
            <div className="scan-progress">
              <div className="scan-progress-bar">
                <div className="scan-progress-fill"></div>
              </div>
              <p className="scan-progress-text">
                Fetching and analyzing repository files — this may take a moment for large repos...
              </p>
            </div>
          )}

          {error && (
            <div className="error-message">
              <AlertTriangle className="error-icon" />
              {error}
            </div>
          )}

          <div className="instructions">
            <p>Enter a public GitHub repository URL to scan for security vulnerabilities</p>
            <p>Example: https://github.com/facebook/react</p>
          </div>
        </div>

        {result && (
          <div className="results-card">
            <div className="results-header">
              <h3 className="results-title">
                <FileWarning className="results-icon" /> Security Report: {result.repoName}
              </h3>
              <div className="summary-stats">
                <div className="stat-card">
                  <div className={`stat-value ${
                    result.securityScore >= 80 ? 'score-low' :
                    result.securityScore >= 50 ? 'score-medium' : 'score-high'
                  }`}>
                    {result.securityScore.toFixed(2)}%
                  </div>
                  <div className="stat-label">Security Score</div>
                </div>
                <div className="stat-card">
                  <div className="stat-value">{result.vulnerabilityCount}</div>
                  <div className="stat-label">Vulnerabilities</div>
                </div>
                <div
                  className="stat-card stat-card-clickable"
                  onClick={() => setShowFileList(true)}
                  title="Click to see all scanned files"
                >
                  <div className="stat-value">{result.filesScanned}</div>
                  <div className="stat-label">
                    <FileText size={14} className="stat-label-icon" />
                    Files Scanned
                  </div>
                </div>
              </div>
            </div>

            <div className="severity-summary">
              <span className={`risk-label ${result.severityLevel.toLowerCase()}-risk`}>
                {result.severityLevel} Risk
              </span>
              <div className="severity-description">
                {result.severityLevel === 'Critical' && "Immediate action required — critical vulnerabilities detected"}
                {result.severityLevel === 'High' && "High risk — urgent remediation needed"}
                {result.severityLevel === 'Medium' && "Medium risk — review and remediation recommended"}
                {result.severityLevel === 'Low' && "Low risk — maintain security best practices"}
              </div>
            </div>

            <div className="issues-container">
              <h4 className="vulnerabilities-heading">
                <Code size={20} />
                Detected Vulnerabilities
              </h4>

              {result.report.length === 0 ? (
                <div className="no-issues">
                  <div className="success-icon">✓</div>
                  <p>No security vulnerabilities detected!</p>
                  <p className="subtext">Great job maintaining security best practices</p>
                </div>
              ) : (
                <div className="vulnerabilities-grid">
                  {result.report.map((item, index) => (
                    <VulnerabilityCard
                      key={index}
                      filePath={item.filePath}
                      line={item.line}
                      codeSnippet={item.codeSnippet}
                      message={item.message}
                      severity={item.severity}
                      remediation={item.remediation}
                    />
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {result && (
          <FileListModal
            files={result.scannedFiles}
            isOpen={showFileList}
            onClose={() => setShowFileList(false)}
          />
        )}
      </div>
    </div>
  );
}
