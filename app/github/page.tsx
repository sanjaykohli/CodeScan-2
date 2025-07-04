"use client";
import { useState, useMemo } from "react";
import { Github, ShieldCheck, AlertTriangle, FileWarning, Code, FileText } from "lucide-react";
import Navbar from "../components/Navbar";
import VulnerabilityCard from "../components/VulnerabilityCard";
import FileListModal from "../components/FileListModal";

interface VulnerabilityReportItem {
  filePath: string;
  line: number;
  codeSnippet: string;
  message: string;
  severity: string;
  remediation: string;
}

interface SecurityResult {
  securityScore: number;
  report: VulnerabilityReportItem[];
  severityLevel: 'Low' | 'Medium' | 'High' | 'Critical';
  vulnerabilityCount: number;
  filesScanned: number;
  scannedFiles: string[];
  repoName: string;
}

export default function GitHubPage() {
  const [repoUrl, setRepoUrl] = useState<string>("");
  const [result, setResult] = useState<SecurityResult | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [showFileList, setShowFileList] = useState<boolean>(false);
  
  // For progress indicator
  const [progress, setProgress] = useState<number>(0);
  const progressMessage = useMemo(() => {
    if (progress < 20) return "Fetching repository structure...";
    if (progress < 40) return "Scanning files...";
    if (progress < 60) return "Analyzing code patterns...";
    if (progress < 80) return "Checking security vulnerabilities...";
    return "Finalizing results...";
  }, [progress]);

  const isValidGitHubUrl = (url: string) => {
    return url.startsWith("https://github.com/") && url.split("/").length >= 5;
  };

  const handleCheck = async () => {
    if (!isValidGitHubUrl(repoUrl)) {
      setError("Please enter a valid GitHub repository URL");
      return;
    }

    setLoading(true);
    setResult(null);
    setError(null);
    setProgress(10);

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

      const data = await response.json();
      setResult(data);
      setProgress(100);
    } catch (error: any) {
      console.error("Error:", error);
      setError(error.message || "Failed to analyze repository");
      setProgress(0);
    } finally {
      setLoading(false);
      // Reset progress after a delay
      setTimeout(() => setProgress(0), 2000);
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
            />
            <button
              onClick={handleCheck}
              disabled={loading}
              className="check-security-btn"
            >
              {loading ? (
                <div className="flex items-center">
                  <span className="mr-2">Analyzing...</span>
                  <div className="spinner"></div>
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
            <div className="mt-4">
              <div className="w-full bg-gray-700 rounded-full h-2.5">
                <div 
                  className="bg-blue-600 h-2.5 rounded-full transition-all duration-300" 
                  style={{ width: `${progress}%` }}
                ></div>
              </div>
              <div className="text-sm text-gray-400 mt-2">
                {progressMessage}
              </div>
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
                <FileWarning className="results-icon" /> Security Report for: {result.repoName}
              </h3>
              <div className="summary-stats">
                <div className="stat-card">
                  <div className={`stat-value ${result.securityScore >= 80 ? 'text-green-500' : result.securityScore >= 50 ? 'text-yellow-500' : 'text-red-500'}`}>
                    {result.securityScore.toFixed(2)}%
                  </div>
                  <div className="stat-label">Security Score</div>
                </div>
                <div className="stat-card">
                  <div className="stat-value">{result.vulnerabilityCount}</div>
                  <div className="stat-label">Vulnerabilities</div>
                </div>
                <div 
                  className="stat-card cursor-pointer hover:bg-gray-800 transition-colors"
                  onClick={() => setShowFileList(true)}
                >
                  <div className="stat-value">{result.filesScanned}</div>
                  <div className="stat-label flex items-center justify-center">
                    <FileText className="mr-1" size={14} />
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
                {result.severityLevel === 'Critical' && "Immediate action required - critical vulnerabilities detected"}
                {result.severityLevel === 'High' && "High risk - urgent remediation needed"}
                {result.severityLevel === 'Medium' && "Medium risk - review recommended"}
                {result.severityLevel === 'Low' && "Low risk - maintain security best practices"}
              </div>
            </div>
            
            <div className="issues-container">
              <h4 className="flex items-center">
                <Code className="mr-2" size={20} />
                Detected Vulnerabilities:
              </h4>
              
              {result.report.length === 0 ? (
                <div className="no-issues">
                  <div className="success-icon">✓</div>
                  <p>No security vulnerabilities detected!</p>
                  <p className="subtext">Good job maintaining security best practices</p>
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