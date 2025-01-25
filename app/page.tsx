"use client";
import { useState } from "react";
import { ShieldCheck, AlertTriangle, CodeIcon } from "lucide-react";
import Navbar from "./components/Navbar";

export default function Home() {
  const [code, setCode] = useState<string>("");
  const [result, setResult] = useState<{
    securityScore: number;
    report: string[];
    severityLevel: 'Low' | 'Medium' | 'High'
  } | null>(null);
  const [loading, setLoading] = useState<boolean>(false);

  const handleCheck = async () => {
    setLoading(true);
    setResult(null);
    try {
      const response = await fetch("/api/evaluate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code }),
      });

      if (!response.ok) {
        throw new Error("Error evaluating the code");
      }

      const data = await response.json();
      setResult({
        ...data,
        severityLevel:
          data.securityScore >= 80 ? 'Low' :
          data.securityScore >= 50 ? 'Medium' : 'High'
      });
    } catch (error) {
      console.error("Error:", error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="page-container">
      <Navbar />
      <div className="content-wrapper">
        <div className="code-checker-card">
          <h1 className="page-title">
            <ShieldCheck className="title-icon" /> Security Code Analyzer
          </h1>
          <textarea
            className="code-textarea"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder="Paste your code here for security analysis..."
          />
          <button
            onClick={handleCheck}
            disabled={loading}
            className="check-security-btn"
          >
            {loading ? "Analyzing..." : "Check Security"}
            <CodeIcon className="btn-icon" />
          </button>
        </div>
        {result && (
          <div className="results-card">
            <h3 className="results-title">
              <AlertTriangle className="results-icon" /> Security Analysis Results
            </h3>
            <div className="results-summary">
              <p className={`security-score ${
                result.securityScore >= 80 ? 'score-low' :
                result.securityScore >= 50 ? 'score-medium' : 'score-high'
              }`}>
                Security Score: {result.securityScore.toFixed(2)}%
              </p>
              <span className={`risk-label ${result.severityLevel.toLowerCase()}-risk`}>
                {result.severityLevel} Risk
              </span>
            </div>
            <ul className="issues-list">
              {result.report.map((issue, index) => (
                <li key={index} className="issue-item">
                  <AlertTriangle className="issue-icon" size={18} />
                  {issue}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
}