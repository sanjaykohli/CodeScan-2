import { NextRequest, NextResponse } from "next/server";
import { Octokit } from "@octokit/rest";
import { securityChecks, performSecurityAnalysis } from "@/lib/securityAnalysis";
import { VulnerabilityReportItem } from "@/types";

const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });

// Recursive function to get all files in repository
const getAllFiles = async (owner: string, repo: string, path = ""): Promise<any[]> => {
  try {
    const { data: contents } = await octokit.repos.getContent({
      owner,
      repo,
      path
    });

    if (!Array.isArray(contents)) {
      return [];
    }

    const files: any[] = [];
    const directories: any[] = [];

    // Separate files and directories
    for (const item of contents) {
      if (item.type === "file") {
        files.push(item);
      } else if (item.type === "dir") {
        directories.push(item);
      }
    }

    // Recursively process directories
    for (const directory of directories) {
      const subFiles = await getAllFiles(owner, repo, directory.path);
      files.push(...subFiles);
    }

    return files;
  } catch (error) {
    console.error(`Error processing directory ${path}:`, error);
    return [];
  }
};

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { repoUrl } = body;

    if (!repoUrl || typeof repoUrl !== 'string') {
      return NextResponse.json({
        error: "Repository URL is required",
        securityScore: 0,
        report: ["No valid repository URL provided"]
      }, { status: 400 });
    }

    // Parse GitHub URL
    const match = repoUrl.match(/github\.com\/([^\/]+)\/([^\/]+)(\/|$)/i);
    if (!match) {
      return NextResponse.json({
        error: "Invalid GitHub URL format",
        securityScore: 0,
        report: ["URL must be in format: https://github.com/owner/repo"]
      }, { status: 400 });
    }

    const owner = match[1];
    const repo = match[2];
    
    // Get all files recursively
    const allFiles = await getAllFiles(owner, repo);
    
    // Filter for code files
    const codeFiles = allFiles.filter(
      item => /\.(js|jsx|ts|tsx|py|java|cpp|c|go|rb|php|html|css|scss|less|json|yml|yaml|xml|md|sh|env|config)$/i.test(item.name)
    );

    console.log(`Found ${codeFiles.length} code files to analyze in ${owner}/${repo}`);

    // Analyze each file
    let totalSecurityScore = 0;
    const report: VulnerabilityReportItem[] = [];
    let vulnerabilityCount = 0;
    let filesScanned = 0;
    const scannedFiles: string[] = [];

    // Process files in batches
    const BATCH_SIZE = 5;
    for (let i = 0; i < codeFiles.length; i += BATCH_SIZE) {
      const batch = codeFiles.slice(i, i + BATCH_SIZE);
      const batchResults = await Promise.all(
        batch.map(async (file) => {
          try {
            const { data: fileContent } = await octokit.repos.getContent({
              owner,
              repo,
              path: file.path,
              mediaType: { format: "raw" }
            });
            
            const code = fileContent as unknown as string;
            const analysis = performSecurityAnalysis(code, securityChecks);
            
            const vulnerabilities: VulnerabilityReportItem[] = [];
            analysis.vulnerabilities.forEach(vuln => {
              vuln.detections.forEach(detection => {
                vulnerabilities.push({
                  filePath: file.path,
                  line: detection.line,
                  codeSnippet: detection.lineContent,
                  message: `${vuln.check.message}: ${detection.context || detection.matchedPattern}`,
                  severity: vuln.check.severity,
                  remediation: vuln.check.remediation
                });
              });
            });
            
            // Add to scanned files list
            scannedFiles.push(file.path);
            
            return {
              securityScore: analysis.securityScore,
              vulnerabilities,
              count: vulnerabilities.length
            };
          } catch (error) {
            console.error(`Error processing file ${file.path}:`, error);
            scannedFiles.push(file.path); // Still count as scanned
            return {
              securityScore: 100, // Perfect score if error
              vulnerabilities: [],
              count: 0
            };
          }
        })
      );

      // Aggregate batch results
      batchResults.forEach(result => {
        totalSecurityScore += result.securityScore;
        report.push(...result.vulnerabilities);
        vulnerabilityCount += result.count;
        filesScanned++;
      });
    }

    // Calculate overall score
    const securityScore = filesScanned > 0 
      ? Math.max(0, Math.min(100, totalSecurityScore / filesScanned))
      : 100; // No code files = perfect score

    // Determine severity level
    let severityLevel: 'Low' | 'Medium' | 'High' | 'Critical' = 'Low';
    if (securityScore < 40) severityLevel = 'Critical';
    else if (securityScore < 60) severityLevel = 'High';
    else if (securityScore < 80) severityLevel = 'Medium';

    return NextResponse.json({
      securityScore,
      report,
      severityLevel,
      vulnerabilityCount,
      filesScanned: scannedFiles.length,
      scannedFiles, // Return the list of scanned files
      repoName: `${owner}/${repo}`
    }, { status: 200 });
    
  } catch (error) {
    console.error("Error processing request:", error);
    return NextResponse.json({
      error: "Failed to process repository analysis",
      securityScore: 0,
      report: ["Error encountered during analysis"]
    }, { status: 500 });
  }
}