import { NextRequest, NextResponse } from "next/server";
import { Octokit } from "@octokit/rest";
import { securityChecks, performSecurityAnalysis } from "@/lib/securityAnalysis";
import { rateLimit } from "@/lib/rateLimit";
import type { VulnerabilityReportItem } from "@/types";

const CODE_FILE_EXTENSIONS = /\.(js|jsx|ts|tsx|py|java|cpp|c|go|rb|php|html|css|scss|less|json|yml|yaml|xml|md|sh|config)$/i;
const MAX_FILE_SIZE_BYTES = 500_000; // 500 KB
const BATCH_SIZE = 5;
const SAFE_NAME_REGEX = /^[A-Za-z0-9_.-]+$/;

export async function POST(req: NextRequest) {
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0].trim() ?? "unknown";
  const limit = rateLimit(ip, 10, 60_000); // 10 repo scans/min per IP
  if (!limit.allowed) {
    return NextResponse.json(
      { error: "Too many scan requests. Please wait before scanning again." },
      { status: 429, headers: { "Retry-After": String(Math.ceil(limit.resetInMs / 1000)) } }
    );
  }

  if (!process.env.GITHUB_TOKEN) {
    return NextResponse.json(
      { error: "GitHub token is not configured. Set GITHUB_TOKEN in your .env.local file." },
      { status: 503 }
    );
  }

  const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });

  try {
    const body = await req.json();
    const { repoUrl } = body;

    if (!repoUrl || typeof repoUrl !== "string") {
      return NextResponse.json({ error: "Repository URL is required" }, { status: 400 });
    }

    // Parse and validate GitHub URL
    const match = repoUrl.match(/github\.com\/([^\/]+)\/([^\/]+?)(?:\.git)?(\/|$)/i);
    if (!match) {
      return NextResponse.json(
        { error: "Invalid GitHub URL. Expected format: https://github.com/owner/repo" },
        { status: 400 }
      );
    }

    const owner = match[1];
    const repo = match[2];

    // Validate safe characters to prevent injection
    if (!SAFE_NAME_REGEX.test(owner) || !SAFE_NAME_REGEX.test(repo)) {
      return NextResponse.json(
        { error: "Repository owner or name contains invalid characters." },
        { status: 400 }
      );
    }

    // Fetch entire file tree in a single API call (much faster than recursive getContent)
    let treeData;
    try {
      const { data } = await octokit.git.getTree({
        owner,
        repo,
        tree_sha: "HEAD",
        recursive: "1",
      });
      treeData = data;
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Unknown error";
      if (message.includes("Not Found")) {
        return NextResponse.json(
          { error: `Repository ${owner}/${repo} not found or is private.` },
          { status: 404 }
        );
      }
      throw err;
    }

    // Filter to supported code files under the size limit
    const codeFiles = (treeData.tree || []).filter(
      (item) =>
        item.type === "blob" &&
        CODE_FILE_EXTENSIONS.test(item.path ?? "") &&
        (item.size ?? 0) <= MAX_FILE_SIZE_BYTES
    );

    const skippedLargeFiles = (treeData.tree || []).filter(
      (item) =>
        item.type === "blob" &&
        CODE_FILE_EXTENSIONS.test(item.path ?? "") &&
        (item.size ?? 0) > MAX_FILE_SIZE_BYTES
    ).length;

    const scannedFiles: string[] = [];
    const report: VulnerabilityReportItem[] = [];
    let vulnerabilityCount = 0;
    const fileScores: number[] = [];
    let fetchErrorCount = 0;

    // Process files in batches
    for (let i = 0; i < codeFiles.length; i += BATCH_SIZE) {
      const batch = codeFiles.slice(i, i + BATCH_SIZE);
      const batchResults = await Promise.all(
        batch.map(async (file) => {
          const filePath = file.path ?? "";
          try {
            const { data: fileData } = await octokit.repos.getContent({
              owner,
              repo,
              path: filePath,
            });

            // getContent returns an array for directories; skip those
            if (Array.isArray(fileData) || fileData.type !== "file" || !fileData.content) {
              return null;
            }

            // content is always base64-encoded in the standard response
            const fileContent = Buffer.from(fileData.content, "base64").toString("utf-8");

            const analysis = performSecurityAnalysis(fileContent, securityChecks);
            const vulnerabilities: VulnerabilityReportItem[] = [];

            analysis.vulnerabilities.forEach((vuln) => {
              vuln.detections.forEach((detection) => {
                vulnerabilities.push({
                  filePath,
                  line: detection.line,
                  codeSnippet: detection.lineContent,
                  message: `${vuln.check.message}: ${detection.matchedPattern}`,
                  severity: vuln.check.severity,
                  remediation: vuln.check.remediation,
                });
              });
            });

            scannedFiles.push(filePath);
            return { securityScore: analysis.securityScore, vulnerabilities };
          } catch (err) {
            fetchErrorCount++;
            console.error(`Failed to fetch ${filePath}:`, err instanceof Error ? err.message : err);
            return null;
          }
        })
      );

      for (const result of batchResults) {
        if (result === null) continue;
        fileScores.push(result.securityScore);
        report.push(...result.vulnerabilities);
        vulnerabilityCount += result.vulnerabilities.length;
      }
    }

    if (fileScores.length === 0) {
      const reason = codeFiles.length === 0
        ? "No scannable files found in this repository."
        : `All ${codeFiles.length} file(s) failed to download (${fetchErrorCount} fetch error(s)).`;
      return NextResponse.json({ error: reason }, { status: 422 });
    }

    // Score: weight toward the worst file so a single critical vuln isn't buried
    const avgScore = fileScores.reduce((a, b) => a + b, 0) / fileScores.length;
    const worstScore = Math.min(...fileScores);
    // Blend: 60% average + 40% worst file, floor at 0
    const securityScore = Math.max(0, Math.min(100, Math.round(avgScore * 0.6 + worstScore * 0.4)));

    // Determine severity from score AND highest-severity finding
    const highestFindingSeverity = report.reduce((acc, item) => {
      const order: Record<string, number> = { low: 1, medium: 2, high: 3, critical: 4 };
      return (order[item.severity] ?? 0) > (order[acc] ?? 0) ? item.severity : acc;
    }, "low");

    let severityLevel: "Low" | "Medium" | "High" | "Critical" = "Low";
    if (highestFindingSeverity === "critical" || securityScore < 40) severityLevel = "Critical";
    else if (highestFindingSeverity === "high" || securityScore < 60) severityLevel = "High";
    else if (highestFindingSeverity === "medium" || securityScore < 80) severityLevel = "Medium";

    return NextResponse.json({
      securityScore,
      report,
      severityLevel,
      vulnerabilityCount,
      filesScanned: scannedFiles.length,
      skippedLargeFiles,
      scannedFiles,
      repoName: `${owner}/${repo}`,
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : "Failed to process repository";
    console.error("GitHub scan error:", message);
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
