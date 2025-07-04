import { NextResponse } from "next/server";
import { securityChecks, performSecurityAnalysis } from "@/lib/securityAnalysis";

export async function POST(req: Request) {
  try {
    const body = await req.json();
    const { code } = body;

    if (!code || typeof code !== 'string') {
      return NextResponse.json({
        error: "Code is required for evaluation and must be a string.",
        securityScore: 0,
        report: ["No valid code provided for analysis."]
      }, { status: 400 });
    }

    return NextResponse.json(performSecurityAnalysis(code, securityChecks), { status: 200 });
  } catch (error) {
    console.error("Error processing request:", error);
    return NextResponse.json({
      error: "Failed to process security analysis",
      securityScore: 0,
      report: ["Error encountered during analysis."]
    }, { status: 500 });
  }
}