import { NextRequest, NextResponse } from "next/server";
import { securityChecks, performSecurityAnalysis } from "@/lib/securityAnalysis";
import { rateLimit } from "@/lib/rateLimit";

const MAX_CODE_LENGTH = 200_000; // 200 KB

export async function POST(req: NextRequest) {
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0].trim() ?? "unknown";
  const limit = rateLimit(ip, 30, 60_000); // 30 req/min per IP
  if (!limit.allowed) {
    return NextResponse.json(
      { error: "Too many requests. Please wait a moment before trying again." },
      { status: 429, headers: { "Retry-After": String(Math.ceil(limit.resetInMs / 1000)) } }
    );
  }

  try {
    const body = await req.json();
    const { code } = body;

    if (!code || typeof code !== "string") {
      return NextResponse.json(
        { error: "Code is required and must be a string." },
        { status: 400 }
      );
    }

    if (code.length > MAX_CODE_LENGTH) {
      return NextResponse.json(
        { error: `Code must be under ${MAX_CODE_LENGTH / 1000} KB. Please split your code into smaller sections.` },
        { status: 413 }
      );
    }

    return NextResponse.json(performSecurityAnalysis(code, securityChecks));
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : "Failed to process security analysis";
    console.error("Evaluate error:", message);
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
