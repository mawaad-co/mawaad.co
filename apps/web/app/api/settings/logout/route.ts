import { NextResponse } from "next/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  const sso = process.env.SETTINGS_SSO_URL;
  const web = process.env.NEXT_PUBLIC_WEBAPP_URL || "http://localhost:3000";
  if (!sso) {
    return NextResponse.json({ error: "Missing SETTINGS_SSO_URL" }, { status: 500 });
  }
  const u = new URL(sso);
  u.pathname = "/api/logout"; // chain through settings logout
  const cb = new URL("/auth/login", web).toString();
  u.searchParams.set("callbackUrl", cb);
  return NextResponse.redirect(u.toString());
}
