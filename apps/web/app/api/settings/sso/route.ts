import jwt from "jsonwebtoken";
import { headers, cookies } from "next/headers";
import { NextResponse } from "next/server";

import { getServerSession } from "@calcom/features/auth/lib/getServerSession";

import { buildLegacyRequest } from "@lib/buildLegacyCtx";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  // Require a valid Cal session
  const session = await getServerSession({
    req: buildLegacyRequest(await headers(), await cookies()),
  });

  if (!session?.user?.email) {
    // Send to login first, then resume SSO
    const cb = encodeURIComponent("/api/settings/sso");
    return NextResponse.redirect(`/auth/login?callbackUrl=${cb}`);
  }

  // Derive org id (teams or personal org)
  const orgId =
    (session.user as any).org?.id ||
    (session.user as any).profile?.organizationId ||
    `org_${session.user.id}`;

  const search = new URL(req.url).searchParams;
  const redirectPath = search.get("redirect") || "/billing";

  // HS256 shared secret
  const secret = process.env.CAL_TO_SETTINGS_SSO_SECRET || process.env.NEXTAUTH_SECRET;
  const ssoUrl = process.env.SETTINGS_SSO_URL;
  if (!secret) return NextResponse.json({ error: "Missing CAL_TO_SETTINGS_SSO_SECRET" }, { status: 500 });
  if (!ssoUrl) return NextResponse.json({ error: "Missing SETTINGS_SSO_URL" }, { status: 500 });

  // Short-lived, single-use ticket (nonce)
  const payload = {
    iss: "cal-core",
    aud: "mawaad-settings",
    sub: session.user.id,
    email: session.user.email,
    org_id: orgId,
    name: session.user.name ?? "",
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 60,
    nonce: (globalThis.crypto || crypto).randomUUID(),
  } as const;

  const token = jwt.sign(payload, secret, { algorithm: "HS256" });

  const url = new URL(ssoUrl);
  url.searchParams.set("token", token);
  url.searchParams.set("redirect", redirectPath);
  return NextResponse.redirect(url.toString());
}
