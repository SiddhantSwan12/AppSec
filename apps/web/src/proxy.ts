import { NextResponse, type NextRequest } from "next/server";

/**
 * Content-Security-Policy for the wallet interface (SW-10).
 *
 * React escaping is the primary control against stored XSS; this is the second
 * layer that decides what a successful injection would be able to do. A fresh
 * nonce per response lets Next.js's own inline hydration scripts run while an
 * injected `<script>` tag does not, and `strict-dynamic` lets the nonced bundle
 * load its own chunks without allowlisting hosts.
 *
 * Two deliberate relaxations, both confined to directives that cannot execute:
 * - `style-src 'unsafe-inline'`: React and Next.js set inline *style
 *   attributes*, and a style attribute cannot carry a nonce — only a `<style>`
 *   element can. Nonce-ing this directive blocks the application's own layout
 *   while stopping no attacker, so the strictness stays where execution
 *   happens, in `script-src`.
 * - `'unsafe-eval'` in development only, where React uses eval to rebuild
 *   server error stacks. Production responses omit it.
 */
export function proxy(request: NextRequest) {
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");
  const development = process.env.NODE_ENV === "development";
  const policy = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${development ? " 'unsafe-eval'" : ""}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' blob: data:",
    "font-src 'self'",
    "connect-src 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "object-src 'none'",
    "worker-src 'self'",
    // Local development is plain HTTP by design, so the upgrade directive would
    // break the demo. A deployment over HTTPS should carry it.
    ...(development ? [] : ["upgrade-insecure-requests"]),
  ].join("; ");

  // Next.js reads the nonce back out of the request-side policy to stamp its
  // own tags, so the header is set on both the request and the response.
  const headers = new Headers(request.headers);
  headers.set("x-nonce", nonce);
  headers.set("Content-Security-Policy", policy);
  const response = NextResponse.next({ request: { headers } });
  response.headers.set("Content-Security-Policy", policy);
  return response;
}

export const config = {
  // /api is proxied to Express, which sets its own headers through helmet.
  // Static assets carry no script surface of their own.
  matcher: ["/((?!api|_next/static|_next/image|favicon.ico).*)"],
};
