import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import * as jwt from "jose";
import { JWTExpired } from "jose/errors";

interface ExtendedRequest extends NextRequest {
  id?: string;
}

const publicPaths = ["/signin", "/signup", "/api/auth/signin", "/api/auth/signup", "/api/auth/signout", "/"];

export async function middleware(request: ExtendedRequest) {
  const path = request.nextUrl.pathname;

  if (publicPaths.includes(path)) {
    return NextResponse.next();
  }

  const token = request.cookies.get("token")?.value;
  const refreshToken = request.cookies.get("refreshToken")?.value;

  if (!token) {
    return NextResponse.redirect(new URL("/signin", request.nextUrl));
  }

  if (path === "/api/auth/refreshToken" && refreshToken) {
    return NextResponse.next();
  }

  const enc = new TextEncoder();
  const jwtSecret = process.env.JWT_SECRET;

  if (!jwtSecret) {
    console.error("JWT_SECRET is not set");
    return NextResponse.redirect(new URL("/signin", request.nextUrl));
  }

  try {
    const decoded = await jwt.jwtVerify(token, enc.encode(jwtSecret));
    request.id = decoded.payload.sub as string;
    return NextResponse.next();
  } catch (err) {
    console.error("Middleware error:", err);
    if (err instanceof JWTExpired && refreshToken) {
      return NextResponse.redirect(new URL("/api/auth/refreshToken", request.nextUrl));
    } else {
      return NextResponse.redirect(new URL("/signin", request.nextUrl));
    }
  }
}

export const config = {
  matcher: [
    "/api/:path*",
    "/Ai/:path*",
    "/game",
    "/profile",
  ],
};