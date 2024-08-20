import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import * as jwt from "jose";

interface ExtendedRequest extends NextRequest {
  id?: string;
}

const publicPaths = ["/signin", "/signup", "/api/auth/signin", "/api/auth/signup", "/api/auth/signout", "/"];

export async function middleware(request: ExtendedRequest) {
  const path = request.nextUrl.pathname;
  console.log("middleware called with path:", path);

  if (publicPaths.includes(path)) {
    return NextResponse.next();
  }

  const token = request.cookies.get("token")?.value;
  const refreshToken = request.cookies.get("refreshToken")?.value;

  if (!token) {
    return NextResponse.redirect(new URL("/signin", request.url));
  }

  if (path === "/api/auth/refreshToken" && refreshToken) {
    return NextResponse.next();
  }

  const enc = new TextEncoder();
  const jwtSecret = process.env.JWT_SECRET;

  if (!jwtSecret) {
    console.error("JWT_SECRET is not set");
    return NextResponse.redirect(new URL("/signin", request.url));
  }

  try {
    const decoded = await jwt.jwtVerify(token, enc.encode(jwtSecret));
    request.id = decoded.payload.sub as string;
    return NextResponse.next();
  } catch (err) {
    console.error("Middleware error:", err);
    if (err instanceof jwt.errors.JWTExpired && refreshToken) {
      return NextResponse.redirect(new URL("/api/auth/refreshToken", request.url));
    } else {
      return NextResponse.redirect(new URL("/signin", request.url));
    }
  }
}

export const config = {
  matcher: [
    "/api/:path*",
    "/profile",
    "/game",
    "/Ai/:path*",
  ],
};