// src/pages/api/register/start.js
import { Elysia } from "elysia";
import { swagger } from "@elysiajs/swagger";
import { randomBytes } from "crypto";
import { sessions, rateLimitStore } from "../lib/storage";
import { securityMiddleware } from "../middleware/security";

const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const RATE_LIMIT_MAX = 100; // 100 requests per IP

const plugin = new Elysia()
    .decorate('plugin', 'hi')
    .get('/plugin', ({ plugin }) => plugin)

const app = new Elysia()
  .use(securityMiddleware)
  .use(plugin)
  .use(swagger({ prefix: "/api/docs" }))
  .get("/api/register/start", ({ request, cookie, set }) => {
    const ip = request.headers.get("x-forwarded-for") || "unknown";
    const now = Date.now();
    if (!rateLimitStore[ip]) {
      rateLimitStore[ip] = { count: 1, resetTime: now + RATE_LIMIT_WINDOW_MS };
    } else {
      if (now > rateLimitStore[ip].resetTime) {
        rateLimitStore[ip] = {
          count: 1,
          resetTime: now + RATE_LIMIT_WINDOW_MS,
        };
      } else if (rateLimitStore[ip].count >= RATE_LIMIT_MAX) {
        set.status = 429;
        return "Too Many Requests";
      } else {
        rateLimitStore[ip].count += 1;
      }
    }

    console.log("Session store:", sessions);
    console.log("Rate limit store:", rateLimitStore);

    const sessionToken = cookie.sessionToken?.value;
    if (!sessionToken || !isValidSession(sessionToken)) {
      set.status = 401;
      return "Unauthorized";
    }

    const challenge = randomBytes(32);
    const userId = Buffer.from("unique-user-id"); // Replace with real user ID logic
    const sessionId = crypto.randomUUID();

    sessions[sessionId] = { challenge, userId, expires: now + 600000 };

    cookie.sessionId.set({
      value: sessionId,
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      maxAge: 600,
    });

    const publicKey = {
      challenge: challenge.toString("base64"),
      rp: { name: "MyApp" },
      user: {
        id: userId,
        name: "user@example.com",
        displayName: "User Name",
      },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      timeout: 60000,
      attestation: "none",
    };
    console.log("Public Key:", publicKey);
    return publicKey;
  });

function isValidSession(token) {
  console.log("Validating session token:", token);
  return token === "valid-token"; // Replace with real logic
}

// Export handler for Astro
export const GET = (context) => app.handle(context.request);
