// src/pages/api/register/start.js
import { Elysia } from "elysia";
import { swagger } from "@elysiajs/swagger";
import { randomBytes } from "crypto";
import { sessions, rateLimitStore } from "../lib/storage";
import { securityMiddleware } from "../middleware/security";

const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const RATE_LIMIT_MAX = 100; // 100 requests per IP

const plugin = new Elysia()
  .decorate("plugin", "hi")
  .get("/plugin", ({ plugin }) => plugin);

const app = new Elysia()
  .use(securityMiddleware)
  .use(plugin)
  .use(swagger({ prefix: "/api/docs" }))
  .get("/ping", () => "pong")
  .derive(({ cookie }) => {
    const sessionId = cookie.sessionId?.value;
    const sessionData = sessions[sessionId];
    const isValid = sessionData && Date.now() < sessionData.expires;
    return { session: { isValid, id: sessionId, data: sessionData } };
  })
  /**
   * @openapi
   * /api/register/start:
   *   get:
   *     description: Starts WebAuthn registration by providing public key options
   *     responses:
   *       200:
   *         description: Returns WebAuthn publicKey options
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 challenge: { type: string }
   *                 rp: { type: object }
   *                 user: { type: object }
   *       401:
   *         description: Unauthorized
   *       429:
   *         description: Too Many Requests
   */
  .get("/api/register/start", ({ request, cookie, set, session }) => {
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

    if (!session.isValid && Object.keys(sessions).length > 0) {
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

    //or
    /*
    set.headers['Set-Cookie'] = [
      `sessionId=${sessionId}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=600`,
    ];
    */

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
  })
  .post("/api/register/complete", async ({ request, body, set, session }) => {
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

    if (!session.isValid) {
      set.status = 401;
      return "Session expired or invalid";
    }

    const { id, rawId, response, type } = body;
    if (type !== "public-key") {
      set.status = 400;
      return "Invalid credential type";
    }

    const clientDataJSON = Buffer.from(
      response.clientDataJSON,
      "base64"
    ).toString("utf-8");
    const clientData = JSON.parse(clientDataJSON);
    const originalChallenge = session.data.challenge.toString("base64");

    if (clientData.challenge !== originalChallenge) {
      set.status = 400;
      return "Challenge mismatch";
    }

    if (clientData.type !== "webauthn.create") {
      set.status = 400;
      return "Invalid client data type";
    }

    if (clientData.origin !== "http://localhost:4321") {
      set.status = 400;
      return "Invalid origin";
    }

    const attestationObject = Buffer.from(response.attestationObject, "base64");

    credentials[id] = {
      userId: session.data.userId,
      publicKey: "not-extracted-yet",
      createdAt: now,
    };

    delete sessions[session.id];

    return "Registration successful";
  });

function isValidSession(token) {
  console.log("Validating session token:", token);
  return token === "valid-token"; // Replace with real logic
}

// Export handler for Astro
export const GET = (context) => app.handle(context.request);
export const POST = (context) => app.handle(context.request);

export const prerender = false;
