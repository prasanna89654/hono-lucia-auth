import { initializeLucia } from "./auth/lib";
import { verifyRequestOrigin } from "lucia";
import { getCookie } from "hono/cookie";
import { DrizzleD1Database } from "drizzle-orm/d1";
import { MiddlewareHandler } from "hono";
import type { Context } from "./types";
import * as schema from "./db/schema";

type Handler = MiddlewareHandler<Context>;
export type DrizzleDB = DrizzleD1Database<typeof schema>;

export const csrf = (): Handler => {
  return async (c, next) => {
    if (c.req.method === "GET") {
      return next();
    }
    const originHeader = c.req.header("Origin");
    const hostHeader = c.req.header("Host");
    if (
      !originHeader ||
      !hostHeader ||
      !verifyRequestOrigin(originHeader, [hostHeader])
    ) {
      return c.body(null, 403);
    }
    return next();
  };
};

export const validateRequest = (): Handler => {
  return async (c, next) => {
    const lucia = initializeLucia(c.env.DB);
    const sessionId = getCookie(c, lucia.sessionCookieName) ?? null;

    if (!sessionId) {
      c.set("user", null);
      c.set("session", null);
      return next();
    }

    const { session, user } = await lucia.validateSession(sessionId);

    if (session && session.fresh) {
      c.header(
        "Set-Cookie",
        lucia.createSessionCookie(session.id).serialize(),
        {
          append: true,
        },
      );
    }

    if (!session) {
      c.header("Set-Cookie", lucia.createBlankSessionCookie().serialize(), {
        append: true,
      });
    }

    c.set("user", user);
    c.set("session", session);

    return next();
  };
};


