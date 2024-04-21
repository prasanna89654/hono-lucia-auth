import { Context, Hono } from "hono";

import { Scrypt } from "lucia";
import { UserModule } from "./user";
import { getDB } from "./db";
import { initializeLucia } from "./auth/lib";

const authRoutes = new Hono();

authRoutes.post("/signup", async (c: Context) => {
  const userModule = UserModule(getDB(c));
  const lucia = initializeLucia(c.env.DB);

  const { email, password } = await c.req.json();

  if (!email || !password) {
    return c.text("Missing email or password", 400);
  }

  const existing = await userModule.getUserByEmail(email);
  if (existing) {
    return c.text(`Invalid Email or Password`, 400);
  }

  const newUser = await userModule.createUser(email, password);

  const session = await lucia.createSession(newUser.id, {});
  const sessionCookie = lucia.createSessionCookie(session.id);
  c.header("Set-Cookie", sessionCookie.serialize(), {
    append: true,
  });
  return c.json({ message: "Signed up sucessfully" });
});

authRoutes.post("/login", async (c: Context) => {
  const { email, password } = await c.req.json();

  if (!email || !password) {
    return c.text("Missing email or password", 400);
  }

  const userModule = UserModule(c.get("db"));
  const lucia = initializeLucia(c.env.DB);

  const user = await userModule.getUserByEmail(email);

  if (!user) {
    return c.text(`Invalid Email or Password`, 400);
  }

  const scrypt = new Scrypt();
  const isValid = await scrypt.verify(user.password, password);

  if (!isValid) {
    return c.text(`Invalid Email or Password`, 400);
  }

  const session = await lucia.createSession(user.id, {});
  const sessionCookie = lucia.createSessionCookie(session.id);
  c.header("Set-Cookie", sessionCookie.serialize(), {
    append: true,
  });
  return c.json({ message: "Logged in" });
});

authRoutes.get("/logout", async (c: Context) => {
  const lucia = initializeLucia(c.env.DB);
  const session = c.get("session");

  if (session) {
    const blankSession = lucia.createBlankSessionCookie();
    c.header("Set-Cookie", blankSession.serialize(), {
      append: true,
    });
  }
  return c.json({ message: "Logged out" });
});

export default authRoutes;
