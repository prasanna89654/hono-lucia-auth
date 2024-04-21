import { csrf, validateRequest } from "./middleware";
import authRoutes from "./routes";
import { Context } from "./types";
import { Hono } from "hono";

const app = new Hono<Context>();

app.use("*", csrf());
app.use("*", validateRequest());
app.get("/", (c) => c.json({ message: "Hello, World!" }));
app.route("/auth", authRoutes);

export default app;
