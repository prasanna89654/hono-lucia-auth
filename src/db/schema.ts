import { integer, sqliteTable, text } from "drizzle-orm/sqlite-core";

export const user = sqliteTable("user", {
  id: text("id").primaryKey(),
  email: text("email").notNull(),
  password: text("password").notNull(),
});

export const session = sqliteTable("session", {
  id: text("id").primaryKey(),
  expires_at: integer("expires_at").notNull(),
  user_id: integer("user_id")
    .notNull()
    .references(() => user.id),
  fresh: integer("fresh", { mode: "boolean" }),
});

