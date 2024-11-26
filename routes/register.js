import { Hono } from "https://deno.land/x/hono/mod.ts";
import client from "../db/db.js";
import * as bcrypt from "https://deno.land/x/bcrypt/mod.ts";
import { z } from "https://deno.land/x/zod/mod.ts";

const registerRoutes = new Hono();

// Zod schema for validating registration data
const registrationSchema = z.object({
  username: z.string().email("Invalid email format"),
  password: z.string().min(8, "Password must be at least 8 characters"),
  birthdate: z.string().refine((date) => !isNaN(new Date(date).getTime()), {
    message: "Invalid birthdate format",
  }),
  role: z.enum(["reserver", "administrator"], {
    errorMap: () => ({ message: "Role must be 'reserver' or 'administrator'" }),
  }),
});

// Directory configuration
const BASE_DIR = "./views";
const allowedFiles = {
  "register": `${BASE_DIR}/register.html`,
};

// Serve the registration form
registerRoutes.get('/', async (c) => {
  const filePath = allowedFiles["register"];
  try {
    const realPath = await Deno.realPath(filePath);
    if (!realPath.startsWith(await Deno.realPath(BASE_DIR))) {
      return c.text("Access denied", 403);
    }
    return c.html(await Deno.readTextFile(realPath));
  } catch (error) {
    console.error("Error serving file:", error);
    return c.text("File not found", 404);
  }
});

// Handle user registration
registerRoutes.post('/', async (c) => {
  const body = await c.req.parseBody();
  try {
    const { username, password, birthdate, role } = registrationSchema.parse(body);

    const existingUser = await client.queryArray(
      `SELECT 1 FROM xyz123_users WHERE username = $1 LIMIT 1`,
      [username]
    );

    if (existingUser.rowCount > 0) {
      return c.text("Email is already in use. Please use a different email.", 409);
    }

    const salt = await bcrypt.genSalt(12);
    const hashedPassword = await bcrypt.hash(password, salt);

    await client.queryArray(
      `INSERT INTO xyz123_users (username, password_hash, role, birthdate)
       VALUES ($1, $2, $3, $4)`,
      [username, hashedPassword, role, birthdate]
    );

// Redirect to index page after successful registration
return c.redirect('/');
} catch (error) {
  if (error instanceof z.ZodError) {
    const errorMessage = error.errors.map((err) => err.message).join(", ");
    return c.text(`Validation failed: ${errorMessage}`, 400);
  }
  console.error(error);
  return c.text('Error during registration', 500);
}
});

export default registerRoutes;
