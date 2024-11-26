import client from "../db/db.js";
import * as bcrypt from "https://deno.land/x/bcrypt/mod.ts";
import { z } from "https://deno.land/x/zod@v3.16.1/mod.ts";

// Zod schema for login validation
const loginSchema = z.object({
    username: z.string().email({ message: "Invalid email address" }),
    password: z.string().min(8, "Password must be at least 8 characters long"),
});

// Helper function to fetch the user by email
async function getUserByEmail(email) {
    const result = await client.queryArray(
        `SELECT user_token, username, password_hash FROM xyz123_users WHERE username = $1`,
        [email]
    );
    return result.rows.length > 0 ? result.rows[0] : null;
}

// Helper function to log login attempts to the database
async function logLoginAttemptToDb(userToken, ip, status) {
    try {
        await client.queryArray(
            `INSERT INTO login_logs (user_token, ip_address, login_timestamp) 
             VALUES ($1, $2, CURRENT_TIMESTAMP)`,
            [userToken || null, ip]
        );
        console.log(`Login attempt logged: User=${userToken || "Unknown"}, IP=${ip}, Status=${status}`);
    } catch (error) {
        console.error("Failed to log login attempt:", error);
    }
}

// Handle user login
export async function loginUser(c) {
    const body = await c.req.parseBody();
    const { username, password } = body;

    // Fetch client IP address
   // const clientIp = c.req.header('x-forwarded-for')?.split(',')[0].trim()
     //   || c.req.raw?.conn?.remoteAddr?.hostname
      //  || "Unknown IP";
        
        const clientIp = c.req.header('x-forwarded-for')?.split(',')[0].trim() 
        || c.req.raw?.conn?.remoteAddr?.hostname 
        || "127.0.0.1";


    try {
        // Validate the input data using Zod
        loginSchema.parse({ username, password });

        // Fetch the user by email
        const user = await getUserByEmail(username);
        if (!user) {
            await logLoginAttemptToDb(null, clientIp, "Failure: User not found");
            return c.text("Invalid email or password", 400);
        }

        const [userToken, storedUsername, storedPasswordHash] = user;

        // Compare provided password with the stored hashed password
        const passwordMatches = await bcrypt.compare(password, storedPasswordHash);
        if (!passwordMatches) {
            await logLoginAttemptToDb(userToken, clientIp, "Failure: Incorrect password");
            return c.text("Invalid email or password", 400);
        }

        // Log successful login
        await logLoginAttemptToDb(userToken, clientIp, "Success");

        // Authentication successful, redirect to the index page
        return c.redirect('/');
    } catch (error) {
        if (error instanceof z.ZodError) {
            return c.text(`Validation Error: ${error.errors.map((e) => e.message).join(", ")}`, 400);
        }
        console.error(error);
        return c.text("Error during login", 500);
    }
}
