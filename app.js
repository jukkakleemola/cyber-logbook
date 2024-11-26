import { Hono } from "https://deno.land/x/hono/mod.ts";
import { loginUser } from "./routes/login.js"; // Import login logic
import { serveStatic } from "https://deno.land/x/hono/middleware.ts";
import registerRoutes from "./routes/register.js";

const app = new Hono();

// Middleware to set security headers globally
app.use(async (c, next) => {
  // Set security headers
  c.header("Content-Security-Policy", 
    "default-src 'self'; " +
    "script-src 'self'; " +
    "style-src 'self'; " +
    "img-src 'self'; " +
    "frame-ancestors 'none'; " +
    "form-action 'self';"); // Allow form submissions only to your domain

  c.header("X-Frame-Options", "DENY"); // Prevent Clickjacking
  c.header("X-Content-Type-Options", "nosniff"); // Prevent MIME type sniffing

  await next();
});

// Serve static files from "static" directory
app.use('/static/*', serveStatic({ root: '.' }));

// Register routes from the routes file
app.route('/register', registerRoutes);

// Serve login page
app.get('/login', async (c) => {
  return c.html(await Deno.readTextFile('./views/login.html')); // Use the login.html file
});

// Handle user login
app.post('/login', loginUser);

// Serve the index page
app.get('/', async (c) => {
  return c.html(await Deno.readTextFile('./views/index.html'));
});

// Start the app
Deno.serve(app.fetch);
