const express   = require("express");
const cors      = require("cors");
const mongoose  = require("mongoose");
const bcrypt    = require("bcryptjs");
const jwt       = require("jsonwebtoken");
const { Resend } = require("resend");
require("dotenv").config();

const app    = express();
const PORT   = process.env.PORT || 5000;
const resend = new Resend(process.env.RESEND_API_KEY);

// ── Middleware ────────────────────────────────────────────────────
app.use(cors({
  origin: [
    "http://localhost:5173",           // local dev
    "https://apex-home-stores.vercel.app", // your Vercel frontend
  ]
}));
app.use(express.json());

// ── Connect to MongoDB ────────────────────────────────────────────
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch(err => console.error("❌ MongoDB error:", err));

// ════════════════════════════════════════════════════════════════
// MODELS — these define the shape of data in your database
// Think of a Model like a template for every document stored
// ════════════════════════════════════════════════════════════════

// ── User Model ───────────────────────────────────────────────────
// This defines what a user looks like in the database.
// mongoose.Schema() is like saying "every user MUST have these fields"
const UserSchema = new mongoose.Schema({
  name:      { type: String, required: true, trim: true },
  email:     { type: String, required: true, unique: true, lowercase: true, trim: true },
  password:  { type: String, required: true, minlength: 6 },
  createdAt: { type: Date, default: Date.now },
});

// Before saving a user, hash their password
// "pre save" is a Mongoose hook — runs automatically before .save() is called
// bcrypt.hash(password, 10) — the 10 is the "salt rounds" (how hard to crack)
// NEVER store plain text passwords — if your database is ever leaked,
// hashed passwords cannot be reversed back to the original
UserSchema.pre("save", async function () {
  if (!this.isModified("password")) return; // Just return, don't call next()
  
  this.password = await bcrypt.hash(this.password, 10);
  // No next() call needed here for async hooks!
});

const User = mongoose.model("User", UserSchema);

// ── Order Model ──────────────────────────────────────────────────
const OrderSchema = new mongoose.Schema({
  userId:      { type: mongoose.Schema.Types.ObjectId, ref: "User" }, // links to a User
  orderNumber: { type: String, required: true },
  items:       [{ name: String, price: Number, quantity: Number, image: String }],
  total:       { type: Number, required: true },
  delivery:    { type: String },
  address:     { type: String },
  city:        { type: String },
  postcode:    { type: String },
  paystackRef: { type: String }, // Paystack payment reference
  status:      { type: String, default: "confirmed" },
  createdAt:   { type: Date, default: Date.now },
});

const Order = mongoose.model("Order", OrderSchema);

// ════════════════════════════════════════════════════════════════
// MIDDLEWARE — auth guard
// This function runs BEFORE protected routes
// It checks the request has a valid JWT token
// If not, it blocks the request with a 401 error
// ════════════════════════════════════════════════════════════════
function requireAuth(req, res, next) {
  // JWT tokens are sent in the "Authorization" header as "Bearer <token>"
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Not authenticated" });
  }

  const token = authHeader.split(" ")[1];

  try {
    // jwt.verify() decodes the token and checks it was signed with our secret
    // If the token was tampered with or expired, it throws an error
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId; // attach userId to the request for use in the route
    next(); // token is valid — continue to the route handler
  } catch (err) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}

// ════════════════════════════════════════════════════════════════
// ROUTES
// ════════════════════════════════════════════════════════════════

// ── Health check ─────────────────────────────────────────────────
app.get("/api/health", (req, res) => {
  res.json({ status: "Apex Backend running ✅" });
});

// ── REGISTER ─────────────────────────────────────────────────────
// POST /api/auth/register
// Body: { name, email, password }
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Basic validation
    if (!name || !email || !password) {
      return res.status(400).json({ message: "All fields are required." });
    }
    if (password.length < 6) {
      return res.status(400).json({ message: "Password must be at least 6 characters." });
    }

    // Check if email already exists in database
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "An account with this email already exists." });
    }

    // Create and save user — password gets hashed by the pre-save hook above
    const user = new User({ name, email, password });
    await user.save();

    // Create a JWT token — this is what the user will send with every request
    // to prove they're logged in. It expires in 7 days.
    // jwt.sign(payload, secret, options)
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });

    // Send welcome email via Resend
    // This runs async — we don't wait for it before responding
    // so a slow email doesn't delay the user's registration
    try {
  await resend.emails.send({
    from: "Apex Home Furnishings <onboarding@resend.dev>",
    to:   email,
    subject: "Welcome to Apex Home Furnishings 🛋️",
    html: `
      <div style="font-family: Georgia, serif; max-width: 560px; margin: 0 auto;">
        <div style="background-color: #8b7355; padding: 24px; text-align: center;">
          <h1 style="color: white; margin: 0;">Apex Home Furnishings</h1>
        </div>
        <div style="padding: 32px; background: #f9f6f2;">
          <h2>Welcome, ${name}! 🎉</h2>
          <p style="color: #5a5550; line-height: 1.7;">
            Your account has been created. You can now shop our full collection,
            track orders, and enjoy faster checkout.
          </p>
          <a href="http://localhost:5173/shop"
            style="display: inline-block; margin-top: 20px; padding: 14px 32px;
            background-color: #8b7355; color: white; text-decoration: none;
            font-weight: 700;">
            START SHOPPING
          </a>
        </div>
      </div>
    `,
  });
} catch (emailErr) {
  // Email failed — log it but DON'T crash the registration
  console.error("Welcome email failed:", emailErr.message);
}

    // Respond with the token and user info
    // The frontend stores this token and sends it with future requests
    res.status(201).json({
      token,
      user: { id: user._id, name: user.name, email: user.email },
    });

  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ message: "Server error. Please try again." });
  }
});

// ── LOGIN ─────────────────────────────────────────────────────────
// POST /api/auth/login
// Body: { email, password }
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required." });
    }

    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      // Use a vague message — never confirm whether an email exists
      return res.status(401).json({ message: "Incorrect email or password." });
    }

    // Compare the entered password against the stored hash
    // bcrypt.compare() hashes the plain text and compares — it NEVER decrypts
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Incorrect email or password." });
    }

    // Issue a new token
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });

    res.json({
      token,
      user: { id: user._id, name: user.name, email: user.email },
    });

  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Server error. Please try again." });
  }
});

// ── GET CURRENT USER ──────────────────────────────────────────────
// GET /api/auth/me
// Protected — requires a valid JWT token in the Authorization header
// React calls this on app load to check if the saved token is still valid
app.get("/api/auth/me", requireAuth, async (req, res) => {
  try {
    // req.userId was set by requireAuth middleware
    const user = await User.findById(req.userId).select("-password"); // exclude password
    if (!user) return res.status(404).json({ message: "User not found." });
    res.json({ user: { id: user._id, name: user.name, email: user.email } });
  } catch (err) {
    res.status(500).json({ message: "Server error." });
  }
});

// ── SAVE ORDER ────────────────────────────────────────────────────
// POST /api/orders
// Protected — user must be logged in to save an order
app.post("/api/orders", requireAuth, async (req, res) => {
  try {
    const { orderNumber, items, total, delivery, address, city, postcode, paystackRef } = req.body;

    const order = new Order({
      userId:      req.userId,
      orderNumber,
      items,
      total,
      delivery,
      address,
      city,
      postcode,
      paystackRef,
    });

    await order.save();
    res.status(201).json({ order });

  } catch (err) {
    console.error("Save order error:", err);
    res.status(500).json({ message: "Could not save order." });
  }
});

// ── GET MY ORDERS ─────────────────────────────────────────────────
// GET /api/orders
// Protected — returns all orders for the logged-in user
app.get("/api/orders", requireAuth, async (req, res) => {
  try {
    const orders = await Order.find({ userId: req.userId }).sort({ createdAt: -1 });
    res.json({ orders });
  } catch (err) {
    res.status(500).json({ message: "Could not fetch orders." });
  }
});

// ── VERIFY PAYSTACK PAYMENT ───────────────────────────────────────
// POST /api/verify-payment
// Body: { reference }
// This is the secure server-side verification step.
// Your SECRET key never leaves this file — React never sees it.
app.post("/api/verify-payment", requireAuth, async (req, res) => {
  try {
    const { reference } = req.body;
    if (!reference) return res.status(400).json({ message: "Reference required." });

    // Call Paystack's verify endpoint using your SECRET key
    const response = await fetch(
      `https://api.paystack.co/transaction/verify/${reference}`,
      {
        headers: {
          Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
        },
      }
    );

    const data = await response.json();

    if (data.status && data.data.status === "success") {
      res.json({ verified: true, amount: data.data.amount, reference });
    } else {
      res.json({ verified: false, message: "Payment not confirmed." });
    }

  } catch (err) {
    console.error("Payment verify error:", err);
    res.status(500).json({ message: "Could not verify payment." });
  }
});

// ── VERIFY EMAIL IS REAL ──────────────────────────────────────────
// GET /api/verify-email?email=test@gmail.com
// We do this on the backend so our Abstract API key stays secret
app.get("/api/verify-email", async (req, res) => {
  try {
    const { email } = req.query;
    if (!email) return res.status(400).json({ valid: false });

    const response = await fetch(
      `https://emailvalidation.abstractapi.com/v1/?api_key=${process.env.ABSTRACT_API_KEY}&email=${encodeURIComponent(email)}`
    );
    const data = await response.json();

    // Abstract API returns:
    // deliverability: "DELIVERABLE" | "UNDELIVERABLE" | "UNKNOWN"
    // is_valid_format.value: true/false
    // is_disposable_email.value: true/false (catches temp mail services)
    const isReal = (
      data.deliverability === "DELIVERABLE" &&
      data.is_valid_format?.value === true &&
      data.is_disposable_email?.value === false
    );

    res.json({
      valid: isReal,
      reason: !data.is_valid_format?.value    ? "Invalid email format."           :
              data.is_disposable_email?.value ? "Disposable emails are not allowed." :
              data.deliverability !== "DELIVERABLE" ? "This email address does not exist." :
              "Valid",
    });

  } catch (err) {
    console.error("Email verify error:", err);
    // If the API fails, don't block registration — just allow it
    res.json({ valid: true, reason: "Could not verify" });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});

