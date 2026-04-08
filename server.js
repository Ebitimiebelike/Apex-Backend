const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Resend } = require("resend");
const crypto = require("crypto");

require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 5000;
const resend = new Resend(process.env.RESEND_API_KEY);

// ── Middleware ────────────────────────────────────────────────────
app.use(cors({
  origin: (origin, cb) => {
    const allowed =
      !origin ||
      origin === "http://localhost:5173" ||
      origin === "https://apex-home-stores.vercel.app" ||
      /^https:\/\/apex-home-stores.*\.vercel\.app$/.test(origin);

    if (allowed) return cb(null, true);
    return cb(new Error("Not allowed by CORS"));
  },
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));
app.use(express.json());

// ── Connect to MongoDB ────────────────────────────────────────────
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ MongoDB error:", err));

// ── Helpers ─────────────────────────────────────────────────────────
function sha256(str) {
  return crypto.createHash("sha256").update(str).digest("hex");
}

// ════════════════════════════════════════════════════════════════
// MODELS
// ════════════════════════════════════════════════════════════════

// ── User Model ───────────────────────────────────────────────────
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },

  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
  },

  password: { type: String, required: true, minlength: 6 },

  createdAt: { type: Date, default: Date.now },

  // NEW: Email verification fields
  isVerified: { type: Boolean, default: false },

  emailVerificationTokenHash: { type: String },
  emailVerificationExpires: { type: Date },
});

// Hash password before save
UserSchema.pre("save", async function () {
  if (!this.isModified("password")) return;
  this.password = await bcrypt.hash(this.password, 10);
});

const User = mongoose.model("User", UserSchema);

// ── Order Model ──────────────────────────────────────────────────
const OrderSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  orderNumber: { type: String, required: true },
  items: [{ name: String, price: Number, quantity: Number, image: String }],
  total: { type: Number, required: true },
  delivery: { type: String },
  address: { type: String },
  city: { type: String },
  postcode: { type: String },
  paystackRef: { type: String },
  status: { type: String, default: "confirmed" },
  createdAt: { type: Date, default: Date.now },
});

const Order = mongoose.model("Order", OrderSchema);

// ════════════════════════════════════════════════════════════════
// AUTH MIDDLEWARE
// ════════════════════════════════════════════════════════════════
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Not authenticated" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}

// ════════════════════════════════════════════════════════════════
// ROUTES
// ════════════════════════════════════════════════════════════════

// Health check
app.get("/api/health", (req, res) => {
  res.json({ status: "Apex Backend running ✅" });
});

// ── REGISTER (send verification link) ─────────────────────────────
// POST /api/auth/register
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ message: "All fields are required." });
    }
    if (password.length < 6) {
      return res
        .status(400)
        .json({ message: "Password must be at least 6 characters." });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res
        .status(400)
        .json({ message: "An account with this email already exists." });
    }

    // Create user as NOT verified yet
    const user = new User({ name, email, password, isVerified: false });

    // Create verification token
    const verificationToken = crypto.randomBytes(32).toString("hex");
    user.emailVerificationTokenHash = sha256(verificationToken);
    user.emailVerificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24h

    await user.save();

    // Need frontend URL to build verification link
    const FRONTEND_URL = process.env.FRONTEND_URL;
    if (!FRONTEND_URL) {
      // cleanup created user if misconfigured
      await User.findByIdAndDelete(user._id).catch(() => {});
      return res.status(500).json({ message: "FRONTEND_URL is not configured." });
    }

    const verificationLink = `${FRONTEND_URL}/verify-email?token=${encodeURIComponent(
      verificationToken
    )}`;

    // Send email via Resend
    try {
      await resend.emails.send({
        from: "Apex Home Furnishings <onboarding@resend.dev>",
        to: email,
        subject: "Verify your Apex Home account",
        html: `
          <div style="font-family: Georgia, serif; max-width: 560px; margin: 0 auto;">
            <div style="background-color: #8b7355; padding: 24px; text-align: center;">
              <h1 style="color: white; margin: 0; font-size: 22px;">Apex Home Furnishings</h1>
            </div>

            <div style="padding: 32px; background: #f9f6f2;">
              <h2 style="margin-top: 0;">Welcome, ${name}! 🎉</h2>
              <p style="color: #5a5550; line-height: 1.7;">
                Please verify your email to activate your account.
              </p>

              <a href="${verificationLink}"
                 style="display:inline-block;margin-top: 18px;padding: 14px 28px;
                        background-color:#8b7355;color:white;text-decoration:none;
                        font-weight:700;border-radius:6px;">
                Verify Email
              </a>

              <p style="color:#777; font-size: 12px; margin-top: 16px;">
                This link expires in 24 hours.
              </p>
            </div>
          </div>
        `,
      });
    } catch (emailErr) {
      console.error("Verification email failed:", emailErr.message);
      // cleanup created user so they can re-register
      await User.findByIdAndDelete(user._id).catch(() => {});
      return res.status(500).json({ message: "Could not send verification email." });
    }

    // IMPORTANT: no JWT token here
    return res.status(201).json({
      message: "Verification email sent. Please check your inbox to activate your account.",
    });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ message: "Server error. Please try again." });
  }
});

// ── VERIFY EMAIL ───────────────────────────────────────────────────
// GET /api/auth/verify-email?token=...
app.get("/api/auth/verify-email", async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) return res.status(400).json({ message: "Token is required." });

    const tokenHash = sha256(token);

    const user = await User.findOne({
      emailVerificationTokenHash: tokenHash,
    });

    if (!user) return res.status(400).json({ message: "Invalid token." });

    if (!user.emailVerificationExpires || user.emailVerificationExpires < new Date()) {
      return res.status(400).json({ message: "Token expired." });
    }

    user.isVerified = true;
    user.emailVerificationTokenHash = undefined;
    user.emailVerificationExpires = undefined;

    await user.save();

    return res.json({ message: "Email verified. You can now log in." });
  } catch (err) {
    console.error("Verify email error:", err);
    res.status(500).json({ message: "Server error." });
  }
});

// ── LOGIN (block if not verified) ──────────────────────────────────
// POST /api/auth/login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required." });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: "Incorrect email or password." });
    }

    if (!user.isVerified) {
      return res.status(403).json({
        message: "Please verify your email before logging in.",
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Incorrect email or password." });
    }

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
app.get("/api/auth/me", requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("-password");
    if (!user) return res.status(404).json({ message: "User not found." });
    res.json({ user: { id: user._id, name: user.name, email: user.email, isVerified: user.isVerified } });
  } catch (err) {
    res.status(500).json({ message: "Server error." });
  }
});

// ── SAVE ORDER ────────────────────────────────────────────────────
app.post("/api/orders", requireAuth, async (req, res) => {
  try {
    const { orderNumber, items, total, delivery, address, city, postcode, paystackRef } = req.body;

    const order = new Order({
      userId: req.userId,
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
app.get("/api/orders", requireAuth, async (req, res) => {
  try {
    const orders = await Order.find({ userId: req.userId }).sort({ createdAt: -1 });
    res.json({ orders });
  } catch (err) {
    res.status(500).json({ message: "Could not fetch orders." });
  }
});

// ── VERIFY PAYSTACK PAYMENT ───────────────────────────────────────
app.post("/api/verify-payment", requireAuth, async (req, res) => {
  try {
    const { reference } = req.body;
    if (!reference) return res.status(400).json({ message: "Reference required." });

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

app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server running on port ${PORT}`);
});