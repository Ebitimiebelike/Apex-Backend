const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Resend } = require("resend");
const crypto = require("crypto"); // Built-in for generating random tokens
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 5000;
const resend = new Resend(process.env.RESEND_API_KEY);

// ── Middleware ────────────────────────────────────────────────────
app.use(cors({
  origin: [
    "http://localhost:5173", 
    "https://apex-home-stores.vercel.app", 
  ]
}));
app.use(express.json());

// ── Connect to MongoDB ────────────────────────────────────────────
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch(err => console.error("❌ MongoDB error:", err));

// ── User Model ───────────────────────────────────────────────────
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true, minlength: 6 },
  isVerified: { type: Boolean, default: false }, // New: Tracks verification status
  verificationToken: { type: String },           // New: Stores the secret token
  createdAt: { type: Date, default: Date.now },
});

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

// ── Auth Middleware ──────────────────────────────────────────────
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

// ── ROUTES ───────────────────────────────────────────────────────

app.get("/api/health", (req, res) => {
  res.json({ status: "Apex Backend running ✅" });
});

// ── REGISTER (Updated with Verification) ─────────────────────────
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ message: "All fields are required." });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "An account with this email already exists." });
    }

    // 1. Create verification token
    const verificationToken = crypto.randomBytes(32).toString("hex");

    // 2. Save user (isVerified is false by default)
    const user = new User({ name, email, password, verificationToken });
    await user.save();

    // 3. Set the verify URL (Change to your Vercel link for production)
    const verifyUrl = `http://localhost:5173/verify/${verificationToken}`;

    // 4. Send Email
    try {
      await resend.emails.send({
        from: "Apex Home <onboarding@resend.dev>",
        to: email,
        subject: "Verify your email - Apex Home Furnishings",
        html: `
          <div style="font-family: Georgia, serif; max-width: 560px; margin: 0 auto; border: 1px solid #e8e4df;">
            <div style="background-color: #8b7355; padding: 24px; text-align: center; color: white;">
              <h1>Apex Home</h1>
            </div>
            <div style="padding: 32px; text-align: center;">
              <h2>Verify Your Email</h2>
              <p>Thanks for signing up! Click the button below to activate your account.</p>
              <a href="${verifyUrl}" style="display: inline-block; background: #8b7355; color: white; padding: 14px 28px; text-decoration: none; font-weight: bold; margin-top: 20px;">
                VERIFY ACCOUNT
              </a>
            </div>
          </div>
        `,
      });
    } catch (emailErr) {
      console.error("Verification email failed:", emailErr.message);
    }

    res.status(201).json({ message: "Registration successful! Please check your email to verify your account." });

  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ message: "Server error. Please try again." });
  }
});

// ── VERIFY EMAIL ─────────────────────────────────────────────────
app.get("/api/auth/verify/:token", async (req, res) => {
  try {
    const { token } = req.params;
    const user = await User.findOne({ verificationToken: token });

    if (!user) {
      return res.status(400).json({ message: "Invalid or expired verification token." });
    }

    user.isVerified = true;
    user.verificationToken = undefined; // Clear the token once used
    await user.save();

    res.json({ success: true, message: "Email verified! You can now log in." });
  } catch (err) {
    res.status(500).json({ message: "Verification failed." });
  }
});

// ── LOGIN (Updated with Verification Check) ─────────────────────
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user) return res.status(401).json({ message: "Incorrect email or password." });

    // Block login if not verified
    if (!user.isVerified) {
      return res.status(401).json({ message: "Please verify your email before logging in." });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: "Incorrect email or password." });

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });

    res.json({
      token,
      user: { id: user._id, name: user.name, email: user.email },
    });
  } catch (err) {
    res.status(500).json({ message: "Server error." });
  }
});

// ── REMAINING ROUTES (Unchanged) ─────────────────────────────────
app.get("/api/auth/me", requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("-password");
    if (!user) return res.status(404).json({ message: "User not found." });
    res.json({ user: { id: user._id, name: user.name, email: user.email } });
  } catch (err) {
    res.status(500).json({ message: "Server error." });
  }
});

app.post("/api/orders", requireAuth, async (req, res) => {
  try {
    const order = new Order({ ...req.body, userId: req.userId });
    await order.save();
    res.status(201).json({ order });
  } catch (err) {
    res.status(500).json({ message: "Could not save order." });
  }
});

app.get("/api/orders", requireAuth, async (req, res) => {
  try {
    const orders = await Order.find({ userId: req.userId }).sort({ createdAt: -1 });
    res.json({ orders });
  } catch (err) {
    res.status(500).json({ message: "Could not fetch orders." });
  }
});

app.post("/api/verify-payment", requireAuth, async (req, res) => {
  try {
    const { reference } = req.body;
    const response = await fetch(`https://api.paystack.co/transaction/verify/${reference}`, {
      headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` },
    });
    const data = await response.json();
    if (data.status && data.data.status === "success") {
      res.json({ verified: true, amount: data.data.amount, reference });
    } else {
      res.json({ verified: false });
    }
  } catch (err) {
    res.status(500).json({ message: "Payment verification error." });
  }
});

app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));