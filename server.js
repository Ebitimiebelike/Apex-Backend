const axios = require("axios");
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 5000;

// ── Middleware ────────────────────────────────────────────────────
const corsOptions = {
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
  preflightContinue: false,
  optionsSuccessStatus: 204
};

// This applies CORS and handles ALL HTTP OPTIONS requests automatically 
// without relying on Express's wildcard router.
app.use(cors(corsOptions));

app.use(express.json());

// ── Connect to MongoDB ────────────────────────────────────────────
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ MongoDB error:", err));

// ── Helpers ───────────────────────────────────────────────────────
function sha256(str) {
  return crypto.createHash("sha256").update(str).digest("hex");
}

function frontendUrl() {
  return process.env.FRONTEND_URL || "http://localhost:5173";
}

async function sendEmailBrevo({ to, subject, html }) {
  if (!process.env.BREVO_API_KEY) throw new Error("BREVO_API_KEY not configured");
  if (!process.env.BREVO_SENDER_EMAIL) throw new Error("BREVO_SENDER_EMAIL not configured");

  const resp = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "api-key": process.env.BREVO_API_KEY,
    },
    body: JSON.stringify({
      sender: {
        name: process.env.BREVO_SENDER_NAME || "Apex Home Furnishings",
        email: process.env.BREVO_SENDER_EMAIL,
      },
      to: [{ email: to }],
      subject,
      htmlContent: html,
    }),
  });

  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    throw new Error(data?.message || `Brevo send failed (${resp.status})`);
  }
  return data;
}

// ════════════════════════════════════════════════════════════════
// MODELS
// ════════════════════════════════════════════════════════════════

const UserSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true, minlength: 6 },
  createdAt: { type: Date, default: Date.now },

  isVerified: { type: Boolean, default: false },
  emailVerificationTokenHash: { type: String },
  emailVerificationExpires: { type: Date },
});

UserSchema.pre("save", async function () {
  if (!this.isModified("password")) return;
  this.password = await bcrypt.hash(this.password, 10);
});

const User = mongoose.model("User", UserSchema);

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

app.get("/api/health", (req, res) => {
  res.json({ status: "Apex Backend running ✅" });
});

// REGISTER (send verification link)
// REGISTER (Validate email with Abstract, save user, then send Brevo verification link)
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // 1. Input Validation
    if (!name || !email || !password) {
      return res.status(400).json({ message: "All fields are required." });
    }
    if (password.length < 6) {
      return res.status(400).json({ message: "Password must be at least 6 characters." });
    }

    // 2. Check if user already exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json({ message: "An account with this email already exists." });
    }

    // 3. STITCHED: Abstract API Validation Check
    if (process.env.ABSTRACT_API_KEY) {
      try {
        const absResponse = await fetch(
          `https://emailvalidation.abstractapi.com/v1/?api_key=${process.env.ABSTRACT_API_KEY}&email=${encodeURIComponent(email)}`
        );
        
        if (absResponse.ok) {
          const absData = await absResponse.json();
          
          // Check Abstract API's strict deliverability metrics
          const isInvalidEmail = 
            absData.deliverability !== "DELIVERABLE" || 
            absData.is_disposable_email?.value === true || 
            absData.is_valid_format?.value === false;

          if (isInvalidEmail) {
            let reason = "This email address is invalid or not deliverable.";
            if (absData.is_disposable_email?.value === true) {
              reason = "Disposable/temporary emails are not allowed.";
            } else if (absData.is_valid_format?.value === false) {
              reason = "Invalid email format.";
            }
            return res.status(400).json({ message: reason });
          }
        }
      } catch (abstractErr) {
        // Fail silently: If Abstract API is down or out of monthly credits, 
        // we log it but don't block legitimate user sign-ups.
        console.error("⚠️ Abstract API validation skipped due to error:", abstractErr.message);
      }
    } else {
      console.warn("⚠️ Warning: ABSTRACT_API_KEY is missing from environment variables.");
    }

    // 4. Create User & Verification Tokens
    const user = new User({ name, email, password, isVerified: false });

    // token
    const verificationToken = crypto.randomBytes(32).toString("hex");
    user.emailVerificationTokenHash = sha256(verificationToken);
    user.emailVerificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);

    await user.save();

    if (!process.env.FRONTEND_URL) {
      await User.findByIdAndDelete(user._id).catch(() => {});
      return res.status(500).json({ message: "FRONTEND_URL is not configured." });
    }

    // include email in link (optional, but helps frontend)
    const verificationLink =
      `${frontendUrl()}/verify-email?token=${encodeURIComponent(verificationToken)}` +
      `&email=${encodeURIComponent(user.email)}`;

    // 5. Send Email via Brevo
    try {
      await sendEmailBrevo({
        to: user.email,
        subject: "Verify your Apex Home account",
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 560px; margin: 0 auto;">
            <div style="background-color: #8b7355; padding: 24px; text-align: center;">
              <h1 style="color: white; margin: 0; font-size: 22px;">Apex Home Furnishings</h1>
            </div>
            <div style="padding: 32px; background: #f9f6f2;">
              <h2 style="margin-top: 0;">Welcome, ${name}!</h2>
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
      console.error("Brevo verification email failed:", emailErr.message);
      // Clean up the created user if the email completely fails to send
      await User.findByIdAndDelete(user._id).catch(() => {});
      return res.status(500).json({ message: "Could not send verification email." });
    }

    return res.status(201).json({
      message: "Verification email sent. Please check your inbox to activate your account.",
    });
  } catch (err) {
    console.error("Register error:", err);
    return res.status(500).json({ message: "Server error. Please try again." });
  }
});

// VERIFY EMAIL (POST — matches your VerifyEmailPage)
app.post("/api/auth/verify-email", async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) return res.status(400).json({ message: "Token is required." });

    const tokenHash = sha256(token);

    const user = await User.findOne({
      emailVerificationTokenHash: tokenHash,
      emailVerificationExpires: { $gt: new Date() },
    });

    if (!user) return res.status(400).json({ message: "Invalid or expired token." });

    user.isVerified = true;
    user.emailVerificationTokenHash = undefined;
    user.emailVerificationExpires = undefined;
    await user.save();

    return res.json({ message: "Email verified. You can now log in." });
  } catch (err) {
    console.error("Verify email error:", err);
    return res.status(500).json({ message: "Server error." });
  }
});

// LOGIN (block if not verified)
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required." });
    }

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(401).json({ message: "Incorrect email or password." });

    if (!user.isVerified) {
      return res.status(403).json({ message: "Please verify your email before logging in." });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: "Incorrect email or password." });

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });

    return res.json({
      token,
      user: { id: user._id, name: user.name, email: user.email },
    });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ message: "Server error. Please try again." });
  }
});

// ME
app.get("/api/auth/me", requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("-password");
    if (!user) return res.status(404).json({ message: "User not found." });
    return res.json({
      user: { id: user._id, name: user.name, email: user.email, isVerified: user.isVerified },
    });
  } catch (err) {
    return res.status(500).json({ message: "Server error." });
  }
});

// Orders (unchanged)
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
    return res.status(201).json({ order });
  } catch (err) {
    console.error("Save order error:", err);
    return res.status(500).json({ message: "Could not save order." });
  }
});

app.get("/api/orders", requireAuth, async (req, res) => {
  try {
    const orders = await Order.find({ userId: req.userId }).sort({ createdAt: -1 });
    return res.json({ orders });
  } catch (err) {
    return res.status(500).json({ message: "Could not fetch orders." });
  }
});

app.get("/api/validate-checkout-email", async (req, res) => {  
  try {    
    const { email } = req.query;    
    if (!email) return res.status(400).json({ valid: false, message: "Email is required." });    
    
    console.log(`[Validation Request] Checking email: ${email}`);

    const apiKey = process.env.ABSTRACT_API_KEY;
    if (!apiKey) {
      console.error("❌ Backend Error: ABSTRACT_API_KEY environment variable is missing on Render!");
      return res.json({ valid: true, reason: "Server configuration missing key" });
    }
    
    // Using Axios instead of native fetch for rock-solid network requests
    const response = await axios.get("https://emailvalidation.abstractapi.com/v1/", {
      params: {
        api_key: apiKey,
        email: email
      },
      timeout: 6000 // 6 seconds timeout limit
    });

    const data = response.data;    
    
    console.log("➡️ Abstract API Raw Response Data:", JSON.stringify(data));
    
    // Strict Verification Logic
    const isDeliverable = data.deliverability === "DELIVERABLE";
    const isValidFormat = data.is_valid_format?.value === true;
    const isNotDisposable = data.is_disposable_email?.value === false;

    const isValid = isDeliverable && isValidFormat && isNotDisposable;
    
    let reason = "Valid";
    if (!isValidFormat) {
      reason = "Invalid email format.";
    } else if (!isNotDisposable) {
      reason = "Disposable/temporary emails are not allowed.";
    } else if (!isDeliverable) {
      reason = "This email address cannot be verified or does not exist.";
    }

    console.log(`[Validation Result] Email: ${email} | Valid: ${isValid} | Reason: ${reason}`);

    return res.json({ valid: isValid, reason });  
  } catch (err) {    
    // Check if it's an Axios-specific network error to give you a clean log trace
    if (err.response) {
      console.error(`❌ Abstract API responded with status code: ${err.response.status}`);
      console.error("Response data details:", err.response.data);
    } else {
      console.error("❌ Network connectivity error details:", err.message);
    }
    
    // Fallback safety net: allow checkout if API is genuinely dead or rate-limited
    return res.json({ valid: true, reason: "Could not verify service" });  
  }
});

// Paystack verify (unchanged)
app.post("/api/verify-payment", requireAuth, async (req, res) => {
  try {
    const { reference } = req.body;
    if (!reference) return res.status(400).json({ message: "Reference required." });

    const response = await fetch(`https://api.paystack.co/transaction/verify/${reference}`, {
      headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` },
    });

    const data = await response.json();

    if (data.status && data.data.status === "success") {
      return res.json({ verified: true, amount: data.data.amount, reference });
    }
    return res.json({ verified: false, message: "Payment not confirmed." });
  } catch (err) {
    console.error("Payment verify error:", err);
    return res.status(500).json({ message: "Could not verify payment." });
  }
});

app.get("/api/validate-email-status", async (req, res) => {  
  try {    
    const { email } = req.query;    
    if (!email) return res.status(400).json({ valid: false });    
    
    const response = await fetch(      
      `https://emailvalidation.abstractapi.com/v1/?api_key=${process.env.ABSTRACT_API_KEY}&email=${encodeURIComponent(email)}`    
    );    
    const data = await response.json();    
    
    // Abstract API delivers strict metrics:
    const isReal = (      
      data.deliverability === "DELIVERABLE" &&      
      data.is_valid_format?.value === true &&      
      data.is_disposable_email?.value === false    
    );    
    
    res.json({      
      valid: isReal,      
      reason: !data.is_valid_format?.value ? "Invalid email format."           
            : data.is_disposable_email?.value ? "Disposable/temporary emails are not allowed." 
            : data.deliverability !== "DELIVERABLE" ? "This email address does not exist." 
            : "Valid",    
    });  
  } catch (err) {    
    console.error("Email verification service error:", err);    
    // Fail silently: If API breaks, allow registration rather than breaking sign-ups
    res.json({ valid: true, reason: "Could not verify" });  
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server running on port ${PORT}`);
});