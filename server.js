
require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const path = require("path");
const crypto = require("crypto");
const fs = require("fs");

const app = express();
const PORT = Number(process.env.PORT || 3000);

// =====================================================
// 1. DATABASE CONFIGURATION
// =====================================================

const DB_FILE =
  process.env.DB_FILE ||
  path.join(__dirname, "data", "football-tips.sqlite");

fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });

// =====================================================
// 2. REQUIRED ENVIRONMENT VARIABLES
// =====================================================

if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
  console.error("FATAL: JWT_SECRET must contain at least 32 characters.");
  process.exit(1);
}

if (!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD_HASH) {
  console.error("FATAL: Set ADMIN_EMAIL and ADMIN_PASSWORD_HASH.");
  process.exit(1);
}

if (process.env.DARAJA_ENABLED === "true") {
  const required = [
    "DARAJA_CONSUMER_KEY",
    "DARAJA_CONSUMER_SECRET",
    "DARAJA_PASSKEY",
    "MPESA_SHORTCODE",
    "MPESA_TILL_NUMBER",
    "MPESA_CALLBACK_URL"
  ];

  for (const key of required) {
    if (!process.env[key]) {
      console.error(`FATAL: Missing environment variable ${key}`);
      process.exit(1);
    }
  }

  if (!process.env.MPESA_CALLBACK_URL.startsWith("https://")) {
    console.error("FATAL: MPESA_CALLBACK_URL must use HTTPS.");
    process.exit(1);
  }

  const transactionType =
    process.env.MPESA_TRANSACTION_TYPE ||
    (process.env.DARAJA_ENV === "production"
      ? "CustomerBuyGoodsOnline"
      : "CustomerPayBillOnline");

  const allowedTypes = [
    "CustomerPayBillOnline",
    "CustomerBuyGoodsOnline"
  ];

  if (!allowedTypes.includes(transactionType)) {
    console.error("FATAL: Invalid MPESA_TRANSACTION_TYPE.");
    process.exit(1);
  }
}

// =====================================================
// 3. SECURITY AND MIDDLEWARE
// =====================================================

app.disable("x-powered-by");

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: false, limit: "20kb" }));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many attempts. Please try again later." }
});

const paymentLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 8,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many payment attempts. Please wait and try again." }
});

const adminLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many admin login attempts. Try again later." }
});

app.use("/api/auth", authLimiter);
app.use("/api/payments", paymentLimiter);
app.use("/api/admin/login", adminLoginLimiter);

// =====================================================
// 4. DATABASE INITIALIZATION
// =====================================================

const db = new Database(DB_FILE);

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.pragma("busy_timeout = 5000");

db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  phone TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  expires_at TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS plans(
  key TEXT PRIMARY KEY,
  label TEXT NOT NULL,
  days INTEGER NOT NULL,
  price INTEGER NOT NULL CHECK(price > 0)
);

CREATE TABLE IF NOT EXISTS fixtures(
  id TEXT PRIMARY KEY,
  league TEXT NOT NULL,
  home TEXT NOT NULL,
  away TEXT NOT NULL,
  kickoff TEXT,
  market TEXT,
  prediction TEXT,
  odds TEXT,
  analysis TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS payments(
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  plan_key TEXT NOT NULL,
  amount INTEGER NOT NULL,
  phone TEXT NOT NULL,
  status TEXT NOT NULL,
  checkout_request_id TEXT UNIQUE,
  merchant_request_id TEXT,
  mpesa_receipt TEXT UNIQUE,
  result_code TEXT,
  result_desc TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
`);

// =====================================================
// 5. DEFAULT SUBSCRIPTION PLANS
// =====================================================

const seedPlans = [
  ["daily", "Daily access", 1, 300],
  ["weekly", "Weekly access", 7, 500],
  ["monthly", "Monthly access", 30, 1000]
];

const insertPlan = db.prepare(`
  INSERT OR IGNORE INTO plans(key, label, days, price)
  VALUES(?, ?, ?, ?)
`);

for (const plan of seedPlans) {
  insertPlan.run(...plan);
}

// =====================================================
// 6. SAMPLE FIXTURES
// =====================================================

const fixtureCount =
  db.prepare("SELECT COUNT(*) AS n FROM fixtures").get().n;

if (!fixtureCount) {
  const insertFixture = db.prepare(`
    INSERT INTO fixtures(
      id, league, home, away, kickoff, market,
      prediction, odds, analysis, created_at
    )
    VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const now = new Date().toISOString();

  const sampleFixtures = [
    [
      "m1",
      "Premier League",
      "Arsenal",
      "Chelsea",
      null,
      "Over 1.5 Goals",
      "Over 1.5 Goals",
      "1.42",
      "Sample only: add your own verified team news and analysis."
    ],
    [
      "m2",
      "Premier League",
      "Liverpool",
      "Manchester City",
      null,
      "BTTS",
      "Both Teams To Score — Yes",
      "1.70",
      "Sample only: add your own verified team news and analysis."
    ],
    [
      "m3",
      "La Liga",
      "Barcelona",
      "Sevilla",
      null,
      "1X2",
      "Barcelona win",
      "1.55",
      "Sample only: add your own verified team news and analysis."
    ]
  ];

  for (const fixture of sampleFixtures) {
    insertFixture.run(...fixture, now);
  }
}

// =====================================================
// 7. PREPARED DATABASE QUERIES
// =====================================================

const q = {
  userById: db.prepare("SELECT * FROM users WHERE id = ?"),

  plans: db.prepare(
    "SELECT key, label, days, price FROM plans"
  ),

  plan: db.prepare(
    "SELECT * FROM plans WHERE key = ?"
  ),

  fixtureList: db.prepare(`
    SELECT * FROM fixtures
    ORDER BY COALESCE(kickoff, '9999') ASC, created_at DESC
  `),

  paymentById: db.prepare(
    "SELECT * FROM payments WHERE id = ?"
  ),

  paymentByCheckout: db.prepare(
    "SELECT * FROM payments WHERE checkout_request_id = ?"
  )
};

// =====================================================
// 8. GENERAL HELPERS
// =====================================================

const nowIso = () => new Date().toISOString();

function normalizePhone(raw) {
  let phone = String(raw || "").replace(/[^\d+]/g, "");

  if (phone.startsWith("+")) {
    phone = phone.slice(1);
  }

  if (phone.startsWith("0")) {
    phone = "254" + phone.slice(1);
  }

  if (phone.startsWith("7") || phone.startsWith("1")) {
    phone = "254" + phone;
  }

  if (!/^254[17]\d{8}$/.test(phone)) {
    throw new Error(
      "Enter a valid Kenyan mobile number, e.g. 0712345678."
    );
  }

  return phone;
}

function tokenFor(id, role = "member") {
  return jwt.sign(
    { sub: id, role },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";

  try {
    if (!header.startsWith("Bearer ")) {
      throw new Error("Missing token");
    }

    req.auth = jwt.verify(
      header.slice(7),
      process.env.JWT_SECRET
    );

    next();
  } catch {
    return res.status(401).json({
      error: "Please log in again."
    });
  }
}

const adminOnly = (req, res, next) => {
  if (req.auth?.role === "admin") {
    return next();
  }

  return res.status(403).json({
    error: "Admin access required."
  });
};

function safeUser(user) {
  return {
    id: user.id,
    name: user.name,
    phone: user.phone,
    email: user.email,
    expiresAt: user.expires_at,
    subscriptionActive: Boolean(
      user.expires_at &&
      new Date(user.expires_at) > new Date()
    )
  };
}

function publicPlans() {
  return Object.fromEntries(
    q.plans.all().map(plan => [
      plan.key,
      {
        label: plan.label,
        days: plan.days,
        price: plan.price
      }
    ])
  );
}

function isPaid(user) {
  return Boolean(
    user.expires_at &&
    new Date(user.expires_at) > new Date()
  );
}

function memberFixtures(user) {
  return q.fixtureList.all().map(fixture => {
    if (isPaid(user)) {
      return fixture;
    }

    return {
      id: fixture.id,
      league: fixture.league,
      home: fixture.home,
      away: fixture.away,
      kickoff: fixture.kickoff,
      market: fixture.market,
      prediction: null,
      odds: null,
      analysis: null
    };
  });
}

function asyncRoute(fn) {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

// =====================================================
// 9. HEALTH AND PUBLIC INFORMATION
// =====================================================

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    service: "Football Tips Hub"
  });
});

app.get("/api/public", (req, res) => {
  res.json({
    plans: publicPlans(),

    fixtures: q.fixtureList.all().map(fixture => ({
      id: fixture.id,
      league: fixture.league,
      home: fixture.home,
      away: fixture.away,
      kickoff: fixture.kickoff,
      market: fixture.market
    }))
  });
});

// =====================================================
// 10. MEMBER REGISTRATION
// =====================================================

app.post(
  "/api/auth/register",
  asyncRoute(async (req, res) => {
    const name = String(req.body.name || "").trim();

    const email = String(req.body.email || "")
      .trim()
      .toLowerCase();

    const password = String(req.body.password || "");

    let phone;

    try {
      phone = normalizePhone(req.body.phone);
    } catch (error) {
      return res.status(400).json({
        error: error.message
      });
    }

    if (name.length < 2 || name.length > 80) {
      return res.status(400).json({
        error: "Enter your full name."
      });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({
        error: "Enter a valid email address."
      });
    }

    if (password.length < 8 || password.length > 100) {
      return res.status(400).json({
        error: "Password must be at least 8 characters."
      });
    }

    const hash = await bcrypt.hash(password, 12);
    const id = crypto.randomUUID();

    try {
      db.prepare(`
        INSERT INTO users(
          id, name, phone, email, password_hash, created_at
        )
        VALUES(?, ?, ?, ?, ?, ?)
      `).run(
        id,
        name,
        phone,
        email,
        hash,
        nowIso()
      );
    } catch (error) {
      if (String(error).includes("UNIQUE")) {
        return res.status(409).json({
          error: "That phone number or email is already registered."
        });
      }

      throw error;
    }

    res.status(201).json({
      token: tokenFor(id),
      user: safeUser(q.userById.get(id))
    });
  })
);

// =====================================================
// 11. MEMBER LOGIN
// =====================================================

app.post(
  "/api/auth/login",
  asyncRoute(async (req, res) => {
    const identity = String(req.body.identity || "")
      .trim()
      .toLowerCase();

    const password = String(req.body.password || "");

    if (!identity || !password) {
      return res.status(400).json({
        error: "Enter your email or phone number and password."
      });
    }

    let phoneIdentity = identity;

    if (!identity.includes("@")) {
      try {
        phoneIdentity = normalizePhone(identity);
      } catch {
        phoneIdentity = "";
      }
    }

    const user = db.prepare(`
      SELECT * FROM users
      WHERE lower(email) = ? OR phone = ?
    `).get(
      identity,
      phoneIdentity
    );

    if (
      !user ||
      !(await bcrypt.compare(password, user.password_hash))
    ) {
      return res.status(401).json({
        error: "Email/phone or password is incorrect."
      });
    }

    res.json({
      token: tokenFor(user.id),
      user: safeUser(user)
    });
  })
);

// =====================================================
// 12. MEMBER ACCOUNT AND SUBSCRIPTION INFORMATION
// =====================================================

app.get("/api/me", auth, (req, res) => {
  if (req.auth.role !== "member") {
    return res.status(403).json({
      error: "Member account required."
    });
  }

  const user = q.userById.get(req.auth.sub);

  if (!user) {
    return res.status(401).json({
      error: "Account not found."
    });
  }

  const payments = db.prepare(`
    SELECT id, plan_key, amount, status, created_at
    FROM payments
    WHERE user_id = ?
    ORDER BY created_at DESC
  `).all(user.id);

  res.json({
    user: safeUser(user),

    fixtures: memberFixtures(user),

    payments: payments.map(payment => ({
      ...payment,
      planLabel:
        q.plan.get(payment.plan_key)?.label ||
        payment.plan_key
    }))
  });
});

// =====================================================
// 13. DARAJA AUTHENTICATION
// =====================================================

async function darajaToken() {
  const production =
    process.env.DARAJA_ENV === "production";

  const base = production
    ? "https://api.safaricom.co.ke"
    : "https://sandbox.safaricom.co.ke";

  const credentials = Buffer.from(
    `${process.env.DARAJA_CONSUMER_KEY}:${process.env.DARAJA_CONSUMER_SECRET}`
  ).toString("base64");

  const response = await fetch(
    `${base}/oauth/v1/generate?grant_type=client_credentials`,
    {
      headers: {
        Authorization: `Basic ${credentials}`
      },
      signal: AbortSignal.timeout(20000)
    }
  );

  const data = await response.json().catch(() => ({}));

  if (!response.ok || !data.access_token) {
    console.error("Daraja authentication failed:", data);

    throw new Error(
      data.errorMessage ||
      "Could not authenticate with Daraja."
    );
  }

  return {
    base,
    accessToken: data.access_token
  };
}

// =====================================================
// 14. SAFARICOM TIMESTAMP - KENYA TIME
// =====================================================

function mpesaTimestamp() {
  const parts = new Intl.DateTimeFormat("en-GB", {
    timeZone: "Africa/Nairobi",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23"
  }).formatToParts(new Date());

  const values = {};

  for (const part of parts) {
    values[part.type] = part.value;
  }

  return (
    values.year +
    values.month +
    values.day +
    values.hour +
    values.minute +
    values.second
  );
}

// =====================================================
// 15. M-PESA STK PUSH
// =====================================================

app.post(
  "/api/payments/stk",
  auth,
  asyncRoute(async (req, res) => {
    if (req.auth.role !== "member") {
      return res.status(403).json({
        error: "Members only."
      });
    }

    if (process.env.DARAJA_ENABLED !== "true") {
      return res.status(503).json({
        error: "M-Pesa payments are not enabled yet. Ask the site administrator."
      });
    }

    const user = q.userById.get(req.auth.sub);

    if (!user) {
      return res.status(401).json({
        error: "Please log in again."
      });
    }

    const plan = q.plan.get(String(req.body.plan || ""));

    if (!plan) {
      return res.status(400).json({
        error: "Select a valid subscription plan."
      });
    }

    let phone;

    try {
      phone = normalizePhone(req.body.phone || user.phone);
    } catch (error) {
      return res.status(400).json({
        error: error.message
      });
    }

    const id = crypto.randomUUID();
    const created = nowIso();

    db.prepare(`
      INSERT INTO payments(
        id, user_id, plan_key, amount, phone,
        status, created_at, updated_at
      )
      VALUES(?, ?, ?, ?, ?, 'pending', ?, ?)
    `).run(
      id,
      user.id,
      plan.key,
      plan.price,
      phone,
      created,
      created
    );

    try {
      const {
        base,
        accessToken
      } = await darajaToken();

      const timestamp = mpesaTimestamp();

      const shortcode = process.env.MPESA_SHORTCODE;
      const passkey = process.env.DARAJA_PASSKEY;

      const password = Buffer.from(
        shortcode + passkey + timestamp
      ).toString("base64");

      const transactionType =
        process.env.MPESA_TRANSACTION_TYPE ||
        (process.env.DARAJA_ENV === "production"
          ? "CustomerBuyGoodsOnline"
          : "CustomerPayBillOnline");

      // In Sandbox, use the sandbox shortcode as PartyB.
      // In production, use the actual configured Till number.
      const partyB =
        process.env.MPESA_PARTY_B ||
        process.env.MPESA_TILL_NUMBER ||
        shortcode;

      const payload = {
        BusinessShortCode: shortcode,
        Password: password,
        Timestamp: timestamp,
        TransactionType: transactionType,
        Amount: plan.price,
        PartyA: phone,
        PartyB: partyB,
        PhoneNumber: phone,
        CallBackURL: process.env.MPESA_CALLBACK_URL,
        AccountReference:
          `FTH${id.replace(/-/g, "").slice(0, 8)}`,
        TransactionDesc:
          `${plan.label} Football Tips`
      };

      const response = await fetch(
        `${base}/mpesa/stkpush/v1/processrequest`,
        {
          method: "POST",

          headers: {
            Authorization: `Bearer ${accessToken}`,
            "Content-Type": "application/json"
          },

          body: JSON.stringify(payload),

          signal: AbortSignal.timeout(30000)
        }
      );

      const data = await response.json().catch(() => ({}));

      if (
        !response.ok ||
        data.ResponseCode !== "0" ||
        !data.CheckoutRequestID
      ) {
        const errorMessage =
          data.errorMessage ||
          data.ResponseDescription ||
          "Daraja did not accept the STK request.";

        db.prepare(`
          UPDATE payments
          SET status = 'failed',
              result_desc = ?,
              updated_at = ?
          WHERE id = ?
        `).run(
          String(errorMessage).slice(0, 250),
          nowIso(),
          id
        );

        console.error("STK Push rejected:", data);

        return res.status(502).json({
          error: errorMessage
        });
      }

      db.prepare(`
        UPDATE payments
        SET checkout_request_id = ?,
            merchant_request_id = ?,
            updated_at = ?
        WHERE id = ?
      `).run(
        data.CheckoutRequestID,
        data.MerchantRequestID || null,
        nowIso(),
        id
      );

      return res.status(202).json({
        paymentId: id,
        status: "pending",
        message: "STK request sent. Check your phone and enter your M-Pesa PIN."
      });

    } catch (error) {
      console.error("STK Push error:", error);

      db.prepare(`
        UPDATE payments
        SET status = 'failed',
            result_desc = ?,
            updated_at = ?
        WHERE id = ?
      `).run(
        String(error.message || "Payment request failed").slice(0, 250),
        nowIso(),
        id
      );

      throw error;
    }
  })
);

// =====================================================
// 16. CHECK PAYMENT STATUS
// =====================================================

app.get("/api/payments/:id", auth, (req, res) => {
  const payment = q.paymentById.get(req.params.id);

  if (!payment || payment.user_id !== req.auth.sub) {
    return res.status(404).json({
      error: "Payment not found."
    });
  }

  res.json({
    id: payment.id,
    status: payment.status,
    message: payment.result_desc || null,
    receipt: payment.mpesa_receipt || null
  });
});

// =====================================================
// 17. M-PESA CALLBACK AND SUBSCRIPTION ACTIVATION
// =====================================================

app.post("/api/mpesa/callback", (req, res) => {
  try {
    const body = req.body?.Body?.stkCallback;

    if (!body?.CheckoutRequestID) {
      return res.status(400).json({
        ResultCode: 1,
        ResultDesc: "Invalid callback payload"
      });
    }

    const payment = q.paymentByCheckout.get(
      body.CheckoutRequestID
    );

    if (!payment) {
      console.error(
        "Callback received for unknown checkout:",
        body.CheckoutRequestID
      );

      // Do not activate an unknown payment.
      return res.json({
        ResultCode: 0,
        ResultDesc: "Unknown checkout reference"
      });
    }

    const resultCode = String(body.ResultCode);

    // Customer cancelled, payment timed out or failed.
    if (resultCode !== "0") {
      db.prepare(`
        UPDATE payments
        SET status = 'failed',
            result_code = ?,
            result_desc = ?,
            updated_at = ?
        WHERE id = ?
          AND status = 'pending'
      `).run(
        resultCode,
        String(body.ResultDesc || "Payment not completed").slice(0, 250),
        nowIso(),
        payment.id
      );

      return res.json({
        ResultCode: 0,
        ResultDesc: "Callback processed"
      });
    }

    const items = body.CallbackMetadata?.Item || [];

    const metadata = Object.fromEntries(
      items.map(item => [item.Name, item.Value])
    );

    const amount = Number(metadata.Amount);
    const receipt = String(metadata.MpesaReceiptNumber || "");
    const phone = String(metadata.PhoneNumber || "");

    // Verify the callback against the original payment.
    if (
      amount !== Number(payment.amount) ||
      !receipt ||
      !phone ||
      phone !== payment.phone
    ) {
      db.prepare(`
        UPDATE payments
        SET status = 'review',
            result_code = ?,
            result_desc = ?,
            updated_at = ?
        WHERE id = ?
          AND status = 'pending'
      `).run(
        resultCode,
        "Payment details did not match the order. Manual review required.",
        nowIso(),
        payment.id
      );

      return res.json({
        ResultCode: 0,
        ResultDesc: "Payment sent for manual review"
      });
    }

    // Activate membership and mark payment as paid
    // in one atomic database transaction.
    const activatePayment = db.transaction(() => {
      const freshPayment = q.paymentById.get(payment.id);

      // Protect against duplicate callbacks.
      if (!freshPayment || freshPayment.status !== "pending") {
        return;
      }

      const user = q.userById.get(freshPayment.user_id);
      const plan = q.plan.get(freshPayment.plan_key);

      if (!user || !plan) {
        throw new Error("Payment user or subscription plan not found.");
      }

      const now = new Date();

      const existingExpiry = user.expires_at
        ? new Date(user.expires_at)
        : now;

      const baseDate =
        existingExpiry > now
          ? existingExpiry
          : now;

      baseDate.setDate(
        baseDate.getDate() + plan.days
      );

      const newExpiry = baseDate.toISOString();

      db.prepare(`
        UPDATE users
        SET expires_at = ?
        WHERE id = ?
      `).run(
        newExpiry,
        user.id
      );

      const update = db.prepare(`
        UPDATE payments
        SET status = 'paid',
            mpesa_receipt = ?,
            result_code = '0',
            result_desc = 'Payment confirmed by Safaricom',
            updated_at = ?
        WHERE id = ?
          AND status = 'pending'
      `).run(
        receipt,
        nowIso(),
        payment.id
      );

      if (update.changes !== 1) {
        throw new Error("Payment status could not be updated.");
      }
    });

    try {
      activatePayment();
    } catch (error) {
      console.error(
        "Payment activation transaction failed:",
        error
      );

      // Do not acknowledge a failed activation as successful.
      return res.status(500).json({
        ResultCode: 1,
        ResultDesc: "Payment activation failed"
      });
    }

    return res.json({
      ResultCode: 0,
      ResultDesc: "Payment processed successfully"
    });

  } catch (error) {
    console.error("M-Pesa callback error:", error);

    return res.status(500).json({
      ResultCode: 1,
      ResultDesc: "Callback processing failed"
    });
  }
});

// =====================================================
// 18. ADMIN LOGIN
// =====================================================

app.post(
  "/api/admin/login",
  asyncRoute(async (req, res) => {
    const email = String(req.body.email || "")
      .trim()
      .toLowerCase();

    const password = String(req.body.password || "");

    if (
      email !== String(process.env.ADMIN_EMAIL).toLowerCase() ||
      !(await bcrypt.compare(
        password,
        process.env.ADMIN_PASSWORD_HASH
      ))
    ) {
      return res.status(401).json({
        error: "Admin email or password is incorrect."
      });
    }

    res.json({
      token: tokenFor("admin", "admin"),

      user: {
        role: "admin",
        email
      }
    });
  })
);

// =====================================================
// 19. ADMIN DASHBOARD DATA
// =====================================================

app.get("/api/admin/data", auth, adminOnly, (req, res) => {
  const users = db.prepare(`
    SELECT id, name, phone, email, expires_at
    FROM users
    ORDER BY created_at DESC
  `).all().map(user => ({
    id: user.id,
    name: user.name,
    phone: user.phone,
    email: user.email,
    expiresAt: user.expires_at,

    subscriptionActive: Boolean(
      user.expires_at &&
      new Date(user.expires_at) > new Date()
    )
  }));

  const payments = db.prepare(`
    SELECT
      p.id,
      p.plan_key,
      p.amount,
      p.phone,
      p.status,
      p.mpesa_receipt,
      p.created_at,
      u.name
    FROM payments p
    JOIN users u ON u.id = p.user_id
    ORDER BY p.created_at DESC
  `).all().map(payment => ({
    ...payment,

    planLabel:
      q.plan.get(payment.plan_key)?.label ||
      payment.plan_key
  }));

  res.json({
    plans: publicPlans(),
    fixtures: q.fixtureList.all(),
    users,
    payments
  });
});

// =====================================================
// 20. ADMIN - ADD FIXTURE
// =====================================================

app.post("/api/admin/fixtures", auth, adminOnly, (req, res) => {
  const body = req.body;

  if (
    !body.league ||
    !body.home ||
    !body.away ||
    !body.prediction
  ) {
    return res.status(400).json({
      error: "League, teams and prediction are required."
    });
  }

  const id = crypto.randomUUID();

  db.prepare(`
    INSERT INTO fixtures(
      id, league, home, away, kickoff, market,
      prediction, odds, analysis, created_at
    )
    VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    String(body.league).slice(0, 80),
    String(body.home).slice(0, 80),
    String(body.away).slice(0, 80),
    body.kickoff || null,
    body.market || "1X2",
    String(body.prediction).slice(0, 120),
    String(body.odds || "").slice(0, 20),
    String(body.analysis || "").slice(0, 2000),
    nowIso()
  );

  res.status(201).json({
    ok: true,
    id
  });
});

// =====================================================
// 21. ADMIN - UPDATE FIXTURE
// =====================================================

app.put("/api/admin/fixtures/:id", auth, adminOnly, (req, res) => {
  const body = req.body;

  const result = db.prepare(`
    UPDATE fixtures
    SET league = ?,
        home = ?,
        away = ?,
        kickoff = ?,
        market = ?,
        prediction = ?,
        odds = ?,
        analysis = ?
    WHERE id = ?
  `).run(
    String(body.league || "").slice(0, 80),
    String(body.home || "").slice(0, 80),
    String(body.away || "").slice(0, 80),
    body.kickoff || null,
    body.market || "1X2",
    String(body.prediction || "").slice(0, 120),
    String(body.odds || "").slice(0, 20),
    String(body.analysis || "").slice(0, 2000),
    req.params.id
  );

  if (!result.changes) {
    return res.status(404).json({
      error: "Fixture not found."
    });
  }

  res.json({ ok: true });
});

// =====================================================
// 22. ADMIN - DELETE FIXTURE
// =====================================================

app.delete("/api/admin/fixtures/:id", auth, adminOnly, (req, res) => {
  const result = db.prepare(
    "DELETE FROM fixtures WHERE id = ?"
  ).run(req.params.id);

  if (!result.changes) {
    return res.status(404).json({
      error: "Fixture not found."
    });
  }

  res.json({ ok: true });
});

// =====================================================
// 23. ADMIN - UPDATE SUBSCRIPTION PRICES
// =====================================================

app.put("/api/admin/plans", auth, adminOnly, (req, res) => {
  const body = req.body;

  const updatePrice = db.prepare(`
    UPDATE plans
    SET price = ?
    WHERE key = ?
  `);

  const updateAll = db.transaction(() => {
    for (const key of ["daily", "weekly", "monthly"]) {
      const amount = Number(body[key]);

      if (
        !Number.isInteger(amount) ||
        amount < 1 ||
        amount > 1000000
      ) {
        throw new Error(
          "Prices must be valid whole KES amounts."
        );
      }

      updatePrice.run(amount, key);
    }
  });

  try {
    updateAll();
  } catch (error) {
    return res.status(400).json({
      error: error.message
    });
  }

  res.json({
    plans: publicPlans()
  });
});

// =====================================================
// 24. ADMIN - REJECT / CLOSE PAYMENT FOR REVIEW
// =====================================================

app.post(
  "/api/admin/payments/:id/reject",
  auth,
  adminOnly,
  (req, res) => {
    const result = db.prepare(`
      UPDATE payments
      SET status = 'failed',
          result_desc = 'Marked for review by administrator',
          updated_at = ?
      WHERE id = ?
        AND status IN ('pending', 'review')
    `).run(
      nowIso(),
      req.params.id
    );

    if (!result.changes) {
      return res.status(404).json({
        error: "Pending or review payment not found."
      });
    }

    res.json({ ok: true });
  }
);

// =====================================================
// 25. FRONTEND STATIC FILES
// =====================================================

app.use(express.static(path.join(__dirname, "public")));

app.get("*", (req, res) => {
  res.sendFile(
    path.join(__dirname, "public", "index.html")
  );
});

// =====================================================
// 26. GLOBAL ERROR HANDLER
// =====================================================

app.use((error, req, res, next) => {
  console.error("Application error:", error);

  if (res.headersSent) {
    return next(error);
  }

  res.status(500).json({
    error: "Server error. Please try again or contact support."
  });
});

// =====================================================
// 27. START SERVER
// =====================================================

app.listen(PORT, () => {
  console.log(
    `Football Tips Hub listening on port ${PORT} (${process.env.DARAJA_ENV || "sandbox"} Daraja mode)`
  );

  console.log(`Database location: ${DB_FILE}`);

  console.log(
    `M-Pesa enabled: ${process.env.DARAJA_ENABLED === "true"}`
  );
});
