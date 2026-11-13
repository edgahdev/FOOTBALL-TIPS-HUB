require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { MongoClient } = require("mongodb");
const crypto = require("crypto");
const path = require("path");

const app = express();
const PORT = Number(process.env.PORT || 3000);

if (!process.env.MONGODB_URI) {
  console.error("FATAL: Set MONGODB_URI to your MongoDB Atlas connection string.");
  process.exit(1);
}
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
    "DARAJA_CONSUMER_KEY", "DARAJA_CONSUMER_SECRET", "DARAJA_PASSKEY",
    "MPESA_SHORTCODE", "MPESA_TILL_NUMBER", "MPESA_CALLBACK_URL"
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
  const transactionType = process.env.MPESA_TRANSACTION_TYPE ||
    (process.env.DARAJA_ENV === "production" ? "CustomerBuyGoodsOnline" : "CustomerPayBillOnline");
  if (!["CustomerPayBillOnline", "CustomerBuyGoodsOnline"].includes(transactionType)) {
    console.error("FATAL: Invalid MPESA_TRANSACTION_TYPE.");
    process.exit(1);
  }
}

app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: false, limit: "20kb" }));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, limit: 30,
  standardHeaders: true, legacyHeaders: false,
  message: { error: "Too many attempts. Please try again later." }
});
const paymentLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, limit: 8,
  standardHeaders: true, legacyHeaders: false,
  message: { error: "Too many payment attempts. Please wait and try again." }
});
const adminLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, limit: 10,
  standardHeaders: true, legacyHeaders: false,
  message: { error: "Too many admin login attempts. Try again later." }
});
app.use("/api/auth", authLimiter);
app.use("/api/payments", paymentLimiter);
app.use("/api/admin/login", adminLoginLimiter);

const client = new MongoClient(process.env.MONGODB_URI, {
  serverSelectionTimeoutMS: 15000,
  connectTimeoutMS: 15000,
  maxPoolSize: 10
});
let db;
let users, plans, fixtures, payments;

const nowIso = () => new Date().toISOString();

async function initializeDatabase() {
  await client.connect();
  db = client.db(process.env.MONGODB_DB_NAME || "football_tips_hub");
  users = db.collection("users");
  plans = db.collection("plans");
  fixtures = db.collection("fixtures");
  payments = db.collection("payments");

  await Promise.all([
    users.createIndex({ phone: 1 }, { unique: true }),
    users.createIndex({ email: 1 }, { unique: true }),
    payments.createIndex({ checkout_request_id: 1 }, { unique: true, sparse: true }),
    payments.createIndex({ mpesa_receipt: 1 }, { unique: true, sparse: true }),
    payments.createIndex({ user_id: 1, created_at: -1 }),
    fixtures.createIndex({ kickoff: 1, created_at: -1 })
  ]);

  const seedPlans = [
    { _id: "daily", label: "Daily access", days: 1, price: 300 },
    { _id: "weekly", label: "Weekly access", days: 7, price: 500 },
    { _id: "monthly", label: "Monthly access", days: 30, price: 1000 }
  ];
  for (const plan of seedPlans) {
    await plans.updateOne({ _id: plan._id }, { $setOnInsert: plan }, { upsert: true });
  }

  if (await fixtures.countDocuments() === 0) {
    const created = nowIso();
    await fixtures.insertMany([
      { _id: "m1", league: "Premier League", home: "Arsenal", away: "Chelsea",
        kickoff: null, market: "Over 1.5 Goals", prediction: "Over 1.5 Goals",
        odds: "1.42", analysis: "Sample only: add your own verified team news and analysis.", created_at: created },
      { _id: "m2", league: "Premier League", home: "Liverpool", away: "Manchester City",
        kickoff: null, market: "BTTS", prediction: "Both Teams To Score — Yes",
        odds: "1.70", analysis: "Sample only: add your own verified team news and analysis.", created_at: created },
      { _id: "m3", league: "La Liga", home: "Barcelona", away: "Sevilla",
        kickoff: null, market: "1X2", prediction: "Barcelona win",
        odds: "1.55", analysis: "Sample only: add your own verified team news and analysis.", created_at: created }
    ]);
  }
  console.log(`MongoDB connected: ${db.databaseName}`);
}

function normalizePhone(raw) {
  let phone = String(raw || "").replace(/[^\d+]/g, "");
  if (phone.startsWith("+")) phone = phone.slice(1);
  if (phone.startsWith("0")) phone = "254" + phone.slice(1);
  if (phone.startsWith("7") || phone.startsWith("1")) phone = "254" + phone;
  if (!/^254[17]\d{8}$/.test(phone)) {
    throw new Error("Enter a valid Kenyan mobile number, e.g. 0712345678.");
  }
  return phone;
}

function tokenFor(id, role = "member") {
  return jwt.sign({ sub: id, role }, process.env.JWT_SECRET, { expiresIn: "7d" });
}
function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    if (!header.startsWith("Bearer ")) throw new Error("Missing token");
    req.auth = jwt.verify(header.slice(7), process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Please log in again." });
  }
}
const adminOnly = (req, res, next) => {
  if (req.auth?.role === "admin") return next();
  return res.status(403).json({ error: "Admin access required." });
};
function safeUser(user) {
  return {
    id: user._id, name: user.name, phone: user.phone, email: user.email,
    expiresAt: user.expires_at || null,
    subscriptionActive: Boolean(user.expires_at && new Date(user.expires_at) > new Date())
  };
}
async function publicPlans() {
  const all = await plans.find({}).toArray();
  return Object.fromEntries(all.map(p => [p._id, { label: p.label, days: p.days, price: p.price }]));
}
async function getPlan(key) { return plans.findOne({ _id: key }); }
function isPaid(user) {
  return Boolean(user?.expires_at && new Date(user.expires_at) > new Date());
}
async function memberFixtures(user) {
  const list = await fixtures.find({}).sort({ kickoff: 1, created_at: -1 }).toArray();
  return list.map(f => {
    const item = { id: f._id, league: f.league, home: f.home, away: f.away,
      kickoff: f.kickoff, market: f.market };
    if (isPaid(user)) Object.assign(item, {
      prediction: f.prediction, odds: f.odds, analysis: f.analysis
    });
    else Object.assign(item, { prediction: null, odds: null, analysis: null });
    return item;
  });
}
function asyncRoute(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

app.get("/api/health", asyncRoute(async (req, res) => {
  await db.command({ ping: 1 });
  res.json({ ok: true, service: "Football Tips Hub", database: "connected" });
}));

app.get("/api/public", asyncRoute(async (req, res) => {
  const list = await fixtures.find({}).sort({ kickoff: 1, created_at: -1 }).toArray();
  res.json({
    plans: await publicPlans(),
    fixtures: list.map(f => ({ id: f._id, league: f.league, home: f.home,
      away: f.away, kickoff: f.kickoff, market: f.market }))
  });
}));

app.post("/api/auth/register", asyncRoute(async (req, res) => {
  const name = String(req.body.name || "").trim();
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  let phone;
  try { phone = normalizePhone(req.body.phone); }
  catch (e) { return res.status(400).json({ error: e.message }); }

  if (name.length < 2 || name.length > 80) return res.status(400).json({ error: "Enter your full name." });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: "Enter a valid email address." });
  if (password.length < 8 || password.length > 100) return res.status(400).json({ error: "Password must be at least 8 characters." });

  const user = { _id: crypto.randomUUID(), name, phone, email,
    password_hash: await bcrypt.hash(password, 12), expires_at: null, created_at: nowIso() };
  try { await users.insertOne(user); }
  catch (e) {
    if (e.code === 11000) return res.status(409).json({ error: "That phone number or email is already registered." });
    throw e;
  }
  res.status(201).json({ token: tokenFor(user._id), user: safeUser(user) });
}));

app.post("/api/auth/login", asyncRoute(async (req, res) => {
  const identity = String(req.body.identity || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  if (!identity || !password) return res.status(400).json({ error: "Enter your email or phone number and password." });
  let phoneIdentity = identity;
  if (!identity.includes("@")) {
    try { phoneIdentity = normalizePhone(identity); } catch { phoneIdentity = ""; }
  }
  const user = await users.findOne({ $or: [{ email: identity }, { phone: phoneIdentity }] });
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({ error: "Email/phone or password is incorrect." });
  }
  res.json({ token: tokenFor(user._id), user: safeUser(user) });
}));

app.get("/api/me", auth, asyncRoute(async (req, res) => {
  if (req.auth.role !== "member") return res.status(403).json({ error: "Member account required." });
  const user = await users.findOne({ _id: req.auth.sub });
  if (!user) return res.status(401).json({ error: "Account not found." });
  const history = await payments.find({ user_id: user._id },
    { projection: { _id: 1, plan_key: 1, amount: 1, status: 1, created_at: 1 } })
    .sort({ created_at: -1 }).toArray();
  res.json({
    user: safeUser(user),
    fixtures: await memberFixtures(user),
    payments: await Promise.all(history.map(async p => ({
      id: p._id, plan_key: p.plan_key, amount: p.amount, status: p.status,
      created_at: p.created_at, planLabel: (await getPlan(p.plan_key))?.label || p.plan_key
    })))
  });
}));

async function darajaToken() {
  const production = process.env.DARAJA_ENV === "production";
  const base = production ? "https://api.safaricom.co.ke" : "https://sandbox.safaricom.co.ke";
  const credentials = Buffer.from(`${process.env.DARAJA_CONSUMER_KEY}:${process.env.DARAJA_CONSUMER_SECRET}`).toString("base64");
  const response = await fetch(`${base}/oauth/v1/generate?grant_type=client_credentials`, {
    headers: { Authorization: `Basic ${credentials}` }, signal: AbortSignal.timeout(20000)
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.access_token) {
    console.error("Daraja authentication failed:", data);
    throw new Error(data.errorMessage || data.error_description || "Daraja authentication failed. Check API credentials and environment.");
  }
  return { base, accessToken: data.access_token };
}
function mpesaTimestamp() {
  const parts = new Intl.DateTimeFormat("en-GB", {
    timeZone: "Africa/Nairobi", year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23"
  }).formatToParts(new Date());
  const v = {};
  for (const p of parts) v[p.type] = p.value;
  return v.year + v.month + v.day + v.hour + v.minute + v.second;
}

app.post("/api/payments/stk", auth, asyncRoute(async (req, res) => {
  if (req.auth.role !== "member") return res.status(403).json({ error: "Members only." });
  if (process.env.DARAJA_ENABLED !== "true") return res.status(503).json({ error: "M-Pesa payments are not enabled. Contact the administrator." });
  const user = await users.findOne({ _id: req.auth.sub });
  if (!user) return res.status(401).json({ error: "Please log in again." });
  const plan = await getPlan(String(req.body.plan || ""));
  if (!plan) return res.status(400).json({ error: "Select a valid subscription plan." });
  let phone;
  try { phone = normalizePhone(req.body.phone || user.phone); }
  catch (e) { return res.status(400).json({ error: e.message }); }

  const id = crypto.randomUUID();
  const created = nowIso();
  await payments.insertOne({ _id: id, user_id: user._id, plan_key: plan._id,
    amount: plan.price, phone, status: "pending", checkout_request_id: null,
    merchant_request_id: null, mpesa_receipt: null, result_code: null,
    result_desc: null, created_at: created, updated_at: created });

  try {
    const { base, accessToken } = await darajaToken();
    const timestamp = mpesaTimestamp();
    const shortcode = process.env.MPESA_SHORTCODE;
    const password = Buffer.from(shortcode + process.env.DARAJA_PASSKEY + timestamp).toString("base64");
    const transactionType = process.env.MPESA_TRANSACTION_TYPE ||
      (process.env.DARAJA_ENV === "production" ? "CustomerBuyGoodsOnline" : "CustomerPayBillOnline");
    const partyB = process.env.MPESA_PARTY_B || process.env.MPESA_TILL_NUMBER || shortcode;
    const payload = {
      BusinessShortCode: shortcode, Password: password, Timestamp: timestamp,
      TransactionType: transactionType, Amount: plan.price, PartyA: phone,
      PartyB: partyB, PhoneNumber: phone, CallBackURL: process.env.MPESA_CALLBACK_URL,
      AccountReference: `FTH${id.replace(/-/g, "").slice(0, 8)}`,
      TransactionDesc: `${plan.label} Football Tips`
    };
    const response = await fetch(`${base}/mpesa/stkpush/v1/processrequest`, {
      method: "POST", headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
      body: JSON.stringify(payload), signal: AbortSignal.timeout(30000)
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok || data.ResponseCode !== "0" || !data.CheckoutRequestID) {
      const message = data.errorMessage || data.ResponseDescription || data.CustomerMessage || "Safaricom did not accept the STK request.";
      await payments.updateOne({ _id: id }, { $set: { status: "failed", result_desc: String(message).slice(0, 250), updated_at: nowIso() } });
      console.error("STK Push rejected:", { httpStatus: response.status, response: data });
      return res.status(502).json({ error: message, paymentId: id });
    }
    await payments.updateOne({ _id: id }, { $set: {
      checkout_request_id: data.CheckoutRequestID,
      merchant_request_id: data.MerchantRequestID || null,
      updated_at: nowIso()
    }});
    return res.status(202).json({ paymentId: id, status: "pending",
      message: "STK request sent. Check your phone and enter your M-Pesa PIN." });
  } catch (e) {
    console.error("STK Push error:", e);
    await payments.updateOne({ _id: id }, { $set: {
      status: "failed", result_desc: String(e.message || "Payment request failed").slice(0, 250),
      updated_at: nowIso()
    }});
    return res.status(502).json({ error: e.message || "Could not start M-Pesa payment. Check server logs.", paymentId: id });
  }
}));

app.get("/api/payments/:id", auth, asyncRoute(async (req, res) => {
  const payment = await payments.findOne({ _id: req.params.id, user_id: req.auth.sub });
  if (!payment) return res.status(404).json({ error: "Payment not found." });
  res.json({ id: payment._id, status: payment.status,
    message: payment.result_desc || null, receipt: payment.mpesa_receipt || null });
}));

app.post("/api/mpesa/callback", asyncRoute(async (req, res) => {
  const body = req.body?.Body?.stkCallback;
  if (!body?.CheckoutRequestID) return res.status(400).json({ ResultCode: 1, ResultDesc: "Invalid callback payload" });
  const payment = await payments.findOne({ checkout_request_id: body.CheckoutRequestID });
  if (!payment) {
    console.error("Callback for unknown checkout:", body.CheckoutRequestID);
    return res.json({ ResultCode: 0, ResultDesc: "Unknown checkout reference" });
  }
  if (payment.status !== "pending") return res.json({ ResultCode: 0, ResultDesc: "Callback already processed" });

  const resultCode = String(body.ResultCode);
  if (resultCode !== "0") {
    await payments.updateOne({ _id: payment._id, status: "pending" }, { $set: {
      status: "failed", result_code: resultCode,
      result_desc: String(body.ResultDesc || "Payment not completed").slice(0, 250),
      updated_at: nowIso()
    }});
    return res.json({ ResultCode: 0, ResultDesc: "Callback processed" });
  }

  const items = body.CallbackMetadata?.Item || [];
  const metadata = Object.fromEntries(items.map(item => [item.Name, item.Value]));
  const amount = Number(metadata.Amount);
  const receipt = String(metadata.MpesaReceiptNumber || "");
  const phone = String(metadata.PhoneNumber || "");
  if (amount !== Number(payment.amount) || !receipt || phone !== payment.phone) {
    await payments.updateOne({ _id: payment._id, status: "pending" }, { $set: {
      status: "review", result_code: resultCode,
      result_desc: "Payment details did not match the order. Manual review required.",
      updated_at: nowIso()
    }});
    return res.json({ ResultCode: 0, ResultDesc: "Payment sent for manual review" });
  }

  // MongoDB Atlas supports transactions on replica sets; payment and membership
  // are committed together so a duplicate callback cannot grant access twice.
  const session = client.startSession();
  try {
    await session.withTransaction(async () => {
      const fresh = await payments.findOne({ _id: payment._id }, { session });
      if (!fresh || fresh.status !== "pending") return;
      const member = await users.findOne({ _id: fresh.user_id }, { session });
      const selectedPlan = await getPlan(fresh.plan_key);
      if (!member || !selectedPlan) throw new Error("Payment user or subscription plan not found.");
      const now = new Date();
      const expiry = member.expires_at ? new Date(member.expires_at) : now;
      const baseDate = expiry > now ? expiry : now;
      baseDate.setDate(baseDate.getDate() + selectedPlan.days);
      await users.updateOne({ _id: member._id }, { $set: { expires_at: baseDate.toISOString() } }, { session });
      await payments.updateOne({ _id: fresh._id, status: "pending" }, { $set: {
        status: "paid", mpesa_receipt: receipt, result_code: "0",
        result_desc: "Payment confirmed by Safaricom", updated_at: nowIso()
      }}, { session });
    });
  } catch (e) {
    console.error("Payment activation transaction failed:", e);
    return res.status(500).json({ ResultCode: 1, ResultDesc: "Payment activation failed" });
  } finally {
    await session.endSession();
  }
  return res.json({ ResultCode: 0, ResultDesc: "Payment processed successfully" });
}));

app.post("/api/admin/login", asyncRoute(async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  if (email !== String(process.env.ADMIN_EMAIL).toLowerCase() ||
      !(await bcrypt.compare(password, process.env.ADMIN_PASSWORD_HASH))) {
    return res.status(401).json({ error: "Admin email or password is incorrect." });
  }
  res.json({ token: tokenFor("admin", "admin"), user: { role: "admin", email } });
}));

app.get("/api/admin/data", auth, adminOnly, asyncRoute(async (req, res) => {
  const [allUsers, allPayments, allFixtures] = await Promise.all([
    users.find({}, { projection: { password_hash: 0 } }).sort({ created_at: -1 }).toArray(),
    payments.find({}).sort({ created_at: -1 }).toArray(),
    fixtures.find({}).sort({ kickoff: 1, created_at: -1 }).toArray()
  ]);
  const userRows = allUsers.map(u => ({ id: u._id, name: u.name, phone: u.phone,
    email: u.email, expiresAt: u.expires_at || null, subscriptionActive: isPaid(u) }));
  const paymentRows = await Promise.all(allPayments.map(async p => {
    const owner = allUsers.find(u => u._id === p.user_id);
    return { id: p._id, plan_key: p.plan_key, amount: p.amount, phone: p.phone,
      status: p.status, mpesa_receipt: p.mpesa_receipt, created_at: p.created_at,
      name: owner?.name || "Unknown user",
      planLabel: (await getPlan(p.plan_key))?.label || p.plan_key };
  }));
  res.json({ plans: await publicPlans(),
    fixtures: allFixtures.map(f => ({ ...f, id: f._id })),
    users: userRows, payments: paymentRows });
}));

app.post("/api/admin/fixtures", auth, adminOnly, asyncRoute(async (req, res) => {
  const b = req.body;
  if (!b.league || !b.home || !b.away || !b.prediction)
    return res.status(400).json({ error: "League, teams and prediction are required." });
  const id = crypto.randomUUID();
  await fixtures.insertOne({ _id: id, league: String(b.league).slice(0, 80),
    home: String(b.home).slice(0, 80), away: String(b.away).slice(0, 80),
    kickoff: b.kickoff || null, market: b.market || "1X2",
    prediction: String(b.prediction).slice(0, 120), odds: String(b.odds || "").slice(0, 20),
    analysis: String(b.analysis || "").slice(0, 2000), created_at: nowIso() });
  res.status(201).json({ ok: true, id });
}));

app.put("/api/admin/fixtures/:id", auth, adminOnly, asyncRoute(async (req, res) => {
  const b = req.body;
  const result = await fixtures.updateOne({ _id: req.params.id }, { $set: {
    league: String(b.league || "").slice(0, 80), home: String(b.home || "").slice(0, 80),
    away: String(b.away || "").slice(0, 80), kickoff: b.kickoff || null,
    market: b.market || "1X2", prediction: String(b.prediction || "").slice(0, 120),
    odds: String(b.odds || "").slice(0, 20), analysis: String(b.analysis || "").slice(0, 2000)
  }});
  if (!result.matchedCount) return res.status(404).json({ error: "Fixture not found." });
  res.json({ ok: true });
}));

app.delete("/api/admin/fixtures/:id", auth, adminOnly, asyncRoute(async (req, res) => {
  const result = await fixtures.deleteOne({ _id: req.params.id });
  if (!result.deletedCount) return res.status(404).json({ error: "Fixture not found." });
  res.json({ ok: true });
}));

app.put("/api/admin/plans", auth, adminOnly, asyncRoute(async (req, res) => {
  const b = req.body;
  for (const key of ["daily", "weekly", "monthly"]) {
    const amount = Number(b[key]);
    if (!Number.isInteger(amount) || amount < 1 || amount > 1000000)
      return res.status(400).json({ error: "Prices must be valid whole KES amounts." });
  }
  await Promise.all(["daily", "weekly", "monthly"].map(key =>
    plans.updateOne({ _id: key }, { $set: { price: Number(b[key]) } })));
  res.json({ plans: await publicPlans() });
}));

app.post("/api/admin/payments/:id/reject", auth, adminOnly, asyncRoute(async (req, res) => {
  const result = await payments.updateOne({ _id: req.params.id, status: { $in: ["pending", "review"] } },
    { $set: { status: "failed", result_desc: "Marked for review by administrator", updated_at: nowIso() } });
  if (!result.modifiedCount) return res.status(404).json({ error: "Pending or review payment not found." });
  res.json({ ok: true });
}));

app.use(express.static(path.join(__dirname, "public")));
app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

app.use((error, req, res, next) => {
  console.error("Application error:", error);
  if (res.headersSent) return next(error);
  if (error.code === 11000) return res.status(409).json({ error: "A record with those details already exists." });
  res.status(500).json({ error: "Server error. Please try again or contact support." });
});

initializeDatabase()
  .then(() => app.listen(PORT, () => {
    console.log(`Football Tips Hub listening on port ${PORT} (${process.env.DARAJA_ENV || "sandbox"} Daraja mode)`);
    console.log(`MongoDB database: ${process.env.MONGODB_DB_NAME || "football_tips_hub"}`);
    console.log(`M-Pesa enabled: ${process.env.DARAJA_ENABLED === "true"}`);
  }))
  .catch(error => {
    console.error("FATAL: Could not connect to MongoDB:", error);
    process.exit(1);
  });

process.on("SIGTERM", async () => {
  await client.close();
  process.exit(0);
});
