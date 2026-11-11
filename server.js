require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DB_FILE = process.env.DB_FILE || path.join(__dirname, "data", "football-tips.sqlite");
const fs = require("fs");
fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });

if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
  console.error("FATAL: Set a random JWT_SECRET of at least 32 characters in .env");
  process.exit(1);
}
const required = ["DARAJA_CONSUMER_KEY","DARAJA_CONSUMER_SECRET","DARAJA_PASSKEY","MPESA_SHORTCODE","MPESA_TILL_NUMBER","MPESA_CALLBACK_URL"];
if (process.env.DARAJA_ENABLED === "true") {
  for (const k of required) if (!process.env[k]) { console.error(`FATAL: Missing ${k}`); process.exit(1); }
  if (!process.env.MPESA_CALLBACK_URL.startsWith("https://")) { console.error("FATAL: MPESA_CALLBACK_URL must be public HTTPS"); process.exit(1); }
}
if (!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD_HASH) {
  console.error("FATAL: Set ADMIN_EMAIL and ADMIN_PASSWORD_HASH in .env");
  process.exit(1);
}

app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: false, limit: "20kb" }));
app.use("/api/auth", rateLimit({ windowMs: 15*60*1000, limit: 30, standardHeaders: true, legacyHeaders: false }));
app.use("/api/payments", rateLimit({ windowMs: 10*60*1000, limit: 8, standardHeaders: true, legacyHeaders: false }));

const db = new Database(DB_FILE);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id TEXT PRIMARY KEY, name TEXT NOT NULL, phone TEXT NOT NULL UNIQUE,
 email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
 expires_at TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS plans(
 key TEXT PRIMARY KEY, label TEXT NOT NULL, days INTEGER NOT NULL,
 price INTEGER NOT NULL CHECK(price > 0)
);
CREATE TABLE IF NOT EXISTS fixtures(
 id TEXT PRIMARY KEY, league TEXT NOT NULL, home TEXT NOT NULL, away TEXT NOT NULL,
 kickoff TEXT, market TEXT, prediction TEXT, odds TEXT, analysis TEXT,
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS payments(
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
 plan_key TEXT NOT NULL, amount INTEGER NOT NULL, phone TEXT NOT NULL,
 status TEXT NOT NULL, checkout_request_id TEXT UNIQUE, merchant_request_id TEXT,
 mpesa_receipt TEXT UNIQUE, result_code TEXT, result_desc TEXT,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
`);
const seedPlans = [
 ["daily","Daily access",1,300],["weekly","Weekly access",7,500],["monthly","Monthly access",30,1000]
];
for (const p of seedPlans) db.prepare("INSERT OR IGNORE INTO plans(key,label,days,price) VALUES(?,?,?,?)").run(...p);
const fixtureCount = db.prepare("SELECT COUNT(*) n FROM fixtures").get().n;
if (!fixtureCount) {
 const ins = db.prepare("INSERT INTO fixtures(id,league,home,away,kickoff,market,prediction,odds,analysis,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)");
 const now = new Date().toISOString();
 [
 ["m1","Premier League","Arsenal","Chelsea",null,"Over 1.5 Goals","Over 1.5 Goals","1.42","Sample only: add your own verified team news and analysis."],
 ["m2","Premier League","Liverpool","Manchester City",null,"BTTS","Both Teams To Score — Yes","1.70","Sample only: add your own verified team news and analysis."],
 ["m3","La Liga","Barcelona","Sevilla",null,"1X2","Barcelona win","1.55","Sample only: add your own verified team news and analysis."]
 ].forEach(x=>ins.run(...x,now));
}
const q = {
 userById: db.prepare("SELECT * FROM users WHERE id=?"),
 plans: db.prepare("SELECT key,label,days,price FROM plans"),
 plan: db.prepare("SELECT * FROM plans WHERE key=?"),
 fixtureList: db.prepare("SELECT * FROM fixtures ORDER BY COALESCE(kickoff,'9999') ASC, created_at DESC"),
 paymentById: db.prepare("SELECT * FROM payments WHERE id=?"),
 paymentByCheckout: db.prepare("SELECT * FROM payments WHERE checkout_request_id=?"),
 updateExpiry: db.prepare("UPDATE users SET expires_at=? WHERE id=?")
};
const nowIso=()=>new Date().toISOString();
const normalizePhone = raw => {
 let p=String(raw||"").replace(/[^\d+]/g,"");
 if(p.startsWith("+"))p=p.slice(1);
 if(p.startsWith("0"))p="254"+p.slice(1);
 if(p.startsWith("7")||p.startsWith("1"))p="254"+p;
 if(!/^254[17]\d{8}$/.test(p)) throw new Error("Enter a valid Kenyan Safaricom number, e.g. 0712345678.");
 return p;
};
const tokenFor=(id,role="member")=>jwt.sign({sub:id,role},process.env.JWT_SECRET,{expiresIn:"7d"});
function auth(req,res,next){
 const h=req.headers.authorization||"";
 try{if(!h.startsWith("Bearer "))throw 0;req.auth=jwt.verify(h.slice(7),process.env.JWT_SECRET);next()}
 catch{return res.status(401).json({error:"Please log in again."})}
}
const adminOnly=(req,res,next)=>req.auth?.role==="admin"?next():res.status(403).json({error:"Admin access required."});
const safeUser=u=>({id:u.id,name:u.name,phone:u.phone,email:u.email,expiresAt:u.expires_at,subscriptionActive:!!(u.expires_at&&new Date(u.expires_at)>new Date())});
const publicPlans=()=>Object.fromEntries(q.plans.all().map(p=>[p.key,{label:p.label,days:p.days,price:p.price}]));
const isPaid=u=>!!(u.expires_at&&new Date(u.expires_at)>new Date());
function memberFixtures(u){return q.fixtureList.all().map(f=>isPaid(u)?f:{id:f.id,league:f.league,home:f.home,away:f.away,kickoff:f.kickoff,market:f.market,prediction:null,odds:null,analysis:null})}
function asyncRoute(fn){return (req,res,next)=>Promise.resolve(fn(req,res,next)).catch(next)}

app.get("/api/health",(req,res)=>res.json({ok:true,service:"Football Tips Hub"}));
app.get("/api/public",(req,res)=>res.json({plans:publicPlans(),fixtures:q.fixtureList.all().map(f=>({id:f.id,league:f.league,home:f.home,away:f.away,kickoff:f.kickoff,market:f.market}))}));

app.post("/api/auth/register",asyncRoute(async(req,res)=>{
 const name=String(req.body.name||"").trim(),email=String(req.body.email||"").trim().toLowerCase(),password=String(req.body.password||"");
 let phone;try{phone=normalizePhone(req.body.phone)}catch(e){return res.status(400).json({error:e.message})}
 if(name.length<2||name.length>80)return res.status(400).json({error:"Enter your full name."});
 if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))return res.status(400).json({error:"Enter a valid email address."});
 if(password.length<8||password.length>100)return res.status(400).json({error:"Password must be at least 8 characters."});
 const hash=await bcrypt.hash(password,12),id=crypto.randomUUID();
 try{db.prepare("INSERT INTO users(id,name,phone,email,password_hash,created_at) VALUES(?,?,?,?,?,?)").run(id,name,phone,email,hash,nowIso())}
 catch(e){if(String(e).includes("UNIQUE"))return res.status(409).json({error:"That phone number or email is already registered."});throw e}
 res.status(201).json({token:tokenFor(id),user:safeUser(q.userById.get(id))});
}));
app.post("/api/auth/login",asyncRoute(async(req,res)=>{
 const identity=String(req.body.identity||"").trim().toLowerCase(),password=String(req.body.password||"");
 const u=db.prepare("SELECT * FROM users WHERE lower(email)=? OR phone=?").get(identity,identity);
 if(!u||!(await bcrypt.compare(password,u.password_hash)))return res.status(401).json({error:"Email/phone or password is incorrect."});
 res.json({token:tokenFor(u.id),user:safeUser(u)});
}));
app.get("/api/me",auth,(req,res)=>{
 if(req.auth.role!=="member")return res.status(403).json({error:"Member account required."});
 const u=q.userById.get(req.auth.sub);if(!u)return res.status(401).json({error:"Account not found."});
 const payments=db.prepare("SELECT id,plan_key,amount,status,created_at FROM payments WHERE user_id=? ORDER BY created_at DESC").all(u.id);
 res.json({user:safeUser(u),fixtures:memberFixtures(u),payments:payments.map(p=>({...p,planLabel:q.plan.get(p.plan_key)?.label||p.plan_key}))});
});

async function darajaToken(){
 const base=process.env.DARAJA_ENV==="production"?"https://api.safaricom.co.ke":"https://sandbox.safaricom.co.ke";
 const auth=Buffer.from(`${process.env.DARAJA_CONSUMER_KEY}:${process.env.DARAJA_CONSUMER_SECRET}`).toString("base64");
 const r=await fetch(`${base}/oauth/v1/generate?grant_type=client_credentials`,{headers:{Authorization:`Basic ${auth}`}});
 const d=await r.json();if(!r.ok||!d.access_token)throw new Error(d.errorMessage||"Could not authenticate with Daraja.");
 return {base,accessToken:d.access_token};
}
function mpesaTimestamp(){const d=new Date();return d.getFullYear()+String(d.getMonth()+1).padStart(2,"0")+String(d.getDate()).padStart(2,"0")+String(d.getHours()).padStart(2,"0")+String(d.getMinutes()).padStart(2,"0")+String(d.getSeconds()).padStart(2,"0")}
app.post("/api/payments/stk",auth,asyncRoute(async(req,res)=>{
 if(req.auth.role!=="member")return res.status(403).json({error:"Members only."});
 if(process.env.DARAJA_ENABLED!=="true")return res.status(503).json({error:"M-Pesa payments are not enabled yet. Ask the site administrator."});
 const user=q.userById.get(req.auth.sub);if(!user)return res.status(401).json({error:"Please log in again."});
 const plan=q.plan.get(String(req.body.plan||""));if(!plan)return res.status(400).json({error:"Select a valid subscription plan."});
 let phone;try{phone=normalizePhone(req.body.phone||user.phone)}catch(e){return res.status(400).json({error:e.message})}
 const id=crypto.randomUUID(),created=nowIso();
 db.prepare("INSERT INTO payments(id,user_id,plan_key,amount,phone,status,created_at,updated_at) VALUES(?,?,?,?,?,'pending',?,?)").run(id,user.id,plan.key,plan.price,phone,created,created);
 try{
  const {base,accessToken}=await darajaToken(),timestamp=mpesaTimestamp();
  const shortcode=process.env.MPESA_SHORTCODE,passkey=process.env.DARAJA_PASSKEY;
  const password=Buffer.from(shortcode+passkey+timestamp).toString("base64");
  const payload={
   BusinessShortCode:shortcode,Password:password,Timestamp:timestamp,
   TransactionType:"CustomerBuyGoodsOnline",Amount:plan.price,
   PartyA:phone,PartyB:process.env.MPESA_TILL_NUMBER,PhoneNumber:phone,
   CallBackURL:process.env.MPESA_CALLBACK_URL,
   AccountReference:`FTH${id.replace(/-/g,"").slice(0,8)}`,
   TransactionDesc:`${plan.label} Football Tips`
  };
  const r=await fetch(`${base}/mpesa/stkpush/v1/processrequest`,{method:"POST",headers:{Authorization:`Bearer ${accessToken}`,"Content-Type":"application/json"},body:JSON.stringify(payload)});
  const d=await r.json();
  if(!r.ok||d.ResponseCode!=="0"||!d.CheckoutRequestID){
   db.prepare("UPDATE payments SET status='failed',result_desc=?,updated_at=? WHERE id=?").run(d.errorMessage||d.ResponseDescription||"Daraja did not accept the STK request.",nowIso(),id);
   return res.status(502).json({error:d.errorMessage||d.ResponseDescription||"Safaricom rejected the STK request. Check Daraja configuration."});
  }
  db.prepare("UPDATE payments SET checkout_request_id=?,merchant_request_id=?,updated_at=? WHERE id=?").run(d.CheckoutRequestID,d.MerchantRequestID||null,nowIso(),id);
  res.status(202).json({paymentId:id,status:"pending",message:"STK request sent. Check your phone and enter your M-Pesa PIN."});
 }catch(e){
  db.prepare("UPDATE payments SET status='failed',result_desc=?,updated_at=? WHERE id=?").run(e.message,nowIso(),id);
  throw e;
 }
}));
app.get("/api/payments/:id",auth,(req,res)=>{
 const p=q.paymentById.get(req.params.id);if(!p||p.user_id!==req.auth.sub)return res.status(404).json({error:"Payment not found."});
 res.json({id:p.id,status:p.status,message:p.result_desc||null,receipt:p.mpesa_receipt||null});
});

// Safaricom sends this callback. Do not trust the browser to mark a payment as paid.
app.post("/api/mpesa/callback",(req,res)=>{
 try{
  const body=req.body?.Body?.stkCallback;
  if(!body?.CheckoutRequestID)return res.json({ResultCode:0,ResultDesc:"Accepted"});
  const p=q.paymentByCheckout.get(body.CheckoutRequestID);
  if(!p)return res.json({ResultCode:0,ResultDesc:"Unknown checkout reference recorded"});
  const resultCode=String(body.ResultCode);
  if(resultCode!=="0"){
   db.prepare("UPDATE payments SET status='failed',result_code=?,result_desc=?,updated_at=? WHERE id=? AND status='pending'").run(resultCode,String(body.ResultDesc||"Payment not completed").slice(0,250),nowIso(),p.id);
   return res.json({ResultCode:0,ResultDesc:"Callback processed"});
  }
  const items=body.CallbackMetadata?.Item||[];
  const meta=Object.fromEntries(items.map(x=>[x.Name,x.Value]));
  const amount=Number(meta.Amount),receipt=String(meta.MpesaReceiptNumber||"");
  const phone=String(meta.PhoneNumber||"");
  if(amount!==Number(p.amount)||!receipt||(phone&&phone!==p.phone)){
   db.prepare("UPDATE payments SET status='review',result_code=?,result_desc=?,updated_at=? WHERE id=?").run(resultCode,"Payment callback details did not match the order; manual review required.",nowIso(),p.id);
   return res.json({ResultCode:0,ResultDesc:"Payment sent for review"});
  }
  const transaction=db.transaction(()=>{
   const fresh=q.paymentById.get(p.id);if(!fresh||fresh.status!=="pending")return;
   const u=q.userById.get(fresh.user_id),plan=q.plan.get(fresh.plan_key);if(!u||!plan)return;
   const now=new Date(),old=u.expires_at?new Date(u.expires_at):now,base=old>now?old:now;
   base.setDate(base.getDate()+plan.days);
   db.prepare("UPDATE users SET expires_at=? WHERE id=?").run(base.toISOString(),u.id);
   db.prepare("UPDATE payments SET status='paid',mpesa_receipt=?,result_code='0',result_desc='Payment confirmed by Safaricom',updated_at=? WHERE id=?").run(receipt,nowIso(),p.id);
  });
  try{transaction()}catch(e){console.error("Payment activation transaction failed",e)}
  res.json({ResultCode:0,ResultDesc:"Callback processed"});
 }catch(e){console.error("M-Pesa callback error",e);res.status(200).json({ResultCode:0,ResultDesc:"Callback received"})}
});

app.post("/api/admin/login",asyncRoute(async(req,res)=>{
 const email=String(req.body.email||"").trim().toLowerCase(),password=String(req.body.password||"");
 if(email!==String(process.env.ADMIN_EMAIL).toLowerCase()||!(await bcrypt.compare(password,process.env.ADMIN_PASSWORD_HASH)))return res.status(401).json({error:"Admin email or password is incorrect."});
 res.json({token:tokenFor("admin","admin"),user:{role:"admin",email}});
}));
app.get("/api/admin/data",auth,adminOnly,(req,res)=>{
 const users=db.prepare("SELECT id,name,phone,email,expires_at FROM users ORDER BY created_at DESC").all().map(u=>({...{id:u.id,name:u.name,phone:u.phone,email:u.email,expiresAt:u.expires_at},subscriptionActive:!!(u.expires_at&&new Date(u.expires_at)>new Date())}));
 const payments=db.prepare("SELECT p.id,p.plan_key,p.amount,p.phone,p.status,p.mpesa_receipt,p.created_at,u.name FROM payments p JOIN users u ON u.id=p.user_id ORDER BY p.created_at DESC").all().map(p=>({...p,planLabel:q.plan.get(p.plan_key)?.label||p.plan_key}));
 res.json({plans:publicPlans(),fixtures:q.fixtureList.all(),users,payments});
});
app.post("/api/admin/fixtures",auth,adminOnly,(req,res)=>{
 const b=req.body;if(!b.league||!b.home||!b.away||!b.prediction)return res.status(400).json({error:"League, teams and prediction are required."});
 const id=crypto.randomUUID();db.prepare("INSERT INTO fixtures(id,league,home,away,kickoff,market,prediction,odds,analysis,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)").run(id,String(b.league).slice(0,80),String(b.home).slice(0,80),String(b.away).slice(0,80),b.kickoff||null,b.market||"1X2",String(b.prediction).slice(0,120),String(b.odds||"").slice(0,20),String(b.analysis||"").slice(0,2000),nowIso());res.status(201).json({ok:true,id});
});
app.put("/api/admin/fixtures/:id",auth,adminOnly,(req,res)=>{
 const b=req.body;const r=db.prepare("UPDATE fixtures SET league=?,home=?,away=?,kickoff=?,market=?,prediction=?,odds=?,analysis=? WHERE id=?").run(String(b.league||"").slice(0,80),String(b.home||"").slice(0,80),String(b.away||"").slice(0,80),b.kickoff||null,b.market||"1X2",String(b.prediction||"").slice(0,120),String(b.odds||"").slice(0,20),String(b.analysis||"").slice(0,2000),req.params.id);if(!r.changes)return res.status(404).json({error:"Fixture not found."});res.json({ok:true});
});
app.delete("/api/admin/fixtures/:id",auth,adminOnly,(req,res)=>{db.prepare("DELETE FROM fixtures WHERE id=?").run(req.params.id);res.json({ok:true})});
app.put("/api/admin/plans",auth,adminOnly,(req,res)=>{
 const b=req.body;for(const k of ["daily","weekly","monthly"]){const n=Number(b[k]);if(!Number.isInteger(n)||n<1||n>1000000)return res.status(400).json({error:"Prices must be valid whole KES amounts."});db.prepare("UPDATE plans SET price=? WHERE key=?").run(n,k)}res.json({plans:publicPlans()});
});
app.post("/api/admin/payments/:id/reject",auth,adminOnly,(req,res)=>{
 const r=db.prepare("UPDATE payments SET status='failed',result_desc='Marked for review by administrator',updated_at=? WHERE id=? AND status IN ('pending','review')").run(nowIso(),req.params.id);if(!r.changes)return res.status(404).json({error:"Pending payment not found."});res.json({ok:true});
});
app.use(express.static(path.join(__dirname,"public")));
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.use((err,req,res,next)=>{console.error(err);if(res.headersSent)return next(err);res.status(500).json({error:"Server error. Please try again or contact support."})});
app.listen(PORT,()=>console.log(`Football Tips Hub listening on port ${PORT} (${process.env.DARAJA_ENV||"sandbox"} Daraja mode)`));
