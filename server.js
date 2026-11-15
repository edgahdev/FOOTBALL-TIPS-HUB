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
const TILL_NUMBER = process.env.MPESA_TILL_NUMBER || "1868026";
const TILL_NAME = process.env.MPESA_TILL_NAME || "MEGASUCCEED AGENCIES";
if (!process.env.MONGODB_URI) throw new Error("Set MONGODB_URI in environment variables.");
if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) throw new Error("JWT_SECRET must be at least 32 characters.");
if (!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD_HASH) throw new Error("Set ADMIN_EMAIL and ADMIN_PASSWORD_HASH.");
if (process.env.DARAJA_ENABLED === "true") {
  for (const k of ["DARAJA_CONSUMER_KEY","DARAJA_CONSUMER_SECRET","DARAJA_PASSKEY","MPESA_SHORTCODE","MPESA_CALLBACK_URL"]) if (!process.env[k]) throw new Error(`Missing ${k}`);
  if (!process.env.MPESA_CALLBACK_URL.startsWith("https://")) throw new Error("MPESA_CALLBACK_URL must be HTTPS.");
}
app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: false, limit: "20kb" }));
const authLimiter = rateLimit({windowMs:15*60*1000,limit:30,standardHeaders:true,legacyHeaders:false,message:{error:"Too many attempts. Try again later."}});
const payLimiter = rateLimit({windowMs:10*60*1000,limit:10,standardHeaders:true,legacyHeaders:false,message:{error:"Too many payment attempts. Wait and try again."}});
const adminLimiter = rateLimit({windowMs:15*60*1000,limit:10,standardHeaders:true,legacyHeaders:false});
app.use("/api/auth",authLimiter); app.use("/api/payments",payLimiter); app.use("/api/admin/login",adminLimiter);
const client = new MongoClient(process.env.MONGODB_URI,{serverSelectionTimeoutMS:15000,connectTimeoutMS:15000,maxPoolSize:10});
let db,users,plans,fixtures,payments,notifications;
const now = () => new Date(); const iso = () => now().toISOString();
const asyncRoute = fn => (req,res,next)=>Promise.resolve(fn(req,res,next)).catch(next);
function normalizePhone(raw){let p=String(raw||"").replace(/[^\d+]/g,"");if(p.startsWith("+"))p=p.slice(1);if(p.startsWith("0"))p="254"+p.slice(1);if(p.startsWith("7")||p.startsWith("1"))p="254"+p;if(!/^254[17]\d{8}$/.test(p))throw new Error("Enter a valid Kenyan mobile number, e.g. 0712345678.");return p;}
function tokenFor(id,role="member"){return jwt.sign({sub:id,role},process.env.JWT_SECRET,{expiresIn:"7d"});}
function auth(req,res,next){try{const h=req.headers.authorization||"";if(!h.startsWith("Bearer "))throw 0;req.auth=jwt.verify(h.slice(7),process.env.JWT_SECRET);next();}catch{return res.status(401).json({error:"Please log in again."});}}
const adminOnly=(req,res,next)=>req.auth?.role==="admin"?next():res.status(403).json({error:"Admin access required."});
function isPaid(u){return !!(u?.expires_at && new Date(u.expires_at)>now());}
function safeUser(u){return {id:u._id,name:u.name,phone:u.phone,email:u.email,expiresAt:u.expires_at||null,subscriptionActive:isPaid(u)};}
async function publicPlans(){const a=await plans.find({}).toArray();return Object.fromEntries(a.map(p=>[p._id,{label:p.label,days:p.days,price:p.price}]));}
const getPlan=key=>plans.findOne({_id:key});
async function memberFixtures(user){const rows=await fixtures.find({}).sort({kickoff:1,created_at:-1}).toArray();return rows.map(f=>{const x={id:f._id,league:f.league,home:f.home,away:f.away,kickoff:f.kickoff,market:f.market};if(isPaid(user))Object.assign(x,{prediction:f.prediction,odds:f.odds,analysis:f.analysis});else Object.assign(x,{prediction:null,odds:null,analysis:null});return x;});}
async function createExpiryNotice(user){if(!user.expires_at)return;const expiry=new Date(user.expires_at);if(expiry<=now())await notifications.updateOne({user_id:user._id,type:"subscription_expired",expires_at:user.expires_at},{$setOnInsert:{_id:crypto.randomUUID(),user_id:user._id,type:"subscription_expired",title:"Your subscription has expired",message:"Your access to premium predictions has ended. Choose a plan and subscribe again to unlock the latest odds and analysis.",expires_at:user.expires_at,created_at:iso(),read:false}},{upsert:true});}
async function activatePayment(paymentId,receipt,source="safaricom"){
  const session=client.startSession();
  try{await session.withTransaction(async()=>{
    const p=await payments.findOne({_id:paymentId},{session}); if(!p||p.status!=="pending"&&p.status!=="review")return;
    const duplicate=await payments.findOne({mpesa_receipt:receipt,_id:{$ne:p._id}},{session});if(duplicate)throw new Error("This M-Pesa transaction code has already been used.");
    const u=await users.findOne({_id:p.user_id},{session});const plan=await plans.findOne({_id:p.plan_key},{session});if(!u||!plan)throw new Error("Member or subscription plan not found.");
    const currentExpiry=u.expires_at?new Date(u.expires_at):now();const start=currentExpiry>now()?currentExpiry:now();start.setDate(start.getDate()+plan.days);
    await users.updateOne({_id:u._id},{$set:{expires_at:start.toISOString(),updated_at:iso()}},{session});
    await payments.updateOne({_id:p._id,status:{$in:["pending","review"]}},{$set:{status:"paid",mpesa_receipt:receipt,verified_by:source,result_desc:source==="admin"?"Manually verified and approved by admin":"Payment confirmed by Safaricom",approved_at:iso(),updated_at:iso()}},{session});
    await notifications.insertOne({_id:crypto.randomUUID(),user_id:u._id,type:"payment_approved",title:"Payment approved",message:`Your ${plan.label} subscription is active until ${start.toLocaleString("en-KE")}. Enjoy the tips!`,created_at:iso(),read:false},{session});
  });}finally{await session.endSession();}
}
async function initializeDatabase(){
 await client.connect();db=client.db(process.env.MONGODB_DB_NAME||"football_tips_hub");users=db.collection("users");plans=db.collection("plans");fixtures=db.collection("fixtures");payments=db.collection("payments");notifications=db.collection("notifications");
 await Promise.all([users.createIndex({phone:1},{unique:true}),users.createIndex({email:1},{unique:true}),payments.createIndex({checkout_request_id:1},{unique:true,sparse:true}),payments.createIndex({mpesa_receipt:1},{unique:true,sparse:true}),payments.createIndex({manual_receipt:1},{unique:true,sparse:true}),payments.createIndex({user_id:1,created_at:-1}),fixtures.createIndex({kickoff:1,created_at:-1}),notifications.createIndex({user_id:1,created_at:-1})]);
 const seed=[{_id:"daily",label:"Daily access",days:1,price:300},{_id:"weekly",label:"Weekly access",days:7,price:500},{_id:"monthly",label:"Monthly access",days:30,price:1000}];for(const p of seed)await plans.updateOne({_id:p._id},{$setOnInsert:p},{upsert:true});
 if(await fixtures.countDocuments()===0){const t=iso();await fixtures.insertMany([{_id:"m1",league:"Premier League",home:"Arsenal",away:"Chelsea",kickoff:null,market:"Over 1.5 Goals",prediction:"Sample prediction — edit this",odds:"1.42",analysis:"Sample fixture. Replace with your own researched analysis.",created_at:t},{_id:"m2",league:"Premier League",home:"Liverpool",away:"Manchester City",kickoff:null,market:"BTTS",prediction:"Sample prediction — edit this",odds:"1.70",analysis:"Sample fixture. Replace with your own researched analysis.",created_at:t}]);}
 console.log(`MongoDB connected: ${db.databaseName}`);
}
app.get("/api/health",asyncRoute(async(req,res)=>{await db.command({ping:1});res.json({ok:true,database:"connected",mpesaEnabled:process.env.DARAJA_ENABLED==="true"});}));
app.get("/api/public",asyncRoute(async(req,res)=>{const a=await fixtures.find({}).sort({kickoff:1,created_at:-1}).toArray();res.json({plans:await publicPlans(),fixtures:a.map(f=>({id:f._id,league:f.league,home:f.home,away:f.away,kickoff:f.kickoff,market:f.market}))});}));
app.post("/api/auth/register",asyncRoute(async(req,res)=>{const name=String(req.body.name||"").trim(),email=String(req.body.email||"").trim().toLowerCase(),password=String(req.body.password||"");let phone;try{phone=normalizePhone(req.body.phone);}catch(e){return res.status(400).json({error:e.message});}if(name.length<2||name.length>80)return res.status(400).json({error:"Enter your full name."});if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))return res.status(400).json({error:"Enter a valid email."});if(password.length<8||password.length>100)return res.status(400).json({error:"Password must be at least 8 characters."});const u={_id:crypto.randomUUID(),name,phone,email,password_hash:await bcrypt.hash(password,12),expires_at:null,created_at:iso()};try{await users.insertOne(u);}catch(e){if(e.code===11000)return res.status(409).json({error:"That phone number or email is already registered."});throw e;}res.status(201).json({token:tokenFor(u._id),user:safeUser(u)});}));
app.post("/api/auth/login",asyncRoute(async(req,res)=>{const identity=String(req.body.identity||"").trim().toLowerCase(),password=String(req.body.password||"");let ph="";if(!identity.includes("@")){try{ph=normalizePhone(identity);}catch{}}const u=await users.findOne({$or:[{email:identity},{phone:ph}]});if(!u||!(await bcrypt.compare(password,u.password_hash)))return res.status(401).json({error:"Email/phone or password is incorrect."});res.json({token:tokenFor(u._id),user:safeUser(u)});}));
app.get("/api/me",auth,asyncRoute(async(req,res)=>{if(req.auth.role!=="member")return res.status(403).json({error:"Member account required."});const u=await users.findOne({_id:req.auth.sub});if(!u)return res.status(401).json({error:"Account not found."});await createExpiryNotice(u);const history=await payments.find({user_id:u._id}).sort({created_at:-1}).toArray();const notes=await notifications.find({user_id:u._id}).sort({created_at:-1}).limit(20).toArray();res.json({user:safeUser(u),fixtures:await memberFixtures(u),plans:await publicPlans(),payments:await Promise.all(history.map(async p=>({id:p._id,plan_key:p.plan_key,amount:p.amount,status:p.status,method:p.method||"stk",receipt:p.mpesa_receipt||p.manual_receipt||null,created_at:p.created_at,planLabel:(await getPlan(p.plan_key))?.label||p.plan_key}))),notifications:notes.map(n=>({id:n._id,title:n.title,message:n.message,read:n.read,created_at:n.created_at,type:n.type}))});}));
async function darajaToken(){const prod=process.env.DARAJA_ENV==="production",base=prod?"https://api.safaricom.co.ke":"https://sandbox.safaricom.co.ke",authz=Buffer.from(`${process.env.DARAJA_CONSUMER_KEY}:${process.env.DARAJA_CONSUMER_SECRET}`).toString("base64");const r=await fetch(`${base}/oauth/v1/generate?grant_type=client_credentials`,{headers:{Authorization:`Basic ${authz}`},signal:AbortSignal.timeout(20000)});const d=await r.json().catch(()=>({}));if(!r.ok||!d.access_token)throw new Error(d.errorMessage||d.error_description||"Daraja authentication failed.");return{base,accessToken:d.access_token};}
function mpesaTimestamp(){const a=new Intl.DateTimeFormat("en-GB",{timeZone:"Africa/Nairobi",year:"numeric",month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit",second:"2-digit",hourCycle:"h23"}).formatToParts(new Date()),v={};for(const x of a)v[x.type]=x.value;return v.year+v.month+v.day+v.hour+v.minute+v.second;}
app.post("/api/payments/stk",auth,asyncRoute(async(req,res)=>{if(req.auth.role!=="member")return res.status(403).json({error:"Members only."});if(process.env.DARAJA_ENABLED!=="true")return res.status(503).json({error:"STK Push is not enabled. Use manual Till payment or contact admin."});const u=await users.findOne({_id:req.auth.sub}),plan=await getPlan(String(req.body.plan||""));if(!u)return res.status(401).json({error:"Please log in again."});if(!plan)return res.status(400).json({error:"Select a valid plan."});let phone;try{phone=normalizePhone(req.body.phone||u.phone);}catch(e){return res.status(400).json({error:e.message});}const id=crypto.randomUUID(),t=iso();await payments.insertOne({_id:id,user_id:u._id,plan_key:plan._id,amount:plan.price,phone,method:"stk",status:"pending",created_at:t,updated_at:t});try{const {base,accessToken}=await darajaToken(),timestamp=mpesaTimestamp(),shortcode=process.env.MPESA_SHORTCODE,password=Buffer.from(shortcode+process.env.DARAJA_PASSKEY+timestamp).toString("base64"),type=process.env.MPESA_TRANSACTION_TYPE||(process.env.DARAJA_ENV==="production"?"CustomerBuyGoodsOnline":"CustomerBuyGoodsOnline"),partyB=process.env.MPESA_PARTY_B||process.env.MPESA_TILL_NUMBER||shortcode;const payload={BusinessShortCode:shortcode,Password:password,Timestamp:timestamp,TransactionType:type,Amount:Math.round(plan.price),PartyA:phone,PartyB:partyB,PhoneNumber:phone,CallBackURL:process.env.MPESA_CALLBACK_URL,AccountReference:`FTH${id.replace(/-/g,"").slice(0,8)}`,TransactionDesc:`${plan.label} Football Tips`};const r=await fetch(`${base}/mpesa/stkpush/v1/processrequest`,{method:"POST",headers:{Authorization:`Bearer ${accessToken}`,"Content-Type":"application/json"},body:JSON.stringify(payload),signal:AbortSignal.timeout(30000)});const d=await r.json().catch(()=>({}));if(!r.ok||d.ResponseCode!=="0"||!d.CheckoutRequestID){const m=d.errorMessage||d.ResponseDescription||d.CustomerMessage||"Safaricom did not accept the STK request.";await payments.updateOne({_id:id},{$set:{status:"failed",result_desc:String(m).slice(0,250),updated_at:iso()}});return res.status(502).json({error:m});}await payments.updateOne({_id:id},{$set:{checkout_request_id:d.CheckoutRequestID,merchant_request_id:d.MerchantRequestID||null,updated_at:iso()}});res.status(202).json({paymentId:id,status:"pending",message:"STK request sent. Enter your M-Pesa PIN on your phone."});}catch(e){await payments.updateOne({_id:id},{$set:{status:"failed",result_desc:String(e.message).slice(0,250),updated_at:iso()}});res.status(502).json({error:e.message||"Could not start STK payment."});}}));
app.post("/api/payments/manual",auth,asyncRoute(async(req,res)=>{if(req.auth.role!=="member")return res.status(403).json({error:"Members only."});const u=await users.findOne({_id:req.auth.sub}),plan=await getPlan(String(req.body.plan||""));if(!u||!plan)return res.status(400).json({error:"Select a valid plan and log in again."});let phone;try{phone=normalizePhone(req.body.phone||u.phone);}catch(e){return res.status(400).json({error:e.message});}const receipt=String(req.body.receipt||"").trim().toUpperCase().replace(/\s/g,"");if(!/^[A-Z0-9]{10}$/.test(receipt))return res.status(400).json({error:"Enter the 10-character M-Pesa transaction code exactly as shown in your SMS."});if(await payments.findOne({$or:[{mpesa_receipt:receipt},{manual_receipt:receipt}]}))return res.status(409).json({error:"This M-Pesa transaction code has already been submitted."});const id=crypto.randomUUID(),t=iso();await payments.insertOne({_id:id,user_id:u._id,plan_key:plan._id,amount:plan.price,phone,method:"manual",manual_receipt:receipt,status:"pending",created_at:t,updated_at:t});await notifications.insertOne({_id:crypto.randomUUID(),user_id:u._id,type:"payment_submitted",title:"Payment submitted for verification",message:"Your Till payment details have been sent to the admin. Your premium access will begin after approval.",created_at:t,read:false});res.status(201).json({paymentId:id,status:"pending",message:`Payment submitted. Admin will verify transaction ${receipt}. Your tips remain locked until approval.`});}));
app.get("/api/payments/:id",auth,asyncRoute(async(req,res)=>{const p=await payments.findOne({_id:req.params.id,user_id:req.auth.sub});if(!p)return res.status(404).json({error:"Payment not found."});res.json({id:p._id,status:p.status,message:p.result_desc||null,receipt:p.mpesa_receipt||p.manual_receipt||null});}));
app.post("/api/mpesa/callback",asyncRoute(async(req,res)=>{const b=req.body?.Body?.stkCallback;if(!b?.CheckoutRequestID)return res.status(400).json({ResultCode:1,ResultDesc:"Invalid callback"});const p=await payments.findOne({checkout_request_id:b.CheckoutRequestID});if(!p)return res.json({ResultCode:0,ResultDesc:"Unknown checkout reference"});if(p.status!=="pending")return res.json({ResultCode:0,ResultDesc:"Already processed"});if(String(b.ResultCode)!=="0"){await payments.updateOne({_id:p._id,status:"pending"},{$set:{status:"failed",result_code:String(b.ResultCode),result_desc:String(b.ResultDesc||"Payment not completed").slice(0,250),updated_at:iso()}});return res.json({ResultCode:0,ResultDesc:"Callback processed"});}const meta=Object.fromEntries((b.CallbackMetadata?.Item||[]).map(x=>[x.Name,x.Value]));const amount=Number(meta.Amount),receipt=String(meta.MpesaReceiptNumber||""),phone=String(meta.PhoneNumber||"");if(amount!==Number(p.amount)||!receipt||phone!==p.phone){await payments.updateOne({_id:p._id,status:"pending"},{$set:{status:"review",result_desc:"Safaricom callback details did not match the payment. Admin review required.",updated_at:iso()}});return res.json({ResultCode:0,ResultDesc:"Sent for manual review"});}try{await activatePayment(p._id,receipt,"safaricom");}catch(e){console.error("STK activation:",e);return res.status(500).json({ResultCode:1,ResultDesc:"Payment activation failed"});}res.json({ResultCode:0,ResultDesc:"Payment processed"});}));
app.post("/api/admin/login",asyncRoute(async(req,res)=>{const email=String(req.body.email||"").trim().toLowerCase(),password=String(req.body.password||"");if(email!==String(process.env.ADMIN_EMAIL).toLowerCase()||!(await bcrypt.compare(password,process.env.ADMIN_PASSWORD_HASH)))return res.status(401).json({error:"Admin email or password is incorrect."});res.json({token:tokenFor("admin","admin"),user:{role:"admin",email}});}));
app.get("/api/admin/data",auth,adminOnly,asyncRoute(async(req,res)=>{const [us,ps,fs]=await Promise.all([users.find({}, {projection:{password_hash:0}}).sort({created_at:-1}).toArray(),payments.find({}).sort({created_at:-1}).toArray(),fixtures.find({}).sort({kickoff:1,created_at:-1}).toArray()]);const userRows=us.map(u=>({...safeUser(u),createdAt:u.created_at}));const paymentRows=await Promise.all(ps.map(async p=>{const owner=us.find(u=>u._id===p.user_id);return{id:p._id,userId:p.user_id,name:owner?.name||"Deleted user",email:owner?.email||"",plan_key:p.plan_key,amount:p.amount,phone:p.phone,method:p.method||"stk",receipt:p.manual_receipt||p.mpesa_receipt||"",status:p.status,created_at:p.created_at,planLabel:(await getPlan(p.plan_key))?.label||p.plan_key};}));res.json({plans:await publicPlans(),fixtures:fs.map(f=>({...f,id:f._id})),users:userRows,payments:paymentRows,till:{number:TILL_NUMBER,name:TILL_NAME}});}));
app.post("/api/admin/fixtures",auth,adminOnly,asyncRoute(async(req,res)=>{const b=req.body;if(!b.league||!b.home||!b.away||!b.prediction)return res.status(400).json({error:"League, home team, away team and prediction are required."});const odds=String(b.odds||"").trim();if(odds&&(!Number.isFinite(Number(odds))||Number(odds)<=1))return res.status(400).json({error:"Odds must be a decimal greater than 1.00."});const id=crypto.randomUUID();await fixtures.insertOne({_id:id,league:String(b.league).slice(0,80),home:String(b.home).slice(0,80),away:String(b.away).slice(0,80),kickoff:b.kickoff||null,market:String(b.market||"1X2").slice(0,80),prediction:String(b.prediction).slice(0,120),odds,analysis:String(b.analysis||"").slice(0,3000),created_at:iso()});res.status(201).json({ok:true,id});}));
app.put("/api/admin/fixtures/:id",auth,adminOnly,asyncRoute(async(req,res)=>{const b=req.body,odds=String(b.odds||"").trim();if(odds&&(!Number.isFinite(Number(odds))||Number(odds)<=1))return res.status(400).json({error:"Odds must be greater than 1.00."});const r=await fixtures.updateOne({_id:req.params.id},{$set:{league:String(b.league||"").slice(0,80),home:String(b.home||"").slice(0,80),away:String(b.away||"").slice(0,80),kickoff:b.kickoff||null,market:String(b.market||"1X2").slice(0,80),prediction:String(b.prediction||"").slice(0,120),odds,analysis:String(b.analysis||"").slice(0,3000)}});if(!r.matchedCount)return res.status(404).json({error:"Fixture not found."});res.json({ok:true});}));
app.delete("/api/admin/fixtures/:id",auth,adminOnly,asyncRoute(async(req,res)=>{const r=await fixtures.deleteOne({_id:req.params.id});if(!r.deletedCount)return res.status(404).json({error:"Fixture not found."});res.json({ok:true});}));
app.put("/api/admin/plans",auth,adminOnly,asyncRoute(async(req,res)=>{for(const k of ["daily","weekly","monthly"]){const n=Number(req.body[k]);if(!Number.isInteger(n)||n<1||n>1000000)return res.status(400).json({error:"Prices must be whole KES amounts from 1 to 1,000,000."});await plans.updateOne({_id:k},{$set:{price:n}});}res.json({plans:await publicPlans()});}));
app.post("/api/admin/payments/:id/approve",auth,adminOnly,asyncRoute(async(req,res)=>{const p=await payments.findOne({_id:req.params.id});if(!p||!["pending","review"].includes(p.status))return res.status(404).json({error:"Pending payment not found."});const receipt=String(p.manual_receipt||req.body.receipt||"").trim().toUpperCase();if(!/^[A-Z0-9]{10}$/.test(receipt))return res.status(400).json({error:"A valid 10-character M-Pesa receipt code is required."});try{await activatePayment(p._id,receipt,"admin");}catch(e){if(e.code===11000)return res.status(409).json({error:"That M-Pesa code has already been used."});return res.status(400).json({error:e.message});}res.json({ok:true,message:"Payment approved and subscription activated."});}));
app.post("/api/admin/payments/:id/reject",auth,adminOnly,asyncRoute(async(req,res)=>{const r=await payments.updateOne({_id:req.params.id,status:{$in:["pending","review"]}},{$set:{status:"rejected",result_desc:String(req.body.reason||"Payment rejected by administrator").slice(0,250),updated_at:iso()}});if(!r.modifiedCount)return res.status(404).json({error:"Pending payment not found."});res.json({ok:true});}));
app.put("/api/admin/users/:id",auth,adminOnly,asyncRoute(async(req,res)=>{const name=String(req.body.name||"").trim(),email=String(req.body.email||"").trim().toLowerCase();let phone;try{phone=normalizePhone(req.body.phone);}catch(e){return res.status(400).json({error:e.message});}if(name.length<2||name.length>80||!/^\S+@\S+\.\S+$/.test(email))return res.status(400).json({error:"Enter a valid name and email."});const r=await users.updateOne({_id:req.params.id},{$set:{name,email,phone,updated_at:iso()}});if(!r.matchedCount)return res.status(404).json({error:"User not found."});res.json({ok:true});}));
app.delete("/api/admin/users/:id",auth,adminOnly,asyncRoute(async(req,res)=>{const id=req.params.id;if(id==="admin")return res.status(400).json({error:"Invalid user."});const r=await users.deleteOne({_id:id});if(!r.deletedCount)return res.status(404).json({error:"User not found."});await notifications.deleteMany({user_id:id});res.json({ok:true});}));
app.post("/api/notifications/:id/read",auth,asyncRoute(async(req,res)=>{const r=await notifications.updateOne({_id:req.params.id,user_id:req.auth.sub},{$set:{read:true}});if(!r.matchedCount)return res.status(404).json({error:"Notification not found."});res.json({ok:true});}));
app.use(express.static(path.join(__dirname,"public")));
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.use((err,req,res,next)=>{console.error("Application error:",err);if(res.headersSent)return next(err);if(err.code===11000)return res.status(409).json({error:"A record with those details already exists."});res.status(500).json({error:"Server error. Please try again or contact support."});});
initializeDatabase().then(()=>app.listen(PORT,()=>console.log(`Football Tips Hub listening on ${PORT}; M-Pesa STK ${process.env.DARAJA_ENABLED==="true"?"enabled":"disabled"}`))).catch(e=>{console.error("FATAL database startup error:",e);process.exit(1);});
process.on("SIGTERM",async()=>{await client.close();process.exit(0);});
app.put("/api/me/profile", auth, asyncRoute(async (req, res) => {
  if (req.auth.role !== "member") {
    return res.status(403).json({ error: "Members only." });
  }

  const name = String(req.body.name || "").trim();
  const email = String(req.body.email || "").trim().toLowerCase();

  let phone;
  try {
    phone = normalizePhone(req.body.phone);
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }

  if (name.length < 2 || name.length > 80) {
    return res.status(400).json({ error: "Enter a valid full name." });
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: "Enter a valid email address." });
  }

  try {
    const result = await users.updateOne(
      { _id: req.auth.sub },
      {
        $set: {
          name,
          email,
          phone,
          updated_at: iso()
        }
      }
    );

    if (!result.matchedCount) {
      return res.status(404).json({ error: "Account not found." });
    }

    const updatedUser = await users.findOne({ _id: req.auth.sub });
    res.json({
      ok: true,
      message: "Account details updated successfully.",
      user: safeUser(updatedUser)
    });
  } catch (e) {
    if (e.code === 11000) {
      return res.status(409).json({
        error: "That email address or phone number is already registered."
      });
    }
    throw e;
  }
}));
