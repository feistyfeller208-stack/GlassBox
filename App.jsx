import React, { useState, useEffect, useRef, useCallback } from "react";

// ─────────────────────────────────────────────────────────────────────────────
// SUPABASE CLIENT
// ─────────────────────────────────────────────────────────────────────────────
import { createClient } from "@supabase/supabase-js";

const SUPA_URL = "https://lqxaksgskiltryejhkzx.supabase.co";
const SUPA_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImxxeGFrc2dza2lsdHJ5ZWpoa3p4Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzY2OTkzNDUsImV4cCI6MjA5MjI3NTM0NX0.LomF2rKj95NRskD1AYDLCnLM0q6OLQe8SJhz_JZ7JOg";

const supabase = createClient(SUPA_URL, SUPA_KEY);

const headers = { "Content-Type":"application/json", "apikey":SUPA_KEY, "Authorization":`Bearer ${SUPA_KEY}` };

let _token = localStorage.getItem("gb_token") || null;
let _userId = localStorage.getItem("gb_uid") || null;
let _onSessionExpired = null;

const authed = () => ({ ...headers, "Authorization": `Bearer ${_token}` });

function setSession(session) {
  _token = session?.access_token || null;
  _userId = session?.user?.id || null;
  if (_token) { localStorage.setItem("gb_token", _token); localStorage.setItem("gb_uid", _userId); }
  else { localStorage.removeItem("gb_token"); localStorage.removeItem("gb_uid"); }
}

async function sbFetch(path, opts = {}) {
  const res = await fetch(`${SUPA_URL}/rest/v1/${path}`, { headers: { ...headers, ...(opts.headers||{}) }, ...opts });
  if (res.status === 401) { setSession(null); if (_onSessionExpired) _onSessionExpired(); throw new Error("Session expired. Please sign in again."); }
  if (!res.ok) { const e = await res.json().catch(()=>({})); throw new Error(e.message || res.statusText); }
  if (res.status === 204) return null;
  return res.json();
}

async function sbAuth(path, body) {
  const res = await fetch(`${SUPA_URL}/auth/v1/${path}`, { method:"POST", headers:{ "Content-Type":"application/json", "apikey":SUPA_KEY }, body:JSON.stringify(body) });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error_description || data.msg || "Auth error");
  return data;
}

const db = {
  select: (table, query="") => sbFetch(`${table}?${query}`, { headers: authed() }),
  insert: (table, data) => sbFetch(`${table}`, { method:"POST", headers:{ ...authed(), "Prefer":"return=representation" }, body:JSON.stringify(data) }),
  update: (table, query, data) => sbFetch(`${table}?${query}`, { method:"PATCH", headers:{ ...authed(), "Prefer":"return=representation" }, body:JSON.stringify(data) }),
  delete: (table, query) => sbFetch(`${table}?${query}`, { method:"DELETE", headers:{ ...authed() } }),
};

// Real-time using official Supabase client — this is reliable
function subscribe(table, groupId, callback) {
  const channel = supabase
    .channel(`${table}-${groupId}`)
    .on("postgres_changes", {
      event: "*",
      schema: "public",
      table: table,
      filter: `group_id=eq.${groupId}`,
    }, callback)
    .subscribe();
  return () => supabase.removeChannel(channel);
}

// ─────────────────────────────────────────────────────────────────────────────
// SECURITY ENGINE — SHA-256 hash chain
// ─────────────────────────────────────────────────────────────────────────────
async function sha256(msg) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(msg));
  return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,"0")).join("");
}
async function hashRecord(r, prev) { return sha256(JSON.stringify({...r, prev})); }
async function buildEntry(action, data, prevHash, userId, userName, groupId, description) {
  const e = { action, data, user_id:userId, user_name:userName, group_id:groupId, description, prev_hash:prevHash };
  e.hash = await hashRecord(e, prevHash);
  return e;
}
async function verifyChain(log) {
  if (!log?.length) return true;
  for (let i=0; i<log.length; i++) {
    const { hash, ...rest } = log[i];
    const p = i===0 ? "GENESIS" : log[i-1].hash;
    if (await hashRecord(rest, p) !== hash) return false;
  }
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────────────
const uid = () => crypto.randomUUID();
const now = () => new Date().toISOString();
const fmt = n => "TZS " + Number(n||0).toLocaleString();
const fmtD = iso => new Date(iso).toLocaleDateString("en-TZ",{day:"2-digit",month:"short",year:"numeric"});
const fmtT = iso => new Date(iso).toLocaleTimeString("en-TZ",{hour:"2-digit",minute:"2-digit"});
const fmtAge = iso => {
  const diff = Date.now() - new Date(iso).getTime();
  const hrs = Math.floor(diff/3600000);
  const days = Math.floor(diff/86400000);
  if(days>0)return days+"d ago";
  if(hrs>0)return hrs+"h ago";
  return Math.floor(diff/60000)+"m ago";
};
const cleanPhone = p => p.replace(/\s+/g,"").replace(/^0/,"255");
const calcTotal = (amt,rate) => Math.round(amt*(1+rate/100));
const calcInstallment = (total,cycles) => Math.ceil(total/cycles);
const calcCycleEndDate = (startDate, schedule) => {
  const d = new Date(startDate);
  if(schedule==="weekly") d.setDate(d.getDate()+7);
  else d.setMonth(d.getMonth()+1); // monthly
  return d.toISOString();
};
const daysUntil = iso => {
  if(!iso)return null;
  const diff = new Date(iso).getTime() - Date.now();
  if(diff<0)return 0;
  return Math.ceil(diff/86400000);
};

async function getLastHash(groupId) {
  const rows = await db.select("audit_log", `group_id=eq.${groupId}&order=created_at.desc&limit=1`);
  return rows?.length ? rows[0].hash : "GENESIS";
}

async function sysMsg(groupId, text) {
  await db.insert("messages", { group_id:groupId, user_id:_userId, user_name:"System", text, system:true });
}

function poolBalance(contributions, groupId) {
  const inn = contributions.filter(c=>c.group_id===groupId&&c.type==="contribution").reduce((s,c)=>s+c.amount,0);
  const out = contributions.filter(c=>c.group_id===groupId&&["payout","tranche-release","loan-disbursement"].includes(c.type)).reduce((s,c)=>s+c.amount,0);
  return inn - out;
}

// ─────────────────────────────────────────────────────────────────────────────
// PALETTE
// ─────────────────────────────────────────────────────────────────────────────
const C = {
  bg:"#07090f", surface:"#0d1117", card:"#111820", cardHover:"#151e28",
  border:"#1a2738", borderHover:"#22334a",
  accent:"#2563eb", accentSoft:"rgba(37,99,235,.12)",
  green:"#059669", greenSoft:"rgba(5,150,105,.12)",
  amber:"#d97706", amberSoft:"rgba(217,119,6,.12)",
  red:"#dc2626", redSoft:"rgba(220,38,38,.12)",
  purple:"#7c3aed",
  text:"#e2e8f0", textMid:"#7a90a4", muted:"#3d5166",
};

// ─────────────────────────────────────────────────────────────────────────────
// UI ATOMS
// ─────────────────────────────────────────────────────────────────────────────
const Card = ({children,style={},onClick})=>(
  <div onClick={onClick} style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:12,padding:20,...style}}
    onMouseEnter={onClick?e=>{e.currentTarget.style.borderColor=C.borderHover;e.currentTarget.style.background=C.cardHover;}:null}
    onMouseLeave={onClick?e=>{e.currentTarget.style.borderColor=C.border;e.currentTarget.style.background=C.card;}:null}
  >{children}</div>
);
const Inp=({label,error,...p})=>(
  <div style={{marginBottom:14}}>
    {label&&<div style={{color:C.textMid,fontSize:12,fontWeight:600,marginBottom:5}}>{label}</div>}
    <input {...p} style={{width:"100%",background:C.surface,border:`1px solid ${error?C.red:C.border}`,borderRadius:8,padding:"10px 12px",color:C.text,fontSize:14,outline:"none",boxSizing:"border-box",...p.style}}
      onFocus={e=>e.target.style.borderColor=C.accent} onBlur={e=>e.target.style.borderColor=error?C.red:C.border}/>
    {error&&<div style={{color:C.red,fontSize:12,marginTop:4}}>{error}</div>}
  </div>
);
const Sel=({label,children,...p})=>(
  <div style={{marginBottom:14}}>
    {label&&<div style={{color:C.textMid,fontSize:12,fontWeight:600,marginBottom:5}}>{label}</div>}
    <select {...p} style={{width:"100%",background:C.surface,border:`1px solid ${C.border}`,borderRadius:8,padding:"10px 12px",color:C.text,fontSize:14,outline:"none",boxSizing:"border-box"}}>{children}</select>
  </div>
);
const Btn=({children,variant="primary",onClick,style={},disabled,full,size="md"})=>{
  const pad=size==="sm"?"6px 12px":size==="lg"?"13px 28px":"9px 18px";
  const fs=size==="sm"?12:size==="lg"?15:13;
  const v={primary:{background:C.accent,color:"#fff",border:"none"},success:{background:C.green,color:"#fff",border:"none"},danger:{background:C.red,color:"#fff",border:"none"},ghost:{background:"transparent",color:C.textMid,border:`1px solid ${C.border}`},subtle:{background:C.accentSoft,color:C.accent,border:`1px solid rgba(37,99,235,.25)`}};
  return <button onClick={onClick} disabled={disabled} style={{borderRadius:8,padding:pad,fontWeight:600,fontSize:fs,cursor:disabled?"not-allowed":"pointer",opacity:disabled?.45:1,fontFamily:"inherit",width:full?"100%":"auto",...v[variant],...style}}>{children}</button>;
};
const Badge=({color,children,style={}})=>(
  <span style={{background:color+"18",color,border:`1px solid ${color}28`,borderRadius:4,padding:"2px 8px",fontSize:11,fontWeight:700,letterSpacing:".04em",textTransform:"uppercase",...style}}>{children}</span>
);
const Divider=({style={}})=><div style={{height:1,background:C.border,margin:"16px 0",...style}}/>;
const Modal=({title,onClose,children,width=460})=>(
  <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,.8)",zIndex:1000,display:"flex",alignItems:"center",justifyContent:"center",padding:16}} onClick={onClose}>
    <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:14,padding:24,width:"100%",maxWidth:width,maxHeight:"92vh",overflowY:"auto"}} onClick={e=>e.stopPropagation()}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:20}}>
        <div style={{color:C.text,fontWeight:700,fontSize:16}}>{title}</div>
        <button onClick={onClose} style={{background:"none",border:"none",color:C.muted,fontSize:22,cursor:"pointer",lineHeight:1,padding:"0 0 0 12px"}}>×</button>
      </div>
      {children}
    </div>
  </div>
);
function PinPad({value,onChange,label}) {
  const keys=["1","2","3","4","5","6","7","8","9","","0","<"];
  return (
    <div style={{marginBottom:14}}>
      {label&&<div style={{color:C.textMid,fontSize:12,fontWeight:600,marginBottom:10,textAlign:"center"}}>{label}</div>}
      <div style={{display:"flex",justifyContent:"center",gap:16,marginBottom:18}}>
        {[0,1,2,3].map(i=><div key={i} style={{width:12,height:12,borderRadius:"50%",background:i<value.length?C.accent:"transparent",border:`2px solid ${i<value.length?C.accent:C.border}`,transition:"all .12s"}}/>)}
      </div>
      <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:8,maxWidth:210,margin:"0 auto"}}>
        {keys.map((k,i)=><button key={i} onClick={()=>{if(!k)return;if(k==="<"){onChange(value.slice(0,-1));return;}if(value.length<4)onChange(value+k);}} style={{background:!k?"transparent":C.surface,border:!k?"none":`1px solid ${C.border}`,borderRadius:10,padding:"13px 0",fontSize:18,fontWeight:600,color:k==="<"?C.red:C.text,cursor:!k?"default":"pointer"}}>{k}</button>)}
      </div>
    </div>
  );
}
const Steps=({current,total})=>(
  <div style={{display:"flex",gap:6,marginBottom:24}}>
    {Array.from({length:total}).map((_,i)=><div key={i} style={{flex:1,height:3,borderRadius:2,background:i<current?C.accent:C.border,transition:"background .3s"}}/>)}
  </div>
);

// Loading spinner
const Spinner=()=>(
  <div style={{display:"flex",alignItems:"center",justifyContent:"center",height:200}}>
    <div style={{width:32,height:32,border:`3px solid ${C.border}`,borderTop:`3px solid ${C.accent}`,borderRadius:"50%",animation:"spin 1s linear infinite"}}/>
    <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
  </div>
);

function useAsync(fn, deps=[]) {
  const [data,setData]=useState(null);
  const [loading,setLoading]=useState(true);
  const [error,setError]=useState(null);
  useEffect(()=>{
    setLoading(true);
    fn().then(d=>{setData(d);setLoading(false);}).catch(e=>{setError(e.message);setLoading(false);});
  }, deps);
  return {data,loading,error,reload:()=>fn().then(setData)};
}

// ─────────────────────────────────────────────────────────────────────────────
// AUTH
// ─────────────────────────────────────────────────────────────────────────────
function Landing({onLogin,onRegister}) {
  return (
    <div style={{minHeight:"100vh",background:C.bg,display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",padding:24}}>
      <div style={{maxWidth:340,width:"100%",textAlign:"center"}}>
        <div style={{width:48,height:48,background:C.accentSoft,border:`1px solid rgba(37,99,235,.25)`,borderRadius:12,display:"flex",alignItems:"center",justifyContent:"center",margin:"0 auto 18px",color:C.accent,fontWeight:900,fontSize:16}}>GB</div>
        <h1 style={{margin:"0 0 8px",fontSize:28,fontWeight:900,color:C.text,letterSpacing:"-.02em"}}>Glass Box</h1>
        <p style={{color:C.textMid,fontSize:14,lineHeight:1.6,margin:"0 0 32px"}}>Community savings circles built on full transparency.</p>
        <div style={{display:"flex",flexDirection:"column",gap:10}}>
          <Btn full size="lg" onClick={onLogin}>Sign In</Btn>
          <Btn full size="lg" variant="ghost" onClick={onRegister}>Create Account</Btn>
        </div>
      </div>
    </div>
  );
}

function Register({onSuccess,onBack}) {
  const [step,setStep]=useState(1);
  const [form,setForm]=useState({name:"",phone:""});
  const [pin,setPin]=useState(""); const [confirm,setConfirm]=useState("");
  const [err,setErr]=useState({}); const [loading,setLoading]=useState(false);

  async function register() {
    if(pin!==confirm){setErr({pin:"PINs do not match"});setConfirm("");return;}
    setLoading(true);
    try {
      const email = cleanPhone(form.phone)+"@glassbox.app";
      // Step 1: create auth user
      const signupData = await sbAuth("signup", { email, password:pin+pin, data:{ name:form.name, phone:cleanPhone(form.phone) } });
      if (!signupData.user) throw new Error("Signup failed. Try again.");
      // Step 2: sign in immediately to get a real session
      const signinData = await sbAuth("token?grant_type=password", { email, password:pin+pin });
      setSession(signinData);
      // Step 3: create profile
      const profile = { id:signinData.user.id, name:form.name.trim(), phone:cleanPhone(form.phone), role:"member" };
      await db.insert("profiles", profile);
      onSuccess(profile);
    } catch(e) {
      const msg = (e.message||"").toLowerCase();
      if(msg.includes("confirm") || msg.includes("email not confirmed")) {
        setErr({submit:"Almost there — go to Supabase Dashboard → Authentication → Providers → Email and turn off Confirm Email, then try again."});
      } else {
        setErr({submit:e.message});
      }
      setLoading(false);
    }
  }

  return (
    <div style={{minHeight:"100vh",background:C.bg,display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",padding:24}}>
      <div style={{maxWidth:380,width:"100%"}}>
        <button onClick={onBack} style={{background:"none",border:"none",color:C.muted,fontSize:13,cursor:"pointer",marginBottom:24,padding:0}}>← Back</button>
        <h2 style={{color:C.text,margin:"0 0 4px",fontSize:20,fontWeight:800}}>Create Account</h2>
        <p style={{color:C.muted,fontSize:13,margin:"0 0 20px"}}>{["Your details","Set PIN","Confirm PIN"][step-1]}</p>
        <Steps current={step} total={3}/>
        {err.submit&&<div style={{color:C.red,fontSize:13,marginBottom:12}}>{err.submit}</div>}
        {step===1&&<Card>
          <Inp label="Full Name" placeholder="Amina Hassan" value={form.name} error={err.name} onChange={e=>setForm(f=>({...f,name:e.target.value}))}/>
          <Inp label="Phone Number" placeholder="0712 345 678" value={form.phone} error={err.phone} onChange={e=>setForm(f=>({...f,phone:e.target.value}))}/>
          <Btn full onClick={()=>{if(!form.name.trim()||!form.phone.trim()){setErr({name:!form.name?"Required":"",phone:!form.phone?"Required":""});return;}setErr({});setStep(2);}} disabled={!form.name||!form.phone}>Continue</Btn>
        </Card>}
        {step===2&&<Card><PinPad label="Choose a 4-digit PIN" value={pin} onChange={setPin}/><Btn full onClick={()=>pin.length===4&&setStep(3)} disabled={pin.length<4} style={{marginTop:8}}>Continue</Btn></Card>}
        {step===3&&<Card>
          <PinPad label="Confirm PIN" value={confirm} onChange={setConfirm}/>
          {err.pin&&<div style={{color:C.red,fontSize:12,textAlign:"center",marginBottom:10}}>{err.pin}</div>}
          <Btn full onClick={register} disabled={confirm.length<4||loading} style={{marginTop:8}}>{loading?"Creating...":"Create Account"}</Btn>
        </Card>}
      </div>
    </div>
  );
}

function Login({onSuccess,onBack}) {
  const [phone,setPhone]=useState(""); const [pin,setPin]=useState("");
  const [step,setStep]=useState(1); const [err,setErr]=useState(""); const [loading,setLoading]=useState(false);

  async function login() {
    setLoading(true); setErr("");
    try {
      const email = `${cleanPhone(phone)}@glassbox.app`;
      const data = await sbAuth("token?grant_type=password", { email, password:pin+pin });
      setSession(data);
      const profiles = await db.select("profiles", `id=eq.${data.user.id}`);
      const profile = profiles[0];
      onSuccess(profile);
    } catch(e) { setErr("Incorrect PIN or account not found."); setPin(""); setLoading(false); }
  }

  async function checkPhone() {
    setLoading(true); setErr("");
    try {
      const clean = cleanPhone(phone);
      const rows = await sbFetch(`profiles?phone=eq.${clean}&select=id`);
      if (!rows?.length) { setErr("No account found for this number."); setLoading(false); return; }
      setStep(2); setLoading(false);
    } catch { setErr("Something went wrong. Try again."); setLoading(false); }
  }

  return (
    <div style={{minHeight:"100vh",background:C.bg,display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",padding:24}}>
      <div style={{maxWidth:380,width:"100%"}}>
        <button onClick={onBack} style={{background:"none",border:"none",color:C.muted,fontSize:13,cursor:"pointer",marginBottom:24,padding:0}}>← Back</button>
        <div style={{textAlign:"center",marginBottom:28}}>
          <div style={{width:44,height:44,background:C.accentSoft,border:`1px solid rgba(37,99,235,.25)`,borderRadius:12,display:"flex",alignItems:"center",justifyContent:"center",margin:"0 auto 14px",color:C.accent,fontWeight:900,fontSize:15}}>GB</div>
          <h2 style={{color:C.text,margin:"0 0 4px",fontWeight:800}}>Welcome back</h2>
        </div>
        {err&&<div style={{color:C.red,fontSize:13,textAlign:"center",marginBottom:12}}>{err}</div>}
        {step===1&&<Card>
          <Inp label="Phone Number" placeholder="0712 345 678" value={phone} onChange={e=>setPhone(e.target.value)}/>
          <Btn full onClick={checkPhone} disabled={!phone||loading}>{loading?"Checking...":"Continue"}</Btn>
        </Card>}
        {step===2&&<Card>
          <div style={{color:C.muted,fontSize:13,marginBottom:14,textAlign:"center"}}>PIN for <span style={{color:C.text,fontWeight:600}}>{phone}</span></div>
          <PinPad value={pin} onChange={setPin}/>
          <Btn full onClick={login} disabled={pin.length<4||loading} style={{marginTop:8}}>{loading?"Signing in...":"Sign In"}</Btn>
          <div style={{display:"flex",justifyContent:"space-between",marginTop:10}}>
            <button onClick={()=>{setStep(1);setPin("");setErr("");}} style={{background:"none",border:"none",color:C.muted,fontSize:12,cursor:"pointer",padding:0,fontFamily:"inherit"}}>Different number</button>
            <button onClick={()=>setStep(3)} style={{background:"none",border:"none",color:C.accent,fontSize:12,cursor:"pointer",padding:0,fontFamily:"inherit"}}>Forgot PIN?</button>
          </div>
        </Card>}
        {step===3&&<ForgotPin phone={phone} onDone={()=>setStep(2)} onBack={()=>setStep(2)}/>}
      </div>
    </div>
  );
}

// ── Forgot PIN ────────────────────────────────────────────────────────────────
// Since we don't have SMS yet, we use a security question approach:
// User proves identity by providing their full name + phone (both must match exactly)
// Then they set a new PIN. This is a temporary solution until SMS OTP is integrated.
function ForgotPin({phone,onDone,onBack}) {
  const [step,setStep]=useState(1); // 1=verify identity, 2=new pin, 3=confirm
  const [name,setName]=useState("");
  const [newPin,setNewPin]=useState("");
  const [confirmPin,setConfirmPin]=useState("");
  const [err,setErr]=useState(""); const [loading,setLoading]=useState(false);

  async function verifyIdentity(){
    setLoading(true); setErr("");
    try {
      const clean=cleanPhone(phone);
      const rows=await sbFetch(`profiles?phone=eq.${clean}&select=id,name`);
      if(!rows?.length){setErr("No account found.");setLoading(false);return;}
      // Check name matches (case insensitive)
      if(rows[0].name.toLowerCase().trim()!==name.toLowerCase().trim()){
        setErr("Name does not match our records.");setLoading(false);return;
      }
      setStep(2); setLoading(false);
    } catch(e){setErr(e.message);setLoading(false);}
  }

  async function resetPin(){
    if(newPin!==confirmPin){setErr("PINs do not match.");setConfirmPin("");return;}
    setLoading(true); setErr("");
    try {
      // Sign in with a temp approach — we need to re-authenticate
      // Since we verified identity above, we use admin-style password reset via Supabase
      const email=cleanPhone(phone)+"@glassbox.app";
      // We request a password reset — Supabase sends magic link but we intercept with new password
      // For now: use the profile verification as proof, then update password
      // This requires the user to have a valid session OR we use service role
      // Temporary: notify admin to reset manually
      setStep(4); setLoading(false);
    } catch(e){setErr(e.message);setLoading(false);}
  }

  if(step===4) return(
    <Card>
      <div style={{color:C.text,fontWeight:700,fontSize:14,marginBottom:8}}>Contact Group Admin</div>
      <div style={{color:C.textMid,fontSize:13,marginBottom:16,lineHeight:1.6}}>
        Your identity has been verified. PIN reset via SMS is coming soon. For now, contact your Glass Box group admin or the platform administrator to reset your PIN manually.
      </div>
      <div style={{background:C.accentSoft,border:`1px solid rgba(37,99,235,.25)`,borderRadius:8,padding:"10px 14px",marginBottom:16}}>
        <div style={{color:C.accent,fontSize:12,fontWeight:600}}>Your verified identity</div>
        <div style={{color:C.text,fontSize:13,marginTop:2}}>{name} · {phone}</div>
      </div>
      <Btn full onClick={onDone}>Back to Sign In</Btn>
    </Card>
  );

  return(
    <Card>
      {step===1&&(
        <div>
          <div style={{color:C.text,fontWeight:700,fontSize:14,marginBottom:4}}>Verify Your Identity</div>
          <div style={{color:C.muted,fontSize:13,marginBottom:14}}>Enter the full name on your account to confirm your identity.</div>
          {err&&<div style={{color:C.red,fontSize:13,marginBottom:10}}>{err}</div>}
          <Inp label="Full Name" placeholder="As you registered" value={name} onChange={e=>setName(e.target.value)}/>
          <div style={{display:"flex",gap:10}}>
            <Btn full variant="ghost" onClick={onBack}>Cancel</Btn>
            <Btn full onClick={verifyIdentity} disabled={!name.trim()||loading}>{loading?"Verifying...":"Verify"}</Btn>
          </div>
        </div>
      )}
    </Card>
  );
}

// ── Panel Error Boundary ─────────────────────────────────────────────────────
class PanelErrorBoundary extends React.Component {
  constructor(props){super(props);this.state={error:null};}
  static getDerivedStateFromError(e){return {error:e};}
  render(){
    if(this.state.error){
      return(
        <div style={{textAlign:"center",padding:32}}>
          <div style={{color:"#dc2626",fontWeight:600,fontSize:14,marginBottom:8}}>Something went wrong</div>
          <div style={{color:"#3d5166",fontSize:13,marginBottom:16}}>{this.state.error.message||"Unable to load this section."}</div>
          <button onClick={()=>{this.setState({error:null});if(this.props.onBack)this.props.onBack();}} style={{background:"#2563eb",color:"#fff",border:"none",borderRadius:8,padding:"8px 16px",fontSize:13,fontWeight:600,cursor:"pointer"}}>Go Back</button>
        </div>
      );
    }
    return this.props.children;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// NAV
// ─────────────────────────────────────────────────────────────────────────────
function Nav({view,setView}) {
  const items=[{id:"home",label:"Home"},{id:"groups",label:"Groups"},{id:"profile",label:"Profile"}];
  const active=["home","groups","profile"].includes(view)?view:["group-detail","create-group"].includes(view)?"groups":"home";
  return (
    <nav style={{background:C.bg,borderBottom:`1px solid ${C.border}`,padding:"0 20px",display:"flex",alignItems:"center",position:"sticky",top:0,zIndex:200,height:50}}>
      <div style={{color:C.text,fontWeight:900,fontSize:14,letterSpacing:"-.01em",marginRight:24}}>Glass Box</div>
      <div style={{display:"flex",gap:0}}>
        {items.map(it=><button key={it.id} onClick={()=>setView(it.id)} style={{background:"none",border:"none",padding:"13px 14px",fontSize:13,fontWeight:600,color:active===it.id?C.accent:C.muted,cursor:"pointer",borderBottom:active===it.id?`2px solid ${C.accent}`:"2px solid transparent",fontFamily:"inherit"}}>{it.label}</button>)}
      </div>
    </nav>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// HOME
// ─────────────────────────────────────────────────────────────────────────────
function Home({user,setView,setSelectedGroup}) {
  const [myGroups,setMyGroups]=useState([]);
  const [stats,setStats]=useState({contributed:0,received:0});
  const [loading,setLoading]=useState(true);

  async function loadData() {
    try {
      const mems = await db.select("members",`user_id=eq.${user.id}&status=neq.removed&select=group_id`);
      const gids = mems.map(m=>m.group_id);
      if (!gids.length) { setMyGroups([]); setLoading(false); return; }
      const groups = await db.select("groups",`id=in.(${gids.join(",")})&order=created_at.desc`);
      const cycles = await db.select("cycles",`group_id=in.(${gids.join(",")})&status=eq.open`);
      const slots = cycles.length ? await db.select("slots",`cycle_id=in.(${cycles.map(c=>c.id).join(",")})`) : [];
      const contribs = await db.select("contributions",`group_id=in.(${gids.join(",")})&select=amount,type,group_id`);
      const enriched = groups.map(g=>{
        const cycle = cycles.find(c=>c.group_id===g.id);
        const gSlots = slots.filter(s=>s.cycle_id===cycle?.id);
        const pool = poolBalance(contribs, g.id);
        return {...g, cycle, slots:gSlots, paidSlots:gSlots.filter(s=>s.status==="paid"), pool };
      });
      setMyGroups(enriched);
      const myM = await db.select("members",`user_id=eq.${user.id}&select=total_contributed,total_received`);
      const contributed = myM.reduce((s,m)=>s+m.total_contributed,0);
      const received = myM.reduce((s,m)=>s+m.total_received,0);
      setStats({contributed,received});
    } catch(e) { console.error(e); }
    setLoading(false);
  }

  useEffect(()=>{ loadData(); },[user.id]);

  // Realtime — refresh when contributions or cycles change
  useEffect(()=>{
    const unsub1 = subscribe("contributions","",()=>loadData());
    const unsub2 = subscribe("cycles","",()=>loadData());
    return ()=>{ unsub1(); unsub2(); };
  },[]);

  if(loading) return <Spinner/>;
  return (
    <div>
      <div style={{marginBottom:24}}>
        <h2 style={{margin:"0 0 2px",color:C.text,fontSize:20,fontWeight:800}}>Good day, {user.name.split(" ")[0]}</h2>
        <div style={{color:C.muted,fontSize:13}}>Your savings at a glance</div>
      </div>
      <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:12,marginBottom:28}}>
        <Card><div style={{color:C.muted,fontSize:11,fontWeight:600,letterSpacing:".05em",textTransform:"uppercase",marginBottom:4}}>Groups</div><div style={{color:C.accent,fontSize:20,fontWeight:800}}>{myGroups.length}</div></Card>
        <Card><div style={{color:C.muted,fontSize:11,fontWeight:600,letterSpacing:".05em",textTransform:"uppercase",marginBottom:4}}>Contributed</div><div style={{color:C.green,fontSize:16,fontWeight:800}}>{fmt(stats.contributed)}</div></Card>
        <Card><div style={{color:C.muted,fontSize:11,fontWeight:600,letterSpacing:".05em",textTransform:"uppercase",marginBottom:4}}>Received</div><div style={{color:C.amber,fontSize:16,fontWeight:800}}>{fmt(stats.received)}</div></Card>
      </div>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:14}}>
        <div style={{color:C.muted,fontSize:12,fontWeight:600,letterSpacing:".05em",textTransform:"uppercase"}}>My Groups</div>
        <Btn size="sm" variant="subtle" onClick={()=>setView("create-group")}>New Group</Btn>
      </div>
      {myGroups.length===0
        ?<Card style={{textAlign:"center",padding:40}}><div style={{color:C.muted,fontSize:14,marginBottom:16}}>You are not in any groups yet.</div><Btn onClick={()=>setView("create-group")}>Create a Group</Btn></Card>
        :myGroups.map(g=>(
          <Card key={g.id} onClick={()=>{setSelectedGroup(g.id);setView("group-detail");}} style={{marginBottom:10,cursor:"pointer"}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:10}}>
              <div>
                <div style={{color:C.text,fontWeight:700,fontSize:15,marginBottom:3}}>{g.name}</div>
                <div style={{color:C.muted,fontSize:12}}>{g.payoutSchedule}{g.cycle?` · Cycle ${g.cycle.number}`:""}</div>
              </div>
              <div style={{textAlign:"right"}}>
                <div style={{color:g.status==="round-complete"?C.green:C.text,fontWeight:800,fontSize:16}}>{fmt(g.pool)}</div>
                {g.status==="round-complete"&&<div style={{color:C.green,fontSize:11,marginTop:2}}>Round {g.round_number} complete</div>}
                {g.status!=="round-complete"&&g.cycle&&<div style={{color:C.muted,fontSize:11,marginTop:2}}>{g.paidSlots.length}/{g.slots.length} paid</div>}
              </div>
            </div>
            {g.cycle&&g.slots.length>0&&<div style={{height:4,background:C.surface,borderRadius:2,overflow:"hidden"}}><div style={{height:"100%",width:`${Math.round(g.paidSlots.length/g.slots.length*100)}%`,background:C.green,borderRadius:2}}/></div>}
          </Card>
        ))
      }
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// GROUP BROWSER
// ─────────────────────────────────────────────────────────────────────────────
function GroupBrowser({user,setView,setSelectedGroup}) {
  const [groups,setGroups]=useState([]);
  const [myGroupIds,setMyGroupIds]=useState([]);
  const [search,setSearch]=useState("");
  const [loading,setLoading]=useState(true);

  useEffect(()=>{
    Promise.all([
      db.select("groups","order=created_at.desc").catch(()=>[]),
      db.select("members","user_id=eq."+user.id+"&status=neq.removed&select=group_id").catch(()=>[]),
    ]).then(async([rows,myMems])=>{
        setMyGroupIds((myMems||[]).map(m=>m.group_id));
        if(!rows?.length){setGroups([]);setLoading(false);return;}
        const adminIds=[...new Set(rows.map(g=>g.admin_id))];
        // Use member_count column stored on the group — readable by everyone
        // Falls back to 0 if not yet set (for old groups)
        const admins = await sbFetch("profiles?id=in.("+adminIds.join(",")+")"+"&select=id,name").catch(()=>[]);
        setGroups(rows.map(g=>({
          ...g,
          adminName:(admins||[]).find(a=>a.id===g.admin_id)?.name||"",
          memberCount:g.member_count||0,
        })));
        setLoading(false);
      }).catch(()=>setLoading(false));
  },[]);

  const filtered = groups.filter(g=>g.name.toLowerCase().includes(search.toLowerCase()));
  if(loading) return <Spinner/>;
  return (
    <div>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:18}}>
        <h2 style={{margin:0,color:C.text,fontSize:20,fontWeight:800}}>Groups</h2>
        <Btn size="sm" variant="subtle" onClick={()=>setView("create-group")}>New Group</Btn>
      </div>
      <Inp placeholder="Search groups..." value={search} onChange={e=>setSearch(e.target.value)}/>
      {filtered.map(g=>{
        const isMine = g.admin_id===user.id;
        const isMember = !isMine && myGroupIds.includes(g.id);
        return (
          <Card key={g.id} onClick={(isMine||isMember)?()=>{setSelectedGroup(g.id);setView("group-detail");}:null} style={{marginBottom:10,cursor:(isMine||isMember)?"pointer":"default"}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start"}}>
              <div style={{flex:1}}>
                <div style={{color:C.text,fontWeight:700,fontSize:15,marginBottom:3}}>{g.name}</div>
                <div style={{color:C.muted,fontSize:12}}>Admin: {g.adminName} · {g.memberCount||0} members</div>
                <div style={{color:C.muted,fontSize:12,marginTop:1}}>{fmt(g.contribution_amount)}/cycle · {g.payout_schedule}</div>
                {g.description&&<div style={{color:C.muted,fontSize:13,marginTop:4}}>{g.description}</div>}
                {!isMine&&!isMember&&<div style={{color:C.muted,fontSize:11,marginTop:6,fontStyle:"italic"}}>Contact the admin to join</div>}
              </div>
              <div style={{textAlign:"right",flexShrink:0,marginLeft:16}}>
                {isMember&&!isMine&&<div style={{color:C.green,fontSize:11,marginTop:2}}>Member</div>}
                {isMine&&<div style={{color:C.amber,fontSize:11,marginTop:2}}>Admin</div>}
              </div>
            </div>
          </Card>
        );
      })}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// CREATE GROUP
// ─────────────────────────────────────────────────────────────────────────────
function CreateGroup({user,setView,onGroupCreated}) {
  const [otp,setOtp]=useState("");
  const [form,setForm]=useState({name:"",contributionAmount:"",payoutSchedule:"monthly",payoutPercent:"25",interestRate:"10",maxLoanMultiplier:"2",description:""});
  const [loading,setLoading]=useState(false);
  const [emailStep,setEmailStep]=useState(!user.email_verified);
  const [email,setEmail]=useState("");
  const [emailSent,setEmailSent]=useState(false);
  const [emailErr,setEmailErr]=useState("");
  const set=k=>e=>setForm(f=>({...f,[k]:e.target.value}));

  async function sendVerification(){
  if(!email.trim()||!email.includes("@")){setEmailErr("Enter a valid email address.");return;}
  setLoading(true);setEmailErr("");
  try{
    // Use Supabase magic link — sends a link to the email
    const res=await fetch(SUPA_URL+"/auth/v1/magiclink",{
      method:"POST",
      headers:{"Content-Type":"application/json","apikey":SUPA_KEY},
      body:JSON.stringify({email:email.trim()}),
    });
    if(!res.ok){
      const e=await res.json();
      throw new Error(e.msg||e.message||"Could not send verification email.");
    }
    await db.update("profiles","id=eq."+user.id,{email:email.trim()});
    setEmailSent(true);
  }catch(e){setEmailErr(e.message);}
  setLoading(false);
  }

  async function checkVerification(){
    setLoading(true);
    try{
      const res=await fetch(SUPA_URL+"/auth/v1/user",{headers:{...headers,"Authorization":"Bearer "+_token}});
      const data=await res.json();
      if(data.email_confirmed_at){
        await db.update("profiles","id=eq."+user.id,{email_verified:true});
        setEmailStep(false);
      } else {
        setEmailErr("Email not verified yet. Check your inbox and click the link, then come back and tap Check Again.");
      }
    }catch(e){setEmailErr(e.message);}
    setLoading(false);
  }

  async function verifyOtp(){
  setLoading(true);setEmailErr("");
  try{
    // Check if the email in auth has been confirmed
    const res=await fetch(SUPA_URL+"/auth/v1/user",{
      headers:{...headers,"Authorization":"Bearer "+_token}
    });
    const data=await res.json();
    if(data.email===email.trim()&&data.email_confirmed_at){
      await db.update("profiles","id=eq."+user.id,{email_verified:true});
      setEmailStep(false);
    } else {
      setEmailErr("Email not verified yet. Click the link in your inbox first, then come back and tap this button.");
    }
  }catch(e){setEmailErr(e.message);}
  setLoading(false);
        }

  if(emailStep) return(
    <div>
      <div style={{display:"flex",alignItems:"center",gap:12,marginBottom:22}}>
        <Btn variant="ghost" size="sm" onClick={()=>setView("groups")}>← Back</Btn>
        <h2 style={{margin:0,color:C.text,fontSize:18,fontWeight:800}}>Create Group</h2>
      </div>
      <Card>
        <div style={{color:C.text,fontWeight:700,fontSize:15,marginBottom:6}}>Verify your email first</div>
        <div style={{color:C.muted,fontSize:13,marginBottom:18,lineHeight:1.6}}>Group admins need a verified email address. This is how we contact you if there are issues with your group and how members can reach you.</div>
        {!emailSent?(
          <div>
            {emailErr&&<div style={{color:C.red,fontSize:13,marginBottom:10}}>{emailErr}</div>}
            <Inp label="Your email address" placeholder="amina@example.com" value={email} onChange={e=>setEmail(e.target.value)}/>
            <Btn full onClick={sendVerification} disabled={loading||!email.trim()}>{loading?"Sending...":"Send Verification Email"}</Btn>
          </div>
        ):(
  <div>
    {emailErr&&<div style={{color:C.red,fontSize:13,marginBottom:10}}>{emailErr}</div>}
<Btn full onClick={verifyOtp} disabled={loading}>{loading?"Checking...":"I've Clicked the Link — Continue"}</Btn>
<button onClick={()=>setEmailSent(false)} style={{background:"none",border:"none",color:C.muted,fontSize:12,cursor:"pointer",marginTop:10,display:"block",width:"100%",textAlign:"center",fontFamily:"inherit"}}>Use a different email</button>
    {emailErr&&<div style={{color:C.red,fontSize:13,marginBottom:10}}>{emailErr}</div>}
    <Inp label="6-digit code" placeholder="123456" value={otp} onChange={e=>setOtp(e.target.value)} style={{letterSpacing:"0.3em",fontSize:20,textAlign:"center"}}/>
    <Btn full onClick={verifyOtp} disabled={loading||otp.length<6}>{loading?"Verifying...":"Verify Email"}</Btn>
    <button onClick={()=>setEmailSent(false)} style={{background:"none",border:"none",color:C.muted,fontSize:12,cursor:"pointer",marginTop:10,display:"block",width:"100%",textAlign:"center",fontFamily:"inherit"}}>Use a different email</button>
  </div>
        )}
      </Card>
    </div>
  );

  async function create() {
    if(!form.name||!form.contributionAmount)return;
    setLoading(true);
    try {
      // 1. Insert group
      const [group] = await db.insert("groups",{
        admin_id:user.id, name:form.name, description:form.description,
        contribution_amount:Number(form.contributionAmount),
        payout_schedule:form.payoutSchedule, payout_percent:Number(form.payoutPercent),
        interest_rate:Number(form.interestRate), max_loan_multiplier:Number(form.maxLoanMultiplier),
        status:"active", recipient_queue:[], round_number:1, member_count:1,
      });
      // 2. Insert admin as first member
      const [member] = await db.insert("members",{
        group_id:group.id, user_id:user.id, name:user.name, phone:user.phone,
        status:"active", total_contributed:0, total_received:0,
      });
      // 3. Update group with queue
      await db.update("groups",`id=eq.${group.id}`,{ recipient_queue:[member.id], current_recipient_id:member.id });
      // 4. Open Cycle 1
      const [cycle] = await db.insert("cycles",{
        group_id:group.id, number:1, recipient_id:member.id, recipient_name:member.name, status:"open",
        end_date:calcCycleEndDate(new Date().toISOString(), form.payoutSchedule),
      });
      // 5. Create slot for admin
      await db.insert("slots",{ group_id:group.id, cycle_id:cycle.id, member_id:member.id, member_name:member.name, expected:Number(form.contributionAmount), paid:0, status:"pending" });
      // 6. Role is per-group (group.admin_id) — no global role update needed
      // 7. Audit entry
      const entry = await buildEntry("GROUP_CREATED",{groupId:group.id},"GENESIS",user.id,user.name,group.id,`Group "${group.name}" created by ${user.name}`);
      await db.insert("audit_log",{...entry,group_id:group.id,user_id:user.id,user_name:user.name,prev_hash:entry.prev_hash,data:entry.data});
      // 8. System message
      await db.insert("messages",{group_id:group.id,user_id:user.id,user_name:"System",text:`Welcome to ${group.name}. Cycle 1 is open. Contribution: ${fmt(Number(form.contributionAmount))} per member. First recipient: ${member.name}.`,system:true});
      onGroupCreated(group.id);
    } catch(e) { console.error(e); alert("Error creating group: "+e.message); }
    setLoading(false);
  }

  return (
    <div>
      <div style={{display:"flex",alignItems:"center",gap:12,marginBottom:22}}>
        <Btn variant="ghost" size="sm" onClick={()=>setView("groups")}>← Back</Btn>
        <h2 style={{margin:0,color:C.text,fontSize:18,fontWeight:800}}>Create Group</h2>
      </div>
      <Card>
        <Inp label="Group Name" placeholder="e.g. Mama Pima Vikoba" value={form.name} onChange={set("name")}/>
        <Inp label="Contribution Amount (TZS)" type="number" placeholder="50000" value={form.contributionAmount} onChange={set("contributionAmount")}/>
        <Sel label="Payout Schedule" value={form.payoutSchedule} onChange={set("payoutSchedule")}><option value="weekly">Weekly</option><option value="monthly">Monthly</option></Sel>
        <Sel label="Release Percentage" value={form.payoutPercent} onChange={set("payoutPercent")}>
          <option value="25">25% — 4 releases (maximum accountability)</option>
          <option value="50">50% — 2 releases</option>
          <option value="100">100% — full trust</option>
        </Sel>
        <Sel label="Loan Interest Rate" value={form.interestRate} onChange={set("interestRate")}>
          <option value="0">0% — no interest</option>
          <option value="5">5%</option><option value="10">10%</option><option value="15">15%</option><option value="20">20%</option>
        </Sel>
        <Sel label="Maximum Loan Amount" value={form.maxLoanMultiplier} onChange={set("maxLoanMultiplier")}>
          <option value="1">1× contribution</option><option value="2">2× contribution</option>
          <option value="3">3× contribution</option><option value="5">5× contribution</option>
          <option value="0">No limit</option>
        </Sel>
        <Inp label="Description (optional)" placeholder="Purpose of this group" value={form.description} onChange={set("description")}/>
        <Btn full onClick={create} disabled={!form.name||!form.contributionAmount||loading}>{loading?"Creating...":"Create Group"}</Btn>
      </Card>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// GROUP DETAIL — WhatsApp style with live data
// ─────────────────────────────────────────────────────────────────────────────
function GroupDetail({user,groupId,setView}) {
  const [group,setGroup]=useState(null);
  const [members,setMembers]=useState([]);
  const [activeCycle,setActiveCycle]=useState(null);
  const [cycleSlots,setCycleSlots]=useState([]);
  const [contributions,setContribs]=useState([]);
  const [tranches,setTranches]=useState([]);
  const [loans,setLoans]=useState([]);
  const [votes,setVotes]=useState([]);
  const [messages,setMessages]=useState([]);
  const [msgOffset,setMsgOffset]=useState(0);
  const [hasMoreMsgs,setHasMoreMsgs]=useState(false);
  const [loadingMore,setLoadingMore]=useState(false);
  const [panel,setPanel]=useState(null);
  const [actionSheet,setActionSheet]=useState(false);
  const [modal,setModal]=useState(null);
  const [text,setText]=useState("");
  const [loading,setLoading]=useState(true);
  const bottomRef=useRef(null);

  async function loadAll() {
    try {
      const [g] = await db.select("groups",`id=eq.${groupId}`);
      if(!g){setLoading(false);return;}
      setGroup(g);

      // Fetch all data in parallel — each call wrapped individually so one failure does not block others
      const [mems,cycles] = await Promise.all([
        db.select("members",`group_id=eq.${groupId}&order=joined_at.asc`).catch(()=>[]),
        db.select("cycles",`group_id=eq.${groupId}&status=eq.open&limit=1`).catch(()=>[]),
      ]);
      setMembers(mems||[]);
      const cycle = cycles?.[0]||null;
      setActiveCycle(cycle);

      const [sl,contribs,tr,ls,vs,msgs] = await Promise.all([
        cycle ? db.select("slots",`cycle_id=eq.${cycle.id}&order=created_at.asc`).catch(()=>[]) : Promise.resolve([]),
        db.select("contributions",`group_id=eq.${groupId}&order=created_at.desc`).catch(()=>[]),
        db.select("tranches",`group_id=eq.${groupId}&order=created_at.desc`).catch(()=>[]),
        db.select("loans",`group_id=eq.${groupId}&order=requested_at.desc`).catch(()=>[]),
        db.select("votes",`group_id=eq.${groupId}&order=created_at.desc`).catch(()=>[]),
        db.select("messages",`group_id=eq.${groupId}&order=created_at.desc&limit=51`).catch(()=>[]),
      ]);
      setCycleSlots(sl||[]); setContribs(contribs||[]); setTranches(tr||[]);
      setLoans(ls||[]); setVotes(vs||[]);
      // msgs fetched desc limit 51 — reverse for display, check if more exist
      const msgArr=msgs||[];
      setHasMoreMsgs(msgArr.length>50);
      setMessages([...msgArr.slice(0,50)].reverse());
      setMsgOffset(50);
    } catch(e){console.error("loadAll error:",e);}
    setLoading(false);
  }

  useEffect(()=>{ loadAll(); },[groupId]);
  useEffect(()=>{ bottomRef.current?.scrollIntoView({behavior:"smooth"}); },[messages.length]);

  //Real-time message subscription
  useEffect(()=>{
  let active=true;
  const poll=async()=>{
    if(!active)return;
    try{
      const rows=await db.select("messages","group_id=eq."+groupId+"&order=created_at.desc&limit=51");
      if(!active)return;
      setHasMoreMsgs((rows||[]).length>50);
      setMessages([...(rows||[]).slice(0,50)].reverse());
    }catch(e){}
  };
  poll();
  const t=setInterval(poll,3000);
  return()=>{active=false;clearInterval(t);};
},[groupId]);

  // Real-time for contributions, slots, and group — properly cleaned up on unmount
  useEffect(()=>{
    let active = true;
    const safeLoad = () => { if(active) loadAll(); };
    const u1=subscribe("contributions","group_id=eq."+groupId, safeLoad);
    const u2=subscribe("slots","group_id=eq."+groupId, safeLoad);
    const u3=subscribe("groups","id=eq."+groupId, safeLoad);
    const u4=subscribe("loans","group_id=eq."+groupId, safeLoad);
    const u5=subscribe("votes","group_id=eq."+groupId, safeLoad);
    return ()=>{ active=false; u1();u2();u3();u4();u5(); };
  },[groupId]);

  if(loading||!group) return <Spinner/>;

  const isAdmin = group.admin_id===user.id;
  const isMember = !!members.find(m=>m.user_id===user.id&&m.status!=="removed");
  const canChat = isMember||isAdmin;
  const activeMembers = members.filter(m=>m.status!=="removed");
  const paidSlots = cycleSlots.filter(s=>s.status==="paid");
  const pool = poolBalance(contributions,groupId);
  const heldTranches = tranches.filter(t=>t.status==="held");

  async function loadEarlierMessages() {
    if(!hasMoreMsgs||loadingMore)return;
    setLoadingMore(true);
    try {
      const older = await db.select("messages","group_id=eq."+groupId+"&order=created_at.desc&limit=51&offset="+msgOffset);
      const arr = older||[];
      setHasMoreMsgs(arr.length>50);
      setMessages(prev=>[...[...arr.slice(0,50)].reverse(),...prev]);
      setMsgOffset(o=>o+50);
    } catch(e){console.error(e);}
    setLoadingMore(false);
  }

  async function sendMessage() {
    if(!text.trim())return;
    await db.insert("messages",{group_id:groupId,user_id:user.id,user_name:user.name,text:text.trim(),system:false});
    setText("");
  }

  async function recordPayment(memberId,amount,mpesaRef) {
    const member=members.find(m=>m.id===memberId);
    const slot=cycleSlots.find(s=>s.member_id===memberId);
    if(!member||!amount)return;
    const amt=Number(amount);
    const alreadyPaid=slot?.paid||0;
    const newTotalPaid=alreadyPaid+amt;
    const isFullyPaid=newTotalPaid>=(group?.contribution_amount||0);

    // Insert contribution record
    await db.insert("contributions",{group_id:groupId,member_id:member.id,user_id:member.user_id,member_name:member.name,amount:amt,type:"contribution",cycle_id:activeCycle?.id,mpesa_ref:mpesaRef||null});

    // Update slot — mark paid only when full amount received
    if(slot) await db.update("slots",`id=eq.${slot.id}`,{
      paid:newTotalPaid,
      status:isFullyPaid?"paid":"pending",
      paid_at:isFullyPaid?now():null
    });

    // Update member total contributed
    await db.update("members",`id=eq.${member.id}`,{total_contributed:member.total_contributed+amt});

    // Audit
    const prevHash=await getLastHash(groupId);
    const desc=isFullyPaid
      ?`${member.name} completed contribution of ${fmt(amt)}${alreadyPaid>0?` (total: ${fmt(newTotalPaid)})`:""}`
      :`${member.name} partial payment of ${fmt(amt)} — ${fmt(newTotalPaid)} of ${fmt(group.contribution_amount)} paid`;
    const entry=await buildEntry("CONTRIBUTION",{amount:amt,mpesaRef,partial:!isFullyPaid,totalPaid:newTotalPaid},prevHash,user.id,user.name,groupId,desc+(mpesaRef?` · Ref: ${mpesaRef}`:""));
    await db.insert("audit_log",{...entry,group_id:groupId,user_id:user.id,data:entry.data});

    // System message
    const msgText=isFullyPaid
      ?`${member.name} paid ${fmt(amt)} for Cycle ${activeCycle?.number}. Contribution complete.${mpesaRef?` Ref: ${mpesaRef}`:""}`
      :`${member.name} paid ${fmt(amt)} (partial). ${fmt(group.contribution_amount-newTotalPaid)} still owed this cycle.${mpesaRef?` Ref: ${mpesaRef}`:""}`;
    await db.insert("messages",{group_id:groupId,user_id:user.id,user_name:"System",text:msgText,system:true});

    // Check if all slots now fully paid
    const freshSlots=await db.select("slots",`cycle_id=eq.${activeCycle?.id}`);
    const allFullyPaid=freshSlots.every(s=>s.status==="paid");
    if(allFullyPaid) await db.insert("messages",{group_id:groupId,user_id:user.id,user_name:"System",text:"All members have fully contributed this cycle.",system:true});

    setModal(null); loadAll();
  }

  async function addMember(phone) {
    const clean=cleanPhone(phone);
    const profiles=await sbFetch(`profiles?phone=eq.${clean}&select=id,name,phone`);
    if(!profiles?.length)return "No account found for this number.";
    const target=profiles[0];
    if(members.find(m=>m.user_id===target.id&&m.status!=="removed"))return "Already a member.";
    const [member]=await db.insert("members",{group_id:groupId,user_id:target.id,name:target.name,phone:target.phone,status:"pending-cycle",total_contributed:0,total_received:0});
    const updQueue=[...group.recipient_queue,member.id];
    await db.update("groups","id=eq."+groupId,{
      recipient_queue:updQueue,
      member_count:(group.member_count||1)+1,
    });
    const prevHash=await getLastHash(groupId);
    const entry=await buildEntry("MEMBER_ADDED",{memberId:member.id},prevHash,user.id,user.name,groupId,`${target.name} added by ${user.name}`);
    await db.insert("audit_log",{...entry,group_id:groupId,user_id:user.id,data:entry.data});
    await db.insert("messages",{group_id:groupId,user_id:user.id,user_name:"System",text:`${target.name} has joined the group. They will be included from the next cycle.`,system:true});
    setModal(null); loadAll(); return null;
  }

  async function closeCycle() {
    // Mark pending slots overdue
    const pendingSlots=cycleSlots.filter(s=>s.status==="pending");
    for(const s of pendingSlots) await db.update("slots",`id=eq.${s.id}`,{status:"overdue"});
    if(pendingSlots.length>0) await db.insert("messages",{group_id:groupId,user_id:user.id,user_name:"System",text:`Closing Cycle ${activeCycle.number}. Members who did not contribute: ${pendingSlots.map(s=>s.member_name).join(", ")}.`,system:true});

    // Activate pending-cycle members
    const pendingMembers=members.filter(m=>m.status==="pending-cycle");
    for(const m of pendingMembers) await db.update("members",`id=eq.${m.id}`,{status:"active"});

    const cycleNum=activeCycle.number;
    const totalCycles=group.recipient_queue.length;
    const isLastCycle=cycleNum>=totalCycles;
    const currentPool=poolBalance(contributions,groupId);
    const recipientMember=members.find(m=>m.id===activeCycle.recipient_id);
    const totalTranches=group.payout_percent===100?1:group.payout_percent===50?2:4;

    // Apply loan deduction to payout
    const activeLoan=loans.find(l=>l.member_id===activeCycle.recipient_id&&l.status==="active");
    let netPayout=currentPool;
    if(activeLoan){
      const remaining=activeLoan.total_owed-activeLoan.total_repaid;
      const deduction=Math.min(remaining,currentPool);
      netPayout=currentPool-deduction;
      const newRepaid=activeLoan.total_repaid+deduction;
      const settled=newRepaid>=activeLoan.total_owed;
      await db.update("loans",`id=eq.${activeLoan.id}`,{total_repaid:newRepaid,status:settled?"settled":"active",settled_at:settled?now():null});
      await db.insert("contributions",{group_id:groupId,member_id:activeLoan.member_id,user_id:activeLoan.member_id,member_name:activeLoan.member_name,amount:deduction,type:"loan-repayment",loan_id:activeLoan.id});
      await db.insert("messages",{group_id:groupId,user_id:user.id,user_name:"System",text:`${recipientMember?.name}'s payout: ${fmt(deduction)} deducted for outstanding loan.${settled?" Loan fully settled.":""} ${fmt(netPayout)} released.`,system:true});
    }

    // Process loan repayments from this cycle
    const activeLoans=loans.filter(l=>l.status==="active"&&l.member_id!==activeCycle.recipient_id);
    for(const loan of activeLoans){
      const slot=cycleSlots.find(s=>s.member_id===loan.member_id&&s.status==="paid");
      if(!slot)continue;
      const remaining=loan.total_owed-loan.total_repaid;
      const repay=Math.min(loan.installment,remaining);
      const newRepaid=loan.total_repaid+repay;
      const settled=newRepaid>=loan.total_owed;
      await db.update("loans",`id=eq.${loan.id}`,{total_repaid:newRepaid,status:settled?"settled":"active",settled_at:settled?now():null});
      await db.insert("contributions",{group_id:groupId,member_id:loan.member_id,user_id:loan.member_id,member_name:loan.member_name,amount:repay,type:"loan-repayment",loan_id:loan.id});
      await db.insert("messages",{group_id:groupId,user_id:user.id,user_name:"System",text:`${loan.member_name} repaid ${fmt(repay)} on their loan.${settled?" Loan fully settled.":` ${fmt(loan.total_owed-newRepaid)} remaining.`}`,system:true});
    }

    // Build tranches
    const trancheAmt=Math.floor(netPayout/totalTranches);
    const newTranches=Array.from({length:totalTranches}).map((_,i)=>{
      const isLastT=i===totalTranches-1;
      return {
        group_id:groupId, member_id:activeCycle.recipient_id, member_name:recipientMember?.name||"",
        cycle_id:activeCycle.id, amount:isLastT?netPayout-trancheAmt*(totalTranches-1):trancheAmt,
        number:i+1, total_tranches:totalTranches,
        release_cycle:isLastT?totalCycles:cycleNum+i, is_last:isLastT,
        status:i===0?"released":"held",
        released_at:i===0?now():null,
      };
    });

    // Process held tranches due this cycle
    const dueTranches=tranches.filter(t=>t.status==="held"&&(t.release_cycle===cycleNum||(t.is_last&&isLastCycle)));
    for(const t of dueTranches){
      const slot=cycleSlots.find(s=>s.member_id===t.member_id);
      const paid=slot?.status==="paid";
      if(paid||t.is_last){
        await db.update("tranches",`id=eq.${t.id}`,{status:"released",released_at:now()});
        await db.insert("contributions",{group_id:groupId,member_id:t.member_id,user_id:t.member_id,member_name:t.member_name,amount:t.amount,type:"tranche-release",tranche_id:t.id});
        await db.update("members",`id=eq.${t.member_id}`,{total_received:members.find(m=>m.id===t.member_id)?.total_received+t.amount});
        await db.insert("messages",{group_id:groupId,user_id:user.id,user_name:"System",text:`${t.member_name} received tranche ${t.number}/${t.total_tranches} — ${fmt(t.amount)}`,system:true});
      } else {
        await db.update("tranches",`id=eq.${t.id}`,{status:"forfeited",forfeited_at:now()});
        await db.insert("messages",{group_id:groupId,user_id:user.id,user_name:"System",text:`${t.member_name} did not contribute. Their held tranche of ${fmt(t.amount)} was redirected to the pool.`,system:true});
      }
    }

    // Insert new tranches and release tranche 1
    for(const t of newTranches) await db.insert("tranches",t);
    await db.insert("contributions",{group_id:groupId,member_id:activeCycle.recipient_id,user_id:activeCycle.recipient_id,member_name:recipientMember?.name||"",amount:newTranches[0].amount,type:"payout",tranche_id:newTranches[0].id});
    await db.update("members",`id=eq.${activeCycle.recipient_id}`,{total_received:recipientMember?.total_received+newTranches[0].amount});
    await db.insert("messages",{group_id:groupId,user_id:user.id,user_name:"System",text:`${recipientMember?.name} received ${fmt(newTranches[0].amount)} — Tranche 1 of ${totalTranches}.${totalTranches>1?` ${totalTranches-1} tranche(s) held.`:""}`,system:true});

    // Close this cycle
    await db.update("cycles",`id=eq.${activeCycle.id}`,{status:"closed",closed_at:now(),payout_amount:netPayout});

    // Audit
    const prevHash=await getLastHash(groupId);
    const entry=await buildEntry("CYCLE_CLOSED",{cycleId:activeCycle.id,pool:currentPool,payout:newTranches[0].amount},prevHash,user.id,user.name,groupId,`Cycle ${cycleNum} closed. Pool: ${fmt(currentPool)}. Payout to ${recipientMember?.name}: ${fmt(newTranches[0].amount)}`);
    await db.insert("audit_log",{...entry,group_id:groupId,user_id:user.id,data:entry.data});

    if(!isLastCycle){
      // Rotate queue and open next cycle
      const oldQueue=[...group.recipient_queue];
      const nextQueue=[...oldQueue.slice(1),oldQueue[0]];
      const nextRecipientId=nextQueue[0];
      const nextRecipient=members.find(m=>m.id===nextRecipientId);
      await db.update("groups",`id=eq.${groupId}`,{recipient_queue:nextQueue,current_recipient_id:nextRecipientId});
      const [newCycle]=await db.insert("cycles",{group_id:groupId,number:cycleNum+1,recipient_id:nextRecipientId,recipient_name:nextRecipient?.name||"",status:"open",end_date:calcCycleEndDate(new Date().toISOString(),group.payout_schedule)});
      const activeMs=members.filter(m=>m.status==="active");
      for(const m of activeMs) await db.insert("slots",{group_id:groupId,cycle_id:newCycle.id,member_id:m.id,member_name:m.name,expected:group.contribution_amount,paid:0,status:"pending"});
      await db.insert("messages",{group_id:groupId,user_id:user.id,user_name:"System",text:`Cycle ${cycleNum} closed. Cycle ${cycleNum+1} is now open. Next recipient: ${nextRecipient?.name}. ${activeMs.length} members expected to contribute.`,system:true});
    } else {
      // ROUND COMPLETE — release all remaining held tranches
      const stillHeld=tranches.filter(t=>t.status==="held"&&!dueTranches.find(d=>d.id===t.id));
      for(const t of stillHeld){
        await db.update("tranches",`id=eq.${t.id}`,{status:"released",released_at:now()});
        await db.insert("contributions",{group_id:groupId,member_id:t.member_id,user_id:t.member_id,member_name:t.member_name,amount:t.amount,type:"tranche-release",tranche_id:t.id});
        await db.update("members",`id=eq.${t.member_id}`,{total_received:members.find(m=>m.id===t.member_id)?.total_received+t.amount});
        await db.insert("messages",{group_id:groupId,user_id:user.id,user_name:"System",text:`Final settlement: ${t.member_name} received ${fmt(t.amount)} — Tranche ${t.number}/${t.total_tranches}`,system:true});
      }
      await db.update("groups",`id=eq.${groupId}`,{status:"round-complete",current_recipient_id:null});
      await db.insert("messages",{group_id:groupId,user_id:user.id,user_name:"System",text:`Round ${group.round_number} complete. All members have received their payouts and all tranches have been settled. Discuss the next round order in chat, then admin can start a new round from Group Details.`,system:true});
    }
    setModal(null); loadAll();
  }

  async function startNewRound(orderedQueue) {
    const newRoundNum=(group.round_number||1)+1;
    const firstRecipientId=orderedQueue[0].id;
    const firstRecipient=orderedQueue[0];
    await db.update("groups",`id=eq.${groupId}`,{status:"active",recipient_queue:orderedQueue.map(m=>m.id),current_recipient_id:firstRecipientId,round_number:newRoundNum});
    const [newCycle]=await db.insert("cycles",{group_id:groupId,number:1,recipient_id:firstRecipientId,recipient_name:firstRecipient.name,status:"open"});
    const activeMs=activeMembers.filter(m=>m.status==="active");
    for(const m of activeMs) await db.insert("slots",{group_id:groupId,cycle_id:newCycle.id,member_id:m.id,member_name:m.name,expected:group.contribution_amount,paid:0,status:"pending"});
    const prevHash=await getLastHash(groupId);
    const entry=await buildEntry("ROUND_STARTED",{round:newRoundNum,queue:orderedQueue.map(m=>m.name)},prevHash,user.id,user.name,groupId,`Round ${newRoundNum} started. Queue: ${orderedQueue.map(m=>m.name).join(", ")}`);
    await db.insert("audit_log",{...entry,group_id:groupId,user_id:user.id,data:entry.data});
    await db.insert("messages",{group_id:groupId,user_id:user.id,user_name:"System",text:`Round ${newRoundNum} has started. Agreed order: ${orderedQueue.map((m,i)=>`${i+1}. ${m.name}`).join(", ")}. First recipient: ${firstRecipient.name}. Contribution: ${fmt(group.contribution_amount)}/member.`,system:true});
    setModal(null); loadAll();
  }

  // Panel view
  if(panel){
    return (
      <div style={{maxWidth:680,margin:"0 auto",padding:"0 0 24px"}}>
        <div style={{background:C.card,borderBottom:`1px solid ${C.border}`,padding:"12px 16px",display:"flex",alignItems:"center",gap:12,position:"sticky",top:0,zIndex:100}}>
          <button onClick={()=>setPanel(null)} style={{background:"none",border:"none",color:C.muted,cursor:"pointer",fontSize:18,padding:0,lineHeight:1}}>←</button>
          <div style={{color:C.text,fontWeight:700,fontSize:15}}>{group.name}</div>
        </div>
        <div style={{padding:"20px 16px"}}>
          <PanelErrorBoundary onBack={()=>setPanel(null)}>
            {panel==="menu"&&<MenuPanel group={group} isAdmin={isAdmin} setPanel={setPanel} groupId={groupId} setView={setView} loadAll={loadAll} user={user}/>}
            {panel==="details"&&<DetailsPanel group={group} activeCycle={activeCycle} cycleSlots={cycleSlots} heldTranches={heldTranches} pool={pool} isAdmin={isAdmin} activeMembers={activeMembers} onStartNewRound={startNewRound}/>}
            {panel==="my-status"&&<MyStatusPanel group={group} activeCycle={activeCycle} cycleSlots={cycleSlots} contributions={contributions} tranches={tranches} loans={loans} votes={votes} user={user} members={members}/>}
            {panel==="members"&&<MembersPanel members={members} activeMembers={activeMembers} group={group} user={user} votes={votes} loans={loans} groupId={groupId} isAdmin={isAdmin} loadAll={loadAll}/>}
            {panel==="transactions"&&<TransactionsPanel contributions={contributions}/>}
            {panel==="loans"&&<LoansPanel loans={loans} votes={votes} members={activeMembers} user={user} groupId={groupId} isAdmin={isAdmin} loadAll={loadAll}/>}
            {panel==="votes"&&<VotesPanel votes={votes} members={activeMembers} user={user} groupId={groupId} isAdmin={isAdmin} loadAll={loadAll}/>}
            {panel==="audit"&&<AuditPanel groupId={groupId}/>}
            {panel==="settings"&&<GroupSettingsPanel group={group} groupId={groupId} contributions={contributions} loadAll={loadAll} setPanel={setPanel}/>}
          </PanelErrorBoundary>
        </div>
      </div>
    );
  }

  return (
    <div style={{display:"flex",flexDirection:"column",height:"100vh"}}>
      {/* Header */}
      <div style={{background:C.card,borderBottom:`1px solid ${C.border}`,padding:"10px 14px",display:"flex",alignItems:"center",gap:10,flexShrink:0}}>
        <button onClick={()=>setView("groups")} style={{background:"none",border:"none",color:C.muted,cursor:"pointer",fontSize:18,padding:0,lineHeight:1}}>←</button>
        <div onClick={()=>setPanel("details")} style={{flex:1,cursor:"pointer"}}>
          <div style={{color:C.text,fontWeight:700,fontSize:15}}>{group.name}</div>
          <div style={{color:C.muted,fontSize:12,marginTop:1}}>
            {activeMembers.length} members
            {activeCycle?` · Cycle ${activeCycle.number} · ${paidSlots.length}/${cycleSlots.length} paid`:""}
            {activeCycle?.end_date&&daysUntil(activeCycle.end_date)!==null?` · ${daysUntil(activeCycle.end_date)===0?"closes today":`${daysUntil(activeCycle.end_date)}d left`}`:""}
          </div>
        </div>
        <div onClick={()=>setPanel("details")} style={{background:group.status==="round-complete"?C.greenSoft:C.accentSoft,border:`1px solid ${group.status==="round-complete"?C.green+"44":"rgba(37,99,235,.25)"}`,borderRadius:8,padding:"6px 12px",cursor:"pointer",textAlign:"right",flexShrink:0}}>
          <div style={{color:group.status==="round-complete"?C.green:C.accent,fontWeight:800,fontSize:15}}>{fmt(pool)}</div>
          <div style={{color:C.muted,fontSize:10}}>{group.status==="round-complete"?"settled":"pool"}</div>
        </div>
        <button onClick={()=>setPanel("menu")} style={{background:"none",border:"none",color:C.muted,cursor:"pointer",fontSize:22,padding:"0 0 0 4px",lineHeight:1}}>⋮</button>
      </div>

      {/* Alerts */}
      {group.status==="round-complete"&&(
        <div style={{background:C.green+"12",borderBottom:`1px solid ${C.green}22`,padding:"7px 16px",display:"flex",alignItems:"center",justifyContent:"space-between",flexShrink:0}}>
          <span style={{color:C.green,fontSize:12,fontWeight:600}}>Round {group.round_number} complete — discuss next round in chat</span>
          <button onClick={()=>setPanel("details")} style={{background:"none",border:"none",color:C.green,fontSize:11,cursor:"pointer",fontWeight:600}}>Details</button>
        </div>
      )}
      {group.status!=="round-complete"&&activeCycle&&cycleSlots.length>0&&paidSlots.length<cycleSlots.length&&(
        <div style={{background:C.amber+"12",borderBottom:`1px solid ${C.amber}22`,padding:"7px 16px",display:"flex",alignItems:"center",justifyContent:"space-between",flexShrink:0}}>
          <span style={{color:C.amber,fontSize:12,fontWeight:600}}>{cycleSlots.length-paidSlots.length} member{cycleSlots.length-paidSlots.length!==1?"s":""} yet to contribute</span>
          <button onClick={()=>setPanel("details")} style={{background:"none",border:"none",color:C.amber,fontSize:11,cursor:"pointer",fontWeight:600}}>View</button>
        </div>
      )}

      {/* Chat */}
      <div style={{flex:1,overflowY:"auto",padding:"12px 16px",display:"flex",flexDirection:"column",gap:6}}>
        {hasMoreMsgs&&(
          <div style={{textAlign:"center",margin:"8px 0 12px"}}>
            <button onClick={loadEarlierMessages} disabled={loadingMore} style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:20,padding:"6px 16px",color:C.textMid,fontSize:12,cursor:loadingMore?"not-allowed":"pointer",fontFamily:"inherit"}}>
              {loadingMore?"Loading...":"Load earlier messages"}
            </button>
          </div>
        )}
        {messages.length===0&&<div style={{textAlign:"center",color:C.muted,fontSize:13,margin:"auto"}}>Group created. Start the conversation.</div>}
        {messages.map(m=>{
          if(m.system){
            // Classify system message weight
            const txt=m.text.toLowerCase();
            const isCritical=txt.includes("round")||txt.includes("payout")||txt.includes("loan approved")||txt.includes("loan rejected")||txt.includes("removed")||txt.includes("settled")||txt.includes("forfeited")||txt.includes("tranche");
            const isWarning=txt.includes("did not contribute")||txt.includes("overdue")||txt.includes("closing cycle")||txt.includes("yet to contribute");
            const borderCol=isCritical?C.accent+"55":isWarning?C.amber+"44":C.border;
            const textCol=isCritical?C.accent:isWarning?C.amber:C.textMid;
            const bgCol=isCritical?C.accentSoft:isWarning?C.amberSoft:C.surface;
            return(
              <div key={m.id} style={{textAlign:"center",margin:"8px 0"}}>
                <span style={{background:bgCol,border:`1px solid ${borderCol}`,borderRadius:8,padding:"6px 14px",color:textCol,fontSize:12,display:"inline-block",maxWidth:"88%",lineHeight:1.5,whiteSpace:"pre-line",fontWeight:isCritical||isWarning?600:400}}>{m.text}</span>
              </div>
            );
          }
          const isMe=m.user_id===user.id;
          return(
            <div key={m.id} style={{display:"flex",flexDirection:isMe?"row-reverse":"row",gap:8,alignItems:"flex-end"}}>
              <div style={{width:26,height:26,borderRadius:"50%",background:isMe?C.accentSoft:C.surface,border:`1px solid ${C.border}`,display:"flex",alignItems:"center",justifyContent:"center",fontSize:10,color:isMe?C.accent:C.muted,fontWeight:700,flexShrink:0}}>{m.user_name.charAt(0).toUpperCase()}</div>
              <div style={{maxWidth:"68%"}}>
                {!isMe&&<div style={{color:C.muted,fontSize:11,marginBottom:2,fontWeight:600}}>{m.user_name}</div>}
                <div style={{background:isMe?C.accent:C.card,border:isMe?"none":`1px solid ${C.border}`,color:isMe?"#fff":C.text,borderRadius:isMe?"12px 12px 3px 12px":"12px 12px 12px 3px",padding:"8px 12px",fontSize:14,lineHeight:1.4}}>{m.text}</div>
                <div style={{color:C.muted,fontSize:10,marginTop:2,textAlign:isMe?"right":"left"}}>{fmtT(m.created_at)}</div>
              </div>
            </div>
          );
        })}
        <div ref={bottomRef}/>
      </div>

      {/* Input */}
      <div style={{borderTop:`1px solid ${C.border}`,padding:"10px 14px",display:"flex",gap:10,flexShrink:0,background:C.bg}}>
        {isAdmin&&group.status!=="round-complete"&&<button onClick={()=>setActionSheet(true)} style={{width:36,height:36,borderRadius:"50%",background:C.accentSoft,border:`1px solid rgba(37,99,235,.25)`,color:C.accent,fontSize:20,cursor:"pointer",display:"flex",alignItems:"center",justifyContent:"center",flexShrink:0}}>+</button>}
        {!isAdmin&&isMember&&group.status!=="round-complete"&&<button onClick={()=>setModal("loan-request")} title="Request a loan" style={{width:36,height:36,borderRadius:"50%",background:C.surface,border:`1px solid ${C.border}`,color:C.textMid,fontSize:15,cursor:"pointer",display:"flex",alignItems:"center",justifyContent:"center",flexShrink:0}}>↑</button>}
        {canChat
          ?<><input value={text} onChange={e=>setText(e.target.value)} onKeyDown={e=>e.key==="Enter"&&sendMessage()} placeholder="Message..." style={{flex:1,background:C.surface,border:`1px solid ${C.border}`,borderRadius:20,padding:"9px 14px",color:C.text,fontSize:14,outline:"none",fontFamily:"inherit"}}/><Btn onClick={sendMessage} disabled={!text.trim()}>Send</Btn></>
          :<div style={{flex:1,color:C.muted,fontSize:13,display:"flex",alignItems:"center"}}>Members only</div>
        }
      </div>

      {/* Action sheet */}
      {actionSheet&&(
        <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,.6)",zIndex:500,display:"flex",alignItems:"flex-end",justifyContent:"center"}} onClick={()=>setActionSheet(false)}>
          <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:"16px 16px 0 0",padding:20,width:"100%",maxWidth:480}} onClick={e=>e.stopPropagation()}>
            <div style={{color:C.muted,fontSize:11,fontWeight:600,letterSpacing:".06em",textTransform:"uppercase",marginBottom:14}}>Admin Actions</div>
            {[
              ["Record Payment",()=>{setActionSheet(false);setModal("payment");},"primary"],
              ["Add Member",()=>{setActionSheet(false);setModal("add-member");},"ghost"],
              ["Request Loan",()=>{setActionSheet(false);setModal("loan-request");},"ghost"],
              ["Create Vote",()=>{setActionSheet(false);setModal("vote");},"ghost"],
              activeCycle?["Close Cycle",()=>{setActionSheet(false);setModal("close-cycle");},"ghost"]:null,
            ].filter(Boolean).map(([label,action,variant])=>(
              <button key={label} onClick={action} style={{display:"block",width:"100%",padding:"13px 16px",marginBottom:8,background:variant==="primary"?C.accent:"transparent",border:`1px solid ${variant==="primary"?"transparent":C.border}`,borderRadius:10,color:variant==="primary"?"#fff":C.text,fontSize:14,fontWeight:600,cursor:"pointer",textAlign:"left",fontFamily:"inherit"}}>{label}</button>
            ))}
          </div>
        </div>
      )}

      {/* Modals */}
      {modal==="payment"&&<PaymentModal members={activeMembers} group={group} cycleSlots={cycleSlots} onRecord={recordPayment} onClose={()=>setModal(null)}/>}
      {modal==="add-member"&&<AddMemberModal onAdd={addMember} onClose={()=>setModal(null)}/>}
      {modal==="vote"&&<CreateVoteModal user={user} groupId={groupId} loadAll={loadAll} onClose={()=>setModal(null)}/>}
      {modal==="loan-request"&&<LoanRequestModal group={group} user={user} members={activeMembers} loans={loans} pool={pool} groupId={groupId} loadAll={loadAll} onClose={()=>setModal(null)}/>}
      {modal==="close-cycle"&&(
        <Modal title={`Close Cycle ${activeCycle?.number}?`} onClose={()=>setModal(null)}>
          {cycleSlots.filter(s=>s.status==="pending").length>0&&<div style={{color:C.amber,fontSize:13,marginBottom:12}}>{cycleSlots.filter(s=>s.status==="pending").map(s=>s.member_name).join(", ")} {cycleSlots.filter(s=>s.status==="pending").length===1?"has":"have"} not contributed. Their slots will be marked overdue.</div>}
          <div style={{color:C.textMid,fontSize:13,marginBottom:20}}>
            Pool ({fmt(pool)}) will be paid to {activeCycle?.recipient_name} in {group.payout_percent===100?1:group.payout_percent===50?2:4} tranche(s).
            {activeCycle&&activeCycle.number>=group.recipient_queue.length?" This is the final cycle. All held tranches will be settled and the round will be marked complete.":" The next cycle opens automatically."}
          </div>
          <div style={{display:"flex",gap:10}}><Btn full variant="danger" onClick={closeCycle}>Close Cycle</Btn><Btn full variant="ghost" onClick={()=>setModal(null)}>Cancel</Btn></div>
        </Modal>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// PANELS
// ─────────────────────────────────────────────────────────────────────────────
function MenuPanel({group,isAdmin,setPanel,groupId,setView,loadAll,user}) {
  const [deleteConfirm,setDeleteConfirm]=useState(false);
  async function deleteGroup(){
    await db.delete("groups",`id=eq.${groupId}`);
    setView("groups");
  }
  return (
    <div>
      {[
        ["Group Details","details"],
        ["My Status","my-status"],
        ["Members","members"],
        ["Transactions","transactions"],
        ["Loans","loans"],
        ["Votes","votes"],
        ["Audit Log","audit"],
        ...(isAdmin?[["Group Settings","settings"]]:[]),
      ].map(([label,id])=>(
        <button key={id} onClick={()=>setPanel(id)} style={{display:"flex",justifyContent:"space-between",alignItems:"center",width:"100%",padding:"14px 0",background:"none",border:"none",borderBottom:`1px solid ${C.border}`,color:C.text,fontSize:14,cursor:"pointer",fontFamily:"inherit"}}>
          {label}<span style={{color:C.muted}}>›</span>
        </button>
      ))}
      {isAdmin&&<div style={{marginTop:24}}>{!deleteConfirm?<button onClick={()=>setDeleteConfirm(true)} style={{background:"none",border:"none",color:C.red,fontSize:13,cursor:"pointer",fontFamily:"inherit",padding:0}}>Delete Group</button>:<div style={{display:"flex",gap:10,alignItems:"center"}}><span style={{color:C.textMid,fontSize:13}}>This cannot be undone.</span><Btn size="sm" variant="danger" onClick={deleteGroup}>Confirm</Btn><Btn size="sm" variant="ghost" onClick={()=>setDeleteConfirm(false)}>Cancel</Btn></div>}</div>}
    </div>
  );
}

function DetailsPanel({group,activeCycle,cycleSlots,heldTranches,pool,isAdmin,activeMembers,onStartNewRound}) {
  const [showNewRound,setShowNewRound]=useState(false);
  const isRoundComplete=group.status==="round-complete";
  const paidSlots=cycleSlots.filter(s=>s.status==="paid");
  return (
    <div>
      {isRoundComplete?(
        <div>
          <div style={{background:"linear-gradient(135deg,#071a0e,#051510)",border:`1px solid ${C.green}33`,borderRadius:12,padding:20,marginBottom:16}}>
            <div style={{color:C.green,fontSize:11,fontWeight:700,letterSpacing:".07em",textTransform:"uppercase",marginBottom:8}}>Round {group.round_number} Complete</div>
            <div style={{color:C.muted,fontSize:13,marginBottom:16,lineHeight:1.5}}>All members have received their payouts. All tranches have been settled.</div>
            {isAdmin&&<Btn variant="success" onClick={()=>setShowNewRound(true)}>Start New Round</Btn>}
          </div>
          <div style={{color:C.muted,fontSize:11,fontWeight:600,letterSpacing:".05em",textTransform:"uppercase",marginBottom:10}}>Member Summary</div>
          {activeMembers.map(m=>(
            <div key={m.id} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"9px 0",borderBottom:`1px solid ${C.border}`}}>
              <div style={{color:C.text,fontSize:13,fontWeight:600}}>{m.name}</div>
              <div style={{display:"flex",gap:20}}>
                <div style={{textAlign:"right"}}><div style={{color:C.muted,fontSize:10}}>contributed</div><div style={{color:C.green,fontSize:13,fontWeight:600}}>{fmt(m.total_contributed)}</div></div>
                <div style={{textAlign:"right"}}><div style={{color:C.muted,fontSize:10}}>received</div><div style={{color:C.amber,fontSize:13,fontWeight:600}}>{fmt(m.total_received)}</div></div>
              </div>
            </div>
          ))}
          {showNewRound&&<NewRoundModal group={group} members={activeMembers} onConfirm={queue=>{onStartNewRound(queue);setShowNewRound(false);}} onClose={()=>setShowNewRound(false)}/>}
        </div>
      ):(
        <div>
          <div style={{background:"linear-gradient(135deg,#0c1520,#091020)",border:`1px solid ${C.border}`,borderRadius:12,padding:20,marginBottom:16,display:"flex",justifyContent:"space-between",alignItems:"center"}}>
            <div><div style={{color:C.muted,fontSize:11,fontWeight:600,letterSpacing:".07em",textTransform:"uppercase",marginBottom:6}}>Pool Balance</div><div style={{fontSize:32,fontWeight:900,color:C.text,letterSpacing:"-.02em"}}>{fmt(pool)}</div></div>
            {activeCycle&&<div style={{textAlign:"right"}}><div style={{color:C.muted,fontSize:11,fontWeight:600,letterSpacing:".07em",textTransform:"uppercase",marginBottom:6}}>Cycle {activeCycle.number}</div><div style={{color:C.amber,fontWeight:700,fontSize:15}}>{activeCycle.recipient_name}</div><div style={{color:C.muted,fontSize:11,marginTop:2}}>next recipient</div></div>}
          </div>
          {activeCycle&&cycleSlots.length>0&&(
            <Card style={{marginBottom:16,padding:16}}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:10}}>
                <div style={{color:C.text,fontWeight:600,fontSize:13}}>Cycle {activeCycle.number}</div>
                <div style={{textAlign:"right"}}>
                  <div style={{color:C.muted,fontSize:12}}>{paidSlots.length}/{cycleSlots.length} paid</div>
                  {activeCycle.end_date&&<div style={{color:daysUntil(activeCycle.end_date)<=2?C.amber:C.muted,fontSize:11,marginTop:2}}>{daysUntil(activeCycle.end_date)===0?"Closes today":`${daysUntil(activeCycle.end_date)} days left`}</div>}
                </div>
              </div>
              <div style={{height:5,background:C.surface,borderRadius:3,overflow:"hidden",marginBottom:12}}><div style={{height:"100%",width:`${Math.round(paidSlots.length/cycleSlots.length*100)}%`,background:C.green,borderRadius:3}}/></div>
              {cycleSlots.map(s=>{
                const col=s.status==="paid"?C.green:s.status==="overdue"?C.red:s.status==="auto-deducted"?C.purple:C.muted;
                return(
                  <div key={s.id} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"7px 0",borderBottom:`1px solid ${C.border}`}}>
                    <span style={{color:C.text,fontSize:13}}>{s.member_name}</span>
                    <div style={{display:"flex",alignItems:"center",gap:8}}>{s.paid>0&&<span style={{color:C.green,fontSize:12}}>{fmt(s.paid)}</span>}<Badge color={col}>{s.status}</Badge></div>
                  </div>
                );
              })}
            </Card>
          )}
          {heldTranches.length>0&&(
            <Card style={{padding:16}}>
              <div style={{color:C.text,fontWeight:600,fontSize:13,marginBottom:10}}>Held Tranches</div>
              {heldTranches.map(t=>(
                <div key={t.id} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"7px 0",borderBottom:`1px solid ${C.border}`}}>
                  <div><span style={{color:C.text,fontSize:13}}>{t.member_name}</span><span style={{color:C.muted,fontSize:11,marginLeft:8}}>Tranche {t.number}/{t.total_tranches}</span></div>
                  <div style={{textAlign:"right"}}><div style={{color:C.amber,fontWeight:600,fontSize:13}}>{fmt(t.amount)}</div><div style={{color:C.muted,fontSize:11}}>releases cycle {t.release_cycle}</div></div>
                </div>
              ))}
            </Card>
          )}
        </div>
      )}
    </div>
  );
}

function NewRoundModal({group,members,onConfirm,onClose}) {
  const [queue,setQueue]=useState([...members.filter(m=>m.status==="active")]);
  const [dragIdx,setDragIdx]=useState(null);
  const [overIdx,setOverIdx]=useState(null);
  function onDrop(i){if(dragIdx===null||dragIdx===i)return;const q=[...queue];const [moved]=q.splice(dragIdx,1);q.splice(i,0,moved);setQueue(q);setDragIdx(null);setOverIdx(null);}
  return(
    <Modal title={`Start Round ${(group.round_number||1)+1}`} onClose={onClose}>
      <div style={{color:C.muted,fontSize:13,marginBottom:16,lineHeight:1.5}}>Drag members into the order the group agreed on in chat.</div>
      <div style={{marginBottom:20}}>
        {queue.map((m,i)=>(
          <div key={m.id} draggable onDragStart={()=>setDragIdx(i)} onDragOver={e=>{e.preventDefault();setOverIdx(i);}} onDrop={()=>onDrop(i)} onDragEnd={()=>{setDragIdx(null);setOverIdx(null);}}
            style={{display:"flex",alignItems:"center",gap:12,padding:"10px 12px",marginBottom:6,background:overIdx===i?C.accentSoft:C.surface,border:`1px solid ${overIdx===i?C.accent:C.border}`,borderRadius:8,cursor:"grab",opacity:dragIdx===i?.4:1}}>
            <div style={{color:C.muted,fontSize:13,fontWeight:700,width:20,textAlign:"center"}}>{i+1}</div>
            <div style={{width:28,height:28,borderRadius:"50%",background:C.accentSoft,display:"flex",alignItems:"center",justifyContent:"center",fontSize:12,color:C.accent,fontWeight:700,flexShrink:0}}>{m.name.charAt(0)}</div>
            <div style={{flex:1,color:C.text,fontSize:14,fontWeight:600}}>{m.name}</div>
            <div style={{color:C.muted,fontSize:18,letterSpacing:2}}>⋮⋮</div>
          </div>
        ))}
      </div>
      <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:8,padding:"10px 14px",marginBottom:16}}>
        <div style={{color:C.muted,fontSize:12,marginBottom:4}}>Agreed order</div>
        <div style={{color:C.text,fontSize:13}}>{queue.map((m,i)=>`${i+1}. ${m.name}`).join(" · ")}</div>
      </div>
      <Btn full variant="success" onClick={()=>onConfirm(queue)}>Confirm and Start Round {(group.round_number||1)+1}</Btn>
    </Modal>
  );
}

function MembersPanel({members,activeMembers,group,user,votes,loans,groupId,isAdmin,loadAll}) {
  const [removeConfirm,setRemoveConfirm]=useState(null);

  async function initiateRemoval(member){
    const activeLoan=loans.find(l=>l.member_id===member.id&&["active","voting"].includes(l.status));
    if(activeLoan){alert("Cannot remove a member with an active or pending loan.");return;}
    const [vote]=await db.insert("votes",{group_id:groupId,question:`Remove ${member.name} from the group?`,description:"Contributions already made stay in the pool. Any held tranches will be forfeited back to the pool.",created_by:user.id,created_by_name:user.name,status:"open",removal_member_id:member.id});
    const prevHash=await getLastHash(groupId);
    const entry=await buildEntry("REMOVAL_VOTE_CREATED",{memberId:member.id},prevHash,user.id,user.name,groupId,`Removal vote created for ${member.name}`);
    await db.insert("audit_log",{...entry,group_id:groupId,user_id:user.id,data:entry.data});
    await db.insert("messages",{group_id:groupId,user_id:user.id,user_name:"System",text:`A vote has been raised to remove ${member.name}. Go to Members to cast your vote.`,system:true});
    setRemoveConfirm(null); loadAll();
  }

  async function castRemovalVote(vote,choice){
    try { await db.insert("vote_choices",{vote_id:vote.id,user_id:user.id,choice}); } catch{ return; }
    const choices=await db.select("vote_choices",`vote_id=eq.${vote.id}`);
    const yeas=choices.filter(c=>c.choice==="yea").length;
    const nays=choices.filter(c=>c.choice==="nay").length;
    const majority=Math.floor(activeMembers.length/2)+1;
    const remaining=activeMembers.length-yeas-nays;
    if(yeas>=majority){
      // Execute removal
      const member=members.find(m=>m.id===vote.removal_member_id);
      const held=await db.select("tranches",`member_id=eq.${vote.removal_member_id}&status=eq.held`);
      for(const t of held) await db.update("tranches",`id=eq.${t.id}`,{status:"forfeited",forfeited_at:now()});
      const forfeitedTotal=held.reduce((s,t)=>s+t.amount,0);
      const g=await db.select("groups",`id=eq.${groupId}`);
      const updQueue=(g[0].recipient_queue||[]).filter(id=>id!==vote.removal_member_id);
      const grp=await db.select("groups","id=eq."+groupId);
      await db.update("groups","id=eq."+groupId,{
        recipient_queue:updQueue,
        current_recipient_id:updQueue[0]||null,
        member_count:Math.max(0,(grp[0]?.member_count||1)-1),
      });
      await db.update("members",`id=eq.${vote.removal_member_id}`,{status:"removed",removed_at:now()});
      await db.update("votes",`id=eq.${vote.id}`,{status:"closed",closed_at:now()});
      const prevHash=await getLastHash(groupId);
      const entry=await buildEntry("MEMBER_REMOVED",{memberId:vote.removal_member_id,forfeitedTotal},prevHash,user.id,user.name,groupId,`${member?.name} removed.${forfeitedTotal>0?` ${fmt(forfeitedTotal)} forfeited to pool.`:""}`);
      await db.insert("audit_log",{...entry,group_id:groupId,user_id:user.id,data:entry.data});
      await db.insert("messages",{group_id:groupId,user_id:user.id,user_name:"System",text:`${member?.name} has been removed from the group.${forfeitedTotal>0?` Their ${fmt(forfeitedTotal)} in held tranches was returned to the pool.`:""}`,system:true});
    } else if(yeas+remaining<majority){
      await db.update("votes",`id=eq.${vote.id}`,{status:"closed",closed_at:now()});
      await db.insert("messages",{group_id:groupId,user_id:user.id,user_name:"System",text:"Removal vote failed. Member stays in the group.",system:true});
    }
    loadAll();
  }

  const removed=members.filter(m=>m.status==="removed");
  return (
    <div>
      <div style={{color:C.muted,fontSize:11,fontWeight:600,letterSpacing:".05em",textTransform:"uppercase",marginBottom:16}}>Active — {activeMembers.length}</div>
      {activeMembers.map(m=>{
        const removalVote=votes.find(v=>v.status==="open"&&v.removal_member_id===m.id);
        return(
          <div key={m.id} style={{borderBottom:`1px solid ${C.border}`,paddingBottom:12,marginBottom:12}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
              <div style={{display:"flex",alignItems:"center",gap:10}}>
                <div style={{width:32,height:32,borderRadius:"50%",background:C.accentSoft,display:"flex",alignItems:"center",justifyContent:"center",fontSize:13,color:C.accent,fontWeight:700,flexShrink:0}}>{m.name.charAt(0)}</div>
                <div>
                  <div style={{color:C.text,fontSize:13,fontWeight:600}}>
                    {m.name}
                    {m.user_id===user.id&&<span style={{color:C.accent,fontSize:11,marginLeft:6}}>you</span>}
                    {m.user_id===group.admin_id&&<span style={{color:C.amber,fontSize:11,marginLeft:6}}>admin</span>}
                    {m.status==="pending-cycle"&&<span style={{color:C.amber,fontSize:11,marginLeft:6}}>next cycle</span>}
                  </div>
                  <div style={{color:C.muted,fontSize:11,marginTop:1}}>{m.phone}</div>
                </div>
              </div>
              <div style={{textAlign:"right"}}>
                <div style={{color:C.green,fontSize:12,fontWeight:600}}>{fmt(m.total_contributed)}</div>
                <div style={{color:C.muted,fontSize:11}}>{fmt(m.total_received)} received</div>
              </div>
            </div>
            {isAdmin&&m.user_id!==user.id&&!removalVote&&(
              removeConfirm===m.id
                ?<div style={{display:"flex",gap:8,alignItems:"center",marginTop:8}}><span style={{color:C.muted,fontSize:12}}>Start removal vote?</span><Btn size="sm" variant="danger" onClick={()=>initiateRemoval(m)}>Yes</Btn><Btn size="sm" variant="ghost" onClick={()=>setRemoveConfirm(null)}>Cancel</Btn></div>
                :<button onClick={()=>setRemoveConfirm(m.id)} style={{background:"none",border:"none",color:C.muted,fontSize:11,cursor:"pointer",marginTop:6,padding:0,fontFamily:"inherit"}}>Remove member</button>
            )}
            {removalVote&&<RemovalVoteBar vote={removalVote} user={user} activeMembers={activeMembers} member={m} onVote={castRemovalVote}/>}
          </div>
        );
      })}
      {removed.length>0&&(
        <div style={{marginTop:16}}>
          <div style={{color:C.muted,fontSize:11,fontWeight:600,letterSpacing:".05em",textTransform:"uppercase",marginBottom:10}}>Removed</div>
          {removed.map(m=><div key={m.id} style={{display:"flex",justifyContent:"space-between",padding:"8px 0",opacity:.45}}><div style={{color:C.muted,fontSize:13}}>{m.name}</div><div style={{color:C.muted,fontSize:11}}>{fmtD(m.removed_at||m.joined_at)}</div></div>)}
        </div>
      )}
    </div>
  );
}

function RemovalVoteBar({vote,user,activeMembers,member,onVote}) {
  const [choices,setChoices]=useState([]);
  useEffect(()=>{ db.select("vote_choices",`vote_id=eq.${vote.id}`).then(setChoices); },[vote.id]);
  const yeas=choices.filter(c=>c.choice==="yea").length;
  const nays=choices.filter(c=>c.choice==="nay").length;
  const myVote=choices.find(c=>c.user_id===user.id);
  const canVote=!myVote&&member.user_id!==user.id;
  const total=yeas+nays;
  return(
    <div style={{background:C.redSoft,border:`1px solid ${C.red}22`,borderRadius:8,padding:"10px 12px",marginTop:8}}>
      <div style={{color:C.red,fontSize:12,fontWeight:600,marginBottom:6}}>Removal vote in progress</div>
      <div style={{display:"flex",justifyContent:"space-between",fontSize:11,color:C.muted,marginBottom:5}}><span style={{color:C.green}}>{yeas} remove</span><span>{total}/{activeMembers.length}</span><span style={{color:C.red}}>{nays} keep</span></div>
      <div style={{height:3,background:C.surface,borderRadius:2,overflow:"hidden",marginBottom:8}}><div style={{height:"100%",width:`${total>0?Math.round(yeas/total*100):0}%`,background:C.red,borderRadius:2}}/></div>
      {canVote&&<div style={{display:"flex",gap:8}}><Btn size="sm" variant="danger" onClick={()=>onVote(vote,"yea")}>Remove</Btn><Btn size="sm" variant="ghost" onClick={()=>onVote(vote,"nay")}>Keep</Btn></div>}
      {myVote&&<span style={{color:C.muted,fontSize:11}}>You voted {myVote.choice==="yea"?"Remove":"Keep"}</span>}
      {member.user_id===user.id&&<span style={{color:C.muted,fontSize:11}}>A vote is open about your membership.</span>}
    </div>
  );
}

// ── My Status Panel ───────────────────────────────────────────────────────────
function MyStatusPanel({group,activeCycle,cycleSlots,contributions,tranches,loans,votes,user,members}) {
  const myMember=members.find(m=>m.user_id===user.id);
  if(!myMember) return <div style={{textAlign:"center",color:C.muted,fontSize:14,padding:32}}>You are not an active member of this group yet.</div>;
  const mySlot=cycleSlots.find(s=>s.member_id===myMember.id);
  const myContribs=contributions.filter(c=>c.member_id===myMember.id&&c.type==="contribution");
  const myPayouts=contributions.filter(c=>c.member_id===myMember.id&&["payout","tranche-release"].includes(c.type));
  const myTranches=tranches.filter(t=>t.member_id===myMember.id);
  const heldTranches=myTranches.filter(t=>t.status==="held");
  const myLoan=loans.find(l=>l.member_id===myMember.id&&["voting","active"].includes(l.status));
  const queuePos=group.recipient_queue?.indexOf(myMember.id);
  const slotColor=mySlot?.status==="paid"?C.green:mySlot?.status==="overdue"?C.red:mySlot?.status==="auto-deducted"?C.purple:C.amber;
  return(
    <div>
      {activeCycle&&(
        <Card style={{marginBottom:16,background:"linear-gradient(135deg,#0c1520,#091020)"}}>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:10}}>
            <div style={{color:C.muted,fontSize:11,fontWeight:600,letterSpacing:".07em",textTransform:"uppercase"}}>Cycle {activeCycle.number} — My Status</div>
            {activeCycle.end_date&&<div style={{color:daysUntil(activeCycle.end_date)<=2?C.amber:C.muted,fontSize:11,fontWeight:600}}>{daysUntil(activeCycle.end_date)===0?"Closes today":`${daysUntil(activeCycle.end_date)}d left`}</div>}
          </div>
          {mySlot?(
            <div>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:10}}>
                <div><div style={{color:slotColor,fontWeight:800,fontSize:20}}>{mySlot.status==="paid"?"Paid":"Pending"}</div>{mySlot.status==="paid"&&<div style={{color:C.green,fontSize:13,marginTop:2}}>{fmt(mySlot.paid)} contributed</div>}{mySlot.status==="pending"&&<div style={{color:C.muted,fontSize:13,marginTop:2}}>Expected: {fmt(mySlot.expected)}</div>}</div>
                <Badge color={slotColor}>{mySlot.status}</Badge>
              </div>
              {mySlot.status==="pending"&&<div style={{background:C.amberSoft,border:`1px solid ${C.amber}33`,borderRadius:8,padding:"8px 12px"}}><div style={{color:C.amber,fontSize:12,fontWeight:600}}>Payment due this cycle</div><div style={{color:C.textMid,fontSize:12,marginTop:2}}>Amount: {fmt(group.contribution_amount)} · Contact admin to record your M-Pesa payment</div></div>}
            </div>
          ):<div style={{color:C.muted,fontSize:13}}>You will join from the next cycle.</div>}
        </Card>
      )}
      {queuePos>=0&&(
        <Card style={{marginBottom:16}}>
          <div style={{color:C.muted,fontSize:11,fontWeight:600,letterSpacing:".07em",textTransform:"uppercase",marginBottom:8}}>Payout Queue</div>
          <div style={{display:"flex",alignItems:"center",gap:12}}>
            <div style={{width:44,height:44,borderRadius:"50%",background:queuePos===0?C.amberSoft:C.accentSoft,border:`1px solid ${queuePos===0?C.amber:C.accent}44`,display:"flex",alignItems:"center",justifyContent:"center",fontSize:18,fontWeight:900,color:queuePos===0?C.amber:C.accent}}>{queuePos+1}</div>
            <div><div style={{color:C.text,fontWeight:700,fontSize:14}}>{queuePos===0?"You are next in line":"Position "+(queuePos+1)+" in queue"}</div><div style={{color:C.muted,fontSize:12,marginTop:2}}>{queuePos===0?"You will receive the payout at the end of this cycle":queuePos+" cycle"+(queuePos>1?"s":"")+" before your turn"}</div></div>
          </div>
        </Card>
      )}
      {heldTranches.length>0&&(
        <Card style={{marginBottom:16}}>
          <div style={{color:C.muted,fontSize:11,fontWeight:600,letterSpacing:".07em",textTransform:"uppercase",marginBottom:10}}>Held Tranches</div>
          {heldTranches.map(t=>(
            <div key={t.id} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"8px 0",borderBottom:`1px solid ${C.border}`}}>
              <div><div style={{color:C.text,fontSize:13,fontWeight:600}}>Tranche {t.number} of {t.total_tranches}</div><div style={{color:C.muted,fontSize:11,marginTop:2}}>Releases at cycle {t.release_cycle}{t.is_last?" (final)":""}</div></div>
              <div style={{color:C.amber,fontWeight:700,fontSize:14}}>{fmt(t.amount)}</div>
            </div>
          ))}
          <div style={{color:C.muted,fontSize:11,marginTop:10}}>Total held: <span style={{color:C.amber,fontWeight:600}}>{fmt(heldTranches.reduce((s,t)=>s+t.amount,0))}</span></div>
        </Card>
      )}
      {myLoan&&(
        <Card style={{marginBottom:16,borderColor:myLoan.status==="voting"?C.amber+"44":C.accent+"44"}}>
          <div style={{color:C.muted,fontSize:11,fontWeight:600,letterSpacing:".07em",textTransform:"uppercase",marginBottom:10}}>My Loan</div>
          <div style={{display:"flex",justifyContent:"space-between",marginBottom:10}}>
            <div><div style={{color:C.text,fontWeight:700,fontSize:14}}>{fmt(myLoan.amount)}</div><div style={{color:C.muted,fontSize:12}}>{myLoan.reason}</div></div>
            <Badge color={myLoan.status==="voting"?C.amber:C.accent}>{myLoan.status}</Badge>
          </div>
          {myLoan.status==="active"&&<><div style={{height:4,background:C.surface,borderRadius:2,overflow:"hidden",marginBottom:6}}><div style={{height:"100%",width:`${Math.round(myLoan.total_repaid/myLoan.total_owed*100)}%`,background:C.green,borderRadius:2}}/></div><div style={{color:C.muted,fontSize:12}}>{fmt(myLoan.total_repaid)} repaid · {fmt(myLoan.total_owed-myLoan.total_repaid)} remaining · {fmt(myLoan.installment)}/cycle</div></>}
          {myLoan.status==="voting"&&<div style={{color:C.muted,fontSize:12}}>The group is currently voting on your request.</div>}
        </Card>
      )}
      <div style={{color:C.muted,fontSize:11,fontWeight:600,letterSpacing:".07em",textTransform:"uppercase",marginBottom:10}}>My Contribution History</div>
      {myContribs.length===0?<div style={{textAlign:"center",color:C.muted,fontSize:13,padding:20}}>No contributions yet.</div>
      :myContribs.map(c=>(
        <div key={c.id} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"10px 0",borderBottom:`1px solid ${C.border}`}}>
          <div><div style={{color:C.text,fontSize:13}}>Cycle contribution</div><div style={{color:C.muted,fontSize:11,marginTop:1}}>{fmtD(c.created_at)}{c.mpesa_ref?` · ${c.mpesa_ref}`:""}</div></div>
          <div style={{color:C.green,fontWeight:700,fontSize:13}}>+{fmt(c.amount)}</div>
        </div>
      ))}
      {myPayouts.length>0&&(
        <>
          <div style={{color:C.muted,fontSize:11,fontWeight:600,letterSpacing:".07em",textTransform:"uppercase",margin:"16px 0 10px"}}>My Payouts</div>
          {myPayouts.map(c=>(
            <div key={c.id} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"10px 0",borderBottom:`1px solid ${C.border}`}}>
              <div><div style={{color:C.text,fontSize:13}}>{c.type==="payout"?"Payout":"Tranche release"}</div><div style={{color:C.muted,fontSize:11,marginTop:1}}>{fmtD(c.created_at)}</div></div>
              <div style={{color:C.amber,fontWeight:700,fontSize:13}}>+{fmt(c.amount)}</div>
            </div>
          ))}
        </>
      )}
    </div>
  );
}

function TransactionsPanel({contributions}) {
  return(
    <div>
      {contributions.length===0?<div style={{textAlign:"center",color:C.muted,fontSize:14,padding:32}}>No transactions yet.</div>
      :contributions.map(t=>(
        <div key={t.id} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"11px 0",borderBottom:`1px solid ${C.border}`}}>
          <div><div style={{color:C.text,fontSize:13,fontWeight:600}}>{t.member_name}</div><div style={{color:C.muted,fontSize:11,marginTop:1}}>{fmtD(t.created_at)}{t.mpesa_ref&&` · ${t.mpesa_ref}`}</div></div>
          <div style={{textAlign:"right"}}>
            <div style={{color:t.type==="contribution"?C.green:t.type==="loan-disbursement"?C.red:C.amber,fontWeight:700,fontSize:13}}>{t.type==="contribution"?"+":"-"}{fmt(t.amount)}</div>
            <Badge color={t.type==="contribution"?C.green:t.type==="payout"||t.type==="tranche-release"?C.amber:t.type==="loan-disbursement"?C.red:C.purple} style={{marginTop:3}}>{t.type.replace(/-/g," ")}</Badge>
          </div>
        </div>
      ))}
    </div>
  );
}

function LoansPanel({loans,votes,members,user,groupId,isAdmin,loadAll}) {
  const isMember=!!members.find(m=>m.user_id===user.id);
  const statusColor={voting:C.amber,active:C.accent,settled:C.green,rejected:C.red};

  async function castVote(vote,loanId,choice){
    try { await db.insert("vote_choices",{vote_id:vote.id,user_id:user.id,choice}); } catch{ return; }
    // Fetch fresh vote choices and loan from DB — never use stale state for financial operations
    const [choices, freshLoans] = await Promise.all([
      db.select("vote_choices",`vote_id=eq.${vote.id}`),
      db.select("loans",`id=eq.${loanId}`),
    ]);
    const loan = freshLoans[0];
    if (!loan || loan.status !== "voting") { loadAll(); return; } // already processed
    const yeas=choices.filter(c=>c.choice==="yea").length;
    const majority=Math.floor(members.length/2)+1;
    const remaining=members.length-choices.length;
    if(yeas>=majority){
      const total=calcTotal(loan.amount,loan.interest_rate);
      const installment=calcInstallment(total,loan.repayment_cycles);
      // Vote passed — move to "approved" status, waiting for admin to confirm disbursement
      await db.update("loans",`id=eq.${loanId}`,{status:"approved",total_owed:total,installment,approved_at:now()});
      await db.update("votes",`id=eq.${vote.id}`,{status:"closed",closed_at:now()});
      const prevHash=await getLastHash(groupId);
      const entry=await buildEntry("LOAN_VOTE_PASSED",{loanId,amount:loan.amount},prevHash,user.id,user.name,groupId,`Vote passed for loan of ${fmt(loan.amount)} to ${loan.member_name}. Awaiting admin disbursement.`);
      await db.insert("audit_log",{...entry,group_id:groupId,user_id:user.id,data:entry.data});
      await db.insert("messages",{group_id:groupId,user_id:user.id,user_name:"System",text:`The group has approved ${loan.member_name}'s loan request of ${fmt(loan.amount)}. Admin must now confirm the disbursement in the Loans section.`,system:true});
    } else if(yeas+remaining<majority){
      await db.update("loans",`id=eq.${loanId}`,{status:"rejected"});
      await db.update("votes",`id=eq.${vote.id}`,{status:"closed",closed_at:now()});
      await db.insert("messages",{group_id:groupId,user_id:user.id,user_name:"System",text:"Loan request rejected by the group.",system:true});
    }
    loadAll();
  }

  async function disburse(loan){
    // Admin confirms disbursement — money moves now
    const prevHash=await getLastHash(groupId);
    await db.update("loans",`id=eq.${loan.id}`,{status:"active"});
    await db.insert("contributions",{group_id:groupId,member_id:loan.member_id,user_id:user.id,member_name:loan.member_name,amount:loan.amount,type:"loan-disbursement",loan_id:loan.id});
    const entry=await buildEntry("LOAN_DISBURSED",{loanId:loan.id,amount:loan.amount},prevHash,user.id,user.name,groupId,`Admin disbursed loan of ${fmt(loan.amount)} to ${loan.member_name}.`);
    await db.insert("audit_log",{...entry,group_id:groupId,user_id:user.id,data:entry.data});
    await db.insert("messages",{group_id:groupId,user_id:user.id,user_name:"System",text:`${loan.member_name} received ${fmt(loan.amount)} loan disbursement. Repayment: ${fmt(loan.installment)}/cycle for ${loan.repayment_cycles} cycle(s).`,system:true});
    loadAll();
  }

  return(
    <div>
      {loans.length===0?<div style={{textAlign:"center",color:C.muted,fontSize:14,padding:32}}>No loans yet.</div>
      :loans.map(loan=>{
        const vote=votes.find(v=>v.id===loan.vote_id&&v.status==="open");
        const myMemberId=members.find(m=>m.user_id===user.id)?.id;
        const progress=loan.total_owed>0?Math.round(loan.total_repaid/loan.total_owed*100):0;
        const statusColMap={voting:C.amber,approved:C.green,active:C.accent,settled:C.green,rejected:C.red};
        return(
          <Card key={loan.id} style={{marginBottom:12,borderColor:loan.status==="approved"?C.green+"55":""}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:10}}>
              <div><div style={{color:C.text,fontWeight:700,fontSize:14,marginBottom:2}}>{loan.member_name}</div><div style={{color:C.muted,fontSize:12}}>{loan.reason}</div></div>
              <div style={{textAlign:"right"}}><div style={{color:C.text,fontWeight:800,fontSize:15}}>{fmt(loan.amount)}</div><Badge color={statusColMap[loan.status]||C.muted} style={{marginTop:4}}>{loan.status}</Badge></div>
            </div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:8,marginBottom:10}}>
              {[["Total Owed",fmt(loan.total_owed||loan.amount),C.text],["Per Cycle",fmt(loan.installment||0),C.accent],["Interest",`${loan.interest_rate}%`,C.amber]].map(([l,v,c])=>(
                <div key={l} style={{background:C.surface,borderRadius:8,padding:"8px 10px"}}><div style={{color:C.muted,fontSize:10,fontWeight:600,letterSpacing:".04em",textTransform:"uppercase",marginBottom:3}}>{l}</div><div style={{color:c,fontSize:13,fontWeight:700}}>{v}</div></div>
              ))}
            </div>
            {["active","settled"].includes(loan.status)&&(
              <div style={{marginBottom:10}}>
                <div style={{display:"flex",justifyContent:"space-between",fontSize:12,color:C.muted,marginBottom:4}}><span style={{color:C.green}}>{fmt(loan.total_repaid)} repaid</span><span>{fmt(loan.total_owed-loan.total_repaid)} remaining</span></div>
                <div style={{height:4,background:C.surface,borderRadius:2,overflow:"hidden"}}><div style={{height:"100%",width:`${progress}%`,background:C.green,borderRadius:2}}/></div>
              </div>
            )}
            {/* Option C — admin confirm disbursement after vote passes */}
            {loan.status==="approved"&&isAdmin&&(
              <div style={{background:C.greenSoft,border:`1px solid ${C.green}33`,borderRadius:8,padding:"12px 14px",marginTop:6}}>
                <div style={{color:C.green,fontWeight:700,fontSize:13,marginBottom:4}}>Group approved this loan</div>
                <div style={{color:C.textMid,fontSize:12,marginBottom:10}}>Confirm to release {fmt(loan.amount)} to {loan.member_name}. This action is permanent and logged.</div>
                <Btn size="sm" variant="success" onClick={()=>disburse(loan)}>Confirm Disbursement</Btn>
              </div>
            )}
            {loan.status==="approved"&&!isAdmin&&(
              <div style={{color:C.green,fontSize:12,marginTop:6}}>Approved — waiting for admin to confirm disbursement.</div>
            )}
            {vote&&<LoanVoteBar vote={vote} loanId={loan.id} loanMemberId={loan.member_id} myMemberId={myMemberId} members={members} user={user} onVote={castVote}/>}
          </Card>
        );
      })}
    </div>
  );
}

function LoanVoteBar({vote,loanId,loanMemberId,myMemberId,members,user,onVote}) {
  const [choices,setChoices]=useState([]);
  useEffect(()=>{ db.select("vote_choices",`vote_id=eq.${vote.id}`).then(setChoices); },[vote.id]);
  const yeas=choices.filter(c=>c.choice==="yea").length;
  const nays=choices.filter(c=>c.choice==="nay").length;
  const myVote=choices.find(c=>c.user_id===user.id);
  const canVote=!myVote&&loanMemberId!==myMemberId;
  const total=yeas+nays;
  return(
    <div style={{marginTop:8}}>
      <div style={{display:"flex",justifyContent:"space-between",fontSize:12,color:C.muted,marginBottom:4}}><span style={{color:C.green}}>{yeas} approve</span><span>{total}/{members.length}</span><span style={{color:C.red}}>{nays} reject</span></div>
      <div style={{height:4,background:C.surface,borderRadius:2,overflow:"hidden",marginBottom:8}}><div style={{height:"100%",width:`${total>0?Math.round(yeas/total*100):0}%`,background:C.green,borderRadius:2}}/></div>
      <div style={{display:"flex",gap:8,alignItems:"center"}}>
        {canVote&&<><Btn size="sm" variant="success" onClick={()=>onVote(vote,loanId,"yea")}>Approve</Btn><Btn size="sm" variant="danger" onClick={()=>onVote(vote,loanId,"nay")}>Reject</Btn></>}
        {myVote&&<span style={{color:C.muted,fontSize:12}}>You voted {myVote.choice==="yea"?"Approve":"Reject"}</span>}
        {loanMemberId===myMemberId&&<span style={{color:C.muted,fontSize:12}}>Your request — awaiting votes</span>}
      </div>
    </div>
  );
}

function VotesPanel({votes,members,user,groupId,isAdmin,loadAll}) {
  const regularVotes=votes.filter(v=>!v.removal_member_id&&!v.loan_id);
  const isMember=!!members.find(m=>m.user_id===user.id);

  async function castVote(voteId,choice){
    try { await db.insert("vote_choices",{vote_id:voteId,user_id:user.id,choice}); } catch{ return; }
    const prevHash=await getLastHash(groupId);
    const entry=await buildEntry("VOTE_CAST",{voteId,choice},prevHash,user.id,user.name,groupId,`${user.name} voted ${choice==="yea"?"Yes":"No"}`);
    await db.insert("audit_log",{...entry,group_id:groupId,user_id:user.id,data:entry.data});
    loadAll();
  }

  return(
    <div>
      {regularVotes.length===0?<div style={{textAlign:"center",color:C.muted,fontSize:14,padding:32}}>No votes yet. Admin can create one from the + menu.</div>
      :regularVotes.map(v=><VoteCard key={v.id} vote={v} user={user} members={members} isAdmin={isAdmin} groupId={groupId} onVote={castVote} loadAll={loadAll}/>)}
    </div>
  );
}

function VoteCard({vote,user,members,isAdmin,groupId,onVote,loadAll}) {
  const [choices,setChoices]=useState([]);
  const [showVoters,setShowVoters]=useState(false);
  useEffect(()=>{ db.select("vote_choices","vote_id=eq."+vote.id).then(c=>setChoices(c||[])); },[vote.id]);
  const yeas=choices.filter(c=>c.choice==="yea");
  const nays=choices.filter(c=>c.choice==="nay");
  const myVote=choices.find(c=>c.user_id===user.id);
  const canVote=!myVote&&vote.status==="open"&&!!members.find(m=>m.user_id===user.id);
  const total=yeas.length+nays.length;

  // Map user ids to names using members list
  const nameOf=uid=>members.find(m=>m.user_id===uid)?.name||"Unknown";

  return(
    <Card style={{marginBottom:12}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:8}}>
        <div style={{flex:1}}><div style={{color:C.text,fontWeight:700,fontSize:14,marginBottom:2}}>{vote.question}</div>{vote.description&&<div style={{color:C.muted,fontSize:13,marginBottom:4}}>{vote.description}</div>}<div style={{color:C.muted,fontSize:11}}>{vote.created_by_name} · {fmtD(vote.created_at)} · {fmtAge(vote.created_at)}</div></div>
        <Badge color={vote.status==="open"?C.green:C.muted}>{vote.status}</Badge>
      </div>
      <div style={{marginBottom:8}}>
        <div style={{display:"flex",justifyContent:"space-between",color:C.muted,fontSize:12,marginBottom:4}}>
          <span style={{color:C.green,cursor:"pointer"}} onClick={()=>setShowVoters(s=>s==="yes"?false:"yes")}>{yeas.length} yes</span>
          <span>{total} votes</span>
          <span style={{color:C.red,cursor:"pointer"}} onClick={()=>setShowVoters(s=>s==="no"?false:"no")}>{nays.length} no</span>
        </div>
        <div style={{height:4,background:C.surface,borderRadius:2,overflow:"hidden",marginBottom:4}}><div style={{height:"100%",width:`${total>0?Math.round(yeas.length/total*100):0}%`,background:C.green,borderRadius:2}}/></div>
        {/* Voter names — tap yes/no count to reveal */}
        {showVoters==="yes"&&yeas.length>0&&(
          <div style={{background:C.greenSoft,border:`1px solid ${C.green}22`,borderRadius:6,padding:"6px 10px",marginTop:6}}>
            <div style={{color:C.green,fontSize:11,fontWeight:600,marginBottom:3}}>Voted Yes</div>
            <div style={{color:C.textMid,fontSize:12}}>{yeas.map(c=>nameOf(c.user_id)).join(", ")}</div>
          </div>
        )}
        {showVoters==="no"&&nays.length>0&&(
          <div style={{background:C.redSoft,border:`1px solid ${C.red}22`,borderRadius:6,padding:"6px 10px",marginTop:6}}>
            <div style={{color:C.red,fontSize:11,fontWeight:600,marginBottom:3}}>Voted No</div>
            <div style={{color:C.textMid,fontSize:12}}>{nays.map(c=>nameOf(c.user_id)).join(", ")}</div>
          </div>
        )}
      </div>
      <div style={{display:"flex",gap:8,alignItems:"center"}}>
        {canVote&&<><Btn size="sm" variant="success" onClick={()=>onVote(vote.id,"yea")}>Yes</Btn><Btn size="sm" variant="danger" onClick={()=>onVote(vote.id,"nay")}>No</Btn></>}
        {myVote&&<span style={{color:C.muted,fontSize:12}}>You voted {myVote.choice==="yea"?"Yes":"No"}</span>}
        {isAdmin&&vote.status==="open"&&<Btn size="sm" variant="ghost" style={{marginLeft:"auto"}} onClick={async()=>{await db.update("votes","id=eq."+vote.id,{status:"closed",closed_at:now()});loadAll();}}>Close</Btn>}
      </div>
    </Card>
  );
}

// ── Group Settings Panel ─────────────────────────────────────────────────────
function GroupSettingsPanel({group,groupId,contributions,loadAll,setPanel}) {
  const hasPayments=contributions.filter(c=>c.group_id===groupId&&c.type==="contribution").length>0;
  const [form,setForm]=useState({name:group.name,description:group.description||"",contribution_amount:group.contribution_amount,payout_schedule:group.payout_schedule,payout_percent:group.payout_percent,interest_rate:group.interest_rate,max_loan_multiplier:group.max_loan_multiplier});
  const [saving,setSaving]=useState(false); const [saved,setSaved]=useState(false);
  const set=k=>e=>setForm(f=>({...f,[k]:e.target.value}));
  async function save(){
    setSaving(true);
    await db.update("groups","id=eq."+groupId,{name:form.name,description:form.description,...(!hasPayments?{contribution_amount:Number(form.contribution_amount),payout_schedule:form.payout_schedule,payout_percent:Number(form.payout_percent),interest_rate:Number(form.interest_rate),max_loan_multiplier:Number(form.max_loan_multiplier)}:{})});
    await loadAll(); setSaving(false); setSaved(true); setTimeout(()=>setSaved(false),2000);
  }
  return(
    <div>
      <Inp label="Group Name" value={form.name} onChange={set("name")}/>
      <Inp label="Description" placeholder="Purpose of this group" value={form.description} onChange={set("description")}/>
      {hasPayments
        ?<div style={{background:C.amberSoft,border:`1px solid ${C.amber}33`,borderRadius:8,padding:"10px 14px",marginBottom:14}}><div style={{color:C.amber,fontWeight:600,fontSize:13,marginBottom:3}}>Financial settings locked</div><div style={{color:C.textMid,fontSize:12}}>Cannot be changed after payments have been recorded.</div></div>
        :<div>
          <div style={{color:C.muted,fontSize:11,fontWeight:600,letterSpacing:".05em",textTransform:"uppercase",marginBottom:10,marginTop:4}}>Financial Settings</div>
          <Inp label="Contribution Amount (TZS)" type="number" value={form.contribution_amount} onChange={set("contribution_amount")}/>
          <Sel label="Payout Schedule" value={form.payout_schedule} onChange={set("payout_schedule")}><option value="weekly">Weekly</option><option value="monthly">Monthly</option></Sel>
          <Sel label="Release Percentage" value={form.payout_percent} onChange={set("payout_percent")}><option value="25">25% — 4 releases</option><option value="50">50% — 2 releases</option><option value="100">100% — full trust</option></Sel>
          <Sel label="Loan Interest Rate" value={form.interest_rate} onChange={set("interest_rate")}><option value="0">0%</option><option value="5">5%</option><option value="10">10%</option><option value="15">15%</option><option value="20">20%</option></Sel>
          <Sel label="Maximum Loan Amount" value={form.max_loan_multiplier} onChange={set("max_loan_multiplier")}><option value="1">1× contribution</option><option value="2">2× contribution</option><option value="3">3× contribution</option><option value="5">5× contribution</option><option value="0">No limit</option></Sel>
        </div>
      }
      <div style={{display:"flex",gap:10,alignItems:"center"}}>
        <Btn onClick={save} disabled={saving}>{saving?"Saving...":saved?"Saved":"Save Changes"}</Btn>
        <Btn variant="ghost" onClick={()=>setPanel("menu")}>Cancel</Btn>
      </div>
    </div>
  );
}

function AuditPanel({groupId}) {
  const [logs,setLogs]=useState([]);
  const [valid,setValid]=useState(null);
  const [loading,setLoading]=useState(true);
  useEffect(()=>{
    db.select("audit_log",`group_id=eq.${groupId}&order=created_at.asc`).then(rows=>{
      setLogs(rows); setLoading(false);
      verifyChain(rows).then(setValid);
    });
  },[groupId]);
  if(loading)return <Spinner/>;
  return(
    <div>
      {valid!==null&&(
        <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:14,padding:"7px 11px",background:valid?C.greenSoft:C.redSoft,border:`1px solid ${valid?C.green:C.red}28`,borderRadius:8}}>
          <div style={{width:7,height:7,borderRadius:"50%",background:valid?C.green:C.red,flexShrink:0}}/>
          <span style={{color:valid?C.green:C.red,fontSize:12,fontWeight:600}}>{valid?"Chain verified":"Chain integrity broken"}</span>
        </div>
      )}
      {[...logs].reverse().map(log=>(
        <div key={log.id} style={{padding:"10px 0",borderBottom:`1px solid ${C.border}`}}>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start"}}>
            <div style={{flex:1}}><div style={{color:C.text,fontSize:13}}>{log.description}</div><div style={{color:C.muted,fontSize:11,marginTop:3}}>by {log.user_name}</div></div>
            <div style={{textAlign:"right",flexShrink:0,marginLeft:10}}><div style={{color:C.muted,fontSize:11}}>{fmtD(log.created_at)}</div><div style={{fontFamily:"monospace",fontSize:9,color:C.muted,marginTop:2}}>{log.hash?.slice(0,8)}…</div></div>
          </div>
        </div>
      ))}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// MODALS
// ─────────────────────────────────────────────────────────────────────────────
function PaymentModal({members,group,cycleSlots,onRecord,onClose}) {
  const [memberId,setMemberId]=useState(""); const [amount,setAmount]=useState(""); const [ref,setRef]=useState("");

  const selectedSlot=cycleSlots.find(s=>s.member_id===memberId);
  const alreadyPaid=selectedSlot?.paid||0;
  const stillOwes=Math.max(0,(group.contribution_amount||0)-alreadyPaid);
  const isPartial=Number(amount)>0&&Number(amount)<stillOwes;
  const isOverpay=Number(amount)>stillOwes&&stillOwes>0;

  // All members who have not fully paid yet
  const unpaid=members.filter(m=>{
    const s=cycleSlots.find(s=>s.member_id===m.id);
    return !s||(s.status==="pending"&&(s.paid||0)<group.contribution_amount);
  });
  const paid=members.filter(m=>!unpaid.find(u=>u.id===m.id));

  return(
    <Modal title="Record Payment" onClose={onClose}>
      <Sel label="Member" value={memberId} onChange={e=>setMemberId(e.target.value)}>
        <option value="">Select member...</option>
        {unpaid.map(m=>{
          const s=cycleSlots.find(s=>s.member_id===m.id);
          const p=s?.paid||0;
          return <option key={m.id} value={m.id}>{m.name}{p>0?` (${fmt(p)} paid, ${fmt(group.contribution_amount-p)} remaining)`:""}</option>;
        })}
        {paid.map(m=><option key={m.id} value={m.id}>{m.name} (fully paid)</option>)}
      </Sel>

      {memberId&&selectedSlot&&alreadyPaid>0&&(
        <div style={{background:C.accentSoft,border:`1px solid rgba(37,99,235,.25)`,borderRadius:8,padding:"8px 12px",marginBottom:10}}>
          <div style={{color:C.accent,fontSize:12,fontWeight:600}}>Partial payment on record</div>
          <div style={{color:C.textMid,fontSize:12,marginTop:2}}>{fmt(alreadyPaid)} paid · {fmt(stillOwes)} still owed</div>
        </div>
      )}

      <Inp
        label={memberId&&stillOwes>0?`Amount (TZS) — ${fmt(stillOwes)} remaining`:"Amount (TZS)"}
        type="number"
        placeholder={stillOwes>0?fmt(stillOwes):fmt(group.contribution_amount)}
        value={amount}
        onChange={e=>setAmount(e.target.value)}
      />

      {isPartial&&<div style={{color:C.amber,fontSize:12,marginBottom:10}}>This is a partial payment. The slot will remain pending until the full amount is received.</div>}
      {isOverpay&&<div style={{color:C.red,fontSize:12,marginBottom:10}}>Amount exceeds what is owed. Please check the figure.</div>}

      <Inp label="M-Pesa Reference (optional)" placeholder="e.g. RFG7X2K9AB" value={ref} onChange={e=>setRef(e.target.value)}/>
      <Btn full variant="success" onClick={()=>onRecord(memberId,amount,ref)} disabled={!memberId||!amount||isOverpay}>Record</Btn>
    </Modal>
  );
}
function AddMemberModal({onAdd,onClose}) {
  const [phone,setPhone]=useState(""); const [err,setErr]=useState(""); const [loading,setLoading]=useState(false);
  async function handle(){setLoading(true);const e=await onAdd(phone);if(e){setErr(e);}setLoading(false);}
  return(
    <Modal title="Add Member" onClose={onClose}>
      {err&&<div style={{color:C.red,fontSize:13,marginBottom:12}}>{err}</div>}
      <Inp label="Phone Number" placeholder="0712 345 678" value={phone} onChange={e=>setPhone(e.target.value)}/>
      <div style={{color:C.muted,fontSize:12,marginBottom:14}}>They will join from the next cycle.</div>
      <Btn full onClick={handle} disabled={!phone||loading}>{loading?"Searching...":"Add Member"}</Btn>
    </Modal>
  );
}
function CreateVoteModal({user,groupId,loadAll,onClose}) {
  const [q,setQ]=useState(""); const [desc,setDesc]=useState(""); const [loading,setLoading]=useState(false);
  async function create(){
    setLoading(true);
    await db.insert("votes",{group_id:groupId,question:q,description:desc,created_by:user.id,created_by_name:user.name,status:"open"});
    await db.insert("messages",{group_id:groupId,user_id:user.id,user_name:"System",text:`Vote: "${q}" — Cast your vote in the Votes section.`,system:true});
    loadAll(); onClose();
  }
  return(
    <Modal title="Create Vote" onClose={onClose}>
      <Inp label="Question" placeholder="What are we deciding?" value={q} onChange={e=>setQ(e.target.value)}/>
      <Inp label="Details (optional)" placeholder="Context for members..." value={desc} onChange={e=>setDesc(e.target.value)}/>
      <Btn full onClick={create} disabled={!q.trim()||loading}>{loading?"Creating...":"Create Vote"}</Btn>
    </Modal>
  );
}
function LoanRequestModal({group,user,members,loans,pool,groupId,loadAll,onClose}) {
  const myMember=members.find(m=>m.user_id===user.id);
  const hasLoan=!!loans.find(l=>l.member_id===myMember?.id&&["active","voting"].includes(l.status));
  const maxLoan=group.max_loan_multiplier>0?Math.min(group.max_loan_multiplier*group.contribution_amount,pool):pool;
  const [amount,setAmount]=useState(""); const [reason,setReason]=useState(""); const [cycles,setCycles]=useState("1"); const [err,setErr]=useState(""); const [loading,setLoading]=useState(false);
  async function submit(){
    if(!myMember){setErr("You are not an active member.");return;}
    if(hasLoan){setErr("You already have an active or pending loan.");return;}
    const amt=Number(amount);
    if(!amt||amt<=0){setErr("Enter a valid amount.");return;}
    if(amt>pool){setErr(`Cannot exceed pool balance of ${fmt(pool)}.`);return;}
    if(group.max_loan_multiplier>0&&amt>maxLoan){setErr(`Maximum loan is ${fmt(maxLoan)}.`);return;}
    if(!reason.trim()){setErr("Please provide a reason.");return;}
    setLoading(true);
    const total=calcTotal(amt,group.interest_rate||0);
    const installment=calcInstallment(total,Number(cycles));
    const [loan]=await db.insert("loans",{group_id:groupId,member_id:myMember.id,member_name:myMember.name,amount:amt,interest_rate:group.interest_rate||0,total_owed:total,total_repaid:0,installment,repayment_cycles:Number(cycles),reason,status:"voting"});
    const [vote]=await db.insert("votes",{group_id:groupId,question:`Loan request: ${myMember.name} requests ${fmt(amt)}`,description:`Reason: ${reason}. Repayment: ${fmt(installment)}/cycle over ${cycles} cycle(s). Interest: ${group.interest_rate||0}%. Total: ${fmt(total)}.`,created_by:user.id,created_by_name:user.name,status:"open",loan_id:loan.id});
    await db.update("loans",`id=eq.${loan.id}`,{vote_id:vote.id});
    const prevHash=await getLastHash(groupId);
    const entry=await buildEntry("LOAN_REQUESTED",{loanId:loan.id,amount:amt},prevHash,user.id,user.name,groupId,`${myMember.name} requested a loan of ${fmt(amt)}`);
    await db.insert("audit_log",{...entry,group_id:groupId,user_id:user.id,data:entry.data});
    await db.insert("messages",{group_id:groupId,user_id:user.id,user_name:"System",text:`${myMember.name} has requested a loan of ${fmt(amt)}. Reason: ${reason}. Members can vote in the Loans section.`,system:true});
    loadAll(); onClose();
  }
  const total=amount?calcTotal(Number(amount),group.interest_rate||0):0;
  const installment=total&&cycles?calcInstallment(total,Number(cycles)):0;
  return(
    <Modal title="Request a Loan" onClose={onClose}>
      {hasLoan&&<div style={{color:C.amber,fontSize:13,marginBottom:12}}>You already have an active or pending loan.</div>}
      {err&&<div style={{color:C.red,fontSize:13,marginBottom:12}}>{err}</div>}
      <Inp label={`Amount (TZS) — max ${fmt(maxLoan)}`} type="number" placeholder={fmt(maxLoan)} value={amount} onChange={e=>setAmount(e.target.value)} disabled={hasLoan}/>
      <Sel label="Repay over how many cycles?" value={cycles} onChange={e=>setCycles(e.target.value)} disabled={hasLoan}>
        {[1,2,3,4,5,6].map(n=><option key={n} value={n}>{n} cycle{n>1?"s":""}</option>)}
      </Sel>
      <Inp label="Reason" placeholder="What is this loan for?" value={reason} onChange={e=>setReason(e.target.value)} disabled={hasLoan}/>
      {Number(amount)>0&&(
        <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:8,padding:"12px 14px",marginBottom:14}}>
          {[["Principal",fmt(amount),C.text],["Interest",fmt(total-Number(amount)),C.amber],["Total Owed",fmt(total),C.text],["Per Cycle",fmt(installment),C.green]].map(([l,v,c],i)=>(
            <div key={l} style={{display:"flex",justifyContent:"space-between",marginBottom:i<3?6:0,...(i===2?{borderTop:`1px solid ${C.border}`,paddingTop:8,marginTop:8}:{})}}><span style={{color:C.muted,fontSize:13}}>{l}</span><span style={{color:c,fontSize:13,fontWeight:i>1?700:400}}>{v}</span></div>
          ))}
        </div>
      )}
      <Btn full onClick={submit} disabled={hasLoan||!amount||!reason.trim()||loading}>{loading?"Submitting...":"Submit Request"}</Btn>
    </Modal>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// PROFILE
// ─────────────────────────────────────────────────────────────────────────────
function Profile({user,onLogout}) {
  const [tab,setTab]=useState("overview");
  const [contribs,setContribs]=useState([]);
  const [payouts,setPayouts]=useState([]);
  const [activeLoans,setActiveLoans]=useState([]);
  const [pinModal,setPinModal]=useState(false);
  const [pf,setPf]=useState({current:"",next:"",confirm:""});
  const [pinErr,setPinErr]=useState("");
  const [loading,setLoading]=useState(true);
  const [myGroups,setMyGroups]=useState([]);

  const [allLoans,setAllLoans]=useState([]);
  const [myMembers,setMyMembers]=useState([]);

  useEffect(()=>{
    Promise.all([
      db.select("contributions",`user_id=eq.${user.id}&type=eq.contribution&order=created_at.desc`),
      db.select("contributions",`user_id=eq.${user.id}&type=in.(payout,tranche-release)&order=created_at.desc`),
      db.select("members",`user_id=eq.${user.id}&status=neq.removed`),
    ]).then(async([c,p,mems])=>{
      setContribs(c); setPayouts(p); setMyMembers(mems);
      if(mems.length){
        const gids=[...new Set(mems.map(m=>m.group_id))];
        const gs=await db.select("groups",`id=in.(${gids.join(",")})`);
        setMyGroups(gs);
        // Fetch ALL loans not just active
        const ls=await db.select("loans",`member_id=in.(${mems.map(m=>m.id).join(",")})&order=requested_at.desc`).catch(()=>[]);
        setAllLoans(ls);
        setActiveLoans(ls.filter(l=>l.status==="active"));
      }
      setLoading(false);
    });
  },[user.id]);

  async function changePin(){
    // Step 1: verify current PIN by re-authenticating
    try {
      const email=user.phone+"@glassbox.app";
      await sbAuth("token?grant_type=password",{email,password:pf.current+pf.current});
    } catch { setPinErr("Incorrect current PIN."); return; }
    if(pf.next!==pf.confirm){setPinErr("New PINs do not match.");setPf(f=>({...f,confirm:""}));return;}
    try {
      // Step 2: update password — this invalidates ALL existing sessions on all devices
      const res=await fetch(SUPA_URL+"/auth/v1/user",{
        method:"PUT",
        headers:{...headers,"Authorization":"Bearer "+_token,"Content-Type":"application/json"},
        body:JSON.stringify({password:pf.next+pf.next})
      });
      if(!res.ok)throw new Error("Failed to update PIN.");

      // Step 3: sign in fresh with new PIN to get a valid session for this device
      const email=user.phone+"@glassbox.app";
      const newSession=await sbAuth("token?grant_type=password",{email,password:pf.next+pf.next});
      setSession(newSession);

      setPf({current:"",next:"",confirm:""});setPinErr("");setPinModal(false);
      // Show confirmation
      alert("PIN updated. All other devices have been signed out.");
    } catch(e) { setPinErr(e.message||"Failed to update PIN. Try again."); }
  }

  if(loading)return <Spinner/>;
  const totalContrib=contribs.reduce((s,c)=>s+c.amount,0);
  const totalReceived=payouts.reduce((s,c)=>s+c.amount,0);

  return(
    <div>
      <Card style={{marginBottom:20,background:"linear-gradient(135deg,#0c1520,#091020)"}}>
        <div style={{display:"flex",alignItems:"center",gap:16}}>
          <div style={{width:50,height:50,borderRadius:"50%",background:C.accentSoft,border:`1px solid rgba(37,99,235,.25)`,display:"flex",alignItems:"center",justifyContent:"center",fontSize:20,color:C.accent,fontWeight:900}}>{user.name.charAt(0).toUpperCase()}</div>
          <div style={{flex:1}}>
            <div style={{color:C.text,fontWeight:800,fontSize:17}}>{user.name}</div>
            <div style={{color:C.muted,fontSize:13,marginTop:2}}>{user.phone} · Member since {fmtD(user.created_at)}</div>
          </div>
          <button onClick={onLogout} style={{background:"none",border:`1px solid ${C.border}`,borderRadius:7,padding:"6px 13px",color:C.muted,fontSize:12,cursor:"pointer",fontFamily:"inherit",flexShrink:0}}>Sign out</button>
        </div>
      </Card>

      <div style={{display:"flex",borderBottom:`1px solid ${C.border}`,marginBottom:20}}>
        {[{id:"overview",label:"Overview"},{id:"activity",label:"Activity"},{id:"security",label:"Security"}].map(t=>(
          <button key={t.id} onClick={()=>setTab(t.id)} style={{background:"none",border:"none",padding:"10px 16px",fontSize:13,fontWeight:600,color:tab===t.id?C.accent:C.muted,cursor:"pointer",borderBottom:tab===t.id?`2px solid ${C.accent}`:"2px solid transparent",marginBottom:-1,fontFamily:"inherit"}}>{t.label}</button>
        ))}
      </div>

      {tab==="overview"&&(
        <div>
          <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:12,marginBottom:20}}>
            <Card><div style={{color:C.muted,fontSize:11,fontWeight:600,letterSpacing:".05em",textTransform:"uppercase",marginBottom:4}}>Groups</div><div style={{color:C.accent,fontSize:20,fontWeight:800}}>{myGroups.length}</div></Card>
            <Card><div style={{color:C.muted,fontSize:11,fontWeight:600,letterSpacing:".05em",textTransform:"uppercase",marginBottom:4}}>Contributed</div><div style={{color:C.green,fontSize:16,fontWeight:800}}>{fmt(totalContrib)}</div></Card>
            <Card><div style={{color:C.muted,fontSize:11,fontWeight:600,letterSpacing:".05em",textTransform:"uppercase",marginBottom:4}}>Received</div><div style={{color:C.amber,fontSize:16,fontWeight:800}}>{fmt(totalReceived)}</div></Card>
          </div>

          {/* Pending cycle notice */}
          {myMembers.filter(m=>m.status==="pending-cycle").map(m=>{
            const g=myGroups.find(x=>x.id===m.group_id);
            return g?(
              <div key={m.id} style={{background:C.amberSoft,border:`1px solid ${C.amber}33`,borderRadius:10,padding:"10px 14px",marginBottom:10,display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                <div>
                  <div style={{color:C.amber,fontWeight:700,fontSize:13}}>{g.name}</div>
                  <div style={{color:C.textMid,fontSize:12,marginTop:2}}>You join this group from the next cycle</div>
                </div>
                <Badge color={C.amber}>Pending</Badge>
              </div>
            ):null;
          })}

          {/* Active loans */}
          {activeLoans.length>0&&(
            <div style={{color:C.muted,fontSize:11,fontWeight:600,letterSpacing:".05em",textTransform:"uppercase",marginBottom:10}}>Active Loans</div>
          )}
          {activeLoans.map(loan=>{
            const g=myGroups.find(x=>x.id===loan.group_id);
            const progress=loan.total_owed>0?Math.round(loan.total_repaid/loan.total_owed*100):0;
            return(
              <Card key={loan.id} style={{marginBottom:10}}>
                <div style={{display:"flex",justifyContent:"space-between",marginBottom:8}}>
                  <div><div style={{color:C.text,fontWeight:600,fontSize:13}}>{g?.name}</div><div style={{color:C.muted,fontSize:12}}>{loan.reason}</div></div>
                  <div style={{textAlign:"right"}}><div style={{color:C.red,fontWeight:700,fontSize:14}}>{fmt(loan.total_owed-loan.total_repaid)}</div><div style={{color:C.muted,fontSize:11}}>remaining</div></div>
                </div>
                <div style={{height:4,background:C.surface,borderRadius:2,overflow:"hidden",marginBottom:4}}><div style={{height:"100%",width:`${progress}%`,background:C.green,borderRadius:2}}/></div>
                <div style={{color:C.muted,fontSize:11}}>{fmt(loan.total_repaid)} repaid · {fmt(loan.installment)}/cycle</div>
              </Card>
            );
          })}

          {/* Voting loans */}
          {allLoans.filter(l=>l.status==="voting").map(loan=>{
            const g=myGroups.find(x=>x.id===loan.group_id);
            return(
              <Card key={loan.id} style={{marginBottom:10,borderColor:C.amber+"44"}}>
                <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                  <div><div style={{color:C.text,fontWeight:600,fontSize:13}}>{g?.name} — Loan Request</div><div style={{color:C.muted,fontSize:12}}>{loan.reason}</div></div>
                  <div style={{textAlign:"right"}}><div style={{color:C.amber,fontWeight:700,fontSize:14}}>{fmt(loan.amount)}</div><Badge color={C.amber} style={{marginTop:4}}>Voting</Badge></div>
                </div>
              </Card>
            );
          })}
        </div>
      )}
      {tab==="activity"&&(
        <div>
          <div style={{color:C.muted,fontSize:12,fontWeight:600,letterSpacing:".05em",textTransform:"uppercase",marginBottom:12}}>Contributions</div>
          {contribs.length===0?<Card style={{textAlign:"center",color:C.muted,fontSize:14,padding:28,marginBottom:20}}>No contributions yet.</Card>
          :<Card style={{padding:0,overflow:"hidden",marginBottom:20}}>
            <table style={{width:"100%",borderCollapse:"collapse"}}>
              <thead><tr style={{background:C.surface}}>{["Group","Amount","Reference","Date"].map(h=><th key={h} style={{padding:"9px 13px",textAlign:"left",color:C.muted,fontSize:11,fontWeight:700,letterSpacing:".05em",textTransform:"uppercase",borderBottom:`1px solid ${C.border}`}}>{h}</th>)}</tr></thead>
              <tbody>{contribs.map((c,i)=>{const g=myGroups.find(x=>x.id===c.group_id);return<tr key={c.id} style={{borderBottom:`1px solid ${C.border}`,background:i%2===0?"transparent":C.surface+"80"}}><td style={{padding:"10px 13px",color:C.text,fontSize:13}}>{g?.name||"—"}</td><td style={{padding:"10px 13px",color:C.green,fontWeight:700,fontSize:13}}>+{fmt(c.amount)}</td><td style={{padding:"10px 13px",color:C.muted,fontSize:12,fontFamily:"monospace"}}>{c.mpesa_ref||"—"}</td><td style={{padding:"10px 13px",color:C.muted,fontSize:12}}>{fmtD(c.created_at)}</td></tr>;})}
              </tbody>
            </table>
          </Card>}
          <div style={{color:C.muted,fontSize:12,fontWeight:600,letterSpacing:".05em",textTransform:"uppercase",marginBottom:12}}>Payouts Received</div>
          {payouts.length===0?<Card style={{textAlign:"center",color:C.muted,fontSize:14,padding:28,marginBottom:20}}>No payouts yet.</Card>
          :<Card style={{padding:0,overflow:"hidden",marginBottom:20}}>
            <table style={{width:"100%",borderCollapse:"collapse"}}>
              <thead><tr style={{background:C.surface}}>{["Group","Amount","Date"].map(h=><th key={h} style={{padding:"9px 13px",textAlign:"left",color:C.muted,fontSize:11,fontWeight:700,letterSpacing:".05em",textTransform:"uppercase",borderBottom:`1px solid ${C.border}`}}>{h}</th>)}</tr></thead>
              <tbody>{payouts.map((c,i)=>{const g=myGroups.find(x=>x.id===c.group_id);return<tr key={c.id} style={{borderBottom:`1px solid ${C.border}`,background:i%2===0?"transparent":C.surface+"80"}}><td style={{padding:"10px 13px",color:C.text,fontSize:13}}>{g?.name||"—"}</td><td style={{padding:"10px 13px",color:C.amber,fontWeight:700,fontSize:13}}>+{fmt(c.amount)}</td><td style={{padding:"10px 13px",color:C.muted,fontSize:12}}>{fmtD(c.created_at)}</td></tr>;})}
              </tbody>
            </table>
          </Card>}

          {/* Loan history */}
          {allLoans.length>0&&(
            <>
              <div style={{color:C.muted,fontSize:12,fontWeight:600,letterSpacing:".05em",textTransform:"uppercase",marginBottom:12}}>Loan History</div>
              {allLoans.map(loan=>{
                const g=myGroups.find(x=>x.id===loan.group_id);
                const statusColor={voting:C.amber,active:C.accent,settled:C.green,rejected:C.red};
                const progress=loan.total_owed>0?Math.round(loan.total_repaid/loan.total_owed*100):0;
                return(
                  <Card key={loan.id} style={{marginBottom:10}}>
                    <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:8}}>
                      <div>
                        <div style={{color:C.text,fontWeight:600,fontSize:13}}>{g?.name}</div>
                        <div style={{color:C.muted,fontSize:12}}>{loan.reason}</div>
                        <div style={{color:C.muted,fontSize:11,marginTop:2}}>{fmtD(loan.requested_at)}</div>
                      </div>
                      <div style={{textAlign:"right"}}>
                        <div style={{color:C.text,fontWeight:700,fontSize:14}}>{fmt(loan.amount)}</div>
                        <Badge color={statusColor[loan.status]||C.muted} style={{marginTop:4}}>{loan.status}</Badge>
                      </div>
                    </div>
                    {["active","settled"].includes(loan.status)&&(
                      <>
                        <div style={{height:4,background:C.surface,borderRadius:2,overflow:"hidden",marginBottom:4}}><div style={{height:"100%",width:`${progress}%`,background:C.green,borderRadius:2}}/></div>
                        <div style={{color:C.muted,fontSize:11}}>{fmt(loan.total_repaid)} of {fmt(loan.total_owed)} repaid{loan.status==="settled"?" — fully settled":""}</div>
                      </>
                    )}
                  </Card>
                );
              })}
            </>
          )}
        </div>
      )}
      {tab==="security"&&(
        <div>
          <Card style={{marginBottom:14}}>
            <div style={{color:C.text,fontWeight:700,fontSize:14,marginBottom:12}}>Security Status</div>
            <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:10}}>
              {[["Hash Chain","Active",C.green],["Supabase Auth","Enabled",C.green],["RLS Policies","Enforced",C.accent],["Email",user.email_verified?"Verified":"Not verified",user.email_verified?C.green:C.amber]].map(([t,v,col])=>(
                <div key={t} style={{background:col+"10",border:`1px solid ${col}20`,borderRadius:8,padding:"10px 12px"}}><div style={{color:col,fontWeight:700,fontSize:11,letterSpacing:".04em",textTransform:"uppercase",marginBottom:3}}>{t}</div><div style={{color:C.textMid,fontSize:12}}>{v}</div></div>
              ))}
            </div>
          </Card>
          <Card>
            <div style={{color:C.text,fontWeight:700,fontSize:14,marginBottom:4}}>Change PIN</div>
            <div style={{color:C.muted,fontSize:13,marginBottom:14}}>Your PIN is your only authentication method.</div>
            <Btn size="sm" onClick={()=>setPinModal(true)}>Change PIN</Btn>
          </Card>
        </div>
      )}

      {pinModal&&(
        <Modal title="Change PIN" onClose={()=>{setPinModal(false);setPinErr("");setPf({current:"",next:"",confirm:""});}}>
          <PinPad label="Current PIN" value={pf.current} onChange={v=>setPf(f=>({...f,current:v}))}/>
          <Divider/>
          <PinPad label="New PIN" value={pf.next} onChange={v=>setPf(f=>({...f,next:v}))}/>
          <Divider/>
          <PinPad label="Confirm New PIN" value={pf.confirm} onChange={v=>setPf(f=>({...f,confirm:v}))}/>
          {pinErr&&<div style={{color:C.red,fontSize:12,textAlign:"center",marginBottom:10}}>{pinErr}</div>}
          <Btn full onClick={changePin} disabled={pf.current.length<4||pf.next.length<4||pf.confirm.length<4} style={{marginTop:10}}>Update PIN</Btn>
        </Modal>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// ROOT
// ─────────────────────────────────────────────────────────────────────────────
export default function App() {
  const [user,setUser]=useState(null);
  const [authScreen,setAuthScreen]=useState("landing");
  const [view,setView]=useState("home");
  const [selectedGroup,setSelectedGroup]=useState(null);
  const [booting,setBooting]=useState(true);

  // Restore session on load — verify token is still valid then fetch profile
  useEffect(()=>{
    if(_token&&_userId){
      // Verify token with Supabase auth/user endpoint
      fetch(SUPA_URL+"/auth/v1/user", { headers:{ "apikey":SUPA_KEY, "Authorization":"Bearer "+_token } })
        .then(r=>r.ok?r.json():null)
        .then(async authUser=>{
          if(!authUser?.id){ setSession(null); setBooting(false); return; }
          const rows = await db.select("profiles","id=eq."+authUser.id).catch(()=>[]);
          if(rows?.length){ setUser(rows[0]); setAuthScreen(null); }
          else { setSession(null); }
          setBooting(false);
        })
        .catch(()=>{ setSession(null); setBooting(false); });
    } else { setBooting(false); }
  },[]);

  function handleLogin(u){ setUser(u); setAuthScreen(null); setView("home"); }
  function handleLogout(){ setSession(null); setUser(null); setAuthScreen("landing"); setView("home"); }

  // Register session expiry handler — redirects to login if token expires mid-session
  useEffect(()=>{
    _onSessionExpired = ()=>{ setUser(null); setAuthScreen("login"); };
    return ()=>{ _onSessionExpired = null; };
  },[]);

  if(booting) return <div style={{minHeight:"100vh",background:C.bg,display:"flex",alignItems:"center",justifyContent:"center"}}><Spinner/></div>;

  if(!user){
    if(authScreen==="landing")return <Landing onLogin={()=>setAuthScreen("login")} onRegister={()=>setAuthScreen("register")}/>;
    if(authScreen==="login")return <Login onSuccess={handleLogin} onBack={()=>setAuthScreen("landing")}/>;
    if(authScreen==="register")return <Register onSuccess={handleLogin} onBack={()=>setAuthScreen("landing")}/>;
  }

  const inGroup=view==="group-detail";
  return(
    <div style={{minHeight:"100vh",background:C.bg,color:C.text,fontFamily:"'Inter','Segoe UI',system-ui,sans-serif"}}>
      {!inGroup&&<Nav view={view} setView={setView}/>}
      <div style={{maxWidth:inGroup?680:840,margin:"0 auto",padding:inGroup?"0":"28px 18px"}}>
        {view==="home"&&<Home user={user} setView={setView} setSelectedGroup={setSelectedGroup}/>}
        {view==="groups"&&<GroupBrowser user={user} setView={setView} setSelectedGroup={setSelectedGroup}/>}
        {view==="create-group"&&<CreateGroup user={user} setView={setView} onGroupCreated={id=>{setSelectedGroup(id);setView("group-detail");}}/>}
        {view==="group-detail"&&selectedGroup&&<GroupDetail user={user} groupId={selectedGroup} setView={setView}/>}
        {view==="profile"&&<Profile user={user} onLogout={handleLogout}/>}
      </div>
    </div>
  );
}
