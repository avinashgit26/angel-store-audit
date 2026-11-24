/* Angel store audit: connects the page to Supabase.
   Gives the page the same small storage interface it used before (db, user, assets, downloads),
   and splits every save into a public part and a private part (sales, profit, purchases, KPIs,
   Operations). The private part only goes to super admins and HR; the database enforces it. */
(function(){
  "use strict";
  const C = window.AUDIT_CONFIG;
  // Did this page open from a sign-in email link? Read it before the library tidies the address.
  const linkErr = (() => { const h = new URLSearchParams(location.hash.slice(1) + "&" + location.search.slice(1)); return h.get("error_description") || h.get("error"); })();
  const fromLink = /access_token=|[?&]code=|token_hash=/.test(location.href);
  const sb = window.supabase.createClient(C.url, C.key, { auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: true } });
  let me = { role: "viewer", email: "", actor: null, name: null };
  const MEMBER = () => me.role === "super" || me.role === "hr";
  const CAN_EDIT = () => MEMBER() || me.role === "sm";

  async function refreshMe(){
    try{ const { data, error } = await sb.rpc("whoami"); if(!error && data) me = data; }catch(e){}
    return me;
  }
  const ready = (async () => { try{ await sb.auth.getSession(); }catch(e){} await refreshMe();
    if(fromLink || linkErr){
      try{ history.replaceState(null, "", location.origin + location.pathname); }catch(e){}
      if(linkErr) window.AUTH.linkNote = /expired|invalid/i.test(linkErr) ? "That sign-in link has expired or was already used. Tap Sign in to get a new one." : "Sign-in didn't work: " + linkErr.replace(/\+/g, " ");
      else if(MEMBER()){ try{ await sb.rpc("log_event", { p_action: "Signed in", p_details: null, p_visit: null }); }catch(e){} window.AUTH.linkNote = "Signed in as " + (me.name || me.email) + "."; }
      else if(me.role !== "sm"){ window.AUTH.linkNote = "This email hasn't been given access. Ask a super admin to add it. You can still view the audit."; try{ await sb.auth.signOut(); }catch(e){} me = { role: "viewer", email: "", actor: null, name: null }; }
    }
    return me; })();

  /* ---------- public / private split ---------- */
  const PRIV_TOP = ["kpi", "pur", "dsr", "dsrHR", "ol"];
  const PRIV_MAPS = ["s", "notes", "act", "photos"];
  const PRIV_KEY = k => /^(0|1|o)\./.test(k);           // sections 1 and 2, and the Operations checks
  const PRIV_SUM = ["sales", "target", "net", "gp", "pur", "ol"];
  const PRIV_CFG = ["budget", "catBudget", "cats", "mgmtEmails", "smEmail", "dsrFields"];
  const clone = o => JSON.parse(JSON.stringify(o == null ? null : o));

  function splitState(S){
    const pub = clone(S) || {}, priv = {};
    PRIV_TOP.forEach(k => { if(k in pub){ priv[k] = pub[k]; delete pub[k]; } });
    PRIV_MAPS.forEach(m => { const src = pub[m] || {}; priv[m] = {};
      Object.keys(src).forEach(k => { if(PRIV_KEY(k)){ priv[m][k] = src[k]; delete src[k]; } }); });
    if(MEMBER() && typeof window.__hiddenSections === "function"){ try{ pub._hidden = window.__hiddenSections(S); }catch(e){} }
    return { pub, priv };
  }
  function joinState(pub, priv){
    const out = clone(pub) || {};
    if(priv && Object.keys(priv).length){
      PRIV_TOP.forEach(k => { if(k in priv) out[k] = priv[k]; });
      PRIV_MAPS.forEach(m => { out[m] = Object.assign({}, out[m] || {}, priv[m] || {}); });
      delete out._hidden;
    }
    return out;
  }
  function splitSum(sum){
    if(!sum) return { pub: null, priv: null };
    const pub = clone(sum);
    PRIV_SUM.forEach(k => delete pub[k]);
    if(pub.scores) Object.keys(pub.scores).forEach(k => { if(PRIV_KEY(k)) delete pub.scores[k]; });
    if(Array.isArray(pub.issues)) pub.issues = pub.issues.filter(x => !PRIV_KEY(x.k || ""));
    return { pub, priv: clone(sum) };
  }
  function splitCfg(cfg){
    const pub = clone(cfg) || {}, priv = {};
    PRIV_CFG.forEach(k => { if(k in pub){ priv[k] = pub[k]; delete pub[k]; } });
    return { pub, priv };
  }
  const fail = (error, fallback) => { const e = new Error((error && error.message) || fallback || "save failed"); e.code = (error && (error.code || error.status)) || "error"; return e; };
  const snap = obj => ({ exists: !!obj, data: () => obj });

  /* ---------- documents ---------- */
  async function getDraft(slot){
    const p = await sb.from("drafts").select("*").eq("slot", slot).maybeSingle();
    if(p.error) throw fail(p.error);
    let priv = null, privAt = 0;
    if(MEMBER()){ const q = await sb.from("drafts_private").select("*").eq("slot", slot).maybeSingle(); if(q.data){ priv = q.data.data; privAt = +q.data.updated_at || 0; } }
    if(!p.data) return snap(null);
    const empty = !p.data.data || !Object.keys(p.data.data).length;
    const at = Math.max(+p.data.updated_at || 0, privAt);
    return snap({ json: empty ? "" : JSON.stringify(joinState(p.data.data, priv)), updatedAt: at, updatedBy: p.data.updated_by });
  }
  async function setDraft(slot, v){
    const S = v.json ? JSON.parse(v.json) : null; const at = v.updatedAt || Date.now();
    if(!S){
      const r = await sb.from("drafts").upsert({ slot, data: {}, updated_at: at }); if(r.error) throw fail(r.error);
      if(MEMBER()) await sb.from("drafts_private").upsert({ slot, data: {}, updated_at: at });
      return;
    }
    const { pub, priv } = splitState(S);
    if(!MEMBER() && S._hidden) pub._hidden = S._hidden;     // the store manager keeps the sales section results as they were
    const r = await sb.from("drafts").upsert({ slot, data: pub, updated_at: at }); if(r.error) throw fail(r.error);
    if(MEMBER()){ const q = await sb.from("drafts_private").upsert({ slot, data: priv, updated_at: at }); if(q.error) throw fail(q.error); }
  }
  async function getCfg(){
    const p = await sb.from("config").select("*").eq("id", 1).maybeSingle(); if(p.error) throw fail(p.error);
    if(!p.data) return snap(null);
    let priv = {};
    if(MEMBER()){ const q = await sb.from("config_private").select("*").eq("id", 1).maybeSingle(); if(q.data) priv = q.data.data || {}; }
    return snap({ json: JSON.stringify(Object.assign({}, p.data.data, priv)), updatedAt: +p.data.updated_at || 0 });
  }
  async function setCfg(v){
    if(me.role !== "super") return;
    const { pub, priv } = splitCfg(JSON.parse(v.json || "{}")); const at = v.updatedAt || Date.now();
    const r = await sb.from("config").upsert({ id: 1, data: pub, updated_at: at }); if(r.error) throw fail(r.error);
    const q = await sb.from("config_private").upsert({ id: 1, data: priv, updated_at: at }); if(q.error) throw fail(q.error);
  }
  async function setWeek(id, w){
    if(me.role !== "super") throw fail(null, "only a super admin can approve");
    let S = null; try{ S = JSON.parse(w.json || "null"); }catch(e){}
    const st = S ? splitState(S) : { pub: null, priv: null }; const su = splitSum(w.sum);
    const r = await sb.from("weeks").upsert({ id, saved_at: w.savedAt || Date.now(), approved: !!(w.approved || w.submitted),
      approved_at: w.approvedAt || null, sum: su.pub, data: st.pub });
    if(r.error) throw fail(r.error);
    const q = await sb.from("weeks_private").upsert({ id, sum: su.priv, data: st.priv }); if(q.error) throw fail(q.error);
    weeksBus.forEach(f => f());
  }
  async function listWeeks(){
    const p = await sb.from("weeks").select("*").order("id"); if(p.error) throw fail(p.error);
    let priv = {};
    if(MEMBER()){ const q = await sb.from("weeks_private").select("*"); (q.data || []).forEach(x => priv[x.id] = x); }
    return (p.data || []).map(x => { const pv = priv[x.id];
      const sum = pv && pv.sum ? pv.sum : x.sum; const data = joinState(x.data, pv ? pv.data : null);
      return { id: x.id, data: () => ({ id: x.id, savedAt: +x.saved_at || 0, approved: !!x.approved, approvedAt: +x.approved_at || 0,
        approvedBy: x.approved_by, sum, json: JSON.stringify(data) }) }; });
  }
  const weeksBus = new Set();
  function watch(fetcher, onData, onError, every){
    let stop = false; const run = async () => { if(stop) return; try{ onData(await fetcher()); }catch(e){ if(onError) onError(e); } };
    run(); const t = setInterval(run, every); weeksBus.add(run);
    const vis = () => { if(!document.hidden) run(); }; document.addEventListener("visibilitychange", vis);
    return () => { stop = true; clearInterval(t); weeksBus.delete(run); document.removeEventListener("visibilitychange", vis); };
  }
  async function listLog(){
    if(!MEMBER()) throw fail(null, "history is only for super admins and HR");
    const r = await sb.from("audit_log").select("*").order("at", { ascending: false }).limit(300);
    if(r.error) throw fail(r.error);
    return (r.data || []).map(x => ({ id: String(x.id), data: () => ({ at: Date.parse(x.at), actor: x.actor, role: x.role, visit: x.visit,
      what: Array.isArray(x.details) && x.details.length ? x.details : [x.action] }) }));
  }
  async function writeLog(v){
    const what = (v.what || []).map(String);
    const r = await sb.rpc("log_event", { p_action: what.join("; ").slice(0, 500), p_details: what, p_visit: v.visit || null });
    if(r.error) throw fail(r.error);
  }

  const db = {
    doc(path){
      const [col, id] = path.split("/");
      return {
        async get(){
          if(col === "audit" && (id === "draft" || id === "next")) return getDraft(id);
          if(col === "config") return getCfg();
          return snap(null);
        },
        async set(v){
          if(col === "audit" && (id === "draft" || id === "next")) return setDraft(id, v);
          if(col === "config") return setCfg(v);
          if(col === "weeks") return setWeek(id, v);
          if(col === "log") return writeLog(v);
        }
      };
    },
    collection(name){
      const q = { orderBy: () => q, limit: () => q, where: () => q,
        onSnapshot(onData, onError){
          if(name === "weeks") return watch(listWeeks, docs => onData({ docs }), onError, 60000);
          if(name === "log") return watch(listLog, docs => onData({ docs }), onError, 30000);
          if(onError) onError(new Error("unknown collection")); return () => {};
        } };
      return q;
    }
  };

  const user = {
    isOwner: async () => me.role === "super",
    can: async () => CAN_EDIT(),
    me: async () => ({ email: me.email || me.actor || "" }),
    id: async () => { try{ const { data } = await sb.auth.getUser(); return data && data.user ? data.user.id : ""; }catch(e){ return ""; } },
    profiles: async () => ({})
  };
  const assets = {
    async upload(blob){
      const path = `p/${new Date().toISOString().slice(0, 10)}/${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}.jpg`;
      const r = await sb.storage.from("photos").upload(path, blob, { contentType: blob.type || "image/jpeg", upsert: false });
      if(r.error) throw fail(r.error);
      return { id: "sb:" + path };
    }
  };
  const downloads = {
    async save({ filename, data }){
      const url = URL.createObjectURL(data); const a = document.createElement("a");
      a.href = url; a.download = filename; document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 4000);
    }
  };

  window.claude = { use: async n => { await ready;
    if(n === "db") return db; if(n === "user") return user; if(n === "downloads") return downloads;
    if(n === "assets") return CAN_EDIT() ? assets : null; return null; } };

  window.photoUrl = id => C.url + "/storage/v1/object/public/photos/" + String(id).replace(/^sb:/, "").split("/").map(encodeURIComponent).join("/");

  /* ---------- sign in, store manager mode, people ---------- */
  window.AUTH = {
    sb, ready, get me(){ return me; }, refreshMe, MEMBER, CAN_EDIT,
    async sendCode(email){
      const r = await sb.auth.signInWithOtp({ email: email.trim().toLowerCase(), options: { shouldCreateUser: true, emailRedirectTo: location.origin + location.pathname } });
      if(r.error) throw fail(r.error);
    },
    async verifyCode(email, code){
      const r = await sb.auth.verifyOtp({ email: email.trim().toLowerCase(), token: code.trim(), type: "email" });
      if(r.error) throw fail(r.error);
      await refreshMe();
      if(MEMBER()){ try{ await sb.rpc("log_event", { p_action: "Signed in", p_details: null, p_visit: null }); }catch(e){} }
      return me;
    },
    async smUnlock(pin){
      let s = (await sb.auth.getSession()).data.session;
      if(!s){ const a = await sb.auth.signInAnonymously(); if(a.error) throw fail(a.error); }
      const r = await sb.rpc("sm_unlock", { p_pin: String(pin) }); if(r.error) throw fail(r.error);
      await refreshMe(); return r.data || {};
    },
    async signOut(){
      try{ if(me.role === "sm") await sb.rpc("sm_lock"); else if(MEMBER()) await sb.rpc("log_event", { p_action: "Signed out", p_details: null, p_visit: null }); }catch(e){}
      await sb.auth.signOut(); me = { role: "viewer", email: "", actor: null, name: null };
    },
    async members(){ const r = await sb.from("members").select("*").order("role").order("email"); if(r.error) throw fail(r.error); return r.data || []; },
    async addMember(email, role, name){
      const r = await sb.from("members").upsert({ email: email.trim().toLowerCase(), role, name: name || null }); if(r.error) throw fail(r.error);
      await sb.rpc("log_event", { p_action: `Gave ${email.trim().toLowerCase()} ${role === "super" ? "super admin" : "HR"} access`, p_details: null, p_visit: null });
    },
    async removeMember(email){
      const r = await sb.from("members").delete().eq("email", email); if(r.error) throw fail(r.error);
      await sb.rpc("log_event", { p_action: `Removed access for ${email}`, p_details: null, p_visit: null });
    },
    async setPin(pin){ const r = await sb.rpc("set_sm_pin", { p_pin: String(pin) }); if(r.error) throw fail(r.error); }
  };
})();
