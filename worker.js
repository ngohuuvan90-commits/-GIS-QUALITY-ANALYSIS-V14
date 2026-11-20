const SESSION_SECONDS = 8 * 60 * 60;
const enc = new TextEncoder();
const json = (data, status=200, headers={}) => new Response(JSON.stringify(data), {status, headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store',...headers}});
const b64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const random = n => crypto.getRandomValues(new Uint8Array(n));
async function sha(value){ return b64(await crypto.subtle.digest('SHA-256', enc.encode(value))); }
function fromB64url(value){ let s=value.replace(/-/g,'+').replace(/_/g,'/'); while(s.length%4)s+='='; return Uint8Array.from(atob(s),c=>c.charCodeAt(0)); }
async function pwHash(password,salt){
  const key=await crypto.subtle.importKey('raw',enc.encode(password),'PBKDF2',false,['deriveBits']);
  return b64(await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:fromB64url(salt),iterations:310000},key,256));
}
function cookieVal(req,name){return (req.headers.get('Cookie')||'').split(';').map(x=>x.trim()).find(x=>x.startsWith(name+'='))?.slice(name.length+1)||'';}
const sessionCookie=(value,max=SESSION_SECONDS)=>`gis_session=${value}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${max}`;
async function userFor(req,env){
  const raw=cookieVal(req,'gis_session'); if(!raw)return null;
  const tokenHash=await sha(raw);
  const row=await env.DB.prepare('SELECT u.id,u.username,u.role,u.enabled,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?').bind(tokenHash).first();
  if(!row||!row.enabled||row.expires_at<Date.now()){if(row)await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(tokenHash).run();return null;}
  return row;
}
const validUsername = value => /^[a-zA-Z0-9._-]{3,40}$/.test(value||'');
const validPassword = value => typeof value==='string' && value.length>=12 && value.length<=200;
async function serveAsset(req,env,path){
  const url=new URL(req.url);url.pathname=path;
  return env.ASSETS.fetch(new Request(url.toString(),req));
}
async function handle(req,env){
  const url=new URL(req.url),p=url.pathname;
  if(p==='/api/health')return json({ok:true,service:'GIS QA V14'});
  // Only the isolated login shell and its tiny script are public. The app HTML,
  // app JavaScript, samples, icons and all other assets require a valid session.
  // Login resources are always public. Never redirect from the login page:
  // this avoids browser redirect loops when a stale/invalid cookie is present.
  // Public login routes: accept both the canonical file path and the short
  // /login alias used by browser navigation and Cloudflare's Visit flow.
  if((p==='/login' || p==='/login/' || p==='/login.html') && (req.method==='GET' || req.method==='HEAD')) {
    return serveAsset(req,env,'/login.html');
  }
  if(p==='/login.js' && (req.method==='GET' || req.method==='HEAD')) {
    return serveAsset(req,env,'/login.js');
  }
  if(p==='/api/setup-admin'&&req.method==='POST'){
    if(!env.ADMIN_SETUP_KEY)return json({error:'Chưa cấu hình ADMIN_SETUP_KEY'},503);
    const key=req.headers.get('X-Setup-Key')||'';
    if(key!==env.ADMIN_SETUP_KEY)return json({error:'Không được phép'},403);
    const count=await env.DB.prepare('SELECT COUNT(*) AS n FROM users').first();
    if(count.n!==0)return json({error:'Admin đã được khởi tạo'},409);
    const body=await req.json().catch(()=>({}));
    if(!validUsername(body.username)||!validPassword(body.password))return json({error:'Tên tài khoản 3-40 ký tự; mật khẩu tối thiểu 12 ký tự'},400);
    const salt=b64(random(16)),hash=await pwHash(body.password,salt);
    await env.DB.prepare("INSERT INTO users(username,password_salt,password_hash,role,enabled,created_at) VALUES(?,?,?,'admin',1,?)").bind(body.username,salt,hash,Date.now()).run();
    return json({ok:true,message:'Đã tạo Admin. Hãy đăng nhập.'},201);
  }
  if(p==='/api/login'&&req.method==='POST'){
    const ip=req.headers.get('CF-Connecting-IP')||'unknown',body=await req.json().catch(()=>({}));
    const username=String(body.username||'');
    const key=await sha(ip+'|'+username.toLowerCase()),now=Date.now(),windowStart=now-15*60*1000;
    await env.DB.prepare('DELETE FROM login_attempts WHERE window_start<?').bind(windowStart).run();
    const attempt=await env.DB.prepare('SELECT attempts,window_start FROM login_attempts WHERE key=?').bind(key).first();
    if(attempt&&attempt.attempts>=8&&attempt.window_start>windowStart)return json({error:'Thử đăng nhập quá nhiều. Vui lòng chờ 15 phút.'},429);
    const row=await env.DB.prepare('SELECT * FROM users WHERE username=?').bind(username).first();let valid=false;
    if(row&&row.enabled&&validPassword(body.password)){const got=await pwHash(body.password,row.password_salt);valid=got===row.password_hash;}
    if(!valid){
      await env.DB.prepare(`INSERT INTO login_attempts(key,attempts,window_start) VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET attempts=CASE WHEN window_start<? THEN 1 ELSE attempts+1 END,window_start=CASE WHEN window_start<? THEN excluded.window_start ELSE window_start END`).bind(key,now,windowStart,windowStart).run();
      return json({error:'Tài khoản hoặc mật khẩu không đúng'},401);
    }
    await env.DB.prepare('DELETE FROM login_attempts WHERE key=?').bind(key).run();
    const token=b64(random(32)),tokenHash=await sha(token),expires=now+SESSION_SECONDS*1000;
    await env.DB.prepare('INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)').bind(tokenHash,row.id,expires,now).run();
    return json({ok:true,user:{username:row.username,role:row.role}},200,{'set-cookie':sessionCookie(token)});
  }
  if(p==='/api/me'&&req.method==='GET'){
    const user=await userFor(req,env);return user?json({ok:true,user:{username:user.username,role:user.role}}):json({ok:false},401);
  }
  if(p==='/api/logout'&&req.method==='POST'){
    const raw=cookieVal(req,'gis_session');if(raw)await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await sha(raw)).run();
    return json({ok:true},200,{'set-cookie':sessionCookie('',0)});
  }
  const user=await userFor(req,env);
  if(!user){
    if(p.startsWith('/api/'))return json({error:'Cần đăng nhập'},401);
    // Render the login shell directly for the app entry point. A 200 response
    // is intentional: chained redirects are unnecessary and can loop behind
    // proxies or with stale cookies. Other protected assets return 401.
    if((p==='/' || p==='/index.html') && (req.method==='GET' || req.method==='HEAD')) {
      return serveAsset(req,env,'/login.html');
    }
    // Browser page routes should show the login form instead of a plain 401.
    // Keep API and static-resource protection strict.
    const acceptsHtml=(req.headers.get('Accept')||'').includes('text/html');
    if((req.method==='GET' || req.method==='HEAD') && acceptsHtml && !p.startsWith('/api/')) {
      return serveAsset(req,env,'/login.html');
    }
    return new Response('Unauthorized - please sign in at /login', {status:401,headers:{'cache-control':'no-store','content-type':'text/plain; charset=utf-8'}});
  }
  if(p.startsWith('/api/admin/')){
    if(user.role!=='admin')return json({error:'Không có quyền Admin'},403);
    if(p==='/api/admin/users'&&req.method==='GET'){
      const {results}=await env.DB.prepare('SELECT id,username,role,enabled,created_at FROM users ORDER BY id').all();return json({users:results});
    }
    if(p==='/api/admin/users'&&req.method==='POST'){
      const body=await req.json().catch(()=>({}));if(!validUsername(body.username)||!validPassword(body.password))return json({error:'Tên tài khoản 3-40 ký tự; mật khẩu tối thiểu 12 ký tự'},400);
      const salt=b64(random(16)),hash=await pwHash(body.password,salt);
      try{await env.DB.prepare("INSERT INTO users(username,password_salt,password_hash,role,enabled,created_at) VALUES(?,?,?,'user',1,?)").bind(body.username,salt,hash,Date.now()).run();return json({ok:true},201);}catch{return json({error:'Tên tài khoản đã tồn tại'},409);}
    }
    const match=p.match(/^\/api\/admin\/users\/(\d+)(?:\/(reset-password))?$/);
    if(match&&req.method==='PATCH'&&!match[2]){
      const body=await req.json().catch(()=>({}));if(![0,1].includes(body.enabled))return json({error:'Giá trị enabled không hợp lệ'},400);
      await env.DB.prepare("UPDATE users SET enabled=? WHERE id=? AND role<>'admin'").bind(body.enabled,Number(match[1])).run();
      if(!body.enabled)await env.DB.prepare('DELETE FROM sessions WHERE user_id=?').bind(Number(match[1])).run();return json({ok:true});
    }
    if(match&&req.method==='POST'&&match[2]){
      const body=await req.json().catch(()=>({}));if(!validPassword(body.password))return json({error:'Mật khẩu tối thiểu 12 ký tự'},400);
      const salt=b64(random(16)),hash=await pwHash(body.password,salt);
      await env.DB.prepare("UPDATE users SET password_salt=?,password_hash=? WHERE id=? AND role<>'admin'").bind(salt,hash,Number(match[1])).run();
      await env.DB.prepare('DELETE FROM sessions WHERE user_id=?').bind(Number(match[1])).run();return json({ok:true});
    }
    return json({error:'Không tìm thấy API'},404);
  }
  // A logged-in session may access the application and its static assets.
  return env.ASSETS.fetch(req);
}
export default {
  async fetch(req, env) {
    try {
      return await handle(req, env);
   } catch (error) {
  console.error("GIS V14 WORKER ERROR:", error);
  return json({
    error: "Lỗi máy chủ",
    detail: String(error)
  }, 500);
}
  }
};
