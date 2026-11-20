const SESSION_SECONDS = 8 * 60 * 60;
const enc = new TextEncoder();
const json = (data, status=200, headers={}) => new Response(JSON.stringify(data), {status, headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store',...headers}});
const b64 = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const random = n => crypto.getRandomValues(new Uint8Array(n));
async function sha(s){return b64(await crypto.subtle.digest('SHA-256',enc.encode(s)));}
async function pwHash(password,salt){const key=await crypto.subtle.importKey('raw',enc.encode(password),'PBKDF2',false,['deriveBits']);return b64(await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:Uint8Array.from(atob(salt.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0)),iterations:310000},key,256));}
function cookieVal(req,name){return (req.headers.get('Cookie')||'').split(';').map(x=>x.trim()).find(x=>x.startsWith(name+'='))?.slice(name.length+1)||'';}
const cookie=(v,max=SESSION_SECONDS)=>`gis_session=${v}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${max}`;
async function userFor(req,env){const raw=cookieVal(req,'gis_session');if(!raw)return null;const row=await env.DB.prepare('SELECT u.id,u.username,u.role,u.enabled,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?').bind(await sha(raw)).first();if(!row||!row.enabled||row.expires_at<Date.now()){if(row)await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await sha(raw)).run();return null;}return row;}
async function admin(req,env){const u=await userFor(req,env);return u?.role==='admin'?u:null;}
async function handle(req,env){const url=new URL(req.url),p=url.pathname;
 if(p==='/api/health')return json({ok:true,service:'GIS QA V14'});
 if(p==='/api/setup-admin'&&req.method==='POST'){
  if(!env.ADMIN_SETUP_KEY)return json({error:'Chưa cấu hình ADMIN_SETUP_KEY'},503);
  const key=req.headers.get('X-Setup-Key')||'';if(key.length!==env.ADMIN_SETUP_KEY.length||key!==env.ADMIN_SETUP_KEY)return json({error:'Không được phép'},403);
  const count=await env.DB.prepare('SELECT COUNT(*) AS n FROM users').first();if(count.n!==0)return json({error:'Admin đã được khởi tạo'},409);
  const b=await req.json();if(!/^[a-zA-Z0-9._-]{3,40}$/.test(b.username||'')||(b.password||'').length<12)return json({error:'Tên tài khoản 3-40 ký tự; mật khẩu tối thiểu 12 ký tự'},400);
  const salt=b64(random(16)),hash=await pwHash(b.password,salt);await env.DB.prepare('INSERT INTO users(username,password_salt,password_hash,role,enabled,created_at) VALUES(?,?,?,\'admin\',1,?)').bind(b.username,salt,hash,Date.now()).run();return json({ok:true,message:'Đã tạo Admin. Hãy đăng nhập.'},201);
 }
 if(p==='/api/login'&&req.method==='POST'){
  const ip=req.headers.get('CF-Connecting-IP')||'unknown',body=await req.json().catch(()=>({}));
  const key=await sha(ip+'|'+String(body.username||'').toLowerCase()),now=Date.now();
  await env.DB.prepare('DELETE FROM login_attempts WHERE window_start<?').bind(now-15*60*1000).run();
  const attempt=await env.DB.prepare('SELECT attempts,window_start FROM login_attempts WHERE key=?').bind(key).first();if(attempt&&attempt.attempts>=8&&attempt.window_start>now-15*60*1000)return json({error:'Thử đăng nhập quá nhiều. Vui lòng chờ 15 phút.'},429);
  const row=await env.DB.prepare('SELECT * FROM users WHERE username=?').bind(String(body.username||'')).first();let valid=false;
  if(row&&row.enabled&&typeof body.password==='string'&&body.password.length<=200){const got=await pwHash(body.password,row.password_salt);valid=got===row.password_hash;}
  if(!valid){await env.DB.prepare(`INSERT INTO login_attempts(key,attempts,window_start) VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET attempts=CASE WHEN window_start<? THEN 1 ELSE attempts+1 END,window_start=CASE WHEN window_start<? THEN excluded.window_start ELSE window_start END`).bind(key,now,now-15*60*1000,now-15*60*1000).run();return json({error:'Tài khoản hoặc mật khẩu không đúng'},401);}
  await env.DB.prepare('DELETE FROM login_attempts WHERE key=?').bind(key).run();const token=b64(random(32)),hash=await sha(token),expires=now+SESSION_SECONDS*1000;await env.DB.prepare('INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)').bind(hash,row.id,expires,now).run();return json({ok:true,user:{username:row.username,role:row.role}},200,{'set-cookie':cookie(token)});
 }
 if(p==='/api/me'&&req.method==='GET'){const u=await userFor(req,env);return u?json({ok:true,user:{username:u.username,role:u.role}}):json({ok:false},401);}
 if(p==='/api/logout'&&req.method==='POST'){const raw=cookieVal(req,'gis_session');if(raw)await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await sha(raw)).run();return json({ok:true},200,{'set-cookie':cookie('',0)});}
 const u=await userFor(req,env);if(!u)return new Response('Unauthorized',{status:401,headers:{'cache-control':'no-store'}});
 if(p.startsWith('/api/admin/')){
  if(u.role!=='admin')return json({error:'Không có quyền Admin'},403);
  if(p==='/api/admin/users'&&req.method==='GET'){const {results}=await env.DB.prepare('SELECT id,username,role,enabled,created_at FROM users ORDER BY id').all();return json({users:results});}
  if(p==='/api/admin/users'&&req.method==='POST'){const b=await req.json();if(!/^[a-zA-Z0-9._-]{3,40}$/.test(b.username||'')||(b.password||'').length<12)return json({error:'Tên tài khoản 3-40 ký tự; mật khẩu tối thiểu 12 ký tự'},400);const salt=b64(random(16)),hash=await pwHash(b.password,salt);try{await env.DB.prepare('INSERT INTO users(username,password_salt,password_hash,role,enabled,created_at) VALUES(?,?,?,\'user\',1,?)').bind(b.username,salt,hash,Date.now()).run();return json({ok:true},201);}catch{return json({error:'Tên tài khoản đã tồn tại'},409);}}
  const m=p.match(/^\/api\/admin\/users\/(\d+)(?:\/(reset-password))?$/);if(m&&req.method==='PATCH'&&!m[2]){const b=await req.json();if(![0,1].includes(b.enabled))return json({error:'Giá trị enabled không hợp lệ'},400);await env.DB.prepare('UPDATE users SET enabled=? WHERE id=? AND role<>\'admin\'').bind(b.enabled,Number(m[1])).run();if(!b.enabled)await env.DB.prepare('DELETE FROM sessions WHERE user_id=?').bind(Number(m[1])).run();return json({ok:true});}
  if(m&&req.method==='POST'&&m[2]){const b=await req.json();if((b.password||'').length<12)return json({error:'Mật khẩu tối thiểu 12 ký tự'},400);const salt=b64(random(16)),hash=await pwHash(b.password,salt);await env.DB.prepare('UPDATE users SET password_salt=?,password_hash=? WHERE id=? AND role<>\'admin\'').bind(salt,hash,Number(m[1])).run();await env.DB.prepare('DELETE FROM sessions WHERE user_id=?').bind(Number(m[1])).run();return json({ok:true});}
  return json({error:'Không tìm thấy API'},404);
 }
 return env.ASSETS.fetch(req);
}
export default {async fetch(req,env){try{return await handle(req,env);}catch(e){return json({error:'Lỗi máy chủ',detail:env.ENVIRONMENT==='development'?String(e):undefined},500);}}};
