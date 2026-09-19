/* =====================================================
   TARMOC API — Central Dashboard Backend
   Mengikuti MD-01: §15 Skema DB, §17 Security, §20 API
   Run: node server.js
===================================================== */
const express      = require('express');
const Database     = require('better-sqlite3');
const bcrypt       = require('bcryptjs');
const jwt          = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const rateLimit    = require('express-rate-limit');
const path         = require('path');
const fs           = require('fs');
const crypto       = require('crypto');

/* ---------- KONFIGURASI ---------- */
const PORT     = process.env.PORT || 3010;
const NODE_ENV = process.env.NODE_ENV || 'development';
const DB_PATH  = process.env.DB_PATH || path.join(__dirname, 'tarmoc.db');

/* JWT secret: dari env, atau dibuat sekali & disimpan agar sesi bertahan antar restart */
let SECRET = process.env.JWT_SECRET;
if (!SECRET) {
  const f = path.join(__dirname, '.jwt-secret');
  try { SECRET = fs.readFileSync(f, 'utf8').trim(); } catch (e) {}
  if (!SECRET) { SECRET = crypto.randomBytes(48).toString('hex'); fs.writeFileSync(f, SECRET); }
}

/* ---------- DATABASE ---------- */
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL, sys_role TEXT NOT NULL DEFAULT 'user',
  status TEXT NOT NULL DEFAULT 'active', last_login_at INTEGER,
  created_at INTEGER, updated_at INTEGER
);
CREATE TABLE IF NOT EXISTS application_categories (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, slug TEXT, created_at INTEGER
);
CREATE TABLE IF NOT EXISTS applications (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, code TEXT NOT NULL UNIQUE,
  description TEXT, url TEXT, category_id TEXT, color TEXT,
  status TEXT NOT NULL DEFAULT 'active', display_order INTEGER DEFAULT 99,
  created_at INTEGER, updated_at INTEGER,
  FOREIGN KEY (category_id) REFERENCES application_categories(id)
);
CREATE TABLE IF NOT EXISTS roles (
  id TEXT PRIMARY KEY, application_id TEXT NOT NULL,
  name TEXT NOT NULL, description TEXT, created_at INTEGER,
  FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS permissions (
  id TEXT PRIMARY KEY, application_id TEXT NOT NULL,
  code TEXT NOT NULL, name TEXT,
  FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS role_permissions (
  role_id TEXT NOT NULL, permission_id TEXT NOT NULL,
  PRIMARY KEY (role_id, permission_id),
  FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
  FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS user_applications (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL, application_id TEXT NOT NULL,
  role_id TEXT, status TEXT NOT NULL DEFAULT 'active',
  created_at INTEGER, updated_at INTEGER,
  UNIQUE (user_id, application_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE,
  FOREIGN KEY (role_id) REFERENCES roles(id)
);
CREATE TABLE IF NOT EXISTS activity_logs (
  id TEXT PRIMARY KEY, user_id TEXT, application_id TEXT,
  action TEXT NOT NULL, description TEXT,
  ip_address TEXT, user_agent TEXT, created_at INTEGER
);
`);

/* ---------- SEED (data demo identik dengan versi frontend) ---------- */
function seed() {
  if (db.prepare('SELECT COUNT(*) n FROM users').get().n > 0) return;
  const now = Date.now(), D = 864e5, H = 36e5;
  let seq = 100;
  const uid = p => p + '-' + (++seq);
  const hash = bcrypt.hashSync('tarmoc123', 10);

  const tx = db.transaction(() => {
    const insCat = db.prepare('INSERT INTO application_categories(id,name,slug,created_at) VALUES(?,?,?,?)');
    [['c1','Operasional','operasional'],['c2','Keuangan','keuangan'],['c3','SDM','sdm'],['c4','Dukungan','dukungan']]
      .forEach(c => insCat.run(c[0], c[1], c[2], now));

    const insApp = db.prepare('INSERT INTO applications(id,name,code,description,url,category_id,color,status,display_order,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)');
    const insPerm = db.prepare('INSERT INTO permissions(id,application_id,code,name) VALUES(?,?,?,?)');
    const insRole = db.prepare('INSERT INTO roles(id,application_id,name,description,created_at) VALUES(?,?,?,?,?)');
    const insRP  = db.prepare('INSERT INTO role_permissions(role_id,permission_id) VALUES(?,?)');

    const A = o => {
      insApp.run(o.id, o.name, o.code, o.desc, o.url, o.cat, o.color, o.status || 'active', o.order, now - o.age * H, now - o.age * H);
      const ids = o.perms.map(p => { const id = uid('p'); insPerm.run(id, o.id, p[0], p[1]); return id; });
      o.roles.forEach((r, i) => {
        const rid = 'r_' + o.id + '_' + i;
        insRole.run(rid, o.id, r[0], r[1], now - o.age * H);
        const pids = r[2] === '*' ? ids
          : o.perms.map((p, idx) => r[2].includes(p[0]) ? ids[idx] : null).filter(Boolean);
        pids.forEach(pid => insRP.run(rid, pid));
      });
    };

    A({id:'a1',name:'KasStore',code:'KASSTORE',desc:'Manajemen penjualan & kasir',url:'https://kas.example.com',cat:'c1',order:1,color:'#1D5C48',age:2200,
      perms:[['dashboard.view','Akses dasbor'],['product.view','Lihat produk'],['product.create','Buat produk'],['product.update','Ubah produk'],['product.delete','Hapus produk'],['sales.view','Lihat penjualan'],['sales.create','Buat transaksi'],['sales.delete','Hapus transaksi'],['report.view','Lihat laporan'],['settings.manage','Kelola pengaturan']],
      roles:[['Admin','Akses penuh aplikasi','*'],
             ['Manager','Kelola operasional harian',['dashboard.view','product.view','product.update','sales.view','sales.create','report.view']],
             ['Staff','Operasional kasir',['dashboard.view','product.view','sales.create']]]});
    A({id:'a2',name:'Inventory',code:'INVENTORY',desc:'Manajemen stok & gudang',url:'https://inventory.example.com',cat:'c1',order:2,color:'#A8502B',age:1900,
      perms:[['dashboard.view','Akses dasbor'],['item.view','Lihat item'],['item.create','Buat item'],['item.update','Ubah item'],['item.delete','Hapus item'],['stock.adjust','Penyesuaian stok'],['stock.count','Stok opname'],['supplier.view','Lihat pemasok'],['supplier.manage','Kelola pemasok'],['report.view','Lihat laporan'],['settings.manage','Kelola pengaturan']],
      roles:[['Admin','Akses penuh aplikasi','*'],
             ['Warehouse','Operasional gudang',['dashboard.view','item.view','item.create','stock.adjust','stock.count']],
             ['Supervisor','Pengawasan persediaan',['dashboard.view','item.view','stock.adjust','stock.count','report.view']],
             ['Viewer','Hanya melihat',['dashboard.view','item.view','report.view']]]});
    A({id:'a3',name:'Finance',code:'FINANCE',desc:'Sistem pelaporan keuangan',url:'https://finance.example.com',cat:'c2',order:3,color:'#5C5330',age:1500,
      perms:[['dashboard.view','Akses dasbor'],['invoice.view','Lihat faktur'],['invoice.create','Buat faktur'],['invoice.update','Ubah faktur'],['invoice.delete','Hapus faktur'],['ledger.view','Lihat buku besar'],['ledger.post','Posting jurnal'],['report.view','Lihat laporan'],['export.data','Ekspor data'],['settings.manage','Kelola pengaturan']],
      roles:[['Admin','Akses penuh aplikasi','*'],
             ['Accountant','Akuntansi & pembukuan',['dashboard.view','invoice.view','invoice.create','invoice.update','ledger.view','ledger.post','report.view','export.data']],
             ['Viewer','Hanya melihat',['dashboard.view','invoice.view','report.view']]]});
    A({id:'a4',name:'HR',code:'HRIS',desc:'Sumber daya manusia',url:'https://hr.example.com',cat:'c3',order:4,color:'#6E3B54',age:1200,
      perms:[['dashboard.view','Akses dasbor'],['employee.view','Lihat karyawan'],['employee.create','Buat karyawan'],['employee.update','Ubah karyawan'],['employee.delete','Hapus karyawan'],['attendance.view','Lihat kehadiran'],['attendance.approve','Setujui kehadiran'],['payroll.view','Lihat payroll'],['payroll.run','Jalankan payroll'],['report.view','Lihat laporan'],['settings.manage','Kelola pengaturan']],
      roles:[['Admin','Akses penuh aplikasi','*'],
             ['HR Staff','Operasional HR',['dashboard.view','employee.view','employee.create','employee.update','attendance.view','attendance.approve','report.view']],
             ['Employee','Portal karyawan',['dashboard.view','attendance.view']]]});
    A({id:'a5',name:'Helpdesk',code:'HELPDESK',desc:'Tiket & dukungan pelanggan',url:'https://help.example.com',cat:'c4',order:5,color:'#256B66',age:800,
      perms:[['dashboard.view','Akses dasbor'],['ticket.view','Lihat tiket'],['ticket.create','Buat tiket'],['ticket.update','Ubah tiket'],['ticket.close','Tutup tiket'],['kb.view','Lihat basis pengetahuan'],['kb.edit','Edit basis pengetahuan'],['customer.view','Lihat pelanggan'],['report.view','Lihat laporan'],['settings.manage','Kelola pengaturan']],
      roles:[['Admin','Akses penuh aplikasi','*'],
             ['Agent','Agen dukungan',['dashboard.view','ticket.view','ticket.create','ticket.update','ticket.close','kb.view','customer.view']],
             ['Viewer','Hanya melihat',['dashboard.view','ticket.view','kb.view']]]});
    A({id:'a6',name:'AssetsHub',code:'ASSETS',desc:'Pencatatan aset perusahaan',url:'https://assets.example.com',cat:'c1',order:6,color:'#8C3A30',status:'disabled',age:500,
      perms:[['dashboard.view','Akses dasbor'],['asset.view','Lihat aset'],['asset.create','Buat aset'],['asset.update','Ubah aset'],['asset.delete','Hapus aset'],['report.view','Lihat laporan'],['settings.manage','Kelola pengaturan']],
      roles:[['Admin','Akses penuh aplikasi','*'],['Viewer','Hanya melihat',['dashboard.view','asset.view']]]});

    const insU = db.prepare('INSERT INTO users(id,name,email,password_hash,sys_role,status,last_login_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)');
    insU.run('u1','Heru Riyadi','heru@tarmoc.io',hash,'super','active',now-4*6e4,now-90*D,now);
    insU.run('u2','Budi Santoso','budi@tarmoc.io',hash,'user','active',now-38*6e4,now-90*D,now);
    insU.run('u3','Andi Pratama','andi@tarmoc.io',hash,'user','active',now-122*6e4,now-90*D,now);
    insU.run('u4','Siti Rahma','siti@tarmoc.io',hash,'user','active',now-600*6e4,now-90*D,now);
    insU.run('u5','Dewi Lestari','dewi@tarmoc.io',hash,'user','active',now-1500*6e4,now-90*D,now);
    insU.run('u6','Rizky Hidayat','rizky@tarmoc.io',hash,'user','disabled',now-4300*6e4,now-90*D,now);

    const insUA = db.prepare('INSERT INTO user_applications(id,user_id,application_id,role_id,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)');
    const G = (u, a, r) => insUA.run(uid('ua'), u, a, r, 'active', now - 60 * D, now - 60 * D);
    G('u1','a1','r_a1_0'); G('u1','a2','r_a2_0'); G('u1','a3','r_a3_0'); G('u1','a4','r_a4_0'); G('u1','a5','r_a5_0');
    G('u2','a1','r_a1_1'); G('u6','a1','r_a1_1'); G('u2','a2','r_a2_3'); G('u2','a4','r_a4_0');
    G('u3','a3','r_a3_1'); G('u3','a5','r_a5_1');
    G('u4','a1','r_a1_2'); G('u4','a2','r_a2_1');
    G('u5','a3','r_a3_2'); G('u5','a4','r_a4_2');

    const insLog = db.prepare('INSERT INTO activity_logs(id,user_id,application_id,action,description,ip_address,user_agent,created_at) VALUES(?,?,?,?,?,?,?,?)');
    const L = (min,u,a,act,d) => insLog.run(uid('lg'),u,a,act,d,'10.20.1.10','Chrome / macOS',now-min*6e4);
    L(2,'u2','a1','app.open','Budi membuka KasStore');
    L(9,'u1','a2','access.assign','Heru mengubah role Budi di Inventory menjadi Viewer');
    L(26,'u1',null,'user.create','Heru menambahkan pengguna baru: Dewi Lestari');
    L(64,'u3','a3','app.open','Andi membuka Finance');
    L(95,'u1','a3','app.create','Aplikasi Finance ditambahkan ke workspace');
    L(150,'u4','a2','app.open','Siti membuka Inventory');
    L(240,'u1','a6','app.status','Aplikasi AssetsHub dinonaktifkan');
    L(1600,'u1',null,'auth.login','Heru masuk ke workspace');
  });
  tx();
  console.log('✔ Database di-seed dengan data demo (6 aplikasi, 6 pengguna)');
}
seed();

/* ---------- HELPER ---------- */
const uid = p => p + '-' + crypto.randomBytes(4).toString('hex') + Date.now().toString(36).slice(-3);
const now = () => Date.now();
const isSuper = u => u && u.sys_role === 'super';
const bad = (res, msg, code = 400) => res.status(code).json({ error: msg });

const clientIp = req => (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress;

function logAct(req, action, description, applicationId = null) {
  db.prepare('INSERT INTO activity_logs(id,user_id,application_id,action,description,ip_address,user_agent,created_at) VALUES(?,?,?,?,?,?,?,?)')
    .run(uid('lg'), req.user ? req.user.id : null, applicationId, action, description,
         clientIp(req), (req.headers['user-agent'] || '').slice(0, 200), now());
}

function hasPerm(userId, appId, code) {
  return !!db.prepare(`
    SELECT 1 FROM user_applications ua
    JOIN role_permissions rp ON rp.role_id = ua.role_id
    JOIN permissions p ON p.id = rp.permission_id
    WHERE ua.user_id = ? AND ua.application_id = ? AND p.code = ? AND ua.status = 'active'
  `).get(userId, appId, code);
}

function hasAppAccess(userId, appId) {
  return isSuper(db.prepare('SELECT sys_role FROM users WHERE id=?').get(userId))
      || !!db.prepare(`SELECT 1 FROM user_applications WHERE user_id=? AND application_id=? AND status='active'`).get(userId, appId);
}

/* pembungkus error → 500 tanpa crash */
const h = fn => (req, res) => { try { fn(req, res); } catch (e) { console.error(e); res.status(500).json({ error: 'Kesalahan internal server' }); } };

/* ---------- MIDDLEWARE ---------- */
function auth(req, res, next) {
  const token = req.cookies.tarmoc_token;
  if (!token) return bad(res, 'Belum terautentikasi', 401);
  let payload;
  try { payload = jwt.verify(token, SECRET); } catch (e) { return bad(res, 'Sesi tidak valid / kedaluwarsa', 401); }
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(payload.sub);
  if (!user) return bad(res, 'Pengguna tidak ditemukan', 401);
  if (user.status !== 'active') return bad(res, 'Akun dinonaktifkan', 401);
  req.user = user; next();
}
const superOnly = (req, res, next) => isSuper(req.user) ? next() : bad(res, '403 Forbidden — khusus Super Admin', 403);

function requireAppAccess(param = 'id') {
  return (req, res, next) => {
    const appId = req.params[param] || req.body.application_id;
    const app = db.prepare('SELECT * FROM applications WHERE id = ?').get(appId);
    if (!app) return bad(res, 'Aplikasi tidak ditemukan', 404);
    req.appRow = app;
    if (isSuper(req.user)) return next();
    const g = db.prepare(`SELECT * FROM user_applications WHERE user_id=? AND application_id=? AND status='active'`).get(req.user.id, appId);
    if (!g) {
      logAct(req, 'access.denied', `${req.user.name} mencoba mengakses ${app.name} tanpa izin`, appId);
      return bad(res, '403 Forbidden — Anda tidak memiliki akses ke aplikasi ini', 403);
    }
    req.grant = g; next();
  };
}
function requirePerm(appParam, code) {
  return (req, res, next) => {
    const appId = req.params[appParam] || req.body.application_id;
    if (isSuper(req.user) || hasPerm(req.user.id, appId, code)) return next();
    logAct(req, 'access.denied', `${req.user.name} ditolak: butuh permission ${code}`, appId);
    bad(res, `403 Forbidden — dibutuhkan permission "${code}"`, 403);
  };
}

/* ---------- APP ---------- */
const app = express();
app.set('trust proxy', false);
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());

const cookieOpts = () => ({ httpOnly: true, sameSite: 'lax', secure: false, path: '/', maxAge: 8 * 3600 * 1000 });

/* rate limit global ringan + throttle ketat khusus login (MD-01 §17) */
app.use('/api/', rateLimit({ windowMs: 60_000, max: 300, standardHeaders: true, legacyHeaders: false }));
const loginLimiter = rateLimit({
  windowMs: 60_000, max: 5, standardHeaders: true, legacyHeaders: false,
  keyGenerator: req => req.ip + '|' + (req.body?.email || '').toLowerCase(),
  message: { error: 'Terlalu banyak percobaan login. Tunggu satu menit.' }
});

/* =====================================================
   AUTH
===================================================== */
app.post('/api/auth/login', loginLimiter, h((req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  if (!email || !password) return bad(res, 'Email dan password wajib diisi');

  const user = db.prepare('SELECT * FROM users WHERE lower(email) = ?').get(email);
  /* hashing selalu dijalankan untuk mencegah timing attack */
  const ok = user ? bcrypt.compareSync(password, user.password_hash) : false;
  if (!ok) {
    db.prepare('INSERT INTO activity_logs(id,user_id,action,description,ip_address,user_agent,created_at) VALUES(?,?,?,?,?,?,?)')
      .run(uid('lg'), user ? user.id : null, 'auth.login.failed', `Percobaan login gagal untuk ${email}`, clientIp(req), req.headers['user-agent'] || '', now());
    return bad(res, 'Email atau password salah', 401);
  }
  if (user.status !== 'active') return bad(res, 'Akun dinonaktifkan. Hubungi administrator.', 403);

  db.prepare('UPDATE users SET last_login_at = ? WHERE id = ?').run(now(), user.id);
  const token = jwt.sign({ sub: user.id, typ: 'session' }, SECRET, { expiresIn: '8h' });
  res.cookie('tarmoc_token', token, cookieOpts());

  req.user = user;
  logAct(req, 'auth.login', `${user.name} masuk ke workspace`);
  res.json({ user: { id: user.id, name: user.name, email: user.email, sys_role: user.sys_role } });
}));

app.post('/api/auth/logout', h((req, res) => {
  if (req.cookies.tarmoc_token) { try { req.user = jwt.verify(req.cookies.tarmoc_token, SECRET) ? db.prepare('SELECT * FROM users WHERE id=?').get(jwt.verify(req.cookies.tarmoc_token, SECRET).sub) : null; if (req.user) logAct(req, 'auth.logout', `${req.user.name} keluar dari workspace`); } catch (e) {} }
  res.clearCookie('tarmoc_token', { path: '/' });
  res.json({ ok: true });
}));

app.get('/api/auth/me', auth, h((req, res) => {
  const grants = db.prepare(`
    SELECT ua.application_id, ua.role_id, a.name app_name, a.code, a.status, r.name role_name
    FROM user_applications ua
    JOIN applications a ON a.id = ua.application_id
    LEFT JOIN roles r ON r.id = ua.role_id
    WHERE ua.user_id = ?`).all(req.user.id);
  const { password_hash, ...safe } = req.user;
  res.json({ user: safe, grants });
}));

/* profil & password mandiri (untuk halaman Settings) */
app.put('/api/auth/profile', auth, h((req, res) => {
  const name = String(req.body.name || '').trim();
  const email = String(req.body.email || '').trim().toLowerCase();
  if (!name || !email) return bad(res, 'Nama dan email wajib diisi');
  const dup = db.prepare('SELECT id FROM users WHERE lower(email)=? AND id<>?').get(email, req.user.id);
  if (dup) return bad(res, 'Email sudah dipakai pengguna lain', 409);
  db.prepare('UPDATE users SET name=?, email=?, updated_at=? WHERE id=?').run(name, email, now(), req.user.id);
  logAct(req, 'profile.update', `${name} memperbarui profilnya`);
  res.json({ ok: true });
}));

app.post('/api/auth/password', auth, h((req, res) => {
  const { current, next } = req.body;
  if (!bcrypt.compareSync(String(current || ''), req.user.password_hash)) return bad(res, 'Password saat ini salah', 401);
  if (String(next || '').length < 6) return bad(res, 'Password baru minimal 6 karakter');
  db.prepare('UPDATE users SET password_hash=?, updated_at=? WHERE id=?').run(bcrypt.hashSync(next, 10), now(), req.user.id);
  logAct(req, 'user.pass', `${req.user.name} mengganti passwordnya`);
  res.json({ ok: true });
}));

/* =====================================================
   APPLICATIONS (MD-01 §20)
===================================================== */
app.get('/api/applications', auth, h((req, res) => {
  if (isSuper(req.user)) {
    const rows = db.prepare(`
      SELECT a.*, c.name category_name,
        (SELECT COUNT(*) FROM user_applications x WHERE x.application_id = a.id) user_count
      FROM applications a LEFT JOIN application_categories c ON c.id = a.category_id
      ORDER BY a.display_order`).all();
    return res.json({ applications: rows });
  }
  /* pengguna biasa: HANYA aplikasi berizin & aktif — filter di server (§7) */
  const rows = db.prepare(`
    SELECT a.*, c.name category_name, ua.role_id, r.name role_name, ua.created_at granted_at
    FROM user_applications ua
    JOIN applications a ON a.id = ua.application_id
    LEFT JOIN application_categories c ON c.id = a.category_id
    LEFT JOIN roles r ON r.id = ua.role_id
    WHERE ua.user_id = ? AND ua.status = 'active' AND a.status = 'active'
    ORDER BY a.display_order`).all(req.user.id);
  res.json({ applications: rows });
}));

app.post('/api/applications', auth, superOnly, h((req, res) => {
  const name = String(req.body.name || '').trim();
  const code = String(req.body.code || '').trim().toUpperCase();
  if (!name || !code) return bad(res, 'Nama dan kode aplikasi wajib diisi');
  if (db.prepare('SELECT 1 FROM applications WHERE code=?').get(code)) return bad(res, 'Kode sudah dipakai aplikasi lain', 409);

  const id = uid('a');
  const ent = String(req.body.entity || 'data').trim().toLowerCase().replace(/\s+/g, '') || 'data';
  const tx = db.transaction(() => {
    db.prepare('INSERT INTO applications(id,name,code,description,url,category_id,color,status,display_order,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)')
      .run(id, name, code, String(req.body.description || '').trim(), String(req.body.url || '').trim(),
           req.body.category_id || null, '#4A4A42', req.body.status || 'active',
           +req.body.display_order || 99, now(), now());
    const codes = [['dashboard.view','Akses dasbor'],[ent+'.view','Lihat '+ent],[ent+'.create','Buat '+ent],[ent+'.update','Ubah '+ent],[ent+'.delete','Hapus '+ent],['report.view','Lihat laporan'],['settings.manage','Kelola pengaturan']];
    const ids = codes.map(c => { const pid = uid('p'); db.prepare('INSERT INTO permissions(id,application_id,code,name) VALUES(?,?,?,?)').run(pid, id, c[0], c[1]); return [pid, c[0]]; });
    [['Admin','Akses penuh aplikasi','*'],
     ['Manager','Kelola operasional harian',['dashboard.view',ent+'.view',ent+'.create',ent+'.update','report.view']],
     ['Viewer','Hanya melihat',['dashboard.view',ent+'.view','report.view']]]
      .forEach(r => {
        const rid = uid('r');
        db.prepare('INSERT INTO roles(id,application_id,name,description,created_at) VALUES(?,?,?,?,?)').run(rid, id, r[0], r[1], now());
        ids.filter(([, c]) => r[2] === '*' || r[2].includes(c)).forEach(([pid]) => db.prepare('INSERT INTO role_permissions(role_id,permission_id) VALUES(?,?)').run(rid, pid));
      });
    /* super admin otomatis mendapat akses aplikasi baru */
    db.prepare('INSERT INTO user_applications(id,user_id,application_id,role_id,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)')
      .run(uid('ua'), req.user.id, id, db.prepare('SELECT id FROM roles WHERE application_id=? AND name=?').get(id, 'Admin').id, 'active', now(), now());
  });
  tx();
  logAct(req, 'app.create', `Aplikasi ${name} ditambahkan ke workspace`, id);
  res.status(201).json({ id });
}));

app.get('/api/applications/:id', auth, requireAppAccess(), h((req, res) => {
  const a = req.appRow;
  a.roles = db.prepare('SELECT * FROM roles WHERE application_id=?').all(a.id);
  a.permissions = db.prepare('SELECT * FROM permissions WHERE application_id=?').all(a.id);
  res.json({ application: a });
}));

app.put('/api/applications/:id', auth, superOnly, h((req, res) => {
  const a = db.prepare('SELECT * FROM applications WHERE id=?').get(req.params.id);
  if (!a) return bad(res, 'Aplikasi tidak ditemukan', 404);
  const name = String(req.body.name ?? a.name).trim();
  const code = String(req.body.code ?? a.code).trim().toUpperCase();
  if (!name || !code) return bad(res, 'Nama dan kode wajib diisi');
  if (db.prepare('SELECT 1 FROM applications WHERE code=? AND id<>?').get(code, a.id)) return bad(res, 'Kode sudah dipakai aplikasi lain', 409);
  db.prepare('UPDATE applications SET name=?, code=?, description=?, url=?, category_id=?, status=?, display_order=?, updated_at=? WHERE id=?')
    .run(name, code, String(req.body.description ?? a.description), String(req.body.url ?? a.url),
         req.body.category_id ?? a.category_id, req.body.status ?? a.status,
         +req.body.display_order || a.display_order, now(), a.id);
  logAct(req, 'app.update', `Aplikasi ${name} diperbarui`, a.id);
  res.json({ ok: true });
}));

app.patch('/api/applications/:id/status', auth, superOnly, h((req, res) => {
  const a = db.prepare('SELECT * FROM applications WHERE id=?').get(req.params.id);
  if (!a) return bad(res, 'Aplikasi tidak ditemukan', 404);
  const status = req.body.status === 'active' ? 'active' : 'disabled';
  db.prepare('UPDATE applications SET status=?, updated_at=? WHERE id=?').run(status, now(), a.id);
  logAct(req, 'app.status', `Aplikasi ${a.name} ${status === 'active' ? 'diaktifkan' : 'dinonaktifkan'}`, a.id);
  res.json({ ok: true, status });
}));

app.delete('/api/applications/:id', auth, superOnly, h((req, res) => {
  const a = db.prepare('SELECT * FROM applications WHERE id=?').get(req.params.id);
  if (!a) return bad(res, 'Aplikasi tidak ditemukan', 404);
  const tx = db.transaction(() => {
    db.prepare('DELETE FROM user_applications WHERE application_id=?').run(a.id);
    db.prepare(`DELETE FROM role_permissions WHERE role_id IN (SELECT id FROM roles WHERE application_id=?)`).run(a.id);
    db.prepare('DELETE FROM roles WHERE application_id=?').run(a.id);
    db.prepare('DELETE FROM permissions WHERE application_id=?').run(a.id);
    db.prepare('DELETE FROM applications WHERE id=?').run(a.id);
  });
  tx();
  logAct(req, 'app.delete', `Aplikasi ${a.name} dihapus beserta seluruh konfigurasinya`);
  res.json({ ok: true });
}));

/* =====================================================
   USERS (MD-01 §20)
===================================================== */
app.get('/api/users', auth, superOnly, h((req, res) => {
  const users = db.prepare(`SELECT id,name,email,sys_role,status,last_login_at,created_at FROM users WHERE sys_role <> 'super' ORDER BY name`).all();
  const grants = db.prepare(`
    SELECT ua.user_id, ua.application_id, ua.role_id, a.name app_name, a.color, r.name role_name
    FROM user_applications ua
    JOIN applications a ON a.id = ua.application_id
    LEFT JOIN roles r ON r.id = ua.role_id`).all();
  const byUser = {};
  grants.forEach(g => (byUser[g.user_id] = byUser[g.user_id] || []).push(g));
  res.json({ users: users.map(u => ({ ...u, grants: byUser[u.id] || [] })) });
}));

app.post('/api/users', auth, superOnly, h((req, res) => {
  const name = String(req.body.name || '').trim();
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || 'tarmoc123');
  if (!name || !email) return bad(res, 'Nama dan email wajib diisi');
  if (db.prepare('SELECT 1 FROM users WHERE lower(email)=?').get(email)) return bad(res, 'Email sudah terdaftar', 409);
  const id = uid('u');
  db.prepare('INSERT INTO users(id,name,email,password_hash,sys_role,status,last_login_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)')
    .run(id, name, email, bcrypt.hashSync(password, 10), 'user', req.body.status || 'active', null, now(), now());
  logAct(req, 'user.create', `Pengguna baru ditambahkan: ${name}`);
  res.status(201).json({ id });
}));

app.put('/api/users/:id', auth, superOnly, h((req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(req.params.id);
  if (!u) return bad(res, 'Pengguna tidak ditemukan', 404);
  const name = String(req.body.name ?? u.name).trim();
  const email = String(req.body.email ?? u.email).trim().toLowerCase();
  if (!name || !email) return bad(res, 'Nama dan email wajib diisi');
  if (db.prepare('SELECT 1 FROM users WHERE lower(email)=? AND id<>?').get(email, u.id)) return bad(res, 'Email sudah terdaftar', 409);
  const status = u.sys_role === 'super' ? 'active' : (req.body.status ?? u.status);
  db.prepare('UPDATE users SET name=?, email=?, status=?, updated_at=? WHERE id=?').run(name, email, status, now(), u.id);
  logAct(req, 'user.update', `Profil ${name} diperbarui`);
  res.json({ ok: true });
}));

app.patch('/api/users/:id/status', auth, superOnly, h((req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(req.params.id);
  if (!u) return bad(res, 'Pengguna tidak ditemukan', 404);
  if (u.sys_role === 'super') return bad(res, 'Super Admin tidak dapat dinonaktifkan', 409);
  const status = req.body.status === 'active' ? 'active' : 'disabled';
  db.prepare('UPDATE users SET status=?, updated_at=? WHERE id=?').run(status, now(), u.id);
  logAct(req, 'user.status', `${u.name} ${status === 'active' ? 'diaktifkan' : 'dinonaktifkan'}`);
  res.json({ ok: true, status });
}));

app.delete('/api/users/:id', auth, superOnly, h((req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(req.params.id);
  if (!u) return bad(res, 'Pengguna tidak ditemukan', 404);
  if (u.id === req.user.id) return bad(res, 'Tidak dapat menghapus akun sendiri', 409);
  if (u.sys_role === 'super') return bad(res, 'Super Admin tidak dapat dihapus', 409);
  db.prepare('DELETE FROM users WHERE id=?').run(u.id);
  logAct(req, 'user.delete', `Pengguna ${u.name} dihapus`);
  res.json({ ok: true });
}));

app.post('/api/users/:id/reset-password', auth, superOnly, h((req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(req.params.id);
  if (!u) return bad(res, 'Pengguna tidak ditemukan', 404);
  const tmp = 'tmp-' + crypto.randomBytes(4).toString('hex');
  db.prepare('UPDATE users SET password_hash=?, updated_at=? WHERE id=?').run(bcrypt.hashSync(tmp, 10), now(), u.id);
  logAct(req, 'user.pass', `Password ${u.name} direset oleh admin`);
  res.json({ temp_password: tmp });  /* produksi: kirim via email, jangan di-response */
}));

/* ---------- penugasan akses per aplikasi ---------- */
app.get('/api/users/:id/applications', auth, h((req, res) => {
  if (!isSuper(req.user) && req.user.id !== req.params.id) return bad(res, '403 Forbidden', 403);
  const rows = db.prepare(`
    SELECT ua.application_id, ua.role_id, ua.status, a.name app_name, a.code, r.name role_name
    FROM user_applications ua
    JOIN applications a ON a.id = ua.application_id
    LEFT JOIN roles r ON r.id = ua.role_id
    WHERE ua.user_id = ?`).all(req.params.id);
  res.json({ grants: rows });
}));

app.post('/api/users/:id/applications', auth, superOnly, h((req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(req.params.id);
  if (!u) return bad(res, 'Pengguna tidak ditemukan', 404);
  const { application_id, role_id } = req.body;
  const appRow = db.prepare('SELECT * FROM applications WHERE id=?').get(application_id);
  if (!appRow) return bad(res, 'Aplikasi tidak ditemukan', 404);
  const role = db.prepare('SELECT * FROM roles WHERE id=? AND application_id=?').get(role_id, application_id);
  if (!role) return bad(res, 'Role tidak valid untuk aplikasi ini', 400);

  const ex = db.prepare('SELECT * FROM user_applications WHERE user_id=? AND application_id=?').get(u.id, application_id);
  if (ex) {
    db.prepare('UPDATE user_applications SET role_id=?, status=?, updated_at=? WHERE id=?').run(role_id, 'active', now(), ex.id);
    logAct(req, 'access.assign', `Role ${u.name} di ${appRow.name} diubah menjadi ${role.name}`, application_id);
    return res.json({ ok: true, updated: true });
  }
  db.prepare('INSERT INTO user_applications(id,user_id,application_id,role_id,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)')
    .run(uid('ua'), u.id, application_id, role_id, 'active', now(), now());
  logAct(req, 'access.assign', `${u.name} diberi akses ${appRow.name} sebagai ${role.name}`, application_id);
  res.status(201).json({ ok: true });
}));

app.delete('/api/users/:id/applications/:applicationId', auth, superOnly, h((req, res) => {
  const ex = db.prepare('SELECT * FROM user_applications WHERE user_id=? AND application_id=?').get(req.params.id, req.params.applicationId);
  if (!ex) return bad(res, 'Penugasan tidak ditemukan', 404);
  const appRow = db.prepare('SELECT * FROM applications WHERE id=?').get(req.params.applicationId);
  db.prepare('DELETE FROM user_applications WHERE id=?').run(ex.id);
  logAct(req, 'access.assign', `Akses ${uName(req.params.id)} pada ${appRow ? appRow.name : ''} dicabut`, req.params.applicationId);
  res.json({ ok: true });
}));
function uName(id) { const u = db.prepare('SELECT name FROM users WHERE id=?').get(id); return u ? u.name : '?'; }

/* =====================================================
   ROLES & PERMISSIONS (MD-01 §20)
===================================================== */
app.get('/api/roles', auth, h((req, res) => {
  const appId = req.query.application_id;
  let rows;
  if (appId) {
    rows = db.prepare(`
      SELECT r.*, (SELECT COUNT(*) FROM role_permissions rp WHERE rp.role_id=r.id) perm_count,
             (SELECT COUNT(*) FROM user_applications ua WHERE ua.role_id=r.id) user_count
      FROM roles r WHERE r.application_id=? ORDER BY r.name`).all(appId);
  } else {
    rows = db.prepare(`
      SELECT r.*, a.name app_name,
        (SELECT COUNT(*) FROM role_permissions rp WHERE rp.role_id=r.id) perm_count
      FROM roles r JOIN applications a ON a.id=r.application_id ORDER BY a.display_order, r.name`).all();
  }
  res.json({ roles: rows });
}));

app.post('/api/roles', auth, superOnly, h((req, res) => {
  const { application_id } = req.body;
  const name = String(req.body.name || '').trim();
  if (!application_id || !name) return bad(res, 'application_id dan nama role wajib diisi');
  if (!db.prepare('SELECT 1 FROM applications WHERE id=?').get(application_id)) return bad(res, 'Aplikasi tidak ditemukan', 404);
  if (db.prepare('SELECT 1 FROM roles WHERE application_id=? AND lower(name)=lower(?)').get(application_id, name)) return bad(res, 'Role dengan nama itu sudah ada', 409);
  const id = uid('r');
  db.prepare('INSERT INTO roles(id,application_id,name,description,created_at) VALUES(?,?,?,?,?)')
    .run(id, application_id, name, String(req.body.description || '—'), now());
  logAct(req, 'role.create', `Role ${name} dibuat pada ${uApp(application_id)}`, application_id);
  res.status(201).json({ id });
}));

app.delete('/api/roles/:id', auth, superOnly, h((req, res) => {
  const r = db.prepare('SELECT * FROM roles WHERE id=?').get(req.params.id);
  if (!r) return bad(res, 'Role tidak ditemukan', 404);
  const used = db.prepare('SELECT COUNT(*) n FROM user_applications WHERE role_id=?').get(r.id).n;
  if (used > 0) return bad(res, `Role masih dipakai ${used} pengguna — cabut dulu penugasannya`, 409);
  db.prepare('DELETE FROM roles WHERE id=?').run(r.id);
  logAct(req, 'role.delete', `Role ${r.name} dihapus dari ${uApp(r.application_id)}`, r.application_id);
  res.json({ ok: true });
}));

app.get('/api/permissions', auth, h((req, res) => {
  const appId = req.query.application_id;
  if (!appId) return bad(res, 'application_id wajib');
  if (!isSuper(req.user) && !hasAppAccess(req.user.id, appId)) return bad(res, '403 Forbidden', 403);
  res.json({ permissions: db.prepare('SELECT * FROM permissions WHERE application_id=? ORDER BY code').all(appId) });
}));

app.post('/api/permissions', auth, superOnly, h((req, res) => {
  const { application_id, code } = req.body;
  const c = String(code || '').trim().toLowerCase();
  if (!application_id || !/^[a-z0-9]+\.[a-z0-9]+$/.test(c)) return bad(res, 'Format kode: modul.aksi (mis. order.export)');
  if (db.prepare('SELECT 1 FROM permissions WHERE application_id=? AND code=?').get(application_id, c)) return bad(res, 'Kode permission sudah ada', 409);
  const id = uid('p');
  db.prepare('INSERT INTO permissions(id,application_id,code,name) VALUES(?,?,?,?)')
    .run(id, application_id, c, String(req.body.name || c));
  logAct(req, 'perm.create', `Permission ${c} ditambahkan pada ${uApp(application_id)}`, application_id);
  res.status(201).json({ id });
}));

/* sinkronisasi checkbox permission pada sebuah role */
app.put('/api/roles/:id/permissions', auth, superOnly, h((req, res) => {
  const r = db.prepare('SELECT * FROM roles WHERE id=?').get(req.params.id);
  if (!r) return bad(res, 'Role tidak ditemukan', 404);
  const ids = Array.isArray(req.body.permission_ids) ? req.body.permission_ids : null;
  if (!ids) return bad(res, 'permission_ids harus berupa array');
  const valid = db.prepare('SELECT id FROM permissions WHERE application_id=?').all(r.application_id).map(x => x.id);
  const clean = ids.filter(i => valid.includes(i));
  const tx = db.transaction(() => {
    db.prepare('DELETE FROM role_permissions WHERE role_id=?').run(r.id);
    clean.forEach(pid => db.prepare('INSERT INTO role_permissions(role_id,permission_id) VALUES(?,?)').run(r.id, pid));
  });
  tx();
  logAct(req, 'perm.update', `Permission role ${r.name} diperbarui (${clean.length} permission)`, r.application_id);
  res.json({ ok: true, count: clean.length });
}));

function uApp(id) { const a = db.prepare('SELECT name FROM applications WHERE id=?').get(id); return a ? a.name : '?'; }

/* =====================================================
   ACTIVITY LOGS
===================================================== */
app.get('/api/logs', auth, h((req, res) => {
  const limit = Math.min(+req.query.limit || 100, 400);
  let rows;
  if (isSuper(req.user)) {
    rows = req.query.action && req.query.action !== 'all'
      ? db.prepare('SELECT * FROM activity_logs WHERE action=? ORDER BY created_at DESC LIMIT ?').all(req.query.action, limit)
      : db.prepare('SELECT * FROM activity_logs ORDER BY created_at DESC LIMIT ?').all(limit);
  } else {
    rows = db.prepare('SELECT * FROM activity_logs WHERE user_id=? ORDER BY created_at DESC LIMIT ?').all(req.user.id, limit);
  }
  res.json({ logs: rows });
}));

/* =====================================================
   CATEGORIES
===================================================== */
app.get('/api/categories', auth, h((req, res) => {
  res.json({ categories: db.prepare('SELECT * FROM application_categories ORDER BY name').all() });
}));

/* =====================================================
   SSO HANDOFF (MD-01 §18)
===================================================== */
app.post('/api/sso/token', auth, requireAppAccess('body'), h((req, res) => {
  const a = req.appRow;
  if (a.status !== 'active') return bad(res, 'Aplikasi sedang dinonaktifkan', 409);
  if (!isSuper(req.user) && !hasPerm(req.user.id, a.id, 'dashboard.view')) return bad(res, '403 Forbidden — tidak ada permission pada aplikasi ini', 403);
  const ua = db.prepare(`SELECT * FROM user_applications WHERE user_id=? AND application_id=? AND status='active'`).get(req.user.id, a.id);
  const token = jwt.sign(
    { app: a.code, user: req.user.email, role: ua ? ua.role_id : null },
    SECRET, { expiresIn: '5m', audience: 'tarmoc-app' }
  );
  logAct(req, 'app.open', `${req.user.name} membuka ${a.name}${a.url ? ' → ' + a.url.replace(/^https?:\/\//, '') : ''}`, a.id);
  res.json({ token, url: a.url ? a.url + (a.url.includes('?') ? '&' : '?') + 'sso_token=' + token + '&from=tarmoc' : null, expires_in: 300 });
}));

/* endpoint verifikasi — dipakai aplikasi tujuan untuk memvalidasi token */
app.get('/api/sso/verify', h((req, res) => {
  try {
    const p = jwt.verify(String(req.query.token || ''), SECRET, { audience: 'tarmoc-app' });
    const appRow = db.prepare('SELECT id,name,code FROM applications WHERE code=?').get(p.app);
    const user = db.prepare('SELECT id,name,email FROM users WHERE email=?').get(p.user);
    const role = p.role ? db.prepare('SELECT id,name FROM roles WHERE id=?').get(p.role) : null;
    res.json({ valid: true, application: appRow, user, role, expires_at: p.exp * 1000 });
  } catch (e) {
    res.status(401).json({ valid: false, error: 'Token tidak valid atau kedaluwarsa' });
  }
}));

/* ---------- health & static ---------- */
app.get('/api/health', (req, res) => res.json({ ok: true, service: 'tarmoc-api', time: now() }));

app.delete('/api/logs', auth, superOnly, h((req, res) => {
  db.prepare('DELETE FROM activity_logs').run();
  logAct(req, 'logs.clear', `Log aktivitas dibersihkan oleh ${req.user.name}`);
  res.json({ ok: true });
}));
/* [PATCH] kirim pemetaan permission sebuah role — dipakai matriks frontend */
app.get('/api/roles/:id/permissions', auth, h((req, res) => {
  const r = db.prepare('SELECT * FROM roles WHERE id=?').get(req.params.id);
  if (!r) return bad(res, 'Role tidak ditemukan', 404);
  if (!isSuper(req.user) && !hasAppAccess(req.user.id, r.application_id)) return bad(res, '403 Forbidden', 403);
  res.json({ permission_ids: db.prepare('SELECT permission_id FROM role_permissions WHERE role_id=?').all(r.id).map(x => x.permission_id) });
}));

app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => {
  const p = path.join(__dirname, 'public', 'index.html');
  if (fs.existsSync(p)) return res.sendFile(p);
  res.type('html').send('<body style="font-family:monospace;background:#161510;color:#F2C10E;padding:40px"><h1>TARMOC API ✔ berjalan</h1><p>Letakkan <b>index.html</b> frontend di folder <code>public/</code> untuk memuat UI.</p></body>');
});

app.use('/api', (req, res) => res.status(404).json({ error: 'Endpoint tidak ditemukan' }));

app.listen(PORT, () => {
  console.log(`✔ TARMOC API berjalan di http://localhost:${PORT}  [${NODE_ENV}]`);
  console.log(`  DB: ${DB_PATH}`);
});
