/* Hapus semua user non-super + kosongkan log — jalankan SETELAH server pertama
   kali start (agar tarmoc.db terbentuk).  node scripts/clean-demo.js */
const path=require('path'), fs=require('fs');
const dbPath=path.join(__dirname,'..','tarmoc.db');
if(!fs.existsSync(dbPath)){console.error('tarmoc.db belum ada — jalankan server dulu: node server.js');process.exit(1)}
const db=require('better-sqlite3')(dbPath); db.pragma('foreign_keys=ON');
const u=db.prepare("DELETE FROM users WHERE sys_role<>'super'").run();
db.prepare('DELETE FROM activity_logs').run();
console.log(`✔ ${u.changes} user demo dihapus · log dikosongkan · tersisa super admin saja`);
