#!/usr/bin/env bash
set -e; cd "$(dirname "$0")"
echo "== 1/3 install dependencies =="; npm install
echo "== 2/3 start via pm2 =="
command -v pm2 >/dev/null || { echo "pm2 belum ada: npm install -g pm2"; exit 1; }
pm2 start server.js --name tarmoc-api 2>/dev/null || pm2 restart tarmoc-api
echo "== 3/3 menunggu server siap =="
for i in $(seq 1 20); do curl -s -m1 http://localhost:3010/api/health | grep -q '"ok":true' && break; sleep 1; done
curl -s http://localhost:3010/api/health; echo
read -p "Hapus user demo (sisakan super admin saja)? [y/N] " a
[ "$a" = "y" ] && node scripts/clean-demo.js
echo "✔ siap → http://<IP-server>:3010  (login super admin / tarmoc123)"
