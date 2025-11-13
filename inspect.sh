# 当前 TMPDIR（macOS 常见差异来源）
echo "TMPDIR=$TMPDIR"

# 当前 user
whoami

# 是否存在 /tmp/screen（我们希望用这个固定目录）
ls -ld /tmp/screen || echo "/tmp/screen not exist"

# 是否存在 macOS /private/tmp/screen
ls -ld /private/tmp/screen || true

# 列出 /var/folders 下所有 .screen 目录（可能有多个）
sudo find /var/folders -type d -name ".screen" -maxdepth 6 2>/dev/null || true

# 列出当前所有 screen 进程（如果有）
ps aux | egrep '[s]creen' || true

# 列出 geth 之类的子进程（确认那些 node 还在）
ps aux | egrep 'geth|reth' || true
