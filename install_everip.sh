#!/usr/bin/env bash
set -euo pipefail

APP_NAME="everip"
APP_DIR="/opt/${APP_NAME}"
SERVICE_NAME="${APP_NAME}.service"
BIN_CTL="/usr/local/bin/everipctl"

# =================== 公共函数 ===================
detect_ipv4() {
  local ip=""
  ip=$(curl -fsSL -4 https://ifconfig.me 2>/dev/null || true)
  [ -z "$ip" ] && ip=$(curl -fsSL -4 https://ipinfo.io/ip 2>/dev/null || true)
  if [ -z "$ip" ] && command -v dig >/dev/null 2>&1; then
    ip=$(dig +short myip.opendns.com @resolver1.opendns.com 2>/dev/null | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n1)
  fi
  [ -z "$ip" ] && ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -n1)
  echo "$ip"
}

confirm() {
  read -r -p "${1:-Are you sure?} [y/N]: " ans
  case "$ans" in [yY][eE][sS]|[yY]) return 0 ;; *) return 1 ;; esac
}

stop_disable_service() {
  if systemctl is-active --quiet "$SERVICE_NAME"; then
    sudo systemctl stop "$SERVICE_NAME" || true
  fi
  if systemctl is-enabled --quiet "$SERVICE_NAME"; then
    sudo systemctl disable "$SERVICE_NAME" || true
  fi
}

remove_everything() {
  echo "[*] Stopping and disabling service..."
  stop_disable_service
  echo "[*] Removing systemd unit..."
  sudo rm -f "/etc/systemd/system/${SERVICE_NAME}" || true
  sudo systemctl daemon-reload || true
  echo "[*] Removing app directory..."
  sudo rm -rf "$APP_DIR" || true
  echo "[*] Removing user 'everip' (if exists)..."
  if id -u everip >/dev/null 2>&1; then
    sudo userdel -r everip 2>/dev/null || true
  fi
  echo "[*] Removing control command ${BIN_CTL}..."
  sudo rm -f "${BIN_CTL}" || true
  echo "✅ EverIP has been completely removed."
}

# =================== 卸载入口（脚本参数） ===================
if [[ "${1:-}" == "--uninstall" ]]; then
  echo "You are about to COMPLETELY remove EverIP:"
  echo " - Stop & disable service"
  echo " - Remove systemd unit"
  echo " - Delete ${APP_DIR}"
  echo " - Delete user 'everip'"
  echo " - Delete ${BIN_CTL}"
  confirm "Proceed" && remove_everything || echo "Canceled."
  exit 0
fi

# =================== 安装参数（可用环境变量覆盖） ===================
USERNAME="${EVERIP_USER:-everip}"
PASSWORD="${EVERIP_PASS:-}"
PORT="${EVERIP_PORT:-2080}"
ALLOW_CIDRS="${EVERIP_ALLOW_CIDRS:-0.0.0.0/0,::/0}"   # 安装后建议改为你的出口IP
OUT_BIND_IP="${EVERIP_OUT_BIND_IP:-}"
OUT_IFACE="${EVERIP_OUT_IFACE:-}"
PUBLIC_HOST="${EVERIP_PUBLIC_IP:-}"                  # 可填固定域名；留空自动探测IPv4

# 强密码
if [ -z "$PASSWORD" ]; then
  if command -v openssl >/dev/null 2>&1; then
    PASSWORD="$(openssl rand -hex 16)"
  else
    PASSWORD="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  fi
fi

# python3
if ! command -v python3 >/dev/null 2>&1; then
  echo "[*] python3 not found, installing..."
  if command -v apt >/dev/null 2>&1; then
    sudo apt update && sudo apt install -y python3
  elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y python3
  elif command -v yum >/dev/null 2>&1; then
    sudo yum install -y python3
  else
    echo "[-] Please install python3 and rerun."; exit 1
  fi
fi

# 自动探测公网主机名/IP
if [ -z "$PUBLIC_HOST" ]; then
  PUBLIC_HOST="$(detect_ipv4)"
  if [ -z "$PUBLIC_HOST" ]; then
    read -rp "请输入 VPS 公网 IPv4 或域名: " PUBLIC_HOST
  fi
fi

# 系统用户
if ! id -u everip >/dev/null 2>&1; then
  sudo useradd --system --no-create-home --shell /usr/sbin/nologin everip || true
fi

# 目录/配置
sudo mkdir -p "$APP_DIR"
sudo chown root:root "$APP_DIR"
sudo chmod 755 "$APP_DIR"

IFS=',' read -r -a CIDRS_ARR <<< "$ALLOW_CIDRS"
OUT_BIND_IP_JSON="null"; [ -n "$OUT_BIND_IP" ] && OUT_BIND_IP_JSON="\"$OUT_BIND_IP\""
OUT_IFACE_JSON="null";   [ -n "$OUT_IFACE" ]   && OUT_IFACE_JSON="\"$OUT_IFACE\""

ALLOW_JSON=""
for c in "${CIDRS_ARR[@]}"; do
  c_trim="$(echo "$c" | xargs)"; [ -z "$c_trim" ] && continue
  ALLOW_JSON="${ALLOW_JSON:+$ALLOW_JSON, }\"${c_trim}\""
done

sudo tee "${APP_DIR}/config.json" >/dev/null <<JSON
{
  "bind_host": "0.0.0.0",
  "bind_port": ${PORT},
  "auth": { "enabled": true, "username": "${USERNAME}", "password": "${PASSWORD}" },
  "allow_cidrs": [ ${ALLOW_JSON} ],
  "timeouts": { "handshake_seconds": 10, "idle_seconds": 900, "dns_seconds": 10 },
  "limits": { "max_clients": 2000, "recv_buffer": 65536, "send_buffer": 65536 },
  "log_level": "INFO",
  "outgoing": { "bind_ip": ${OUT_BIND_IP_JSON}, "interface": ${OUT_IFACE_JSON} }
}
JSON

# EverIP 主程序
sudo tee "${APP_DIR}/everip.py" >/dev/null <<'PY'
#!/usr/bin/env python3
import asyncio, ipaddress, json, logging, os, socket
SOCKS_VERSION=5; METHOD_NOAUTH=0x00; METHOD_USERPASS=0x02; METHOD_REJECT=0xFF
CMD_CONNECT=0x01; ATYP_IPV4=0x01; ATYP_DOMAIN=0x03; ATYP_IPV6=0x04; REP_SUCC=0x00
class Config:
  def __init__(self,d):
    self.bind_host=d["bind_host"]; self.bind_port=int(d["bind_port"])
    self.auth_enabled=bool(d["auth"]["enabled"]); self.username=d["auth"].get("username","")
    self.password=d["auth"].get("password",""); self.allow_cidrs=[ipaddress.ip_network(c, strict=False) for c in d["allow_cidrs"]]
    t=d["timeouts"]; self.handshake_timeout=int(t["handshake_seconds"]); self.idle_timeout=int(t["idle_seconds"]); self.dns_timeout=int(t["dns_seconds"])
    l=d["limits"]; self.max_clients=int(l["max_clients"]); self.recv_buffer=int(l["recv_buffer"]); self.send_buffer=int(l["send_buffer"])
    self.log_level=d.get("log_level","INFO").upper(); o=d["outgoing"]; self.out_bind_ip=o.get("bind_ip"); self.out_iface=o.get("interface")
class LimitCounter: 
  def __init__(self,m): self.sem=asyncio.Semaphore(m)
  async def __aenter__(self): await self.sem.acquire()
  async def __aexit__(self,a,b,c): self.sem.release()
def client_ip_allowed(peer,cidrs):
  try: ip=ipaddress.ip_address(peer); return any(ip in net for net in cidrs)
  except: return False
async def open_remote(host,port,cfg):
  try:
    infos=await asyncio.wait_for(asyncio.get_event_loop().getaddrinfo(host,port,type=socket.SOCK_STREAM),timeout=cfg.dns_timeout)
    af,st,pr,_,sa=infos[0]; sock=socket.socket(af,st,pr)
    if cfg.out_bind_ip: sock.bind((cfg.out_bind_ip,0))
    if cfg.out_iface and hasattr(socket,"SO_BINDTODEVICE"):
      try: sock.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,cfg.out_iface.encode())
      except OSError: logging.warning("SO_BINDTODEVICE failed")
    sock.setblocking(False); await asyncio.get_event_loop().sock_connect(sock,sa)
    return await asyncio.open_connection(sock=sock)
  except Exception as e: logging.debug(f"open_remote error: {e}"); return None
async def relay(c_r,c_w,r_r,r_w,cfg):
  async def pipe(src,dst):
    try:
      while True:
        data=await asyncio.wait_for(src.read(cfg.recv_buffer),timeout=cfg.idle_timeout)
        if not data: break
        dst.write(data); await dst.drain()
    except: pass
    finally:
      try: dst.close()
      except: pass
  await asyncio.gather(pipe(c_r,r_w),pipe(r_r,c_w))
async def http_connect(reader,writer,cfg):
  line=await asyncio.wait_for(reader.readline(),timeout=cfg.handshake_timeout)
  if not line: return
  header=line.decode("latin1","ignore").strip()
  try: method,target,_=header.split(" ",2)
  except: writer.close(); return
  while True:
    h=await asyncio.wait_for(reader.readline(),timeout=cfg.handshake_timeout)
    if not h or h in (b"\r\n",b"\n"): break
  if method.upper()!="CONNECT": writer.write(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n"); await writer.drain(); return
  if ":" not in target: writer.close(); return
  host,port=target.rsplit(":",1); port=int(port)
  remote=await open_remote(host,port,cfg)
  if not remote: writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n"); await writer.drain(); return
  r_reader,r_writer=remote; writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n"); await writer.drain()
  await relay(reader,writer,r_reader,r_writer,cfg)
async def socks5(reader,writer,cfg):
  try: data=await asyncio.wait_for(reader.readexactly(2),timeout=cfg.handshake_timeout)
  except: writer.close(); return
  ver,nmethods=data[0],data[1]
  if ver!=SOCKS_VERSION: writer.close(); return
  methods=await reader.readexactly(nmethods)
  if cfg.auth_enabled: chosen=METHOD_USERPASS if METHOD_USERPASS in methods else METHOD_REJECT
  else: chosen=METHOD_NOAUTH if METHOD_NOAUTH in methods else METHOD_REJECT
  writer.write(bytes([SOCKS_VERSION,chosen])); await writer.drain()
  if chosen==METHOD_REJECT: writer.close(); return
  if chosen==METHOD_USERPASS:
    ver=(await reader.readexactly(1))[0]; ulen=(await reader.readexactly(1))[0]; uname=(await reader.readexactly(ulen)).decode()
    plen=(await reader.readexactly(1))[0]; passwd=(await reader.readexactly(plen)).decode()
    if not (uname==cfg.username and passwd==cfg.password): writer.write(b"\x01\x01"); await writer.drain(); writer.close(); return
    writer.write(b"\x01\x00"); await writer.drain()
  ver,cmd,_,atyp=(await reader.readexactly(4))
  if ver!=SOCKS_VERSION or cmd!=0x01: writer.close(); return
  if atyp==0x01: host=socket.inet_ntoa(await reader.readexactly(4))
  elif atyp==0x03: ln=(await reader.readexactly(1))[0]; host=(await reader.readexactly(ln)).decode()
  elif atyp==0x04: host=socket.inet_ntop(socket.AF_INET6,await reader.readexactly(16))
  else: writer.close(); return
  port=int.from_bytes(await reader.readexactly(2),"big")
  remote=await open_remote(host,port,cfg)
  if not remote: writer.close(); return
  r_reader,r_writer=remote
  rep=bytes([SOCKS_VERSION,REP_SUCC,0,0x01])+socket.inet_aton("0.0.0.0")+(0).to_bytes(2,"big")
  writer.write(rep); await writer.drain()
  await relay(reader,writer,r_reader,r_writer,cfg)
async def handle(reader,writer,cfg,limiter):
  peer=writer.get_extra_info("peername")
  if peer and not client_ip_allowed(peer[0],cfg.allow_cidrs): writer.close(); return
  try: b=await asyncio.wait_for(reader.readexactly(1),timeout=cfg.handshake_timeout)
  except: writer.close(); return
  reader._buffer=b+reader._buffer
  if b==b"\x05": await socks5(reader,writer,cfg)
  else: await http_connect(reader,writer,cfg)
async def main():
  cfg_path=os.environ.get("EVERIP_CONFIG",os.path.join(os.path.dirname(__file__),"config.json"))
  cfg=Config(json.load(open(cfg_path,"r")))
  logging.basicConfig(level=getattr(logging,cfg.log_level,logging.INFO),format="%(asctime)s [%(levelname)s] %(message)s")
  limiter=LimitCounter(cfg.max_clients)
  async def limited(r,w): 
    async with limiter: await handle(r,w,cfg,limiter)
  server=await asyncio.start_server(limited,host=cfg.bind_host,port=cfg.bind_port)
  logging.info("EverIP started @ %s",", ".join(str(s.getsockname()) for s in server.sockets))
  async with server: await server.serve_forever()
if __name__=="__main__":
  try: asyncio.run(main())
  except KeyboardInterrupt: pass
PY

sudo chmod +x "${APP_DIR}/everip.py"
sudo chown -R everip:everip "${APP_DIR}"

# systemd
sudo tee "/etc/systemd/system/${SERVICE_NAME}" >/dev/null <<UNIT
[Unit]
Description=EverIP - Static IP Proxy (SOCKS5 + HTTP CONNECT)
After=network.target

[Service]
User=everip
WorkingDirectory=${APP_DIR}
ExecStart=/usr/bin/env python3 ${APP_DIR}/everip.py
Restart=always
RestartSec=2s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now "${SERVICE_NAME}"

# 分享信息
SOCKS_URI="socks://${USERNAME}:${PASSWORD}@${PUBLIC_HOST}:${PORT}"
HTTP_URI="http://${USERNAME}:${PASSWORD}@${PUBLIC_HOST}:${PORT}"
CLASH_NODE="  - name: EverIP
    type: socks5
    server: ${PUBLIC_HOST}
    port: ${PORT}
    username: ${USERNAME}
    password: ${PASSWORD}
    udp: true"

sudo tee "${APP_DIR}/share.txt" >/dev/null <<EOF
EverIP is running.

v2rayN (copy one of these):
${SOCKS_URI}
${HTTP_URI}

Clash node (YAML snippet):
${CLASH_NODE}

Config:  ${APP_DIR}/config.json
Service: systemctl status ${SERVICE_NAME}
EOF

echo "==========================================="
echo "✅ EverIP 已安装并启动"
echo "Address : ${PUBLIC_HOST}:${PORT}"
echo "Protocol: SOCKS5 / HTTP CONNECT"
echo "User    : ${USERNAME}"
echo "Pass    : ${PASSWORD}"
echo "-------------------------------------------"
echo "v2rayN (复制其一)："
echo "  ${SOCKS_URI}"
echo "  ${HTTP_URI}"
echo "-------------------------------------------"
echo "Clash 片段："
echo "${CLASH_NODE}"
echo "-------------------------------------------"
echo "已保存到: ${APP_DIR}/share.txt"
echo "安全提示：默认 allow_cidrs = ${ALLOW_CIDRS}"
echo "建议改成你的出口IP后执行： sudo systemctl restart ${SERVICE_NAME}"
echo "==========================================="

# 安装管理命令 everipctl
sudo tee "${BIN_CTL}" >/dev/null <<'SH'
#!/usr/bin/env bash
set -euo pipefail
APP_NAME="everip"
APP_DIR="/opt/${APP_NAME}"
SERVICE_NAME="${APP_NAME}.service"

usage() {
  cat <<U
everipctl - manage EverIP
Usage: everipctl {status|start|stop|restart|show|uninstall}
  status    Show systemd status
  start     Start service
  stop      Stop service
  restart   Restart service
  show      Print v2rayN links and Clash snippet
  uninstall Completely remove EverIP (files, user, service)
U
}

confirm() { read -r -p "${1:-Proceed?} [y/N]: " a; case "$a" in [yY]* ) return 0;; * ) return 1;; esac; }

case "${1:-}" in
  status)   systemctl status "$SERVICE_NAME" ;;
  start)    sudo systemctl start "$SERVICE_NAME" ;;
  stop)     sudo systemctl stop "$SERVICE_NAME" ;;
  restart)  sudo systemctl restart "$SERVICE_NAME" ;;
  show)
    if [ -f "${APP_DIR}/share.txt" ]; then cat "${APP_DIR}/share.txt"; else echo "share.txt not found."; fi
    ;;
  uninstall)
    echo "This will STOP & DISABLE service, REMOVE unit, DELETE ${APP_DIR}, DELETE user 'everip', and remove this tool."
    confirm "Uninstall EverIP?" && {
      sudo systemctl stop "$SERVICE_NAME" 2>/dev/null || true
      sudo systemctl disable "$SERVICE_NAME" 2>/dev/null || true
      sudo rm -f "/etc/systemd/system/${SERVICE_NAME}" || true
      sudo systemctl daemon-reload || true
      sudo rm -rf "${APP_DIR}" || true
      if id -u everip >/dev/null 2>&1; then sudo userdel -r everip 2>/dev/null || true; fi
      sudo rm -f "$(readlink -f "$0")" || true
      echo "EverIP completely removed."
    } || echo "Canceled."
    ;;
  *) usage ;;
esac
SH
sudo chmod +x "${BIN_CTL}"

# 可选：二维码（若系统有 qrencode）
if command -v qrencode >/dev/null 2>&1; then
  echo "[二维码] v2rayN socks://"
  echo "${SOCKS_URI}" | qrencode -t ansiutf8
fi
