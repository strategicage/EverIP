#!/usr/bin/env bash
set -euo pipefail

APP_NAME="everip"
APP_DIR="/opt/${APP_NAME}"
SERVICE_NAME="${APP_NAME}.service"

# ===== 可选：从环境变量传入 =====
USERNAME="${EVERIP_USER:-everip}"
PASSWORD="${EVERIP_PASS:-}"
PORT="${EVERIP_PORT:-2080}"
ALLOW_CIDRS="${EVERIP_ALLOW_CIDRS:-0.0.0.0/0,::/0}"   # 建议后续改成你的出口IP，见文末安全建议
OUT_BIND_IP="${EVERIP_OUT_BIND_IP:-}"                 # 多IP机器可指定一个出口IP，例如 1.2.3.4
OUT_IFACE="${EVERIP_OUT_IFACE:-}"                     # 指定网卡(需要root且内核支持)，例如 eth1

if [ -z "$PASSWORD" ]; then
  if command -v openssl >/dev/null 2>&1; then
    PASSWORD="$(openssl rand -hex 16)"
  else
    PASSWORD="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  fi
fi

# ===== 检查并安装 python3 =====
if ! command -v python3 >/dev/null 2>&1; then
  echo "[*] python3 未检测到，尝试安装..."
  if command -v apt >/dev/null 2>&1; then
    sudo apt update && sudo apt install -y python3
  elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y python3
  elif command -v yum >/dev/null 2>&1; then
    sudo yum install -y python3
  else
    echo "[-] 无法自动安装 python3，请手动安装后重试"; exit 1
  fi
fi

# ===== 创建系统用户（更安全）=====
if ! id -u everip >/dev/null 2>&1; then
  sudo useradd --system --no-create-home --shell /usr/sbin/nologin everip || true
fi

# ===== 目录与配置 =====
sudo mkdir -p "$APP_DIR"
sudo chown root:root "$APP_DIR"
sudo chmod 755 "$APP_DIR"

IFS=',' read -r -a CIDRS_ARR <<< "$ALLOW_CIDRS"

# 生成 JSON 片段
OUT_BIND_IP_JSON="null"
[ -n "$OUT_BIND_IP" ] && OUT_BIND_IP_JSON="\"$OUT_BIND_IP\""
OUT_IFACE_JSON="null"
[ -n "$OUT_IFACE" ] && OUT_IFACE_JSON="\"$OUT_IFACE\""

ALLOW_JSON=""
for c in "${CIDRS_ARR[@]}"; do
  c_trim="$(echo "$c" | xargs)"
  [ -z "$c_trim" ] && continue
  if [ -n "$ALLOW_JSON" ]; then
    ALLOW_JSON="${ALLOW_JSON}, \"${c_trim}\""
  else
    ALLOW_JSON="\"${c_trim}\""
  fi
done

sudo tee "${APP_DIR}/config.json" >/dev/null <<JSON
{
  "bind_host": "0.0.0.0",
  "bind_port": ${PORT},

  "auth": {
    "enabled": true,
    "username": "${USERNAME}",
    "password": "${PASSWORD}"
  },

  "allow_cidrs": [ ${ALLOW_JSON} ],

  "timeouts": {
    "handshake_seconds": 10,
    "idle_seconds": 900,
    "dns_seconds": 10
  },

  "limits": {
    "max_clients": 2000,
    "recv_buffer": 65536,
    "send_buffer": 65536
  },

  "log_level": "INFO",

  "outgoing": {
    "bind_ip": ${OUT_BIND_IP_JSON},
    "interface": ${OUT_IFACE_JSON}
  }
}
JSON

# ===== EverIP 主程序 =====
sudo tee "${APP_DIR}/everip.py" >/dev/null <<'PY'
#!/usr/bin/env python3
import asyncio, ipaddress, json, logging, os, socket
from typing import Optional, Tuple

SOCKS_VERSION = 5
METHOD_NOAUTH = 0x00
METHOD_USERPASS = 0x02
METHOD_REJECT  = 0xFF
CMD_CONNECT    = 0x01
ATYP_IPV4      = 0x01
ATYP_DOMAIN    = 0x03
ATYP_IPV6      = 0x04
REP_SUCC       = 0x00
REP_FAIL       = 0x01

class Config:
    def __init__(self, d: dict):
        self.bind_host = d["bind_host"]
        self.bind_port = int(d["bind_port"])
        self.auth_enabled = bool(d["auth"]["enabled"])
        self.username = d["auth"].get("username", "")
        self.password = d["auth"].get("password", "")
        self.allow_cidrs = [ipaddress.ip_network(c, strict=False) for c in d["allow_cidrs"]]
        self.handshake_timeout = int(d["timeouts"]["handshake_seconds"])
        self.idle_timeout = int(d["timeouts"]["idle_seconds"])
        self.dns_timeout = int(d["timeouts"]["dns_seconds"])
        self.max_clients = int(d["limits"]["max_clients"])
        self.recv_buffer = int(d["limits"]["recv_buffer"])
        self.send_buffer = int(d["limits"]["send_buffer"])
        self.log_level = d.get("log_level", "INFO").upper()
        self.out_bind_ip = d["outgoing"].get("bind_ip")
        self.out_iface = d["outgoing"].get("interface")

class LimitCounter:
    def __init__(self, max_clients: int):
        self.sem = asyncio.Semaphore(max_clients)
    async def __aenter__(self): await self.sem.acquire()
    async def __aexit__(self, exc_type, exc, tb): self.sem.release()

def client_ip_allowed(peer_ip: str, cidrs) -> bool:
    try:
        ip_obj = ipaddress.ip_address(peer_ip)
        return any(ip_obj in net for net in cidrs)
    except ValueError:
        return False

async def open_remote(host: str, port: int, cfg: Config):
    try:
        infos = await asyncio.wait_for(asyncio.get_event_loop().getaddrinfo(
            host, port, type=socket.SOCK_STREAM
        ), timeout=cfg.dns_timeout)
        af, socktype, proto, _, sa = infos[0]
        sock = socket.socket(af, socktype, proto)
        if cfg.out_bind_ip:
            sock.bind((cfg.out_bind_ip, 0))
        if cfg.out_iface and hasattr(socket, "SO_BINDTODEVICE"):
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, cfg.out_iface.encode())
            except OSError:
                logging.warning("SO_BINDTODEVICE 失败，可能需要 root 权限或不被支持")
        sock.setblocking(False)
        await asyncio.get_event_loop().sock_connect(sock, sa)
        r, w = await asyncio.open_connection(sock=sock)
        return r, w
    except Exception as e:
        logging.debug(f"open_remote error: {e}")
        return None

async def bidir_relay(c_r, c_w, r_r, r_w, cfg: Config):
    async def pipe(src, dst):
        try:
            while True:
                data = await asyncio.wait_for(src.read(cfg.recv_buffer), timeout=cfg.idle_timeout)
                if not data: break
                dst.write(data); await dst.drain()
        except Exception:
            pass
        finally:
            try: dst.close()
            except: pass
    await asyncio.gather(pipe(c_r, r_w), pipe(r_r, c_w))

async def http_connect_tunnel(reader, writer, cfg: Config):
    line = await asyncio.wait_for(reader.readline(), timeout=cfg.handshake_timeout)
    if not line: return
    header = line.decode("latin1", errors="ignore").strip()
    try:
        method, target, _ = header.split(" ", 2)
    except ValueError:
        writer.close(); return
    # 读完头
    while True:
        h = await asyncio.wait_for(reader.readline(), timeout=cfg.handshake_timeout)
        if not h or h in (b"\r\n", b"\n"): break
    if method.upper() != "CONNECT":
        writer.write(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n"); await writer.drain(); return
    if ":" not in target:
        writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n"); await writer.drain(); return
    host, port = target.rsplit(":", 1)
    port = int(port)
    remote = await open_remote(host, port, cfg)
    if not remote:
        writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n"); await writer.drain(); return
    r_reader, r_writer = remote
    writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n"); await writer.drain()
    await bidir_relay(reader, writer, r_reader, r_writer, cfg)

async def socks5_handler(reader, writer, cfg: Config):
    try:
        data = await asyncio.wait_for(reader.readexactly(2), timeout=cfg.handshake_timeout)
    except Exception:
        writer.close(); return
    ver, nmethods = data[0], data[1]
    if ver != SOCKS_VERSION: writer.close(); return
    methods = await reader.readexactly(nmethods)
    chosen = METHOD_NOAUTH
    if cfg.auth_enabled:
        chosen = METHOD_USERPASS if METHOD_USERPASS in methods else METHOD_REJECT
    else:
        chosen = METHOD_NOAUTH if METHOD_NOAUTH in methods else METHOD_REJECT
    writer.write(bytes([SOCKS_VERSION, chosen])); await writer.drain()
    if chosen == METHOD_REJECT: writer.close(); return

    if chosen == METHOD_USERPASS:
        ver = (await reader.readexactly(1))[0]
        if ver != 1: writer.close(); return
        ulen = (await reader.readexactly(1))[0]
        uname = (await reader.readexactly(ulen)).decode()
        plen = (await reader.readexactly(1))[0]
        passwd = (await reader.readexactly(plen)).decode()
        if not (uname == cfg.username and passwd == cfg.password):
            writer.write(b"\x01\x01"); await writer.drain(); writer.close(); return
        writer.write(b"\x01\x00"); await writer.drain()

    ver, cmd, _, atyp = (await reader.readexactly(4))
    if ver != SOCKS_VERSION or cmd != 0x01:
        writer.write(bytes([SOCKS_VERSION, 0x07, 0x00, ATYP_IPV4]) + socket.inet_aton("0.0.0.0") + (0).to_bytes(2,"big"))
        await writer.drain(); writer.close(); return

    if atyp == ATYP_IPV4:
        dst = await reader.readexactly(4); host = socket.inet_ntoa(dst)
    elif atyp == ATYP_DOMAIN:
        ln = (await reader.readexactly(1))[0]
        host = (await reader.readexactly(ln)).decode()
    elif atyp == ATYP_IPV6:
        dst = await reader.readexactly(16); host = socket.inet_ntop(socket.AF_INET6, dst)
    else:
        writer.close(); return
    port = int.from_bytes(await reader.readexactly(2), "big")

    remote = await open_remote(host, port, cfg)
    if not remote:
        writer.write(bytes([SOCKS_VERSION, 0x05, 0x00, ATYP_IPV4]) + socket.inet_aton("0.0.0.0") + (0).to_bytes(2,"big"))
        await writer.drain(); writer.close(); return
    r_reader, r_writer = remote

    rep = bytes([SOCKS_VERSION, REP_SUCC, 0x00, ATYP_IPV4]) + socket.inet_aton("0.0.0.0") + (0).to_bytes(2,"big")
    writer.write(rep); await writer.drain()
    await bidir_relay(reader, writer, r_reader, r_writer, cfg)

async def handle_client(reader, writer, cfg: Config, limiter: LimitCounter):
    peer = writer.get_extra_info("peername")
    peer_ip = peer[0] if peer else "unknown"
    if not client_ip_allowed(peer_ip, cfg.allow_cidrs):
        logging.warning(f"拒绝 {peer_ip} 不在 allow_cidrs")
        writer.close(); return

    try:
        peek = await asyncio.wait_for(reader.readexactly(1), timeout=cfg.handshake_timeout)
    except Exception:
        writer.close(); return
    # 将字节“塞回去”（依赖当前实现）
    reader._buffer = peek + reader._buffer  # noqa

    if peek == b"\x05":
        await socks5_handler(reader, writer, cfg)
    else:
        await http_connect_tunnel(reader, writer, cfg)

async def main():
    cfg_path = os.environ.get("EVERIP_CONFIG", os.path.join(os.path.dirname(__file__), "config.json"))
    with open(cfg_path, "r", encoding="utf-8") as f:
        cfg = Config(json.load(f))
    logging.basicConfig(level=getattr(logging, cfg.log_level, logging.INFO),
                        format="%(asctime)s [%(levelname)s] %(message)s")
    limiter = LimitCounter(cfg.max_clients)

    async def limited(reader, writer):
        async with limiter:
            await handle_client(reader, writer, cfg, limiter)

    server = await asyncio.start_server(limited, host=cfg.bind_host, port=cfg.bind_port)
    addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
    logging.info(f"EverIP started @ {addrs} (SOCKS5 + HTTP CONNECT)")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
PY

sudo chmod +x "${APP_DIR}/everip.py"
sudo chown -R everip:everip "${APP_DIR}"

# ===== systemd =====
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
# 需要绑定指定网卡时（outgoing.interface），改成 root 运行或加 Capability：
# User=root

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now "${SERVICE_NAME}"

echo "==========================================="
echo "✅ EverIP 已安装并启动"
echo "地址:   0.0.0.0:${PORT}"
echo "协议:   SOCKS5 / HTTP CONNECT"
echo "用户:   ${USERNAME}"
echo "密码:   ${PASSWORD}"
echo "配置:   ${APP_DIR}/config.json"
echo "服务:   systemctl status ${SERVICE_NAME}"
echo "==========================================="
echo "安全提示：默认 allow_cidrs 为 ${ALLOW_CIDRS}"
echo "建议改为你的出口IP后： sudo systemctl restart ${SERVICE_NAME}"
