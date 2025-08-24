# 🌐 EverIP

> 🛡️ A lightweight, high-performance **Static IP Proxy** (SOCKS5 + HTTP CONNECT) that keeps your IP **fixed forever**.

[![GitHub stars](https://img.shields.io/github/stars/strategicage/EverIP?style=flat&logo=github)](https://github.com/strategicage/EverIP/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/strategicage/EverIP?style=flat&logo=github)](https://github.com/strategicage/EverIP/network/members)
[![License](https://img.shields.io/github/license/strategicage/EverIP)](LICENSE)

---

## ✨ Features

- 🔒 **Static IP Binding** – lock your outgoing IP, no more random rotations  
- 🔑 **Auth Support** – optional username/password authentication  
- 📋 **Access Control** – allowlist CIDRs to restrict usage  
- ⚡ **High Performance** – async I/O, 2000+ concurrent connections  
- 🌍 **Multi-Protocol** – SOCKS5 + HTTP CONNECT tunnel in one binary  
- 🛠️ **Easy Deployment** – one-line install, systemd auto-start  

---

## 🚀 Quick Start

### 1. Install
```bash
curl -fsSL https://raw.githubusercontent.com/strategicage/EverIP/main/install_everip.sh | bash

2. Default Credentials (auto-generated)

User: everip

Password: random (shown after installation)

Port: 2080

Configuration file: /opt/everip/config.json

🔍 Verify Your Fixed IP

Test your IP after connecting via EverIP:

curl -x socks5://everip:<password>@<your-vps-ip>:2080 https://ifconfig.me

📊 Use Cases

✅ Twitch / ChatGPT – avoid client errors caused by IP rotation

✅ Business Proxies – keep the same source IP for API whitelisting

✅ Privacy Layer – VPS IP only, no local leakage

🔐 Security Best Practices

EverIP defaults to authentication enabled, but we recommend:

Restrict access to your own IP:

sudo ufw allow from <your-home-ip> to any port 2080 proto tcp


Change the listening port (EVERIP_PORT=24823).

Rotate strong passwords regularly.

⚙️ Advanced Options

Set environment variables before install:

EVERIP_USER=myuser \
EVERIP_PASS=mypassword \
EVERIP_PORT=24823 \
EVERIP_ALLOW_CIDRS="1.2.3.4/32,2001:db8::/32" \
bash install_everip.sh


EVERIP_USER / EVERIP_PASS → auth credentials

EVERIP_PORT → listening port

EVERIP_ALLOW_CIDRS → restrict access by IP/CIDR

EVERIP_OUT_BIND_IP → bind to a specific outgoing IP

EVERIP_OUT_IFACE → bind to a specific interface

🛠️ Systemd Commands
sudo systemctl status everip
sudo systemctl restart everip
sudo journalctl -u everip -f

📜 License

MIT License © 2025 strategicage

⭐ If you find EverIP useful, please give it a star on GitHub!


---

# 📌 建议
1. 在仓库里放置：
   - `install_everip.sh`（一键安装脚本）  
   - `everip.py`（核心代码）  
   - `README.md`（上面这份）  
   - `LICENSE`（MIT）  
2. 可以再加一个 **demo 截图**（运行成功 + curl 验证），让用户更有信心。  
3. 后续可以加 GitHub Actions CI/CD（例如自动 lint/构建）。  
