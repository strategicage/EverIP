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
