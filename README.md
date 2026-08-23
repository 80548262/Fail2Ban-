# Fail2Ban + UFW

独立安装 Fail2Ban 并启用 UFW。脚本会自动识别 SSH 端口，并放行 SSH、80/tcp 和 443/tcp：

```bash
curl -fsSL https://raw.githubusercontent.com/80548262/Fail2Ban-/refs/heads/main/Fail2Ban.sh | bash
```

默认 SSH 防护策略：10 分钟内认证失败 5 次后封禁 1 小时。

带 GoEdge 域名屏蔽的旧版本：

```bash
curl -fsSL https://raw.githubusercontent.com/80548262/Fail2Ban-/refs/heads/main/Fail2Ban-stop-goedge.sh | bash
```

# 其他脚本

```bash
curl -fsSL https://raw.githubusercontent.com/80548262/Fail2Ban-/refs/heads/main/speed_download.sh | bash
curl -fsSL https://raw.githubusercontent.com/80548262/Fail2Ban-/refs/heads/main/install_img_url_probe.sh | bash
bash <(curl -fsSL https://raw.githubusercontent.com/80548262/Fail2Ban-/refs/heads/main/vps-net-optimize.sh)
```

优化之后重启vps
