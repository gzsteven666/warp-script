# WARP 一键脚本

使用 Cloudflare 官方 WARP 客户端，让 Google 流量自动走 WARP，解锁 Gemini、Play 商店等受限服务。

## 一键安装

```bash
bash <(curl -fsSL [https://raw.githubusercontent.com/gzsteven666/warp-script/main/warp.sh]
特性
✅ 自动安装 Cloudflare WARP 官方客户端
✅ 配置透明代理，Google 流量自动走 WARP
✅ 支持 Ubuntu/Debian/CentOS/RHEL/Rocky/AlmaLinux/Fedora
✅ 安装失败自动回滚，不留残留
✅ 非交互式安装，无需手动确认

管理命令
bash
warp status    # 查看状态
warp start     # 启动
warp stop      # 停止
warp restart   # 重启
warp test      # 测试 Google
warp ip        # 查看 IP
warp uninstall # 卸载

支持系统
系统	版本
Ubuntu	20.04 / 22.04 / 24.04
Debian	10 / 11 / 12
CentOS	7 / 8 / Stream
Rocky Linux	8 / 9
AlmaLinux	8 / 9
Fedora	38+
