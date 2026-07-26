# WARP Script

在 Linux VPS 上安装 Cloudflare WARP，并独立控制 Google、Gemini 和
Netflix 的出口。

默认模式是 `google-all`：Google 与 Gemini 使用同一个 WARP 出口，避免
浏览器登录、验证和 Gemini 请求在原生 IP 与 WARP IP 之间跳变。ChatGPT、
OpenAI 和 Netflix 保持直连。

## 安装

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/gzsteven666/warp-script/main/warp.sh)
```

非交互安装：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/gzsteven666/warp-script/main/warp.sh) --install
```

脚本会自动检测以下 sing-box 配置：

- `/etc/v2ray-agent/sing-box/conf/config.json`
- `/etc/sing-box/config.json`
- `/usr/local/etc/sing-box/config.json`

非交互安装可指定模式：

```bash
WARP_ROUTING_MODE=google-all bash warp.sh --install
WARP_ROUTING_MODE=gemini-only bash warp.sh --install
WARP_ROUTING_MODE=direct bash warp.sh --install
```

## 管理命令

```text
warp status
warp test
warp ip
warp restart
warp update
warp upgrade
```

切换路由模式：

```bash
warp mode gemini-only
warp mode google-all
warp mode direct
```

Netflix 默认直连。确认 WARP 出口更适合 Netflix 后再开启：

```bash
warp netflix test
warp netflix on
warp netflix off
```

## 路由模式

`google-all`

整个 Google IPv4 网段通过 WARP，适合在普通浏览器中登录和使用 Gemini。
Google 搜索、Google 登录和 Gemini 会保持相同出口。

`gemini-only`

只把 Gemini、Google AI Studio 和 Gemini API 域名通过 WARP。该模式适合
API、独立浏览器 Profile 或隔离会话，不建议在同一个 Google 登录会话中
同时直连 Google 搜索。

它会向现有 sing-box 配置添加：

- `warp-out`：连接本机 WARP SOCKS5 端口。
- Gemini 域名 TCP 路由规则。
- Gemini 域名 UDP/443 拒绝规则，使浏览器回退到 TCP。
- sing-box 启动前的幂等配置检查。

`direct`

Google 与 Gemini 全部使用 VPS 原生出口，不创建 Google iptables 规则，
也不添加 sing-box WARP 出站。

三种模式互斥，切换时会先清理前一种模式的规则。Netflix 始终由独立开关
控制，不会因为切换到 `google-all` 而自动启用。

Gemini 域名列表保存在：

```text
/etc/warp-google/gemini_domains.txt
```

Netflix 域名列表保存在：

```text
/etc/warp-google/netflix_domains.txt
```

修改列表后运行：

```bash
warp update
systemctl restart sing-box
```

## DNS 和 IPv4

从 2.1.0 开始，脚本默认不修改系统 DNS，也不全局强制 IPv4。

确实需要时可以在安装时启用：

```bash
WARP_CONFIGURE_DNS=1 WARP_PREFER_IPV4=1 bash warp.sh --install
```

## 升级与回滚

`warp upgrade` 必须通过仓库中的 `warp.sh.sha256` 校验。升级会在修改前
备份 sing-box 配置，格式如下：

```text
config.json.bak-warp-v2-YYYYMMDD-HHMMSS
```

配置补丁采用临时文件原子替换，并在写入后运行 `sing-box check`。检查失败
时会恢复升级前的配置。

卸载：

```bash
warp uninstall
```

卸载只移除脚本添加的 `warp-out`、`warp-direct` 和带管理标记的路由规则，
不会重建或覆盖其他 sing-box 入站配置。
