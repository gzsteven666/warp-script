# WARP Script

在 Linux VPS 上安装 Cloudflare WARP，并为 sing-box 节点提供按域名分流。

默认模式是 `gemini-only`：只有 Gemini、Google AI Studio 和 Gemini API
通过 WARP，Google 搜索、YouTube、ChatGPT、OpenAI 和 Netflix 保持直连。
这可以避免把整个 Google IP 段送入共享 WARP 出口而触发验证码。

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

检测到 sing-box 时使用 `gemini-only`。未检测到时回退到兼容的
`google-all` ipset 模式。

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
```

Netflix 默认直连。确认 WARP 出口更适合 Netflix 后再开启：

```bash
warp netflix test
warp netflix on
warp netflix off
```

## 路由方式

`gemini-only` 会向现有 sing-box 配置添加：

- `warp-out`：连接本机 WARP SOCKS5 端口。
- Gemini 域名 TCP 路由规则。
- Gemini 域名 UDP/443 拒绝规则，使浏览器回退到 TCP。
- sing-box 启动前的幂等配置检查。

旧版 `WARP_GOOGLE`、`WARP_NETFLIX` iptables 规则会被移除，
`redsocks` 在该模式下停止。切换到 `google-all` 时会恢复旧架构。

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

从 2.0.3 开始，脚本默认不修改系统 DNS，也不全局强制 IPv4。

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
