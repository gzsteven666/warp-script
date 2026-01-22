#!/usr/bin/env bash
# WARP 一键脚本（Cloudflare 官方客户端）
# Google IPv4 走 WARP：redsocks + iptables + ipset；并阻断 QUIC(UDP/443) 强制回落 TCP
#
# 安装（交互）: bash <(curl -fsSL https://raw.githubusercontent.com/gzsteven666/warp-script/main/warp.sh)
# 安装（非交互）: bash <(curl -fsSL https://raw.githubusercontent.com/gzsteven666/warp-script/main/warp.sh) --install
#
# 安装后：
#   warp status|start|stop|restart|test|ip|update|upgrade|uninstall

set -euo pipefail

WARP_PROXY_PORT="${WARP_PROXY_PORT:-40000}"
REDSOCKS_PORT="${REDSOCKS_PORT:-12345}"
REQUEST_TIMEOUT="${REQUEST_TIMEOUT:-8}"

SCRIPT_VERSION="1.3.0"
REPO_RAW_URL="${REPO_RAW_URL:-https://raw.githubusercontent.com/gzsteven666/warp-script/main/warp.sh}"

LOG_FILE="${LOG_FILE:-/var/log/warp-install.log}"
GAI_MARK="# warp-script: prefer ipv4"

IPSET_NAME="${IPSET_NAME:-warp_google4}"
NAT_CHAIN="${NAT_CHAIN:-WARP_GOOGLE}"
QUIC_CHAIN="${QUIC_CHAIN:-WARP_GOOGLE_QUIC}"

CACHE_DIR="/etc/warp-google"
GOOG_JSON_URL="https://www.gstatic.com/ipranges/goog.json"
IPV4_CACHE_FILE="${CACHE_DIR}/google_ipv4.txt"

STATIC_GOOGLE_IPV4_CIDRS="
8.8.4.0/24
8.8.8.0/24
34.0.0.0/9
35.184.0.0/13
35.192.0.0/12
35.224.0.0/12
35.240.0.0/13
64.233.160.0/19
66.102.0.0/20
66.249.64.0/19
72.14.192.0/18
74.125.0.0/16
104.132.0.0/14
108.177.0.0/17
142.250.0.0/15
172.217.0.0/16
172.253.0.0/16
173.194.0.0/16
209.85.128.0/17
216.58.192.0/19
216.239.32.0/19
"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE" 2>/dev/null || true; }

check_root() {
  [[ ${EUID:-0} -ne 0 ]] && { error "请使用 root 运行！"; exit 1; }
}

show_banner() {
  clear || true
  echo -e "${CYAN}"
  echo "╔════════════════════════════════════════════════════╗"
  echo "║ 🌐 WARP 一键脚本 - Google 自动解锁（ipset版） 🌐 ║"
  echo "║ 使用 Cloudflare 官方客户端                          ║"
  echo "║ v${SCRIPT_VERSION}                                  ║"
  echo "╚════════════════════════════════════════════════════╝"
  echo -e "${NC}"
}

OS=""
VERSION=""
CODENAME=""

detect_system() {
  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS="${ID:-}"
    VERSION="${VERSION_ID:-}"
    CODENAME="${VERSION_CODENAME:-}"
  else
    error "无法检测系统（缺少 /etc/os-release）"
    exit 1
  fi

  if [[ -z "${CODENAME}" ]]; then
    CODENAME="$(lsb_release -cs 2>/dev/null || true)"
  fi
  if [[ -z "${CODENAME}" ]]; then
    case "${OS}" in
      ubuntu)
        case "${VERSION}" in
          20.04*) CODENAME="focal" ;;
          22.04*) CODENAME="jammy" ;;
          24.04*) CODENAME="noble" ;;
        esac
        ;;
      debian)
        case "${VERSION}" in
          10*) CODENAME="buster" ;;
          11*) CODENAME="bullseye" ;;
          12*) CODENAME="bookworm" ;;
        esac
        ;;
    esac
  fi
}

warn_firewall_backend() {
  if systemctl is-active firewalld >/dev/null 2>&1; then
    warn "检测到 firewalld 正在运行，可能会冲掉 iptables 规则。若遇到规则失效，请考虑关闭 firewalld 或改用 direct rules。"
  fi
  if iptables -V 2>/dev/null | grep -qi "nf_tables"; then
    warn "检测到 iptables 使用 nf_tables backend（兼容层）。一般可用，但若规则异常，可能需要改用 nft 原生写法。"
  fi
}

install_prereqs() {
  info "安装依赖（curl/ca-certificates/ipset/iptables 等）..."
  case "${OS}" in
    ubuntu|debian)
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -y >/dev/null 2>&1 || true
      apt-get install -y curl ca-certificates gnupg lsb-release iptables ipset >/dev/null 2>&1
      ;;
    centos|rhel|rocky|almalinux|fedora)
      if command -v dnf >/dev/null 2>&1; then
        dnf install -y curl ca-certificates iptables ipset >/dev/null 2>&1 || true
      else
        yum install -y curl ca-certificates iptables ipset >/dev/null 2>&1 || true
      fi
      ;;
    *)
      error "不支持的系统：${OS}"
      exit 1
      ;;
  esac
}

install_warp_client() {
  if command -v warp-cli >/dev/null 2>&1; then
    success "已检测到 warp-cli，跳过安装 WARP"
  else
    info "安装 Cloudflare WARP..."
    case "${OS}" in
      ubuntu|debian)
        export DEBIAN_FRONTEND=noninteractive
        local arch
        arch="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
        mkdir -p /usr/share/keyrings
        curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg

        [[ -z "${CODENAME}" ]] && { error "无法获取 CODENAME"; return 1; }

        echo "deb [arch=${arch} signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ ${CODENAME} main" \
          > /etc/apt/sources.list.d/cloudflare-client.list

        apt-get update -y >/dev/null 2>&1
        apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" cloudflare-warp >/dev/null 2>&1
        ;;
      centos|rhel|rocky|almalinux|fedora)
        cat > /etc/yum.repos.d/cloudflare-warp.repo <<'EOF'
[cloudflare-warp]
name=Cloudflare WARP
baseurl=https://pkg.cloudflareclient.com/rpm
enabled=1
gpgcheck=1
gpgkey=https://pkg.cloudflareclient.com/pubkey.gpg
EOF
        if command -v dnf >/dev/null 2>&1; then
          dnf install -y cloudflare-warp
        else
          yum install -y cloudflare-warp
        fi
        ;;
      *)
        error "不支持的系统：${OS}"
        return 1
        ;;
    esac
  fi

  command -v warp-cli >/dev/null 2>&1 || { error "WARP 安装失败：未找到 warp-cli"; return 1; }

  info "启动 warp-svc..."
  systemctl enable --now warp-svc >/dev/null 2>&1 || true
  success "WARP 就绪"
}

install_redsocks() {
  if command -v redsocks >/dev/null 2>&1; then
    success "已检测到 redsocks，跳过安装"
    return 0
  fi

  info "安装 redsocks..."
  case "${OS}" in
    ubuntu|debian)
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -y >/dev/null 2>&1 || true
      apt-get install -y redsocks >/dev/null 2>&1
      ;;
    centos|rhel|rocky|almalinux|fedora)
      if command -v dnf >/dev/null 2>&1; then
        dnf install -y redsocks >/dev/null 2>&1 || {
          warn "尝试安装 epel-release..."
          dnf install -y epel-release >/dev/null 2>&1 || true
          dnf install -y redsocks >/dev/null 2>&1
        }
      else
        yum install -y redsocks >/dev/null 2>&1 || {
          warn "尝试安装 epel-release..."
          yum install -y epel-release >/dev/null 2>&1 || true
          yum install -y redsocks >/dev/null 2>&1
        }
      fi
      ;;
    *)
      error "不支持的系统：${OS}"
      return 1
      ;;
  esac

  command -v redsocks >/dev/null 2>&1 || { error "redsocks 安装失败"; return 1; }
  success "redsocks 已安装"
}

configure_warp() {
  info "注册/配置 WARP..."
  warp-cli --accept-tos registration new >/dev/null 2>&1 || warp-cli --accept-tos register >/dev/null 2>&1 || true
  warp-cli --accept-tos tunnel protocol set MASQUE >/dev/null 2>&1 || warp-cli tunnel protocol set MASQUE >/dev/null 2>&1 || true
  warp-cli --accept-tos mode proxy >/dev/null 2>&1 || warp-cli mode proxy >/dev/null 2>&1 || true
  warp-cli --accept-tos proxy port "${WARP_PROXY_PORT}" >/dev/null 2>&1 || warp-cli proxy port "${WARP_PROXY_PORT}" >/dev/null 2>&1 || true
  warp-cli --accept-tos connect >/dev/null 2>&1 || warp-cli connect >/dev/null 2>&1 || true
  sleep 2
  info "WARP 状态：$(warp-cli --accept-tos status 2>/dev/null || warp-cli status 2>/dev/null || echo 未知)"
}

setup_gai_conf() {
  if ! grep -qF "${GAI_MARK}" /etc/gai.conf 2>/dev/null; then
    {
      echo "${GAI_MARK}"
      echo "precedence ::ffff:0:0/96  100"
    } >> /etc/gai.conf
    success "已写入 /etc/gai.conf（带标记，可回滚）"
  else
    info "/etc/gai.conf 已存在标记，跳过"
  fi
}

write_redsocks_conf() {
  info "写入 /etc/redsocks.conf..."
  cat > /etc/redsocks.conf <<EOF
base {
  log_debug = off;
  log_info = on;
  log = "syslog:daemon";
  daemon = on;
  redirector = iptables;
}

redsocks {
  local_ip = 127.0.0.1;
  local_port = ${REDSOCKS_PORT};
  ip = 127.0.0.1;
  port = ${WARP_PROXY_PORT};
  type = socks5;
}
EOF
  success "redsocks 配置完成"
}

write_warp_google() {
  info "创建 /usr/local/bin/warp-google（ipset 版）..."
  mkdir -p "${CACHE_DIR}"

  cat > /usr/local/bin/warp-google <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

WARP_PROXY_PORT="${WARP_PROXY_PORT:-40000}"
REDSOCKS_PORT="${REDSOCKS_PORT:-12345}"

IPSET_NAME="${IPSET_NAME:-warp_google4}"
NAT_CHAIN="${NAT_CHAIN:-WARP_GOOGLE}"
QUIC_CHAIN="${QUIC_CHAIN:-WARP_GOOGLE_QUIC}"

CACHE_DIR="/etc/warp-google"
GOOG_JSON_URL="https://www.gstatic.com/ipranges/goog.json"
IPV4_CACHE_FILE="${CACHE_DIR}/google_ipv4.txt"

STATIC_GOOGLE_IPV4_CIDRS="
8.8.4.0/24
8.8.8.0/24
34.0.0.0/9
35.184.0.0/13
35.192.0.0/12
35.224.0.0/12
35.240.0.0/13
64.233.160.0/19
66.102.0.0/20
66.249.64.0/19
72.14.192.0/18
74.125.0.0/16
104.132.0.0/14
108.177.0.0/17
142.250.0.0/15
172.217.0.0/16
172.253.0.0/16
173.194.0.0/16
209.85.128.0/17
216.58.192.0/19
216.239.32.0/19
"

info() { echo "[warp-google] $*"; }

warp_connect() {
  warp-cli --accept-tos connect 2>/dev/null || warp-cli connect 2>/dev/null || true
}

start_redsocks() {
  pkill redsocks 2>/dev/null || true
  sleep 0.5
  redsocks -c /etc/redsocks.conf
}

ensure_ipset() {
  ipset create "${IPSET_NAME}" hash:net family inet -exist
}

load_ipv4_list() {
  if [[ -s "${IPV4_CACHE_FILE}" ]]; then
    cat "${IPV4_CACHE_FILE}"
  else
    echo "${STATIC_GOOGLE_IPV4_CIDRS}"
  fi
}

ipset_apply() {
  ensure_ipset
  ipset flush "${IPSET_NAME}" || true
  local cidr
  while IFS= read -r cidr; do
    [[ -z "${cidr}" ]] && continue
    ipset add "${IPSET_NAME}" "${cidr}" -exist
  done < <(load_ipv4_list)
}

iptables_apply() {
  iptables -t nat -N "${NAT_CHAIN}" 2>/dev/null || true
  iptables -t nat -F "${NAT_CHAIN}"

  iptables -t nat -A "${NAT_CHAIN}" -p tcp -m set --match-set "${IPSET_NAME}" dst \
    -j REDIRECT --to-ports "${REDSOCKS_PORT}"

  iptables -t nat -C OUTPUT -j "${NAT_CHAIN}" 2>/dev/null || iptables -t nat -I OUTPUT 1 -j "${NAT_CHAIN}"

  iptables -t filter -N "${QUIC_CHAIN}" 2>/dev/null || true
  iptables -t filter -F "${QUIC_CHAIN}"

  iptables -t filter -A "${QUIC_CHAIN}" -p udp --dport 443 -m set --match-set "${IPSET_NAME}" dst \
    -j REJECT

  iptables -t filter -C OUTPUT -j "${QUIC_CHAIN}" 2>/dev/null || iptables -t filter -I OUTPUT 1 -j "${QUIC_CHAIN}"
}

start() {
  info "启动透明代理..."
  warp_connect
  start_redsocks
  ipset_apply
  iptables_apply
  info "完成"
}

stop() {
  info "停止透明代理..."
  pkill redsocks 2>/dev/null || true

  iptables -t nat -D OUTPUT -j "${NAT_CHAIN}" 2>/dev/null || true
  iptables -t nat -F "${NAT_CHAIN}" 2>/dev/null || true
  iptables -t nat -X "${NAT_CHAIN}" 2>/dev/null || true

  iptables -t filter -D OUTPUT -j "${QUIC_CHAIN}" 2>/dev/null || true
  iptables -t filter -F "${QUIC_CHAIN}" 2>/dev/null || true
  iptables -t filter -X "${QUIC_CHAIN}" 2>/dev/null || true

  info "完成"
}

status() {
  echo "=== WARP 状态 ==="
  warp-cli status 2>/dev/null || echo "WARP 未运行"
  echo ""
  echo "=== Redsocks ==="
  pgrep -x redsocks >/dev/null && echo "运行中" || echo "未运行"
  echo ""
  echo "=== ipset（${IPSET_NAME}）=== "
  ipset list "${IPSET_NAME}" 2>/dev/null | awk 'NR==1 || NR==2 || $1=="Number" || $1=="Members:" {print}' || echo "未创建"
  echo ""
  echo "=== NAT 规则（命中计数）==="
  iptables -t nat -L "${NAT_CHAIN}" -n -v 2>/dev/null | head -10 || echo "无规则"
  echo ""
  echo "=== QUIC 阻断（命中计数）==="
  iptables -t filter -L "${QUIC_CHAIN}" -n -v 2>/dev/null | head -10 || echo "无规则"
}

update() {
  info "更新 Google IPv4 段（goog.json）..."
  mkdir -p "${CACHE_DIR}"

  local tmp
  tmp="$(mktemp)"
  if ! curl -fsSL "${GOOG_JSON_URL}" -o "${tmp}"; then
    rm -f "${tmp}"
    echo "下载失败：${GOOG_JSON_URL}" >&2
    return 1
  fi

  if command -v python3 >/dev/null 2>&1; then
    python3 - <<PY > "${IPV4_CACHE_FILE}"
import json
with open("${tmp}","r",encoding="utf-8") as f:
    data=json.load(f)
out=[]
for p in data.get("prefixes",[]):
    v=p.get("ipv4Prefix")
    if v: out.append(v)
print("\n".join(sorted(set(out))))
PY
  else
    grep -oE '"ipv4Prefix"\s*:\s*"[^"]+"' "${tmp}" | sed -E 's/.*"([^"]+)".*/\1/' | sort -u > "${IPV4_CACHE_FILE}"
  fi

  rm -f "${tmp}"

  if [[ ! -s "${IPV4_CACHE_FILE}" ]]; then
    echo "更新失败：未解析到 IPv4 段" >&2
    return 1
  fi

  info "已更新缓存：${IPV4_CACHE_FILE}（$(wc -l < "${IPV4_CACHE_FILE}") 条）"
  info "重启透明代理..."
  stop || true
  start
}

case "${1:-}" in
  start) start ;;
  stop) stop ;;
  restart) stop; sleep 0.5; start ;;
  status) status ;;
  update) update ;;
  *)
    echo "用法: warp-google {start|stop|restart|status|update}"
    ;;
esac
SCRIPT

  chmod +x /usr/local/bin/warp-google
  success "warp-google 已创建"
}

write_systemd_service() {
  info "创建/更新 warp-google.service..."
  cat > /etc/systemd/system/warp-google.service <<EOF
[Unit]
Description=WARP Google Transparent Proxy (ipset)
After=network-online.target warp-svc.service
Wants=network-online.target warp-svc.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/warp-google start
ExecStop=/usr/local/bin/warp-google stop

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable --now warp-google >/dev/null 2>&1 || true
  success "warp-google 服务已启用"
}

write_warp_cli() {
  info "创建 /usr/local/bin/warp（管理命令 + upgrade）..."
  cat > /usr/local/bin/warp <<'WARPSCRIPT'
#!/usr/bin/env bash
set -euo pipefail

WARP_PROXY_PORT="${WARP_PROXY_PORT:-40000}"
REPO_RAW_URL="${REPO_RAW_URL:-https://raw.githubusercontent.com/gzsteven666/warp-script/main/warp.sh}"
GAI_MARK="# warp-script: prefer ipv4"

# shellcheck disable=SC1091
. /etc/os-release 2>/dev/null || true
OS_ID="${ID:-unknown}"

do_status() {
  warp-cli status 2>/dev/null || echo "WARP 未运行/未安装"
  echo ""
  /usr/local/bin/warp-google status 2>/dev/null || echo "warp-google 未安装"
}

do_start() {
  warp-cli connect 2>/dev/null || true
  /usr/local/bin/warp-google start
}

do_stop() {
  /usr/local/bin/warp-google stop 2>/dev/null || true
  warp-cli disconnect 2>/dev/null || true
}

do_restart() {
  do_stop
  sleep 1
  do_start
}

do_test() {
  echo "测试 Google："
  curl -s --max-time 10 -o /dev/null -w "状态码: %{http_code}\n" https://www.google.com || true
  echo ""
  echo "WARP Trace（走 socks5h）："
  curl -s --max-time 10 -x "socks5h://127.0.0.1:${WARP_PROXY_PORT}" https://www.cloudflare.com/cdn-cgi/trace | grep -E "^warp=" || echo "warp=未检测到"
}

do_ip() {
  echo "直连 IP:"
  curl -4 -s --max-time 8 ip.sb || true
  echo ""
  echo "WARP IP（走 socks5h）："
  curl -s --max-time 8 -x "socks5h://127.0.0.1:${WARP_PROXY_PORT}" ip.sb || true
  echo ""
}

do_update() {
  /usr/local/bin/warp-google update
}

do_upgrade() {
  echo "[warp] 正在自升级：下载最新脚本并覆盖升级..."
  local tmp
  tmp="$(mktemp)"
  if ! curl -fsSL "${REPO_RAW_URL}" -o "${tmp}"; then
    echo "[warp] 下载失败：${REPO_RAW_URL}" >&2
    rm -f "${tmp}"
    exit 1
  fi
  chmod +x "${tmp}"
  bash "${tmp}" --install
  rm -f "${tmp}"
  echo "[warp] 升级完成。"
}

do_uninstall() {
  read -r -p "确定要卸载 WARP？[y/N]: " confirm
  [[ "${confirm}" =~ ^[Yy]$ ]] || { echo "已取消"; exit 0; }

  /usr/local/bin/warp-google stop 2>/dev/null || true
  warp-cli disconnect 2>/dev/null || true

  systemctl disable --now warp-google 2>/dev/null || true
  systemctl disable --now warp-svc 2>/dev/null || true

  rm -f /etc/systemd/system/warp-google.service
  rm -f /usr/local/bin/warp-google
  rm -f /etc/redsocks.conf
  rm -rf /etc/warp-google

  systemctl daemon-reload 2>/dev/null || true

  iptables -t nat -D OUTPUT -j WARP_GOOGLE 2>/dev/null || true
  iptables -t nat -F WARP_GOOGLE 2>/dev/null || true
  iptables -t nat -X WARP_GOOGLE 2>/dev/null || true

  iptables -t filter -D OUTPUT -j WARP_GOOGLE_QUIC 2>/dev/null || true
  iptables -t filter -F WARP_GOOGLE_QUIC 2>/dev/null || true
  iptables -t filter -X WARP_GOOGLE_QUIC 2>/dev/null || true

  ipset destroy warp_google4 2>/dev/null || true
  sed -i "/$GAI_MARK/,+1d" /etc/gai.conf 2>/dev/null || true

  case "${OS_ID}" in
    ubuntu|debian)
      export DEBIAN_FRONTEND=noninteractive
      apt-get remove -y cloudflare-warp redsocks 2>/dev/null || true
      rm -f /etc/apt/sources.list.d/cloudflare-client.list
      rm -f /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
      ;;
    centos|rhel|rocky|almalinux|fedora)
      (command -v dnf >/dev/null 2>&1 && dnf remove -y cloudflare-warp redsocks) 2>/dev/null || \
      yum remove -y cloudflare-warp redsocks 2>/dev/null || true
      rm -f /etc/yum.repos.d/cloudflare-warp.repo
      ;;
  esac

  rm -f /usr/local/bin/warp
  echo "WARP 已卸载"
}

case "${1:-}" in
  status) do_status ;;
  start) do_start ;;
  stop) do_stop ;;
  restart) do_restart ;;
  test) do_test ;;
  ip) do_ip ;;
  update) do_update ;;
  upgrade) do_upgrade ;;
  uninstall) do_uninstall ;;
  *)
    echo "用法: warp <命令>"
    echo "  status | start | stop | restart | test | ip | update | upgrade | uninstall"
    ;;
esac
WARPSCRIPT
  chmod +x /usr/local/bin/warp
  success "warp 管理命令已创建"
}

do_install() {
  info "开始安装/覆盖升级 v${SCRIPT_VERSION} ..."
  log "========== install/upgrade v${SCRIPT_VERSION} =========="

  install_prereqs
  warn_firewall_backend

  install_warp_client
  install_redsocks

  setup_gai_conf
  write_redsocks_conf

  write_warp_google
  write_systemd_service
  write_warp_cli

  configure_warp

  if /usr/local/bin/warp-google update >/dev/null 2>&1; then
    success "Google IP 段已更新到最新（goog.json）"
  else
    warn "Google IP 段更新失败（将使用静态兜底段）。你可稍后执行：warp update"
    systemctl restart warp-google >/dev/null 2>&1 || true
  fi

  success "安装/升级完成！"
  echo -e "管理命令：${GREEN}warp status | warp test | warp update | warp upgrade${NC}"
}

do_uninstall() {
  if command -v warp >/dev/null 2>&1; then
    warp uninstall
    return 0
  fi
  warn "未检测到 /usr/local/bin/warp，执行简化卸载..."

  systemctl disable --now warp-google 2>/dev/null || true
  systemctl disable --now warp-svc 2>/dev/null || true

  rm -f /etc/systemd/system/warp-google.service
  rm -f /usr/local/bin/warp-google
  rm -f /usr/local/bin/warp
  rm -f /etc/redsocks.conf
  rm -rf /etc/warp-google

  systemctl daemon-reload 2>/dev/null || true
  ipset destroy "${IPSET_NAME}" 2>/dev/null || true
  sed -i "/$GAI_MARK/,+1d" /etc/gai.conf 2>/dev/null || true

  success "卸载完成"
}

do_status() {
  if command -v warp >/dev/null 2>&1; then
    warp status
  else
    echo "未安装。执行：--install"
  fi
}

show_menu() {
  echo -e "${YELLOW}请选择操作:${NC}\n"
  echo -e "  ${GREEN}1.${NC} 安装/升级 WARP（ipset版）"
  echo -e "  ${GREEN}2.${NC} 卸载"
  echo -e "  ${GREEN}3.${NC} 查看状态"
  echo -e "  ${GREEN}0.${NC} 退出\n"
  read -r -p "请输入选项 [0-3]: " choice
  case "${choice}" in
    1) do_install ;;
    2) do_uninstall ;;
    3) do_status ;;
    0) echo -e "\n${GREEN}再见！${NC}\n"; exit 0 ;;
    *) error "无效选项" ;;
  esac
}

main() {
  check_root
  detect_system

  case "${1:-}" in
    --install|install) show_banner; do_install; exit 0 ;;
    --uninstall|uninstall) show_banner; do_uninstall; exit 0 ;;
    --status|status) do_status; exit 0 ;;
  esac

  show_banner
  show_menu
}

main "$@"
