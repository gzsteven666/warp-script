#!/usr/bin/env bash
# WARP Script - Google unlock via Cloudflare WARP (ipset)
# Author: gzsteven666 (repo) + improvements
#
# Usage:
#   Interactive:
#     bash <(curl -fsSL https://raw.githubusercontent.com/gzsteven666/warp-script/main/warp.sh)
#   Non-interactive install/upgrade:
#     bash <(curl -fsSL https://raw.githubusercontent.com/gzsteven666/warp-script/main/warp.sh) --install
#
# After install:
#   warp status|start|stop|restart|test|ip|update|upgrade|uninstall

set -euo pipefail

#========================
# Config
#========================
SCRIPT_VERSION="1.3.2"

WARP_PROXY_PORT="${WARP_PROXY_PORT:-40000}"
REDSOCKS_PORT="${REDSOCKS_PORT:-12345}"

REPO_RAW_URL="${REPO_RAW_URL:-https://raw.githubusercontent.com/gzsteven666/warp-script/main/warp.sh}"
LOG_FILE="${LOG_FILE:-/var/log/warp-install.log}"

GAI_MARK="# warp-script: prefer ipv4"
IPSET_NAME="${IPSET_NAME:-warp_google4}"
NAT_CHAIN="${NAT_CHAIN:-WARP_GOOGLE}"
QUIC_CHAIN="${QUIC_CHAIN:-WARP_GOOGLE_QUIC}"

CACHE_DIR="/etc/warp-google"
GOOG_JSON_URL="https://www.gstatic.com/ipranges/goog.json"
IPV4_CACHE_FILE="${CACHE_DIR}/google_ipv4.txt"

# Static fallback (only used if update fails)
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

#========================
# Colors
#========================
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
  clear 2>/dev/null || true
  echo -e "${CYAN}"
  echo "╔════════════════════════════════════════════════════╗"
  echo "║ 🌐 WARP Script - Google Unlock (ipset)            ║"
  echo "║ v${SCRIPT_VERSION}                                  ║"
  echo "╚════════════════════════════════════════════════════╝"
  echo -e "${NC}"
}

#========================
# OS detect
#========================
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

#========================
# Install deps
#========================
install_prereqs() {
  info "安装依赖（curl/ca-certificates/ipset/iptables/python3 等）..."
  case "${OS}" in
    ubuntu|debian)
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -y >/dev/null 2>&1 || true
      apt-get install -y curl ca-certificates gnupg lsb-release iptables ipset python3 redsocks >/dev/null 2>&1
      ;;
    centos|rhel|rocky|almalinux|fedora)
      if command -v dnf >/dev/null 2>&1; then
        dnf install -y curl ca-certificates iptables ipset python3 redsocks >/dev/null 2>&1 || true
      else
        yum install -y curl ca-certificates iptables ipset python3 redsocks >/dev/null 2>&1 || true
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

        [[ -z "${CODENAME}" ]] && { error "无法获取系统代号 CODENAME"; return 1; }

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

configure_warp() {
  info "注册/配置 WARP..."
  warp-cli --accept-tos registration new >/dev/null 2>&1 || warp-cli --accept-tos register >/dev/null 2>&1 || true
  warp-cli --accept-tos tunnel protocol set MASQUE >/dev/null 2>&1 || warp-cli tunnel protocol set MASQUE >/dev/null 2>&1 || true
  warp-cli --accept-tos mode proxy >/dev/null 2>&1 || warp-cli mode proxy >/dev/null 2>&1 || true
  warp-cli --accept-tos proxy port "${WARP_PROXY_PORT}" >/dev/null 2>&1 || warp-cli proxy port "${WARP_PROXY_PORT}" >/dev/null 2>&1 || true
  warp-cli --accept-tos connect >/dev/null 2>&1 || warp-cli connect >/dev/null 2>&1 || true
  sleep 1
  info "WARP 状态：$(warp-cli --accept-tos status 2>/dev/null || warp-cli status 2>/dev/null || echo 未知)"
}

setup_gai_conf() {
  if ! grep -qF "${GAI_MARK}" /etc/gai.conf 2>/dev/null; then
    {
      echo "${GAI_MARK}"
      echo "precedence ::ffff:0:0/96  100"
    } >> /etc/gai.conf
    success "已写入 /etc/gai.conf（带标记，可回滚）"
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

#========================
# /usr/local/bin/warp-google (ipset)
#========================
write_warp_google() {
  info "创建 /usr/local/bin/warp-google（ipset 版）..."
  mkdir -p "${CACHE_DIR}"

  cat > /usr/local/bin/warp-google <<EOF
#!/usr/bin/env bash
set -euo pipefail

WARP_PROXY_PORT="${WARP_PROXY_PORT}"
REDSOCKS_PORT="${REDSOCKS_PORT}"

IPSET_NAME="${IPSET_NAME}"
NAT_CHAIN="${NAT_CHAIN}"
QUIC_CHAIN="${QUIC_CHAIN}"

CACHE_DIR="${CACHE_DIR}"
GOOG_JSON_URL="${GOOG_JSON_URL}"
IPV4_CACHE_FILE="${IPV4_CACHE_FILE}"

STATIC_GOOGLE_IPV4_CIDRS='${STATIC_GOOGLE_IPV4_CIDRS}'

info() { echo "[warp-google] \$*"; }

warp_connect() { warp-cli --accept-tos connect 2>/dev/null || warp-cli connect 2>/dev/null || true; }

start_redsocks() {
  pkill redsocks 2>/dev/null || true
  sleep 0.2
  redsocks -c /etc/redsocks.conf
}

ensure_ipset() { ipset create "\${IPSET_NAME}" hash:net family inet -exist; }

load_ipv4_list() {
  if [[ -s "\${IPV4_CACHE_FILE}" ]]; then
    cat "\${IPV4_CACHE_FILE}"
  else
    echo "\${STATIC_GOOGLE_IPV4_CIDRS}"
  fi
}

ipset_apply() {
  ensure_ipset
  ipset flush "\${IPSET_NAME}" || true
  while IFS= read -r cidr; do
    [[ -z "\${cidr}" ]] && continue
    ipset add "\${IPSET_NAME}" "\${cidr}" -exist
  done < <(load_ipv4_list)
}

iptables_apply() {
  # drop old chains (per-CIDR old version compatibility)
  iptables -t nat -D OUTPUT -j "\${NAT_CHAIN}" 2>/dev/null || true
  iptables -t nat -F "\${NAT_CHAIN}" 2>/dev/null || true
  iptables -t nat -X "\${NAT_CHAIN}" 2>/dev/null || true
  iptables -t filter -D OUTPUT -j "\${QUIC_CHAIN}" 2>/dev/null || true
  iptables -t filter -F "\${QUIC_CHAIN}" 2>/dev/null || true
  iptables -t filter -X "\${QUIC_CHAIN}" 2>/dev/null || true

  # NAT (single ipset rule)
  iptables -t nat -N "\${NAT_CHAIN}" 2>/dev/null || true
  iptables -t nat -F "\${NAT_CHAIN}"
  iptables -t nat -A "\${NAT_CHAIN}" -p tcp -m set --match-set "\${IPSET_NAME}" dst -j REDIRECT --to-ports "\${REDSOCKS_PORT}"
  iptables -t nat -I OUTPUT 1 -j "\${NAT_CHAIN}"

  # QUIC block (udp/443 only for google ipset)
  iptables -t filter -N "\${QUIC_CHAIN}" 2>/dev/null || true
  iptables -t filter -F "\${QUIC_CHAIN}"
  iptables -t filter -A "\${QUIC_CHAIN}" -p udp --dport 443 -m set --match-set "\${IPSET_NAME}" dst -j REJECT
  iptables -t filter -I OUTPUT 1 -j "\${QUIC_CHAIN}"
}

update() {
  info "更新 Google IPv4 段（goog.json）..."
  mkdir -p "\${CACHE_DIR}"
  tmp="\$(mktemp)"
  curl -fsSL "\${GOOG_JSON_URL}" -o "\${tmp}"
  if command -v python3 >/dev/null 2>&1; then
    python3 - <<PY > "\${IPV4_CACHE_FILE}"
import json
data=json.load(open("${tmp}","r",encoding="utf-8"))
out=sorted({p["ipv4Prefix"] for p in data.get("prefixes",[]) if "ipv4Prefix" in p})
print("\\n".join(out))
PY
  else
    grep -oE '"ipv4Prefix"\\s*:\\s*"[^"]+"' "\${tmp}" | sed -E 's/.*"([^"]+)".*/\\1/' | sort -u > "\${IPV4_CACHE_FILE}"
  fi
  rm -f "\${tmp}"
  [[ -s "\${IPV4_CACHE_FILE}" ]] || { echo "update failed" >&2; exit 1; }
  info "已更新：\${IPV4_CACHE_FILE}（\$(wc -l < "\${IPV4_CACHE_FILE}") 条）"
}

start() { warp_connect; start_redsocks; ipset_apply; iptables_apply; info "完成"; }
stop() {
  pkill redsocks 2>/dev/null || true
  iptables -t nat -D OUTPUT -j "\${NAT_CHAIN}" 2>/dev/null || true
  iptables -t nat -F "\${NAT_CHAIN}" 2>/dev/null || true
  iptables -t nat -X "\${NAT_CHAIN}" 2>/dev/null || true
  iptables -t filter -D OUTPUT -j "\${QUIC_CHAIN}" 2>/dev/null || true
  iptables -t filter -F "\${QUIC_CHAIN}" 2>/dev/null || true
  iptables -t filter -X "\${QUIC_CHAIN}" 2>/dev/null || true
  info "完成"
}
status() {
  echo "=== ipset ==="
  ipset list "\${IPSET_NAME}" 2>/dev/null | head -n 30 || echo "ipset missing"
  echo
  echo "=== NAT ==="
  iptables -t nat -S "\${NAT_CHAIN}" 2>/dev/null || true
  echo
  echo "=== QUIC ==="
  iptables -t filter -S "\${QUIC_CHAIN}" 2>/dev/null || true
}

case "\${1:-}" in
  update) update ;;
  start) start ;;
  stop) stop ;;
  restart) stop; sleep 0.2; start ;;
  status) status ;;
  *) echo "用法: warp-google {update|start|stop|restart|status}" ;;
esac
EOF

  chmod +x /usr/local/bin/warp-google
  success "warp-google 已创建"
}

#========================
# /usr/local/bin/warp (with upgrade)
#========================
write_warp_cli() {
  info "创建 /usr/local/bin/warp（管理命令 + upgrade）..."
  cat > /usr/local/bin/warp <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

REPO_RAW_URL="${REPO_RAW_URL:-https://raw.githubusercontent.com/gzsteven666/warp-script/main/warp.sh}"

case "${1:-}" in
  status)
    warp-cli status 2>/dev/null || true
    echo
    /usr/local/bin/warp-google status
    ;;
  start)
    warp-cli connect 2>/dev/null || true
    /usr/local/bin/warp-google start
    ;;
  stop)
    /usr/local/bin/warp-google stop || true
    warp-cli disconnect 2>/dev/null || true
    ;;
  restart)
    /usr/local/bin/warp-google restart
    ;;
  test)
    echo "Google:"
    curl -s --max-time 10 -o /dev/null -w "code=%{http_code}\n" https://www.google.com || true
    echo "Trace (socks5h):"
    curl -s --max-time 10 -x "socks5h://127.0.0.1:40000" https://www.cloudflare.com/cdn-cgi/trace | grep -E "^warp=" || true
    ;;
  ip)
    echo "direct:"; curl -4 -s --max-time 8 ip.sb || true
    echo; echo "warp:"; curl -s --max-time 8 -x "socks5h://127.0.0.1:40000" ip.sb || true
    ;;
  update)
    /usr/local/bin/warp-google update
    /usr/local/bin/warp-google restart
    ;;
  upgrade)
    echo "[warp] upgrade: download -> syntax check -> install"
    tmp="$(mktemp)"
    if ! curl -fsSL "${REPO_RAW_URL}" -o "${tmp}"; then
      echo "[warp] download failed: ${REPO_RAW_URL}" >&2
      rm -f "${tmp}"
      exit 1
    fi
    chmod +x "${tmp}"
    if ! bash -n "${tmp}"; then
      echo "[warp] syntax check failed, keep file: ${tmp}" >&2
      exit 1
    fi
    bash "${tmp}" --install || bash "${tmp}"
    rm -f "${tmp}"
    echo "[warp] done"
    ;;
  uninstall)
    echo "请运行安装脚本的卸载入口（或手动清理）。"
    ;;
  *)
    echo "用法: warp {status|start|stop|restart|test|ip|update|upgrade}"
    ;;
esac
EOF
  chmod +x /usr/local/bin/warp
  success "warp 管理命令已创建"
}

#========================
# Install flow
#========================
do_install() {
  show_banner
  info "开始安装/覆盖升级 v${SCRIPT_VERSION} ..."
  log "install/upgrade v${SCRIPT_VERSION}"

  install_prereqs
  warn_firewall_backend
  install_warp_client

  setup_gai_conf
  write_redsocks_conf

  write_warp_google
  write_warp_cli

  configure_warp

  # Update ranges + start
  /usr/local/bin/warp-google update || warn "Google ranges 更新失败，将使用静态兜底"
  /usr/local/bin/warp-google restart || /usr/local/bin/warp-google start || true

  success "安装/升级完成！"
  echo -e "使用：${GREEN}warp status | warp test | warp update | warp upgrade${NC}"
}

do_uninstall() {
  show_banner
  warn "卸载入口建议仍用旧版 warp uninstall 的完整逻辑（可后续补齐）。"
  warn "当前脚本仅提供安装/升级与升级命令。"
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
  echo -e "  ${GREEN}1.${NC} 安装/升级（ipset版）"
  echo -e "  ${GREEN}3.${NC} 查看状态"
  echo -e "  ${GREEN}0.${NC} 退出\n"
  read -r -p "请输入选项 [0/1/3]: " choice
  case "${choice}" in
    1) do_install ;;
    3) do_status ;;
    0) echo "bye"; exit 0 ;;
    *) error "无效选项" ;;
  esac
}

#========================
# Main (single & robust)
#========================
main() {
  check_root
  detect_system

  case "${1:-}" in
    --install|install) do_install ;;
    --status|status) do_status ;;
    --uninstall|uninstall) do_uninstall ;;
    *) show_banner; show_menu ;;
  esac
}

main "$@"
