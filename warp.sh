#!/usr/bin/env bash
# WARP Script - Google unlock via Cloudflare WARP (ipset)
# Author: gzsteven666
#
# Usage:
#   Interactive:
#     bash <(curl -fsSL https://raw.githubusercontent.com/gzsteven666/warp-script/main/warp.sh)
#   Non-interactive install/upgrade:
#     bash <(curl -fsSL https://raw.githubusercontent.com/gzsteven666/warp-script/main/warp.sh) --install

set -euo pipefail

#========================
# Config
#========================
SCRIPT_VERSION="1.3.3"

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
log()     { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE" 2>/dev/null || true; }

# 修复：加 || true 防止 set -e 导致退出
check_root() {
  [[ ${EUID:-0} -ne 0 ]] && { error "请使用 root 运行！"; exit 1; } || true
}

show_banner() {
  clear 2>/dev/null || true
  echo -e "${CYAN}"
  echo "╔════════════════════════════════════════════════════╗"
  echo "║ 🌐 WARP Script - Google Unlock (ipset)            ║"
  echo "║ v${SCRIPT_VERSION}                                           ║"
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
    source /etc/os-release
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
  
  success "系统: ${OS} ${VERSION} (${CODENAME})"
}

warn_firewall_backend() {
  if systemctl is-active firewalld >/dev/null 2>&1; then
    warn "检测到 firewalld 正在运行，可能会冲掉 iptables 规则。"
  fi
  if iptables -V 2>/dev/null | grep -qi "nf_tables"; then
    warn "检测到 iptables 使用 nf_tables backend（兼容层）。"
  fi
}

#========================
# Install deps
#========================
install_prereqs() {
  info "安装依赖..."
  case "${OS}" in
    ubuntu|debian)
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -y >/dev/null 2>&1 || true
      apt-get install -y curl ca-certificates gnupg lsb-release iptables ipset python3 redsocks >/dev/null 2>&1 || {
        error "依赖安装失败"
        return 1
      }
      ;;
    centos|rhel|rocky|almalinux|fedora)
      if command -v dnf >/dev/null 2>&1; then
        dnf install -y epel-release >/dev/null 2>&1 || true
        dnf install -y curl ca-certificates iptables ipset python3 redsocks >/dev/null 2>&1 || true
      else
        yum install -y epel-release >/dev/null 2>&1 || true
        yum install -y curl ca-certificates iptables ipset python3 redsocks >/dev/null 2>&1 || true
      fi
      ;;
    *)
      error "不支持的系统：${OS}"
      exit 1
      ;;
  esac
  success "依赖安装完成"
}

install_warp_client() {
  if command -v warp-cli >/dev/null 2>&1; then
    success "已检测到 warp-cli，跳过安装"
    return 0
  fi

  info "安装 Cloudflare WARP..."
  case "${OS}" in
    ubuntu|debian)
      export DEBIAN_FRONTEND=noninteractive
      local arch
      arch="$(dpkg --print-architecture 2>/dev/null || echo amd64)"

      install -m 0755 -d /usr/share/keyrings
      curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg

      [[ -z "${CODENAME}" ]] && { error "无法获取系统代号 CODENAME"; return 1; } || true

      echo "deb [arch=${arch} signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ ${CODENAME} main" \
        > /etc/apt/sources.list.d/cloudflare-client.list

      apt-get update -y >/dev/null 2>&1
      apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" cloudflare-warp >/dev/null 2>&1 || {
        error "WARP 安装失败"
        return 1
      }
      ;;
    centos|rhel|rocky|almalinux|fedora)
      rpm --import https://pkg.cloudflareclient.com/pubkey.gpg 2>/dev/null || true
      cat > /etc/yum.repos.d/cloudflare-warp.repo <<'EOF'
[cloudflare-warp]
name=Cloudflare WARP
baseurl=https://pkg.cloudflareclient.com/rpm
enabled=1
gpgcheck=1
gpgkey=https://pkg.cloudflareclient.com/pubkey.gpg
EOF
      if command -v dnf >/dev/null 2>&1; then
        dnf install -y cloudflare-warp || { error "WARP 安装失败"; return 1; }
      else
        yum install -y cloudflare-warp || { error "WARP 安装失败"; return 1; }
      fi
      ;;
    *)
      error "不支持的系统：${OS}"
      return 1
      ;;
  esac

  command -v warp-cli >/dev/null 2>&1 || { error "WARP 安装失败：未找到 warp-cli"; return 1; }

  info "启动 warp-svc..."
  systemctl enable --now warp-svc >/dev/null 2>&1 || true
  success "WARP 就绪"
}

configure_warp() {
  info "配置 WARP..."
  warp-cli --accept-tos registration new >/dev/null 2>&1 || warp-cli --accept-tos register >/dev/null 2>&1 || true
  warp-cli --accept-tos tunnel protocol set MASQUE >/dev/null 2>&1 || warp-cli tunnel protocol set MASQUE >/dev/null 2>&1 || true
  warp-cli --accept-tos mode proxy >/dev/null 2>&1 || warp-cli mode proxy >/dev/null 2>&1 || true
  warp-cli --accept-tos proxy port "${WARP_PROXY_PORT}" >/dev/null 2>&1 || warp-cli proxy port "${WARP_PROXY_PORT}" >/dev/null 2>&1 || true
  warp-cli --accept-tos connect >/dev/null 2>&1 || warp-cli connect >/dev/null 2>&1 || true
  sleep 2
  
  local status
  status=$(warp-cli --accept-tos status 2>/dev/null || warp-cli status 2>/dev/null || echo "未知")
  info "WARP 状态：${status}"
}

setup_gai_conf() {
  if ! grep -qF "${GAI_MARK}" /etc/gai.conf 2>/dev/null; then
    {
      echo "${GAI_MARK}"
      echo "precedence ::ffff:0:0/96  100"
    } >> /etc/gai.conf
    success "已写入 /etc/gai.conf"
  fi
}

write_redsocks_conf() {
  info "写入 redsocks 配置..."
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
  info "创建 /usr/local/bin/warp-google..."
  mkdir -p "${CACHE_DIR}"

  cat > /usr/local/bin/warp-google <<'WARPGOOGLEEOF'
#!/usr/bin/env bash
set -euo pipefail

WARP_PROXY_PORT="${WARP_PROXY_PORT:-40000}"
REDSOCKS_PORT="${REDSOCKS_PORT:-12345}"

IPSET_NAME="${IPSET_NAME:-warp_google4}"
NAT_CHAIN="${NAT_CHAIN:-WARP_GOOGLE}"
QUIC_CHAIN="${QUIC_CHAIN:-WARP_GOOGLE_QUIC}"

CACHE_DIR="${CACHE_DIR:-/etc/warp-google}"
GOOG_JSON_URL="${GOOG_JSON_URL:-https://www.gstatic.com/ipranges/goog.json}"
IPV4_CACHE_FILE="${IPV4_CACHE_FILE:-/etc/warp-google/google_ipv4.txt}"

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

warp_connect() { warp-cli --accept-tos connect 2>/dev/null || warp-cli connect 2>/dev/null || true; }

start_redsocks() {
  pkill redsocks 2>/dev/null || true
  sleep 0.5
  redsocks -c /etc/redsocks.conf
}

ensure_ipset() { ipset create "${IPSET_NAME}" hash:net family inet -exist; }

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
  while IFS= read -r cidr; do
    [[ -z "${cidr}" ]] && continue
    ipset add "${IPSET_NAME}" "${cidr}" -exist 2>/dev/null || true
  done < <(load_ipv4_list)
}

iptables_apply() {
  # 清理旧规则
  iptables -t nat -D OUTPUT -j "${NAT_CHAIN}" 2>/dev/null || true
  iptables -t nat -F "${NAT_CHAIN}" 2>/dev/null || true
  iptables -t nat -X "${NAT_CHAIN}" 2>/dev/null || true
  iptables -t filter -D OUTPUT -j "${QUIC_CHAIN}" 2>/dev/null || true
  iptables -t filter -F "${QUIC_CHAIN}" 2>/dev/null || true
  iptables -t filter -X "${QUIC_CHAIN}" 2>/dev/null || true

  # NAT (单条 ipset 规则)
  iptables -t nat -N "${NAT_CHAIN}" 2>/dev/null || true
  iptables -t nat -F "${NAT_CHAIN}"
  iptables -t nat -A "${NAT_CHAIN}" -p tcp -m set --match-set "${IPSET_NAME}" dst -j REDIRECT --to-ports "${REDSOCKS_PORT}"
  iptables -t nat -I OUTPUT 1 -j "${NAT_CHAIN}"

  # QUIC 阻断
  iptables -t filter -N "${QUIC_CHAIN}" 2>/dev/null || true
  iptables -t filter -F "${QUIC_CHAIN}"
  iptables -t filter -A "${QUIC_CHAIN}" -p udp --dport 443 -m set --match-set "${IPSET_NAME}" dst -j REJECT
  iptables -t filter -I OUTPUT 1 -j "${QUIC_CHAIN}"
}

update() {
  info "更新 Google IPv4 段..."
  mkdir -p "${CACHE_DIR}"
  local tmp
  tmp="$(mktemp)"
  
  if ! curl -fsSL "${GOOG_JSON_URL}" -o "${tmp}"; then
    info "下载失败，使用静态列表"
    rm -f "${tmp}"
    return 1
  fi
  
  if command -v python3 >/dev/null 2>&1; then
    python3 -c "
import json
with open('${tmp}', 'r') as f:
    data = json.load(f)
prefixes = sorted({p['ipv4Prefix'] for p in data.get('prefixes', []) if 'ipv4Prefix' in p})
print('\n'.join(prefixes))
" > "${IPV4_CACHE_FILE}" 2>/dev/null || {
      info "Python 解析失败，使用 grep"
      grep -oE '"ipv4Prefix"\s*:\s*"[^"]+"' "${tmp}" | sed -E 's/.*"([^"]+)".*/\1/' | sort -u > "${IPV4_CACHE_FILE}"
    }
  else
    grep -oE '"ipv4Prefix"\s*:\s*"[^"]+"' "${tmp}" | sed -E 's/.*"([^"]+)".*/\1/' | sort -u > "${IPV4_CACHE_FILE}"
  fi
  
  rm -f "${tmp}"
  
  if [[ -s "${IPV4_CACHE_FILE}" ]]; then
    info "已更新：${IPV4_CACHE_FILE}（$(wc -l < "${IPV4_CACHE_FILE}") 条）"
  else
    info "更新失败，将使用静态列表"
    return 1
  fi
}

start() {
  info "启动..."
  warp_connect
  start_redsocks
  ipset_apply
  iptables_apply
  info "完成"
}

stop() {
  info "停止..."
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
  echo "=== ipset ==="
  ipset list "${IPSET_NAME}" 2>/dev/null | head -n 20 || echo "ipset 不存在"
  echo
  echo "=== NAT 规则 ==="
  iptables -t nat -S "${NAT_CHAIN}" 2>/dev/null || echo "无"
  echo
  echo "=== QUIC 阻断 ==="
  iptables -t filter -S "${QUIC_CHAIN}" 2>/dev/null || echo "无"
  echo
  echo "=== redsocks ==="
  pgrep -x redsocks >/dev/null && echo "运行中" || echo "未运行"
}

case "${1:-}" in
  update) update ;;
  start) start ;;
  stop) stop ;;
  restart) stop; sleep 0.5; start ;;
  status) status ;;
  *) echo "用法: warp-google {update|start|stop|restart|status}" ;;
esac
WARPGOOGLEEOF

  chmod +x /usr/local/bin/warp-google
  success "warp-google 已创建"
}

#========================
# /usr/local/bin/warp
#========================
write_warp_cli() {
  info "创建 /usr/local/bin/warp..."
  
  cat > /usr/local/bin/warp <<EOF
#!/usr/bin/env bash
set -euo pipefail

WARP_PROXY_PORT="${WARP_PROXY_PORT}"
REPO_RAW_URL="${REPO_RAW_URL}"
GAI_MARK="${GAI_MARK}"

case "\${1:-}" in
  status)
    echo "=== WARP 状态 ==="
    warp-cli status 2>/dev/null || echo "未运行"
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
    echo "=== Google 连接测试 ==="
    curl -s --max-time 10 -o /dev/null -w "状态码: %{http_code}\n" https://www.google.com || echo "失败"
    echo
    echo "=== WARP Trace ==="
    curl -s --max-time 10 -x "socks5h://127.0.0.1:\${WARP_PROXY_PORT}" https://www.cloudflare.com/cdn-cgi/trace | grep -E "^warp=" || echo "未检测到"
    ;;
  ip)
    echo "直连 IP:"
    curl -4 -s --max-time 8 ip.sb || echo "获取失败"
    echo
    echo "WARP IP:"
    curl -s --max-time 8 -x "socks5h://127.0.0.1:\${WARP_PROXY_PORT}" ip.sb || echo "获取失败"
    echo
    ;;
  update)
    /usr/local/bin/warp-google update
    /usr/local/bin/warp-google restart
    ;;
  upgrade)
    echo "[warp] 升级中..."
    tmp="\$(mktemp)"
    if ! curl -fsSL "\${REPO_RAW_URL}" -o "\${tmp}"; then
      echo "[warp] 下载失败" >&2
      rm -f "\${tmp}"
      exit 1
    fi
    chmod +x "\${tmp}"
    if ! bash -n "\${tmp}"; then
      echo "[warp] 语法检查失败" >&2
      rm -f "\${tmp}"
      exit 1
    fi
    bash "\${tmp}" --install
    rm -f "\${tmp}"
    echo "[warp] 升级完成"
    ;;
  uninstall)
    read -r -p "确定要卸载？[y/N]: " confirm
    [[ "\${confirm}" =~ ^[Yy]$ ]] || { echo "已取消"; exit 0; }
    
    echo "正在卸载..."
    /usr/local/bin/warp-google stop 2>/dev/null || true
    warp-cli disconnect 2>/dev/null || true
    systemctl disable --now warp-google 2>/dev/null || true
    systemctl disable --now warp-svc 2>/dev/null || true
    
    rm -f /etc/systemd/system/warp-google.service
    rm -f /usr/local/bin/warp-google
    rm -f /etc/redsocks.conf
    rm -rf /etc/warp-google
    systemctl daemon-reload 2>/dev/null || true
    
    # 清理 iptables
    iptables -t nat -D OUTPUT -j WARP_GOOGLE 2>/dev/null || true
    iptables -t nat -F WARP_GOOGLE 2>/dev/null || true
    iptables -t nat -X WARP_GOOGLE 2>/dev/null || true
    iptables -t filter -D OUTPUT -j WARP_GOOGLE_QUIC 2>/dev/null || true
    iptables -t filter -F WARP_GOOGLE_QUIC 2>/dev/null || true
    iptables -t filter -X WARP_GOOGLE_QUIC 2>/dev/null || true
    
    # 清理 ipset
    ipset destroy warp_google4 2>/dev/null || true
    
    # 恢复 gai.conf
    sed -i "/\${GAI_MARK}/,+1d" /etc/gai.conf 2>/dev/null || true
    
    # 卸载软件包
    if [[ -f /etc/os-release ]]; then
      source /etc/os-release
      case "\${ID:-}" in
        ubuntu|debian)
          apt-get remove -y cloudflare-warp redsocks 2>/dev/null || true
          rm -f /etc/apt/sources.list.d/cloudflare-client.list
          rm -f /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
          ;;
        centos|rhel|rocky|almalinux|fedora)
          (command -v dnf && dnf remove -y cloudflare-warp redsocks) || yum remove -y cloudflare-warp redsocks 2>/dev/null || true
          rm -f /etc/yum.repos.d/cloudflare-warp.repo
          ;;
      esac
    fi
    
    rm -f /usr/local/bin/warp
    echo "卸载完成"
    ;;
  *)
    echo "WARP 管理工具 v${SCRIPT_VERSION:-1.3.3}"
    echo
    echo "用法: warp <命令>"
    echo
    echo "命令:"
    echo "  status    查看状态"
    echo "  start     启动"
    echo "  stop      停止"
    echo "  restart   重启"
    echo "  test      测试连接"
    echo "  ip        查看 IP"
    echo "  update    更新 Google IP 段"
    echo "  upgrade   升级脚本"
    echo "  uninstall 卸载"
    ;;
esac
EOF

  chmod +x /usr/local/bin/warp
  success "warp 管理命令已创建"
}

#========================
# systemd service
#========================
write_systemd_service() {
  info "创建 systemd 服务..."
  cat > /etc/systemd/system/warp-google.service <<'EOF'
[Unit]
Description=WARP Google Transparent Proxy
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

  systemctl daemon-reload
  systemctl enable warp-google 2>/dev/null || true
  success "systemd 服务已创建"
}

#========================
# Install flow
#========================
do_install() {
  show_banner
  info "开始安装 v${SCRIPT_VERSION} ..."
  log "install v${SCRIPT_VERSION}"

  install_prereqs
  warn_firewall_backend
  install_warp_client

  setup_gai_conf
  write_redsocks_conf

  write_warp_google
  write_warp_cli
  write_systemd_service

  configure_warp

  # 更新 IP 段并启动
  /usr/local/bin/warp-google update || warn "Google IP 更新失败，使用静态列表"
  /usr/local/bin/warp-google start || true

  echo
  success "安装完成！"
  echo -e "\n管理命令: ${GREEN}warp {status|start|stop|restart|test|ip|update|upgrade|uninstall}${NC}\n"
  
  # 测试
  echo -e "${CYAN}测试连接...${NC}"
  sleep 2
  local code
  code=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" https://www.google.com || echo "000")
  if [[ "${code}" == "200" ]]; then
    success "Google 连接成功！"
  else
    warn "Google 测试返回: ${code}"
  fi
  
  local warp_trace
  warp_trace=$(curl -s --max-time 10 -x "socks5h://127.0.0.1:${WARP_PROXY_PORT}" https://www.cloudflare.com/cdn-cgi/trace | grep -E "^warp=" || true)
  if [[ -n "${warp_trace}" ]]; then
    echo -e "WARP Trace: ${GREEN}${warp_trace}${NC}"
  fi
}

do_uninstall() {
  show_banner
  /usr/local/bin/warp uninstall 2>/dev/null || warn "请手动运行: warp uninstall"
}

do_status() {
  if command -v warp >/dev/null 2>&1; then
    warp status
  else
    echo "未安装。请运行: --install"
  fi
}

show_menu() {
  echo -e "${YELLOW}请选择操作:${NC}\n"
  echo -e "  ${GREEN}1.${NC} 安装/升级"
  echo -e "  ${GREEN}2.${NC} 卸载"
  echo -e "  ${GREEN}3.${NC} 查看状态"
  echo -e "  ${GREEN}0.${NC} 退出\n"
  
  read -r -p "请输入选项 [0-3]: " choice
  case "${choice}" in
    1) do_install ;;
    2) do_uninstall ;;
    3) do_status ;;
    0) echo "再见！"; exit 0 ;;
    *) error "无效选项" ;;
  esac
}

#========================
# Main
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
