#!/usr/bin/env bash
# WARP Script - Google unlock via Cloudflare WARP (ipset)
# Author: gzsteven666
# Version: 1.4.0
#
# 使用方法:
#   bash <(curl -fsSL https://raw.githubusercontent.com/gzsteven666/warp-script/main/warp.sh)

set -euo pipefail

SCRIPT_VERSION="1.4.0"

WARP_PROXY_PORT="${WARP_PROXY_PORT:-40000}"
REDSOCKS_PORT="${REDSOCKS_PORT:-12345}"

REPO_RAW_URL="${REPO_RAW_URL:-https://raw.githubusercontent.com/gzsteven666/warp-script/main/warp.sh}"
REPO_SHA256_URL="${REPO_SHA256_URL:-${REPO_RAW_URL}.sha256}"
LOG_FILE="${LOG_FILE:-/var/log/warp-install.log}"

GAI_MARK="# warp-script: prefer ipv4"
IPSET_NAME="${IPSET_NAME:-warp_google4}"
NAT_CHAIN="${NAT_CHAIN:-WARP_GOOGLE}"
QUIC_CHAIN="${QUIC_CHAIN:-WARP_GOOGLE_QUIC}"

CACHE_DIR="/etc/warp-google"
GOOG_JSON_URL="https://www.gstatic.com/ipranges/goog.json"
IPV4_CACHE_FILE="${CACHE_DIR}/google_ipv4.txt"
DNS_MODE_FILE="${CACHE_DIR}/dns_mode"
DNS_BACKUP_FILE="/etc/resolv.conf.warp-backup"
RESOLVED_DROPIN_DIR="/etc/systemd/resolved.conf.d"
RESOLVED_DROPIN_FILE="${RESOLVED_DROPIN_DIR}/99-warp-cloudflare.conf"

WARP_KEEPALIVE_LOCK="${WARP_KEEPALIVE_LOCK:-/run/warp-keepalive.lock}"
WARP_UPDATE_LOCK="${WARP_UPDATE_LOCK:-/run/warp-google-update.lock}"

STATIC_GOOGLE_IPV4_CIDRS="
8.8.4.0/24
8.8.8.0/24
8.34.208.0/20
8.35.192.0/20
23.236.48.0/20
23.251.128.0/19
34.0.0.0/9
35.184.0.0/13
35.192.0.0/12
35.224.0.0/12
35.240.0.0/13
64.18.0.0/20
64.233.160.0/19
66.102.0.0/20
66.249.64.0/19
70.32.128.0/19
72.14.192.0/18
74.114.24.0/21
74.125.0.0/16
104.132.0.0/14
104.154.0.0/15
104.196.0.0/14
104.237.160.0/19
107.167.160.0/19
107.178.192.0/18
108.59.80.0/20
108.170.192.0/18
108.177.0.0/17
130.211.0.0/16
136.112.0.0/12
142.250.0.0/15
146.148.0.0/17
162.216.148.0/22
162.222.176.0/21
172.110.32.0/21
172.217.0.0/16
172.253.0.0/16
173.194.0.0/16
173.255.112.0/20
192.158.28.0/22
192.178.0.0/15
193.186.4.0/24
199.36.154.0/23
199.36.156.0/24
199.192.112.0/22
199.223.232.0/21
203.208.0.0/14
207.223.160.0/20
208.65.152.0/22
208.68.108.0/22
208.81.188.0/22
208.117.224.0/19
209.85.128.0/17
216.58.192.0/19
216.73.80.0/20
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
log()     { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE" 2>/dev/null || true; }

command_exists() { command -v "$1" >/dev/null 2>&1; }

check_root() {
  [[ ${EUID:-0} -ne 0 ]] && { error "请使用 root 运行"; exit 1; } || true
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
    error "无法检测系统"
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

setup_cloudflare_dns() {
  info "配置 Cloudflare DNS..."
  mkdir -p "${CACHE_DIR}"

  if command_exists systemctl && systemctl list-unit-files 2>/dev/null | grep -q '^systemd-resolved\.service'; then
    mkdir -p "${RESOLVED_DROPIN_DIR}"
    cat > "${RESOLVED_DROPIN_FILE}" <<'EOF_DNS'
[Resolve]
DNS=1.1.1.1 1.0.0.1
FallbackDNS=1.1.1.1 1.0.0.1
DNSStubListener=yes
EOF_DNS

    if command_exists resolvectl; then
      while read -r iface; do
        [[ -n "${iface}" ]] || continue
        resolvectl dns "${iface}" 1.1.1.1 1.0.0.1 >/dev/null 2>&1 || true
      done < <(ip -o -4 route show to default 2>/dev/null | awk '{print $5}' | sort -u)
    fi

    systemctl restart systemd-resolved >/dev/null 2>&1 || true
    echo "resolved" > "${DNS_MODE_FILE}"
    success "已通过 systemd-resolved 配置 DNS"
    return 0
  fi

  if [[ -f /etc/resolv.conf ]] && ! [[ -L /etc/resolv.conf ]]; then
    cp /etc/resolv.conf "${DNS_BACKUP_FILE}" 2>/dev/null || true
  fi

  cat > /etc/resolv.conf <<'EOF_DNS_FILE'
nameserver 1.1.1.1
nameserver 1.0.0.1
options timeout:2 attempts:3 rotate
EOF_DNS_FILE

  echo "file" > "${DNS_MODE_FILE}"
  success "DNS 已配置为 Cloudflare"
}

restore_dns() {
  local mode=""
  mode="$(cat "${DNS_MODE_FILE}" 2>/dev/null || true)"

  case "${mode}" in
    resolved)
      if command_exists resolvectl; then
        while read -r iface; do
          [[ -n "${iface}" ]] || continue
          resolvectl revert "${iface}" >/dev/null 2>&1 || true
        done < <(ip -o -4 route show to default 2>/dev/null | awk '{print $5}' | sort -u)
      fi
      rm -f "${RESOLVED_DROPIN_FILE}"
      command_exists systemctl && systemctl restart systemd-resolved >/dev/null 2>&1 || true
      ;;
    file)
      if [[ -f "${DNS_BACKUP_FILE}" ]]; then
        mv "${DNS_BACKUP_FILE}" /etc/resolv.conf 2>/dev/null || true
      fi
      ;;
  esac

  rm -f "${DNS_MODE_FILE}"
}

install_prereqs() {
  info "安装依赖..."
  case "${OS}" in
    ubuntu|debian)
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -y >/dev/null 2>&1 || true
      apt-get install -y curl ca-certificates gnupg lsb-release iptables ipset python3 redsocks dnsutils util-linux cron >/dev/null 2>&1 || {
        error "依赖安装失败"
        return 1
      }
      ;;
    centos|rhel|rocky|almalinux|fedora)
      if command_exists dnf; then
        dnf install -y epel-release >/dev/null 2>&1 || true
        dnf install -y curl ca-certificates iptables ipset python3 redsocks bind-utils util-linux cronie >/dev/null 2>&1 || true
      else
        yum install -y epel-release >/dev/null 2>&1 || true
        yum install -y curl ca-certificates iptables ipset python3 redsocks bind-utils util-linux cronie >/dev/null 2>&1 || true
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
  if command_exists warp-cli; then
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

      [[ -z "${CODENAME}" ]] && { error "无法获取 CODENAME"; return 1; } || true

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
      cat > /etc/yum.repos.d/cloudflare-warp.repo <<'EOF_REPO'
[cloudflare-warp]
name=Cloudflare WARP
baseurl=https://pkg.cloudflareclient.com/rpm
enabled=1
gpgcheck=1
gpgkey=https://pkg.cloudflareclient.com/pubkey.gpg
EOF_REPO
      if command_exists dnf; then
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

  command_exists warp-cli || { error "未找到 warp-cli"; return 1; }

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
    success "已配置 IPv4 优先"
  fi
}

write_redsocks_conf() {
  info "配置 redsocks..."
  cat > /etc/redsocks.conf <<EOF_REDSOCKS
base {
  log_debug = off;
  log_info = on;
  log = "syslog:daemon";
  daemon = off;
  redirector = iptables;
}
redsocks {
  local_ip = 127.0.0.1;
  local_port = ${REDSOCKS_PORT};
  ip = 127.0.0.1;
  port = ${WARP_PROXY_PORT};
  type = socks5;
}
EOF_REDSOCKS
  success "redsocks 配置完成"
}

write_redsocks_service() {
  info "创建 redsocks systemd 服务..."
  local redsocks_bin
  redsocks_bin="$(command -v redsocks || echo /usr/sbin/redsocks)"

  cat > /etc/systemd/system/redsocks.service <<EOF_REDSOCKS_SERVICE
[Unit]
Description=Redsocks transparent proxy daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${redsocks_bin} -c /etc/redsocks.conf
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF_REDSOCKS_SERVICE

  systemctl daemon-reload
  systemctl enable --now redsocks >/dev/null 2>&1 || true
  success "redsocks 服务已创建"
}

write_keepalive() {
  info "创建 keepalive 脚本与 systemd timer..."

  cat > /usr/local/bin/warp-keepalive <<'EOF_KEEPALIVE'
#!/usr/bin/env bash
set -euo pipefail

LOG_TAG="warp-keepalive"
WARP_PROXY_PORT="${WARP_PROXY_PORT:-40000}"
LOCK_FILE="${WARP_KEEPALIVE_LOCK:-/run/warp-keepalive.lock}"

exec 9>"${LOCK_FILE}"
if ! flock -n 9; then
  exit 0
fi

restart_redsocks() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl restart redsocks >/dev/null 2>&1 && return 0
  fi
  pkill -x redsocks 2>/dev/null || true
  sleep 1
  redsocks -c /etc/redsocks.conf >/dev/null 2>&1 &
}

if ! curl -s --max-time 10 -x "socks5h://127.0.0.1:${WARP_PROXY_PORT}" -o /dev/null https://www.google.com; then
  logger -t "${LOG_TAG}" "WARP proxy test failed, trying to reconnect..."
  warp-cli disconnect 2>/dev/null || true
  sleep 2
  warp-cli connect 2>/dev/null || true
  sleep 3
fi

if ! curl -s --max-time 10 -o /dev/null https://www.google.com; then
  logger -t "${LOG_TAG}" "Transparent proxy failed, restarting redsocks..."
  restart_redsocks
  logger -t "${LOG_TAG}" "redsocks restarted"
fi
EOF_KEEPALIVE

  chmod +x /usr/local/bin/warp-keepalive

  cat > /etc/systemd/system/warp-keepalive.service <<'EOF_KEEPALIVE_SERVICE'
[Unit]
Description=WARP keepalive check
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/warp-keepalive
EOF_KEEPALIVE_SERVICE

  cat > /etc/systemd/system/warp-keepalive.timer <<'EOF_KEEPALIVE_TIMER'
[Unit]
Description=Run WARP keepalive every 10 minutes

[Timer]
OnBootSec=3min
OnUnitActiveSec=10min
Persistent=true

[Install]
WantedBy=timers.target
EOF_KEEPALIVE_TIMER

  systemctl daemon-reload
  systemctl enable --now warp-keepalive.timer >/dev/null 2>&1 || true

  if command_exists crontab; then
    (crontab -l 2>/dev/null | grep -v warp-keepalive || true) | crontab - 2>/dev/null || true
  fi

  success "keepalive 已配置（systemd timer 每 10 分钟检测）"
}

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
UPDATE_LOCK="${WARP_UPDATE_LOCK:-/run/warp-google-update.lock}"

STATIC_GOOGLE_IPV4_CIDRS="
8.8.4.0/24
8.8.8.0/24
8.34.208.0/20
8.35.192.0/20
23.236.48.0/20
23.251.128.0/19
34.0.0.0/9
35.184.0.0/13
35.192.0.0/12
35.224.0.0/12
35.240.0.0/13
64.18.0.0/20
64.233.160.0/19
66.102.0.0/20
66.249.64.0/19
70.32.128.0/19
72.14.192.0/18
74.114.24.0/21
74.125.0.0/16
104.132.0.0/14
104.154.0.0/15
104.196.0.0/14
104.237.160.0/19
107.167.160.0/19
107.178.192.0/18
108.59.80.0/20
108.170.192.0/18
108.177.0.0/17
130.211.0.0/16
136.112.0.0/12
142.250.0.0/15
146.148.0.0/17
162.216.148.0/22
162.222.176.0/21
172.110.32.0/21
172.217.0.0/16
172.253.0.0/16
173.194.0.0/16
173.255.112.0/20
192.158.28.0/22
192.178.0.0/15
193.186.4.0/24
199.36.154.0/23
199.36.156.0/24
199.192.112.0/22
199.223.232.0/21
203.208.0.0/14
207.223.160.0/20
208.65.152.0/22
208.68.108.0/22
208.81.188.0/22
208.117.224.0/19
209.85.128.0/17
216.58.192.0/19
216.73.80.0/20
216.239.32.0/19
"

info() { echo "[warp-google] $*"; }

warp_connect() { warp-cli --accept-tos connect 2>/dev/null || warp-cli connect 2>/dev/null || true; }

start_redsocks() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl restart redsocks >/dev/null 2>&1 || systemctl start redsocks >/dev/null 2>&1 || true
  else
    pkill -x redsocks 2>/dev/null || true
    sleep 0.5
    redsocks -c /etc/redsocks.conf >/dev/null 2>&1 &
  fi
}

stop_redsocks() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl stop redsocks >/dev/null 2>&1 || true
  else
    pkill -x redsocks 2>/dev/null || true
  fi
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
  local tmp_set="${IPSET_NAME}_tmp"
  ipset create "${tmp_set}" hash:net family inet -exist
  ipset flush "${tmp_set}" || true

  while IFS= read -r cidr; do
    [[ -z "${cidr}" ]] && continue
    ipset add "${tmp_set}" "${cidr}" -exist 2>/dev/null || true
  done < <(load_ipv4_list)

  ipset swap "${tmp_set}" "${IPSET_NAME}" || true
  ipset destroy "${tmp_set}" 2>/dev/null || true
}

iptables_apply() {
  iptables -t nat -D OUTPUT -j "${NAT_CHAIN}" 2>/dev/null || true
  iptables -t nat -F "${NAT_CHAIN}" 2>/dev/null || true
  iptables -t nat -X "${NAT_CHAIN}" 2>/dev/null || true
  iptables -t filter -D OUTPUT -j "${QUIC_CHAIN}" 2>/dev/null || true
  iptables -t filter -F "${QUIC_CHAIN}" 2>/dev/null || true
  iptables -t filter -X "${QUIC_CHAIN}" 2>/dev/null || true

  iptables -t nat -N "${NAT_CHAIN}" 2>/dev/null || true
  iptables -t nat -F "${NAT_CHAIN}"
  iptables -t nat -A "${NAT_CHAIN}" -p tcp -m set --match-set "${IPSET_NAME}" dst -j REDIRECT --to-ports "${REDSOCKS_PORT}"
  iptables -t nat -I OUTPUT 1 -j "${NAT_CHAIN}"

  iptables -t filter -N "${QUIC_CHAIN}" 2>/dev/null || true
  iptables -t filter -F "${QUIC_CHAIN}"
  iptables -t filter -A "${QUIC_CHAIN}" -p udp --dport 443 -m set --match-set "${IPSET_NAME}" dst -j REJECT
  iptables -t filter -I OUTPUT 1 -j "${QUIC_CHAIN}"
}

update() {
  exec 200>"${UPDATE_LOCK}"
  if ! flock -n 200; then
    info "已有更新任务在执行，跳过"
    return 0
  fi

  info "更新 Google IP 段..."
  mkdir -p "${CACHE_DIR}"
  local tmp
  tmp="$(mktemp)"

  if ! curl -fsSL -x "socks5h://127.0.0.1:${WARP_PROXY_PORT}" --max-time 30 "${GOOG_JSON_URL}" -o "${tmp}" 2>/dev/null; then
    if ! curl -fsSL --max-time 30 "${GOOG_JSON_URL}" -o "${tmp}" 2>/dev/null; then
      info "下载失败，使用静态列表"
      rm -f "${tmp}"
      return 1
    fi
  fi

  if command -v python3 >/dev/null 2>&1; then
    python3 -c "
import json
with open('${tmp}', 'r', encoding='utf-8') as f:
    data = json.load(f)
prefixes = sorted({p['ipv4Prefix'] for p in data.get('prefixes', []) if 'ipv4Prefix' in p})
print('\\n'.join(prefixes))
" > "${IPV4_CACHE_FILE}" 2>/dev/null || {
      grep -oE '"ipv4Prefix"\s*:\s*"[^"]+"' "${tmp}" | sed -E 's/.*"([^"]+)".*/\1/' | sort -u > "${IPV4_CACHE_FILE}"
    }
  else
    grep -oE '"ipv4Prefix"\s*:\s*"[^"]+"' "${tmp}" | sed -E 's/.*"([^"]+)".*/\1/' | sort -u > "${IPV4_CACHE_FILE}"
  fi

  rm -f "${tmp}"

  if [[ -s "${IPV4_CACHE_FILE}" ]]; then
    info "已更新：$(wc -l < "${IPV4_CACHE_FILE}") 条 IP 段"
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
  stop_redsocks
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
  ipset list "${IPSET_NAME}" 2>/dev/null | head -n 15 || echo "不存在"
  echo
  echo "=== NAT 规则 ==="
  iptables -t nat -S "${NAT_CHAIN}" 2>/dev/null || echo "无"
  echo
  echo "=== QUIC 阻断 ==="
  iptables -t filter -S "${QUIC_CHAIN}" 2>/dev/null || echo "无"
  echo
  echo "=== redsocks ==="
  if command -v systemctl >/dev/null 2>&1; then
    systemctl is-active --quiet redsocks && echo "运行中(systemd)" || echo "未运行"
  else
    pgrep -x redsocks >/dev/null && echo "运行中" || echo "未运行"
  fi
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

write_warp_cli() {
  info "创建 /usr/local/bin/warp..."

  cat > /usr/local/bin/warp <<EOF_WARPCLI
#!/usr/bin/env bash
set -euo pipefail

WARP_PROXY_PORT="${WARP_PROXY_PORT}"
REPO_RAW_URL="${REPO_RAW_URL}"
REPO_SHA256_URL="${REPO_SHA256_URL}"
GAI_MARK="${GAI_MARK}"
SCRIPT_VERSION="${SCRIPT_VERSION}"
DNS_MODE_FILE="${DNS_MODE_FILE}"
RESOLVED_DROPIN_FILE="${RESOLVED_DROPIN_FILE}"
SHA256SUM_BIN="\$(command -v sha256sum 2>/dev/null || command -v shasum 2>/dev/null || true)"

verify_checksum() {
  local file="\$1"
  local sum_file="\$2"
  local expected actual

  if [[ "\${WARP_SKIP_CHECKSUM:-0}" == "1" ]]; then
    echo "[warp] 已跳过校验 (WARP_SKIP_CHECKSUM=1)"
    return 0
  fi

  [[ -n "\${SHA256SUM_BIN}" ]] || { echo "[warp] 未找到 sha256 工具，拒绝升级" >&2; return 1; }

  expected="\$(awk '{print \$1}' "\${sum_file}" | head -n1)"
  [[ -n "\${expected}" ]] || { echo "[warp] 校验文件格式无效" >&2; return 1; }

  if [[ "\${SHA256SUM_BIN}" == *shasum ]]; then
    actual="\$(shasum -a 256 "\${file}" | awk '{print \$1}')"
  else
    actual="\$(sha256sum "\${file}" | awk '{print \$1}')"
  fi

  [[ "\${actual}" == "\${expected}" ]] || {
    echo "[warp] SHA256 校验失败" >&2
    echo "[warp] expected=\${expected}" >&2
    echo "[warp] actual=\${actual}" >&2
    return 1
  }

  echo "[warp] SHA256 校验通过"
}

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
    curl -s --max-time 10 -o /dev/null -w "状态码: %{http_code}\\n" https://www.google.com || echo "失败"
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
    sum_tmp="\$(mktemp)"

    if ! curl -fsSL "\${REPO_RAW_URL}" -o "\${tmp}"; then
      echo "[warp] 下载失败" >&2
      rm -f "\${tmp}" "\${sum_tmp}"
      exit 1
    fi

    if ! curl -fsSL "\${REPO_SHA256_URL}" -o "\${sum_tmp}"; then
      echo "[warp] 无法下载校验文件：\${REPO_SHA256_URL}" >&2
      rm -f "\${tmp}" "\${sum_tmp}"
      exit 1
    fi

    verify_checksum "\${tmp}" "\${sum_tmp}" || { rm -f "\${tmp}" "\${sum_tmp}"; exit 1; }

    chmod +x "\${tmp}"
    if ! bash -n "\${tmp}"; then
      echo "[warp] 语法检查失败" >&2
      rm -f "\${tmp}" "\${sum_tmp}"
      exit 1
    fi

    bash "\${tmp}" --install
    rm -f "\${tmp}" "\${sum_tmp}"
    echo "[warp] 升级完成"
    ;;
  uninstall)
    read -r -p "确定要卸载？[y/N]: " confirm
    [[ "\${confirm}" =~ ^[Yy]$ ]] || { echo "已取消"; exit 0; }

    echo "正在卸载..."
    /usr/local/bin/warp-google stop 2>/dev/null || true
    warp-cli disconnect 2>/dev/null || true

    systemctl disable --now warp-keepalive.timer 2>/dev/null || true
    systemctl disable --now warp-keepalive.service 2>/dev/null || true
    systemctl disable --now warp-google 2>/dev/null || true
    systemctl disable --now redsocks 2>/dev/null || true
    systemctl disable --now warp-svc 2>/dev/null || true

    rm -f /etc/systemd/system/warp-keepalive.timer
    rm -f /etc/systemd/system/warp-keepalive.service
    rm -f /etc/systemd/system/warp-google.service
    rm -f /etc/systemd/system/redsocks.service

    rm -f /usr/local/bin/warp-google
    rm -f /usr/local/bin/warp-keepalive
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

    sed -i "/\${GAI_MARK}/,+1d" /etc/gai.conf 2>/dev/null || true

    if [[ -f "\${DNS_MODE_FILE}" ]]; then
      mode="\$(cat "\${DNS_MODE_FILE}" 2>/dev/null || true)"
      if [[ "\${mode}" == "resolved" ]]; then
        rm -f "\${RESOLVED_DROPIN_FILE}"
        systemctl restart systemd-resolved 2>/dev/null || true
      fi
      rm -f "\${DNS_MODE_FILE}"
    fi

    if [[ -f /etc/resolv.conf.warp-backup ]]; then
      mv /etc/resolv.conf.warp-backup /etc/resolv.conf 2>/dev/null || true
      echo "已恢复原 DNS 配置"
    fi

    if [[ -f /etc/os-release ]]; then
      # shellcheck disable=SC1091
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
    echo "WARP 管理工具 v\${SCRIPT_VERSION}"
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
    echo "  upgrade   升级脚本（含 SHA256 校验）"
    echo "  uninstall 卸载"
    ;;
esac
EOF_WARPCLI

  chmod +x /usr/local/bin/warp
  success "warp 管理命令已创建"
}

write_systemd_service() {
  info "创建 systemd 服务..."
  cat > /etc/systemd/system/warp-google.service <<'EOF_WARP_SERVICE'
[Unit]
Description=WARP Google Transparent Proxy
After=network-online.target warp-svc.service redsocks.service
Wants=network-online.target warp-svc.service redsocks.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/warp-google start
ExecStop=/usr/local/bin/warp-google stop

[Install]
WantedBy=multi-user.target
EOF_WARP_SERVICE

  systemctl daemon-reload
  systemctl enable warp-google 2>/dev/null || true
  success "systemd 服务已创建"
}

do_install() {
  show_banner
  info "开始安装 v${SCRIPT_VERSION} ..."
  log "install v${SCRIPT_VERSION}"

  install_prereqs
  setup_cloudflare_dns
  install_warp_client

  setup_gai_conf
  write_redsocks_conf
  write_redsocks_service

  write_warp_google
  write_warp_cli
  write_keepalive
  write_systemd_service

  configure_warp

  /usr/local/bin/warp-google update || warn "Google IP 更新失败，使用静态列表"
  /usr/local/bin/warp-google start || true

  echo
  success "安装完成"
  echo -e "\n管理命令: ${GREEN}warp {status|start|stop|restart|test|ip|update|upgrade|uninstall}${NC}\n"

  echo -e "${CYAN}测试连接...${NC}"
  sleep 2
  local code
  code=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" https://www.google.com || echo "000")
  if [[ "${code}" == "200" ]]; then
    success "Google 连接成功"
  else
    warn "Google 测试返回: ${code}"
  fi
}

do_status() {
  if command_exists warp; then
    warp status
  else
    echo "未安装"
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
    2) /usr/local/bin/warp uninstall 2>/dev/null || warn "请先安装" ;;
    3) do_status ;;
    0) echo "再见"; exit 0 ;;
    *) error "无效选项" ;;
  esac
}

main() {
  check_root
  detect_system

  case "${1:-}" in
    --install|install) do_install ;;
    --status|status) do_status ;;
    *) show_banner; show_menu ;;
  esac
}

main "$@"
