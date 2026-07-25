#!/usr/bin/env bash
# WARP Script - Selective Gemini and Netflix unlock via Cloudflare WARP
# Author: gzsteven666
# Version: 2.0.2
#
# 使用方法:
#   bash <(curl -fsSL https://raw.githubusercontent.com/gzsteven666/warp-script/main/warp.sh)

set -euo pipefail

SCRIPT_VERSION="2.0.2"

WARP_PROXY_PORT="${WARP_PROXY_PORT:-40000}"
REDSOCKS_PORT="${REDSOCKS_PORT:-12345}"

REPO_RAW_URL="${REPO_RAW_URL:-https://raw.githubusercontent.com/gzsteven666/warp-script/main/warp.sh}"
REPO_SHA256_URL="${REPO_SHA256_URL:-${REPO_RAW_URL}.sha256}"
LOG_FILE="${LOG_FILE:-/var/log/warp-install.log}"

GAI_MARK="# warp-script: prefer ipv4"
IPSET_NAME="${IPSET_NAME:-warp_google4}"
NAT_CHAIN="${NAT_CHAIN:-WARP_GOOGLE}"
QUIC_CHAIN="${QUIC_CHAIN:-WARP_GOOGLE_QUIC}"

NETFLIX_IPSET_NAME="${NETFLIX_IPSET_NAME:-warp_netflix4}"
NETFLIX_NAT_CHAIN="${NETFLIX_NAT_CHAIN:-WARP_NETFLIX}"
NETFLIX_QUIC_CHAIN="${NETFLIX_QUIC_CHAIN:-WARP_NETFLIX_QUIC}"

CACHE_DIR="/etc/warp-google"
ROUTING_MODE_FILE="${CACHE_DIR}/routing_mode"
SINGBOX_CONFIG_FILE="${CACHE_DIR}/singbox_config"
GEMINI_DOMAINS_FILE="${CACHE_DIR}/gemini_domains.txt"
NETFLIX_DOMAINS_FILE="${CACHE_DIR}/netflix_domains.txt"
NETFLIX_MODE_FILE="${CACHE_DIR}/netflix_mode"
SINGBOX_PATCHER="/usr/local/bin/warp-singbox-route"
SINGBOX_DROPIN_DIR="/etc/systemd/system/sing-box.service.d"
SINGBOX_DROPIN_FILE="${SINGBOX_DROPIN_DIR}/20-warp-routing.conf"
GOOG_JSON_URL="https://www.gstatic.com/ipranges/goog.json"
IPV4_CACHE_FILE="${CACHE_DIR}/google_ipv4.txt"
NETFLIX_IPV4_CACHE_FILE="${CACHE_DIR}/netflix_ipv4.txt"
NETFLIX_ASN_API_URL="https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS2906"
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

STATIC_NETFLIX_IPV4_CIDRS="
23.246.0.0/18
37.77.184.0/21
38.72.126.0/24
45.57.0.0/17
64.120.128.0/17
66.197.128.0/17
69.53.224.0/19
103.87.204.0/22
108.175.32.0/20
185.2.220.0/22
185.9.188.0/22
192.173.64.0/18
198.38.96.0/19
198.45.48.0/20
208.75.76.0/22
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

warp_cli() {
  warp-cli --accept-tos "$@" 2>/dev/null || warp-cli "$@" 2>/dev/null
}

check_root() {
  [[ ${EUID:-0} -ne 0 ]] && { error "请使用 root 运行"; exit 1; } || true
}

show_banner() {
  clear 2>/dev/null || true
  echo -e "${CYAN}"
  echo "╔════════════════════════════════════════════════════╗"
  echo "║ 🌐 WARP Script - Google & Netflix Unlock           ║"
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
  if [[ "${WARP_CONFIGURE_DNS:-0}" != "1" ]]; then
    info "保留系统 DNS（如需改为 Cloudflare DNS，请设置 WARP_CONFIGURE_DNS=1）"
    return 0
  fi

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

  local dns_write_rc
  set +e
  printf '%s\n' \
    'nameserver 1.1.1.1' \
    'nameserver 1.0.0.1' \
    'options timeout:2 attempts:3 rotate' | tee /etc/resolv.conf >/dev/null
  dns_write_rc=$?
  set -e

  if [[ "${dns_write_rc}" -eq 0 ]]; then
    echo "file" > "${DNS_MODE_FILE}"
    success "DNS 已配置为 Cloudflare"
  else
    warn "无法写入 /etc/resolv.conf，跳过 DNS 配置"
    rm -f "${DNS_BACKUP_FILE}" 2>/dev/null || true
  fi

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

migrate_legacy_network_tweaks() {
  if [[ "${WARP_CONFIGURE_DNS:-0}" != "1" && -f "${DNS_MODE_FILE}" ]]; then
    info "恢复脚本旧版本修改的系统 DNS..."
    restore_dns
  fi

  if [[ "${WARP_PREFER_IPV4:-0}" != "1" ]]; then
    sed -i "/${GAI_MARK}/,+1d" /etc/gai.conf 2>/dev/null || true
  fi
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
    systemctl enable --now warp-svc >/dev/null 2>&1 || true
    success "已检测到 warp-cli，并确认 warp-svc 已启动"
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
  if ! warp_cli registration show >/dev/null 2>&1; then
    warp_cli registration new >/dev/null || warp_cli register >/dev/null || true
  fi
  warp_cli tunnel protocol set MASQUE >/dev/null || true
  warp_cli mode proxy >/dev/null || true
  warp_cli proxy port "${WARP_PROXY_PORT}" >/dev/null || true
  warp_cli connect >/dev/null || true
  sleep 2

  local status
  status=$(warp_cli status || echo "未知")
  info "WARP 状态：${status}"
}

setup_gai_conf() {
  if [[ "${WARP_PREFER_IPV4:-0}" != "1" ]]; then
    return 0
  fi

  if ! grep -qF "${GAI_MARK}" /etc/gai.conf 2>/dev/null; then
    {
      echo "${GAI_MARK}"
      echo "precedence ::ffff:0:0/96  100"
    } >> /etc/gai.conf
    success "已配置 IPv4 优先"
  fi
}

detect_singbox_config() {
  local candidate
  for candidate in \
    "${SINGBOX_CONFIG:-}" \
    "/etc/v2ray-agent/sing-box/conf/config.json" \
    "/etc/sing-box/config.json" \
    "/usr/local/etc/sing-box/config.json"; do
    if [[ -n "${candidate}" && -f "${candidate}" ]]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done
  return 1
}

write_domain_lists() {
  mkdir -p "${CACHE_DIR}"

  if [[ ! -s "${GEMINI_DOMAINS_FILE}" ]]; then
    cat > "${GEMINI_DOMAINS_FILE}" <<'EOF_GEMINI_DOMAINS'
gemini.google.com
aistudio.google.com
ai.google.dev
makersuite.google.com
bard.google.com
generativelanguage.googleapis.com
content-generativelanguage.googleapis.com
alkalimakersuite-pa.clients6.google.com
aisandbox-pa.googleapis.com
proaisandbox-pa.googleapis.com
EOF_GEMINI_DOMAINS
  fi

  if [[ ! -s "${NETFLIX_DOMAINS_FILE}" ]]; then
    cat > "${NETFLIX_DOMAINS_FILE}" <<'EOF_NETFLIX_DOMAINS'
netflix.com
netflix.net
nflxvideo.net
nflximg.net
nflximg.com
nflxso.net
nflxext.com
fast.com
EOF_NETFLIX_DOMAINS
  fi

  [[ -s "${NETFLIX_MODE_FILE}" ]] || echo "off" > "${NETFLIX_MODE_FILE}"
}

write_singbox_patcher() {
  info "创建 sing-box 域名分流补丁..."

  cat > "${SINGBOX_PATCHER}" <<'EOF_SINGBOX_PATCHER'
#!/usr/bin/env python3
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

CACHE_DIR = Path(os.environ.get("WARP_CACHE_DIR", "/etc/warp-google"))
MODE_FILE = CACHE_DIR / "routing_mode"
CONFIG_FILE = CACHE_DIR / "singbox_config"
GEMINI_FILE = CACHE_DIR / "gemini_domains.txt"
NETFLIX_FILE = CACHE_DIR / "netflix_domains.txt"
NETFLIX_MODE_FILE = CACHE_DIR / "netflix_mode"
MANAGED_MARKER = "__warp_script_v2_managed__"
WARP_TAG = "warp-out"
DIRECT_TAG = "warp-direct"
WARP_PORT = int(os.environ.get("WARP_PROXY_PORT", "40000"))


def read_text(path, default=""):
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return default


def read_domains(path):
    values = []
    for line in read_text(path).splitlines():
        value = line.strip().lower().rstrip(".")
        if value and not value.startswith("#") and value not in values:
            values.append(value)
    return values


def find_binary(config_path):
    candidates = [
        os.environ.get("WARP_SINGBOX_BIN"),
        shutil.which("sing-box"),
        str(config_path.parent.parent / "sing-box"),
        "/usr/local/bin/sing-box",
        "/usr/bin/sing-box",
    ]
    for candidate in candidates:
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    raise RuntimeError("找不到 sing-box 可执行文件")


def is_managed_rule(rule):
    if rule.get("outbound") == WARP_TAG:
        return True
    return MANAGED_MARKER in rule.get("domain_keyword", [])


def clean_config(data):
    route = data.setdefault("route", {})
    route["rules"] = [
        rule for rule in route.get("rules", [])
        if not is_managed_rule(rule)
    ]

    outbounds = data.get("outbounds", [])
    outbounds = [
        outbound for outbound in outbounds
        if outbound.get("tag") not in (WARP_TAG, DIRECT_TAG)
    ]
    if outbounds:
        data["outbounds"] = outbounds
    else:
        data.pop("outbounds", None)

    if route.get("final") == DIRECT_TAG:
        route.pop("final", None)
    return data


def domain_fields(domains):
    return {
        "domain": domains,
        "domain_suffix": [f".{domain}" for domain in domains],
        "domain_keyword": [MANAGED_MARKER],
    }


def apply_config(data):
    data = clean_config(data)
    route = data.setdefault("route", {})
    rules = route.setdefault("rules", [])

    if not any(rule.get("action") == "sniff" for rule in rules):
        rules.insert(0, {"action": "sniff"})

    outbounds = data.get("outbounds", [])
    if not outbounds:
        outbounds.append({"type": "direct", "tag": DIRECT_TAG})
        route["final"] = DIRECT_TAG

    outbounds.append({
        "type": "socks",
        "tag": WARP_TAG,
        "server": "127.0.0.1",
        "server_port": WARP_PORT,
        "version": "5",
        "network": "tcp",
    })
    data["outbounds"] = outbounds

    domains = read_domains(GEMINI_FILE)
    if read_text(NETFLIX_MODE_FILE, "off") == "on":
        domains.extend(
            domain for domain in read_domains(NETFLIX_FILE)
            if domain not in domains
        )
    if not domains:
        raise RuntimeError("域名列表为空")

    fields = domain_fields(domains)
    managed_rules = [
        {
            **fields,
            "network": ["udp"],
            "port": 443,
            "action": "reject",
        },
        {
            **fields,
            "network": ["tcp"],
            "action": "route",
            "outbound": WARP_TAG,
        },
    ]

    insert_at = 0
    for index, rule in enumerate(rules):
        if rule.get("action") in ("sniff", "resolve", "route-options"):
            insert_at = index + 1
    rules[insert_at:insert_at] = managed_rules
    return data


def validate(binary, config_path):
    result = subprocess.run(
        [binary, "check", "-c", str(config_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if result.returncode:
        raise RuntimeError(result.stdout.strip() or "sing-box 配置检查失败")


def write_transaction(config_path, data):
    binary = find_binary(config_path)
    original = config_path.read_bytes()
    stat = config_path.stat()
    rendered = (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode()
    if rendered == original:
        validate(binary, config_path)
        print("[warp-route] 配置已是最新")
        return

    backup = config_path.with_name(config_path.name + ".warp-script-txn")
    backup.write_bytes(original)
    os.chmod(backup, stat.st_mode)

    fd, temp_name = tempfile.mkstemp(prefix=".warp-route-", dir=config_path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, stat.st_mode)
        try:
            os.chown(temp_name, stat.st_uid, stat.st_gid)
        except PermissionError:
            pass
        os.replace(temp_name, config_path)
        validate(binary, config_path)
    except Exception:
        config_path.write_bytes(original)
        os.chmod(config_path, stat.st_mode)
        raise
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)
        try:
            backup.unlink()
        except OSError:
            pass
    print("[warp-route] sing-box 域名分流已更新")


def main():
    command = sys.argv[1] if len(sys.argv) > 1 else "apply"
    config_value = read_text(CONFIG_FILE)
    if not config_value:
        raise RuntimeError("未记录 sing-box 配置路径")
    config_path = Path(config_value)
    if not config_path.is_file():
        raise RuntimeError(f"sing-box 配置不存在: {config_path}")

    with config_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    if command == "remove" or read_text(MODE_FILE) != "gemini-only":
        data = clean_config(data)
    elif command == "apply":
        data = apply_config(data)
    else:
        raise RuntimeError("用法: warp-singbox-route {apply|remove}")

    write_transaction(config_path, data)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"[warp-route] 错误: {exc}", file=sys.stderr)
        sys.exit(1)
EOF_SINGBOX_PATCHER

  chmod +x "${SINGBOX_PATCHER}"
}

configure_singbox_routing() {
  local config_path
  config_path="$(detect_singbox_config)" || return 1

  mkdir -p "${CACHE_DIR}" "${SINGBOX_DROPIN_DIR}"
  printf '%s\n' "${config_path}" > "${SINGBOX_CONFIG_FILE}"
  printf '%s\n' "gemini-only" > "${ROUTING_MODE_FILE}"

  cat > "${SINGBOX_DROPIN_FILE}" <<EOF_SINGBOX_DROPIN
[Service]
ExecStartPre=+${SINGBOX_PATCHER} apply
EOF_SINGBOX_DROPIN

  # 清理 v1 的整段 IP 接管，避免覆盖 sing-box 的域名决策。
  /usr/local/bin/warp-google stop >/dev/null 2>&1 || true
  systemctl disable --now warp-google.service >/dev/null 2>&1 || true
  systemctl reset-failed warp-google.service >/dev/null 2>&1 || true
  systemctl disable --now redsocks.service >/dev/null 2>&1 || true

  systemctl daemon-reload
  "${SINGBOX_PATCHER}" apply
  systemctl restart sing-box
  success "已启用 Gemini 域名分流: ${config_path}"
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

  # 清理旧版本遗留的非 systemd 进程，避免端口冲突
  pkill -x redsocks 2>/dev/null || true
  sleep 0.5

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
FAIL_FILE="/run/warp-keepalive.failures"
MODE_FILE="/etc/warp-google/routing_mode"

exec 9>"${LOCK_FILE}"
if ! flock -n 9; then
  exit 0
fi

warp_cli() {
  warp-cli --accept-tos "$@" 2>/dev/null || warp-cli "$@" 2>/dev/null
}

check_warp_proxy() {
  curl -fsSL --max-time 12 -x "socks5h://127.0.0.1:${WARP_PROXY_PORT}" \
    https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | grep -Eq '^warp=(on|plus)$'
}

check_warp_url() {
  local url="$1"
  local code
  code="$(curl -4 -sS --max-time 12 -x "socks5h://127.0.0.1:${WARP_PROXY_PORT}" \
    -o /dev/null -w "%{http_code}" "${url}" 2>/dev/null || echo "000")"
  [[ "${code}" != "000" ]]
}

if check_warp_proxy && check_warp_url "https://gemini.google.com"; then
  rm -f "${FAIL_FILE}"
  if [[ "$(cat "${MODE_FILE}" 2>/dev/null || true)" == "gemini-only" ]] &&
     command -v /usr/local/bin/warp-singbox-route >/dev/null 2>&1; then
    /usr/local/bin/warp-singbox-route apply >/dev/null 2>&1 || \
      logger -t "${LOG_TAG}" "sing-box route apply failed"
  fi
  exit 0
fi

failures="$(cat "${FAIL_FILE}" 2>/dev/null || echo 0)"
[[ "${failures}" =~ ^[0-9]+$ ]] || failures=0
failures=$((failures + 1))
printf '%s\n' "${failures}" > "${FAIL_FILE}"
if (( failures < 2 )); then
  logger -t "${LOG_TAG}" "WARP health check failed once; waiting for confirmation"
  exit 0
fi

logger -t "${LOG_TAG}" "WARP health check failed twice; reconnecting"
if ! check_warp_proxy; then
  logger -t "${LOG_TAG}" "WARP proxy trace failed, trying to reconnect..."
  warp_cli disconnect || true
  sleep 2
  warp_cli connect || true
  sleep 3
fi

if ! check_warp_proxy; then
  logger -t "${LOG_TAG}" "WARP still unhealthy, restarting warp-svc..."
  systemctl restart warp-svc >/dev/null 2>&1 || true
  sleep 5
  warp_cli connect || true
fi

if check_warp_proxy && check_warp_url "https://gemini.google.com"; then
  rm -f "${FAIL_FILE}"
  logger -t "${LOG_TAG}" "WARP recovered"
elif [[ "$(cat "${MODE_FILE}" 2>/dev/null || true)" == "google-all" ]]; then
  /usr/local/bin/warp-google restart >/dev/null 2>&1 || true
  logger -t "${LOG_TAG}" "legacy Google rules reapplied"
else
  logger -t "${LOG_TAG}" "WARP remains unhealthy after recovery"
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
Description=Run WARP keepalive every 5 minutes

[Timer]
OnBootSec=3min
OnUnitActiveSec=5min
Persistent=true

[Install]
WantedBy=timers.target
EOF_KEEPALIVE_TIMER

  systemctl daemon-reload
  systemctl enable --now warp-keepalive.timer >/dev/null 2>&1 || true

  if command_exists crontab; then
    (crontab -l 2>/dev/null | grep -v warp-keepalive || true) | crontab - 2>/dev/null || true
  fi

  success "keepalive 已配置（每 5 分钟检测，连续失败两次才恢复）"
}

write_update_timer() {
  info "创建每日维护 systemd timer..."

  cat > /etc/systemd/system/warp-google-update.service <<'EOF_UPDATE_SERVICE'
[Unit]
Description=Maintain WARP routing
After=network-online.target warp-svc.service
Wants=network-online.target warp-svc.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/warp update
EOF_UPDATE_SERVICE

  cat > /etc/systemd/system/warp-google-update.timer <<'EOF_UPDATE_TIMER'
[Unit]
Description=Maintain WARP routing daily

[Timer]
OnBootSec=5min
OnCalendar=daily
RandomizedDelaySec=2h
Persistent=true

[Install]
WantedBy=timers.target
EOF_UPDATE_TIMER

  systemctl daemon-reload
  systemctl enable --now warp-google-update.timer >/dev/null 2>&1 || true
  success "每日维护已配置（带随机延迟）"
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

NETFLIX_IPSET_NAME="${NETFLIX_IPSET_NAME:-warp_netflix4}"
NETFLIX_NAT_CHAIN="${NETFLIX_NAT_CHAIN:-WARP_NETFLIX}"
NETFLIX_QUIC_CHAIN="${NETFLIX_QUIC_CHAIN:-WARP_NETFLIX_QUIC}"

CACHE_DIR="${CACHE_DIR:-/etc/warp-google}"
GOOG_JSON_URL="${GOOG_JSON_URL:-https://www.gstatic.com/ipranges/goog.json}"
NETFLIX_ASN_API_URL="${NETFLIX_ASN_API_URL:-https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS2906}"
IPV4_CACHE_FILE="${IPV4_CACHE_FILE:-/etc/warp-google/google_ipv4.txt}"
NETFLIX_IPV4_CACHE_FILE="${NETFLIX_IPV4_CACHE_FILE:-/etc/warp-google/netflix_ipv4.txt}"
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

STATIC_NETFLIX_IPV4_CIDRS="
23.246.0.0/18
37.77.184.0/21
38.72.126.0/24
45.57.0.0/17
64.120.128.0/17
66.197.128.0/17
69.53.224.0/19
103.87.204.0/22
108.175.32.0/20
185.2.220.0/22
185.9.188.0/22
192.173.64.0/18
198.38.96.0/19
198.45.48.0/20
208.75.76.0/22
"

info() { echo "[warp-google] $*"; }

warp_cli() {
  warp-cli --accept-tos "$@" 2>/dev/null || warp-cli "$@" 2>/dev/null
}

warp_connect() { warp_cli connect || true; }

delete_jump_all() {
  local table="$1"
  local chain="$2"
  local target="$3"
  while iptables -t "${table}" -D "${chain}" -j "${target}" 2>/dev/null; do
    :
  done
}

start_redsocks() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl restart redsocks >/dev/null 2>&1 || systemctl start redsocks >/dev/null 2>&1 || true
  else
    pkill -x redsocks 2>/dev/null || true
    sleep 0.5
    redsocks -c /etc/redsocks.conf >/dev/null 2>&1 &
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
  delete_jump_all nat OUTPUT "${NAT_CHAIN}"
  iptables -t nat -F "${NAT_CHAIN}" 2>/dev/null || true
  iptables -t nat -X "${NAT_CHAIN}" 2>/dev/null || true
  delete_jump_all filter OUTPUT "${QUIC_CHAIN}"
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

load_netflix_ipv4_list() {
  if [[ -s "${NETFLIX_IPV4_CACHE_FILE}" ]]; then
    cat "${NETFLIX_IPV4_CACHE_FILE}"
  else
    echo "${STATIC_NETFLIX_IPV4_CIDRS}"
  fi
}

netflix_ipset_apply() {
  ipset create "${NETFLIX_IPSET_NAME}" hash:net family inet -exist
  local tmp_set="${NETFLIX_IPSET_NAME}_tmp"
  ipset create "${tmp_set}" hash:net family inet -exist
  ipset flush "${tmp_set}" || true

  while IFS= read -r cidr; do
    [[ -z "${cidr}" ]] && continue
    ipset add "${tmp_set}" "${cidr}" -exist 2>/dev/null || true
  done < <(load_netflix_ipv4_list)

  ipset swap "${tmp_set}" "${NETFLIX_IPSET_NAME}" || true
  ipset destroy "${tmp_set}" 2>/dev/null || true
}

netflix_iptables_apply() {
  delete_jump_all nat OUTPUT "${NETFLIX_NAT_CHAIN}"
  iptables -t nat -F "${NETFLIX_NAT_CHAIN}" 2>/dev/null || true
  iptables -t nat -X "${NETFLIX_NAT_CHAIN}" 2>/dev/null || true
  delete_jump_all filter OUTPUT "${NETFLIX_QUIC_CHAIN}"
  iptables -t filter -F "${NETFLIX_QUIC_CHAIN}" 2>/dev/null || true
  iptables -t filter -X "${NETFLIX_QUIC_CHAIN}" 2>/dev/null || true

  iptables -t nat -N "${NETFLIX_NAT_CHAIN}" 2>/dev/null || true
  iptables -t nat -F "${NETFLIX_NAT_CHAIN}"
  iptables -t nat -A "${NETFLIX_NAT_CHAIN}" -p tcp -m set --match-set "${NETFLIX_IPSET_NAME}" dst -j REDIRECT --to-ports "${REDSOCKS_PORT}"
  iptables -t nat -I OUTPUT 1 -j "${NETFLIX_NAT_CHAIN}"

  iptables -t filter -N "${NETFLIX_QUIC_CHAIN}" 2>/dev/null || true
  iptables -t filter -F "${NETFLIX_QUIC_CHAIN}"
  iptables -t filter -A "${NETFLIX_QUIC_CHAIN}" -p udp --dport 443 -m set --match-set "${NETFLIX_IPSET_NAME}" dst -j REJECT
  iptables -t filter -I OUTPUT 1 -j "${NETFLIX_QUIC_CHAIN}"
}

update_google() {
  info "更新 Google IP 段..."
  local tmp
  tmp="$(mktemp)"

  if ! curl -fsSL -x "socks5h://127.0.0.1:${WARP_PROXY_PORT}" --max-time 30 "${GOOG_JSON_URL}" -o "${tmp}" 2>/dev/null; then
    if ! curl -fsSL --max-time 30 "${GOOG_JSON_URL}" -o "${tmp}" 2>/dev/null; then
      info "Google IP 下载失败，使用静态列表"
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
    info "Google 已更新：$(wc -l < "${IPV4_CACHE_FILE}") 条 IP 段"
  else
    info "Google 更新失败，将使用静态列表"
    return 1
  fi
}

update_netflix() {
  info "更新 Netflix IP 段 (AS2906)..."
  local tmp
  tmp="$(mktemp)"

  if ! curl -fsSL -x "socks5h://127.0.0.1:${WARP_PROXY_PORT}" --max-time 30 "${NETFLIX_ASN_API_URL}" -o "${tmp}" 2>/dev/null; then
    if ! curl -fsSL --max-time 30 "${NETFLIX_ASN_API_URL}" -o "${tmp}" 2>/dev/null; then
      info "Netflix IP 下载失败，使用静态列表"
      rm -f "${tmp}"
      return 1
    fi
  fi

  if command -v python3 >/dev/null 2>&1; then
    python3 -c "
import json, ipaddress
with open('${tmp}', 'r', encoding='utf-8') as f:
    data = json.load(f)
prefixes = set()
for p in data.get('data', {}).get('prefixes', []):
    net = p.get('prefix', '')
    try:
        addr = ipaddress.ip_network(net, strict=False)
        if addr.version == 4:
            prefixes.add(str(addr))
    except ValueError:
        pass
for line in sorted(prefixes):
    print(line)
" > "${NETFLIX_IPV4_CACHE_FILE}" 2>/dev/null || {
      grep -oE '"prefix"\s*:\s*"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+"' "${tmp}" \
        | sed -E 's/.*"([^"]+)".*/\1/' | sort -u > "${NETFLIX_IPV4_CACHE_FILE}"
    }
  else
    grep -oE '"prefix"\s*:\s*"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+"' "${tmp}" \
      | sed -E 's/.*"([^"]+)".*/\1/' | sort -u > "${NETFLIX_IPV4_CACHE_FILE}"
  fi

  rm -f "${tmp}"

  if [[ -s "${NETFLIX_IPV4_CACHE_FILE}" ]]; then
    info "Netflix 已更新：$(wc -l < "${NETFLIX_IPV4_CACHE_FILE}") 条 IP 段"
  else
    info "Netflix 更新失败，将使用静态列表"
    return 1
  fi
}

update() {
  exec 200>"${UPDATE_LOCK}"
  if ! flock -n 200; then
    info "已有更新任务在执行，跳过"
    return 0
  fi

  mkdir -p "${CACHE_DIR}"
  update_google || true
  update_netflix || true
}

start() {
  if [[ "$(cat "${CACHE_DIR}/routing_mode" 2>/dev/null || true)" == "gemini-only" ]]; then
    info "当前为 gemini-only 模式，不启用整段 IP 规则"
    return 0
  fi
  info "启动..."
  warp_connect
  start_redsocks
  ipset_apply
  iptables_apply
  netflix_ipset_apply
  netflix_iptables_apply
  info "完成"
}

stop() {
  info "停止..."
  delete_jump_all nat OUTPUT "${NAT_CHAIN}"
  iptables -t nat -F "${NAT_CHAIN}" 2>/dev/null || true
  iptables -t nat -X "${NAT_CHAIN}" 2>/dev/null || true
  delete_jump_all filter OUTPUT "${QUIC_CHAIN}"
  iptables -t filter -F "${QUIC_CHAIN}" 2>/dev/null || true
  iptables -t filter -X "${QUIC_CHAIN}" 2>/dev/null || true
  delete_jump_all nat OUTPUT "${NETFLIX_NAT_CHAIN}"
  iptables -t nat -F "${NETFLIX_NAT_CHAIN}" 2>/dev/null || true
  iptables -t nat -X "${NETFLIX_NAT_CHAIN}" 2>/dev/null || true
  delete_jump_all filter OUTPUT "${NETFLIX_QUIC_CHAIN}"
  iptables -t filter -F "${NETFLIX_QUIC_CHAIN}" 2>/dev/null || true
  iptables -t filter -X "${NETFLIX_QUIC_CHAIN}" 2>/dev/null || true
  info "完成"
}

status() {
  echo "=== Google ipset ==="
  ipset list "${IPSET_NAME}" 2>/dev/null | head -n 15 || echo "不存在"
  echo
  echo "=== Google NAT 规则 ==="
  iptables -t nat -S "${NAT_CHAIN}" 2>/dev/null || echo "无"
  echo
  echo "=== Google QUIC 阻断 ==="
  iptables -t filter -S "${QUIC_CHAIN}" 2>/dev/null || echo "无"
  echo
  echo "=== Netflix ipset ==="
  ipset list "${NETFLIX_IPSET_NAME}" 2>/dev/null | head -n 15 || echo "不存在"
  echo
  echo "=== Netflix NAT 规则 ==="
  iptables -t nat -S "${NETFLIX_NAT_CHAIN}" 2>/dev/null || echo "无"
  echo
  echo "=== Netflix QUIC 阻断 ==="
  iptables -t filter -S "${NETFLIX_QUIC_CHAIN}" 2>/dev/null || echo "无"
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
MODE_FILE="${ROUTING_MODE_FILE}"
NETFLIX_MODE_FILE="${NETFLIX_MODE_FILE}"
SINGBOX_PATCHER="${SINGBOX_PATCHER}"
SINGBOX_DROPIN_FILE="${SINGBOX_DROPIN_FILE}"
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

warp_cli() {
  warp-cli --accept-tos "\$@" 2>/dev/null || warp-cli "\$@" 2>/dev/null
}

test_http() {
  local name="\$1"
  local url="\$2"
  local proxy="\${3:-}"
  local code
  if [[ -n "\${proxy}" ]]; then
    code="\$(curl -4 -sS --max-time 12 -x "\${proxy}" -o /dev/null -w "%{http_code}" "\${url}" 2>/dev/null || echo "000")"
  else
    code="\$(curl -4 -sS --max-time 12 -o /dev/null -w "%{http_code}" "\${url}" 2>/dev/null || echo "000")"
  fi
  echo "\${name}: HTTP \${code}"
  [[ "\${code}" != "000" ]]
}

routing_mode() {
  cat "\${MODE_FILE}" 2>/dev/null || echo "google-all"
}

apply_smart_routing() {
  /usr/local/bin/warp-google stop >/dev/null 2>&1 || true
  systemctl disable --now warp-google.service >/dev/null 2>&1 || true
  systemctl disable --now redsocks.service >/dev/null 2>&1 || true
  "\${SINGBOX_PATCHER}" apply
  systemctl restart sing-box
}

enable_legacy_routing() {
  "\${SINGBOX_PATCHER}" remove 2>/dev/null || true
  systemctl restart sing-box 2>/dev/null || true
  systemctl enable --now redsocks.service >/dev/null 2>&1 || true
  systemctl enable warp-google.service >/dev/null 2>&1 || true
  /usr/local/bin/warp-google update || true
  /usr/local/bin/warp-google restart
}

case "\${1:-}" in
  status)
    echo "WARP Script v\${SCRIPT_VERSION}"
    echo "路由模式: \$(routing_mode)"
    echo "Netflix: \$(cat "\${NETFLIX_MODE_FILE}" 2>/dev/null || echo off)"
    echo
    echo "=== WARP 状态 ==="
    warp_cli status || echo "未运行"
    echo
    if [[ "\$(routing_mode)" == "gemini-only" ]]; then
      echo "=== sing-box 域名分流 ==="
      systemctl is-active --quiet sing-box && echo "sing-box: 运行中" || echo "sing-box: 未运行"
      grep -q '"tag": "warp-out"' "\$(cat /etc/warp-google/singbox_config 2>/dev/null)" 2>/dev/null &&
        echo "warp-out: 已配置" || echo "warp-out: 未配置"
      iptables -t nat -C OUTPUT -j WARP_GOOGLE 2>/dev/null &&
        echo "旧 Google IP 规则: 仍存在" || echo "旧 Google IP 规则: 已移除"
    else
      /usr/local/bin/warp-google status
    fi
    ;;
  start)
    warp_cli connect || true
    if [[ "\$(routing_mode)" == "gemini-only" ]]; then
      apply_smart_routing
    else
      enable_legacy_routing
    fi
    ;;
  stop)
    /usr/local/bin/warp-google stop || true
    systemctl stop redsocks.service >/dev/null 2>&1 || true
    warp_cli disconnect || true
    ;;
  restart)
    warp_cli disconnect || true
    sleep 1
    warp_cli connect || true
    if [[ "\$(routing_mode)" == "gemini-only" ]]; then
      apply_smart_routing
    else
      /usr/local/bin/warp-google restart
    fi
    ;;
  test)
    proxy="socks5h://127.0.0.1:\${WARP_PROXY_PORT}"
    echo "=== 直连测试 ==="
    test_http "Google Search" "https://www.google.com/generate_204" || true
    test_http "ChatGPT" "https://chatgpt.com/cdn-cgi/trace" || true
    test_http "OpenAI API" "https://api.openai.com/cdn-cgi/trace" || true
    echo
    echo "=== WARP 测试 ==="
    test_http "Gemini" "https://gemini.google.com" "\${proxy}" || true
    test_http "AI Studio" "https://aistudio.google.com" "\${proxy}" || true
    test_http "Gemini API" "https://generativelanguage.googleapis.com" "\${proxy}" || true
    echo
    echo "=== WARP Trace ==="
    curl -s --max-time 10 -x "\${proxy}" https://www.cloudflare.com/cdn-cgi/trace |
      grep -E "^(ip|loc|warp)=" || echo "未检测到"
    ;;
  ip)
    echo "直连 IP:"
    curl -4 -sS --max-time 8 ip.sb 2>/dev/null || echo "获取失败"
    echo
    echo "WARP IP:"
    curl -sS --max-time 8 -x "socks5h://127.0.0.1:\${WARP_PROXY_PORT}" ip.sb 2>/dev/null || echo "获取失败"
    echo
    ;;
  update)
    if [[ "\$(routing_mode)" == "gemini-only" ]]; then
      "\${SINGBOX_PATCHER}" apply
    else
      /usr/local/bin/warp-google update
      /usr/local/bin/warp-google restart
    fi
    ;;
  mode)
    case "\${2:-}" in
      gemini-only)
        echo "gemini-only" > "\${MODE_FILE}"
        apply_smart_routing
        echo "[warp] 已切换为 Gemini 域名分流"
        ;;
      google-all)
        echo "google-all" > "\${MODE_FILE}"
        enable_legacy_routing
        echo "[warp] 已切换为整个 Google IP 段走 WARP"
        ;;
      *)
        echo "当前模式: \$(routing_mode)"
        echo "用法: warp mode {gemini-only|google-all}"
        ;;
    esac
    ;;
  netflix)
    case "\${2:-}" in
      on|off)
        [[ "\$(routing_mode)" == "gemini-only" ]] || {
          echo "[warp] Netflix 域名开关仅适用于 gemini-only 模式" >&2
          exit 1
        }
        echo "\${2}" > "\${NETFLIX_MODE_FILE}"
        apply_smart_routing
        echo "[warp] Netflix WARP: \${2}"
        ;;
      test)
        proxy="socks5h://127.0.0.1:\${WARP_PROXY_PORT}"
        test_http "Netflix 直连" "https://www.netflix.com/title/80018499" || true
        test_http "Netflix WARP" "https://www.netflix.com/title/80018499" "\${proxy}" || true
        ;;
      *)
        echo "Netflix WARP: \$(cat "\${NETFLIX_MODE_FILE}" 2>/dev/null || echo off)"
        echo "用法: warp netflix {on|off|test}"
        ;;
    esac
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

    curl -fsSL "\${REPO_SHA256_URL}" -o "\${sum_tmp}" 2>/dev/null && [[ -s "\${sum_tmp}" ]] || {
      echo "[warp] 无法获取 SHA256 校验文件，拒绝升级" >&2
      rm -f "\${tmp}" "\${sum_tmp}"
      exit 1
    }
    verify_checksum "\${tmp}" "\${sum_tmp}" || { rm -f "\${tmp}" "\${sum_tmp}"; exit 1; }

    chmod +x "\${tmp}"
    if ! bash -n "\${tmp}"; then
      echo "[warp] 语法检查失败" >&2
      rm -f "\${tmp}" "\${sum_tmp}"
      exit 1
    fi

    rm -f "\${sum_tmp}"
    export WARP_UPGRADE_TMP="\${tmp}"
    exec bash "\${tmp}" --install
    ;;
  uninstall)
    read -r -p "确定要卸载？[y/N]: " confirm
    [[ "\${confirm}" =~ ^[Yy]$ ]] || { echo "已取消"; exit 0; }

    echo "正在卸载..."
    "\${SINGBOX_PATCHER}" remove 2>/dev/null || true
    rm -f "\${SINGBOX_DROPIN_FILE}"
    systemctl daemon-reload 2>/dev/null || true
    systemctl restart sing-box 2>/dev/null || true
    /usr/local/bin/warp-google stop 2>/dev/null || true
    warp-cli disconnect 2>/dev/null || true

    systemctl disable --now warp-keepalive.timer 2>/dev/null || true
    systemctl disable --now warp-keepalive.service 2>/dev/null || true
    systemctl disable --now warp-google-update.timer 2>/dev/null || true
    systemctl disable --now warp-google-update.service 2>/dev/null || true
    systemctl disable --now warp-google 2>/dev/null || true
    systemctl disable --now redsocks 2>/dev/null || true
    systemctl disable --now warp-svc 2>/dev/null || true

    rm -f /etc/systemd/system/warp-keepalive.timer
    rm -f /etc/systemd/system/warp-keepalive.service
    rm -f /etc/systemd/system/warp-google-update.timer
    rm -f /etc/systemd/system/warp-google-update.service
    rm -f /etc/systemd/system/warp-google.service
    rm -f /etc/systemd/system/redsocks.service

    rm -f /usr/local/bin/warp-google
    rm -f /usr/local/bin/warp-keepalive
    rm -f "\${SINGBOX_PATCHER}"
    rm -f /etc/redsocks.conf
    rm -rf /etc/warp-google
    systemctl daemon-reload 2>/dev/null || true

    iptables -t nat -D OUTPUT -j WARP_GOOGLE 2>/dev/null || true
    iptables -t nat -F WARP_GOOGLE 2>/dev/null || true
    iptables -t nat -X WARP_GOOGLE 2>/dev/null || true
    iptables -t filter -D OUTPUT -j WARP_GOOGLE_QUIC 2>/dev/null || true
    iptables -t filter -F WARP_GOOGLE_QUIC 2>/dev/null || true
    iptables -t filter -X WARP_GOOGLE_QUIC 2>/dev/null || true

    iptables -t nat -D OUTPUT -j WARP_NETFLIX 2>/dev/null || true
    iptables -t nat -F WARP_NETFLIX 2>/dev/null || true
    iptables -t nat -X WARP_NETFLIX 2>/dev/null || true
    iptables -t filter -D OUTPUT -j WARP_NETFLIX_QUIC 2>/dev/null || true
    iptables -t filter -F WARP_NETFLIX_QUIC 2>/dev/null || true
    iptables -t filter -X WARP_NETFLIX_QUIC 2>/dev/null || true

    ipset destroy warp_google4 2>/dev/null || true
    ipset destroy warp_netflix4 2>/dev/null || true

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
    echo "  test      测试直连与 WARP"
    echo "  ip        查看 IP"
    echo "  mode      切换 gemini-only / google-all"
    echo "  netflix   Netflix WARP 开关与测试"
    echo "  update    更新当前路由"
    echo "  upgrade   校验并升级脚本"
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
TimeoutStopSec=15s

[Install]
WantedBy=multi-user.target
EOF_WARP_SERVICE

  systemctl daemon-reload
  systemctl enable warp-google 2>/dev/null || true
  success "systemd 服务已创建"
}

do_install() {
  local requested_mode config_path backup_path
  show_banner
  info "开始安装 v${SCRIPT_VERSION} ..."
  log "install v${SCRIPT_VERSION}"

  install_prereqs
  migrate_legacy_network_tweaks
  setup_cloudflare_dns
  install_warp_client

  setup_gai_conf
  write_redsocks_conf
  write_redsocks_service

  write_domain_lists
  write_warp_google
  write_singbox_patcher
  write_warp_cli
  write_keepalive
  write_systemd_service
  write_update_timer

  configure_warp

  requested_mode="${WARP_ROUTING_MODE:-$(cat "${ROUTING_MODE_FILE}" 2>/dev/null || true)}"
  [[ -n "${requested_mode}" ]] || requested_mode="gemini-only"

  if [[ "${requested_mode}" == "gemini-only" ]] && config_path="$(detect_singbox_config)"; then
    backup_path="${config_path}.bak-warp-v2-$(date +%Y%m%d-%H%M%S)"
    cp -a "${config_path}" "${backup_path}"
    info "sing-box 配置备份: ${backup_path}"
    configure_singbox_routing
  else
    warn "未启用 sing-box 域名分流，使用 google-all 兼容模式"
    echo "google-all" > "${ROUTING_MODE_FILE}"
    "${SINGBOX_PATCHER}" remove 2>/dev/null || true
    systemctl enable --now redsocks.service >/dev/null 2>&1 || true
    systemctl enable warp-google.service >/dev/null 2>&1 || true
    /usr/local/bin/warp-google update || warn "IP 段更新失败，使用静态列表"
    /usr/local/bin/warp-google start || true
  fi

  echo
  success "安装完成"
  echo -e "\n管理命令: ${GREEN}warp {status|start|stop|restart|test|ip|mode|netflix|update|upgrade|uninstall}${NC}\n"
  /usr/local/bin/warp status || true
  echo
  /usr/local/bin/warp test || true

  if [[ -n "${WARP_UPGRADE_TMP:-}" && "${WARP_UPGRADE_TMP}" == /tmp/* ]]; then
    rm -f "${WARP_UPGRADE_TMP}" 2>/dev/null || true
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
