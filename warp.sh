#!/bin/bash

# WARP 一键脚本 - 使用 Cloudflare 官方客户端
# 让 Google 流量自动走 WARP，解锁受限服务
# 
# 使用方法: bash <(curl -fsSL https://raw.githubusercontent.com/gzsteven666/warp-script/main/warp.sh)

#===========================================
# 配置区
#===========================================
WARP_PROXY_PORT=40000
REDSOCKS_PORT=12345
REQUEST_TIMEOUT=5
LOG_FILE="/var/log/warp-install.log"
SCRIPT_VERSION="1.0.0"

#===========================================
# 颜色定义
#===========================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

#===========================================
# 工具函数
#===========================================
info()    { echo -e "${CYAN}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"
}

show_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════╗"
    echo "║     🌐 WARP 一键脚本 - Google 自动解锁 🌐           ║"
    echo "║         使用 Cloudflare 官方客户端                  ║"
    echo "║                   v$SCRIPT_VERSION                        ║"
    echo "╚════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

check_root() {
    [[ $EUID -ne 0 ]] && { error "请使用 root 运行！"; exit 1; }
}

detect_system() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
        CODENAME=$VERSION_CODENAME
    else
        error "无法检测系统"
        exit 1
    fi
    ARCH=$(dpkg --print-architecture 2>/dev/null || echo "amd64")
    success "系统: $OS $VERSION ($CODENAME) $ARCH"
}

get_ip_info() {
    local ip=$1
    local info=$(curl -s --max-time $REQUEST_TIMEOUT "http://ip-api.com/json/$ip?lang=zh-CN" 2>/dev/null)
    local country=$(echo $info | grep -oP '"country":"\K[^"]+' 2>/dev/null || echo "未知")
    local city=$(echo $info | grep -oP '"city":"\K[^"]+' 2>/dev/null || echo "未知")
    echo "$country - $city"
}

show_current_ip() {
    echo -e "\n${YELLOW}当前 IP 信息:${NC}"
    local current_ip=$(curl -4 -s --max-time $REQUEST_TIMEOUT ip.sb 2>/dev/null || echo "获取失败")
    echo -e "IP: ${GREEN}$current_ip${NC}"
    if [ "$current_ip" != "获取失败" ]; then
        echo -e "位置: ${GREEN}$(get_ip_info $current_ip)${NC}"
    fi
}

#===========================================
# 回滚机制
#===========================================
INSTALL_STAGE=0

cleanup_on_failure() {
    local exit_code=${1:-$?}
    
    [ $exit_code -eq 0 ] && return 0
    [ $INSTALL_STAGE -eq 0 ] && return 0
    
    echo ""
    error "安装在阶段 $INSTALL_STAGE 失败，正在自动回滚..."
    log "安装失败于阶段 $INSTALL_STAGE，开始回滚"
    
    # 停止服务
    /usr/local/bin/warp-google stop 2>/dev/null
    warp-cli disconnect 2>/dev/null
    pkill redsocks 2>/dev/null
    systemctl stop warp-svc 2>/dev/null
    
    # 清理文件
    rm -f /usr/local/bin/warp-google
    rm -f /usr/local/bin/warp
    rm -f /etc/redsocks.conf
    rm -f /etc/systemd/system/warp-google.service
    systemctl daemon-reload 2>/dev/null
    
    # 清理 iptables
    iptables -t nat -D OUTPUT -j WARP_GOOGLE 2>/dev/null
    iptables -t nat -F WARP_GOOGLE 2>/dev/null
    iptables -t nat -X WARP_GOOGLE 2>/dev/null
    
    # 恢复 IPv6
    ip -6 route del blackhole 2607:f8b0::/32 2>/dev/null
    
    # 卸载软件包
    case $OS in
        ubuntu|debian)
            export DEBIAN_FRONTEND=noninteractive
            apt-get remove -y cloudflare-warp redsocks 2>/dev/null
            rm -f /etc/apt/sources.list.d/cloudflare-client.list
            rm -f /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
            ;;
        centos|rhel|rocky|almalinux|fedora)
            yum remove -y cloudflare-warp redsocks 2>/dev/null || dnf remove -y cloudflare-warp redsocks 2>/dev/null
            rm -f /etc/yum.repos.d/cloudflare-warp.repo
            ;;
    esac
    
    success "回滚完成，系统已恢复原状"
    log "回滚完成"
    exit 1
}

#===========================================
# 安装功能
#===========================================
install_warp() {
    INSTALL_STAGE=1
    echo -e "\n${CYAN}[1/3] 安装 Cloudflare WARP 官方客户端...${NC}"
    log "开始安装 WARP 客户端"
    
    case $OS in
        ubuntu|debian)
            # 非交互模式
            export DEBIAN_FRONTEND=noninteractive
            export NEEDRESTART_MODE=a
            
            info "更新软件包列表..."
            apt-get update -y >/dev/null 2>&1 || { error "apt update 失败"; return 1; }
            
            info "安装依赖..."
            apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" \
                gnupg curl wget lsb-release >/dev/null 2>&1 || { error "依赖安装失败"; return 1; }
            
            info "添加 Cloudflare 仓库..."
            curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg || { error "GPG 密钥添加失败"; return 1; }
            
            echo "deb [arch=$ARCH signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $CODENAME main" > /etc/apt/sources.list.d/cloudflare-client.list
            
            apt-get update -y >/dev/null 2>&1 || { error "apt update 失败"; return 1; }
            
            info "安装 WARP 客户端..."
            apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" \
                cloudflare-warp >/dev/null 2>&1 || { error "WARP 安装失败"; return 1; }
            ;;
            
        centos|rhel|rocky|almalinux|fedora)
            info "添加 Cloudflare 仓库..."
            cat > /etc/yum.repos.d/cloudflare-warp.repo << 'EOF'
[cloudflare-warp]
name=Cloudflare WARP
baseurl=https://pkg.cloudflareclient.com/rpm
enabled=1
gpgcheck=1
gpgkey=https://pkg.cloudflareclient.com/pubkey.gpg
EOF
            info "安装 WARP 客户端..."
            if command -v dnf &>/dev/null; then
                dnf install -y cloudflare-warp || { error "WARP 安装失败"; return 1; }
            else
                yum install -y cloudflare-warp || { error "WARP 安装失败"; return 1; }
            fi
            ;;
            
        *)
            error "不支持的系统: $OS"
            warn "支持的系统: Ubuntu, Debian, CentOS, RHEL, Rocky, AlmaLinux, Fedora"
            return 1
            ;;
    esac
    
    if ! command -v warp-cli &>/dev/null; then
        error "WARP 安装失败：找不到 warp-cli"
        return 1
    fi
    
    success "WARP 客户端已安装"
    log "WARP 客户端安装成功"
    return 0
}

configure_warp() {
    INSTALL_STAGE=2
    echo -e "\n${CYAN}[2/3] 配置 WARP...${NC}"
    log "开始配置 WARP"
    
    info "正在注册设备..."
    warp-cli --accept-tos registration new 2>/dev/null || warp-cli --accept-tos register 2>/dev/null || {
        warn "注册命令执行异常，尝试继续..."
    }
    
    info "设置代理模式..."
    warp-cli --accept-tos mode proxy 2>/dev/null || warp-cli mode proxy 2>/dev/null || true
    warp-cli --accept-tos proxy port $WARP_PROXY_PORT 2>/dev/null || warp-cli proxy port $WARP_PROXY_PORT 2>/dev/null || true
    
    info "正在连接 WARP..."
    warp-cli --accept-tos connect 2>/dev/null || warp-cli connect 2>/dev/null
    
    sleep 3
    
    local status=$(warp-cli --accept-tos status 2>/dev/null || warp-cli status 2>/dev/null)
    echo -e "状态: ${GREEN}$status${NC}"
    
    # 验证连接
    local warp_ip=$(curl -x socks5://127.0.0.1:$WARP_PROXY_PORT -s --max-time 10 ip.sb 2>/dev/null)
    if [ -z "$warp_ip" ]; then
        error "WARP 代理连接失败"
        return 1
    fi
    
    success "WARP 配置完成"
    log "WARP 配置完成，代理 IP: $warp_ip"
    return 0
}

setup_transparent_proxy() {
    INSTALL_STAGE=3
    echo -e "\n${CYAN}[3/3] 配置透明代理规则...${NC}"
    log "开始配置透明代理"
    
    info "配置 IPv6 规则..."
    ip -6 route add blackhole 2607:f8b0::/32 2>/dev/null || true
    
    if ! grep -q "precedence ::ffff:0:0/96  100" /etc/gai.conf 2>/dev/null; then
        echo "precedence ::ffff:0:0/96  100" >> /etc/gai.conf
    fi
    
    info "安装 redsocks..."
    case $OS in
        ubuntu|debian)
            export DEBIAN_FRONTEND=noninteractive
            apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" \
                redsocks iptables >/dev/null 2>&1 || { error "redsocks 安装失败"; return 1; }
            ;;
        centos|rhel|rocky|almalinux|fedora)
            if command -v dnf &>/dev/null; then
                dnf install -y redsocks iptables >/dev/null 2>&1 || { error "redsocks 安装失败"; return 1; }
            else
                yum install -y redsocks iptables >/dev/null 2>&1 || { error "redsocks 安装失败"; return 1; }
            fi
            ;;
    esac
    
    info "创建 redsocks 配置..."
    cat > /etc/redsocks.conf << EOF
base {
    log_debug = off;
    log_info = on;
    log = "syslog:daemon";
    daemon = on;
    redirector = iptables;
}

redsocks {
    local_ip = 127.0.0.1;
    local_port = $REDSOCKS_PORT;
    ip = 127.0.0.1;
    port = $WARP_PROXY_PORT;
    type = socks5;
}
EOF

    info "创建透明代理脚本..."
    cat > /usr/local/bin/warp-google << SCRIPT
#!/bin/bash

# Google IP 段
GOOGLE_IPS="
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

start() {
    echo "启动 Google 透明代理..."
    pkill redsocks 2>/dev/null
    sleep 1
    redsocks -c /etc/redsocks.conf
    iptables -t nat -N WARP_GOOGLE 2>/dev/null || iptables -t nat -F WARP_GOOGLE
    for ip in \$GOOGLE_IPS; do
        iptables -t nat -A WARP_GOOGLE -d \$ip -p tcp -j REDIRECT --to-ports $REDSOCKS_PORT
    done
    iptables -t nat -C OUTPUT -j WARP_GOOGLE 2>/dev/null || iptables -t nat -A OUTPUT -j WARP_GOOGLE
    echo "Google 透明代理已启动"
}

stop() {
    echo "停止 Google 透明代理..."
    pkill redsocks 2>/dev/null
    iptables -t nat -D OUTPUT -j WARP_GOOGLE 2>/dev/null
    iptables -t nat -F WARP_GOOGLE 2>/dev/null
    iptables -t nat -X WARP_GOOGLE 2>/dev/null
    echo "Google 透明代理已停止"
}

status() {
    echo "=== WARP 状态 ==="
    warp-cli status 2>/dev/null || echo "WARP 未运行"
    echo ""
    echo "=== Redsocks 状态 ==="
    pgrep -x redsocks >/dev/null && echo "运行中" || echo "未运行"
    echo ""
    echo "=== iptables 规则 ==="
    iptables -t nat -L WARP_GOOGLE -n 2>/dev/null | head -5 || echo "无规则"
}

case "\$1" in
    start) start ;;
    stop) stop ;;
    restart) stop; sleep 1; start ;;
    status) status ;;
    *) echo "用法: \$0 {start|stop|restart|status}" ;;
esac
SCRIPT

    chmod +x /usr/local/bin/warp-google
    
    info "启动透明代理..."
    /usr/local/bin/warp-google start
    
    info "创建 systemd 服务..."
    cat > /etc/systemd/system/warp-google.service << 'EOF'
[Unit]
Description=WARP Google Transparent Proxy
After=network.target warp-svc.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/warp-google start
ExecStop=/usr/local/bin/warp-google stop

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable warp-google 2>/dev/null
    
    success "透明代理配置完成"
    log "透明代理配置完成"
    return 0
}

create_management() {
    info "创建管理脚本..."
    cat > /usr/local/bin/warp << EOF
#!/bin/bash
case "\$1" in
    status)
        warp-cli status 2>/dev/null
        echo ""
        /usr/local/bin/warp-google status 2>/dev/null
        ;;
    start)
        warp-cli connect 2>/dev/null
        /usr/local/bin/warp-google start
        ;;
    stop)
        /usr/local/bin/warp-google stop
        warp-cli disconnect 2>/dev/null
        ;;
    restart)
        \$0 stop
        sleep 2
        \$0 start
        ;;
    test)
        echo "测试 Google 连接..."
        curl -s --max-time 10 -o /dev/null -w "状态码: %{http_code}\n" https://www.google.com
        ;;
    ip)
        echo "直连 IP:"
        curl -4 -s ip.sb
        echo ""
        echo "WARP IP:"
        curl -x socks5://127.0.0.1:$WARP_PROXY_PORT -s ip.sb
        echo ""
        ;;
    uninstall)
        read -p "确定要卸载 WARP？[y/N]: " confirm
        [[ "\$confirm" =~ ^[Yy]$ ]] || { echo "已取消"; exit 0; }
        echo "正在卸载..."
        /usr/local/bin/warp-google stop 2>/dev/null
        warp-cli disconnect 2>/dev/null
        systemctl disable warp-google 2>/dev/null
        rm -f /etc/systemd/system/warp-google.service
        rm -f /usr/local/bin/warp-google
        rm -f /usr/local/bin/warp
        rm -f /etc/redsocks.conf
        iptables -t nat -D OUTPUT -j WARP_GOOGLE 2>/dev/null
        iptables -t nat -F WARP_GOOGLE 2>/dev/null
        iptables -t nat -X WARP_GOOGLE 2>/dev/null
        ip -6 route del blackhole 2607:f8b0::/32 2>/dev/null
        apt-get remove -y cloudflare-warp redsocks 2>/dev/null || yum remove -y cloudflare-warp redsocks 2>/dev/null || dnf remove -y cloudflare-warp redsocks 2>/dev/null
        rm -f /etc/apt/sources.list.d/cloudflare-client.list 2>/dev/null
        rm -f /etc/yum.repos.d/cloudflare-warp.repo 2>/dev/null
        echo "WARP 已卸载"
        ;;
    *)
        echo "WARP 管理工具 v$SCRIPT_VERSION"
        echo ""
        echo "用法: warp <命令>"
        echo ""
        echo "命令:"
        echo "  status    查看状态"
        echo "  start     启动 WARP"
        echo "  stop      停止 WARP"
        echo "  restart   重启 WARP"
        echo "  test      测试 Google"
        echo "  ip        查看 IP"
        echo "  uninstall 卸载 WARP"
        ;;
esac
EOF
    chmod +x /usr/local/bin/warp
}

test_connection() {
    echo -e "\n${CYAN}测试连接...${NC}"
    sleep 2
    
    local google_test=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" https://www.google.com)
    if [ "$google_test" = "200" ]; then
        success "Google 连接成功！"
    else
        warn "Google 测试返回: $google_test (可能需要等待几秒)"
    fi
    
    local warp_ip=$(curl -x socks5://127.0.0.1:$WARP_PROXY_PORT -s --max-time 10 ip.sb 2>/dev/null)
    if [ -n "$warp_ip" ]; then
        echo -e "\nWARP IP: ${GREEN}$warp_ip${NC}"
        echo -e "WARP 位置: ${GREEN}$(get_ip_info $warp_ip)${NC}"
    fi
}

#===========================================
# 主流程
#===========================================
do_install() {
    log "========== 开始安装 v$SCRIPT_VERSION =========="
    
    install_warp || { cleanup_on_failure 1; return 1; }
    configure_warp || { cleanup_on_failure 1; return 1; }
    setup_transparent_proxy || { cleanup_on_failure 1; return 1; }
    create_management
    
    INSTALL_STAGE=0
    
    test_connection
    
    echo -e "\n${GREEN}╔════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║            🎉 安装完成！Google 已解锁 🎉            ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════╝${NC}"
    echo -e "\n${YELLOW}所有 Google 流量现已自动通过 WARP！${NC}"
    echo -e "${YELLOW}无需任何额外配置，直接访问即可。${NC}"
    echo -e "\n管理命令: ${CYAN}warp {status|start|stop|restart|test|ip|uninstall}${NC}\n"
    log "========== 安装完成 =========="
}

do_uninstall() {
    read -p "确定要卸载 WARP？[y/N]: " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || { echo "已取消"; return; }
    
    echo -e "\n${YELLOW}正在卸载 WARP...${NC}"
    log "开始卸载 WARP"
    
    /usr/local/bin/warp-google stop 2>/dev/null
    warp-cli disconnect 2>/dev/null
    systemctl disable warp-google 2>/dev/null
    systemctl stop warp-svc 2>/dev/null
    rm -f /etc/systemd/system/warp-google.service
    rm -f /usr/local/bin/warp-google
    rm -f /usr/local/bin/warp
    rm -f /etc/redsocks.conf
    systemctl daemon-reload
    
    iptables -t nat -D OUTPUT -j WARP_GOOGLE 2>/dev/null
    iptables -t nat -F WARP_GOOGLE 2>/dev/null
    iptables -t nat -X WARP_GOOGLE 2>/dev/null
    ip -6 route del blackhole 2607:f8b0::/32 2>/dev/null
    
    case $OS in
        ubuntu|debian)
            export DEBIAN_FRONTEND=noninteractive
            apt-get remove -y cloudflare-warp redsocks 2>/dev/null
            rm -f /etc/apt/sources.list.d/cloudflare-client.list
            rm -f /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
            ;;
        centos|rhel|rocky|almalinux|fedora)
            yum remove -y cloudflare-warp redsocks 2>/dev/null || dnf remove -y cloudflare-warp redsocks 2>/dev/null
            rm -f /etc/yum.repos.d/cloudflare-warp.repo
            ;;
    esac
    
    success "WARP 已完全卸载"
    log "WARP 卸载完成"
}

do_status() {
    echo -e "\n${CYAN}══════════════ WARP 运行状态 ══════════════${NC}\n"
    
    echo -e "${YELLOW}【WARP 客户端】${NC}"
    if command -v warp-cli &>/dev/null; then
        warp-cli status 2>/dev/null || echo "未运行"
    else
        error "未安装"
    fi
    
    echo ""
    echo -e "${YELLOW}【透明代理】${NC}"
    if pgrep -x redsocks >/dev/null; then
        success "运行中"
    else
        error "未运行"
    fi
    
    echo ""
    echo -e "${YELLOW}【iptables 规则】${NC}"
    iptables -t nat -L WARP_GOOGLE -n 2>/dev/null | head -3 || error "无规则"
    
    echo -e "\n${CYAN}════════════════════════════════════════════${NC}\n"
}

do_show_ip() {
    echo -e "\n${CYAN}══════════════ IP 信息 ══════════════${NC}\n"
    
    echo -e "${YELLOW}【直连 IP】${NC}"
    local direct_ip=$(curl -4 -s --max-time $REQUEST_TIMEOUT ip.sb 2>/dev/null || echo "获取失败")
    echo -e "IP: ${GREEN}$direct_ip${NC}"
    if [ "$direct_ip" != "获取失败" ]; then
        echo -e "位置: $(get_ip_info $direct_ip)\n"
    fi
    
    echo -e "${YELLOW}【WARP IP】${NC}"
    local warp_ip=$(curl -x socks5://127.0.0.1:$WARP_PROXY_PORT -s --max-time $REQUEST_TIMEOUT ip.sb 2>/dev/null)
    if [ -n "$warp_ip" ]; then
        echo -e "IP: ${GREEN}$warp_ip${NC}"
        echo -e "位置: $(get_ip_info $warp_ip)\n"
    else
        error "无法获取 (WARP 可能未运行)\n"
    fi
    
    echo -e "${CYAN}══════════════════════════════════════${NC}\n"
}

do_test_google() {
    echo -e "\n${CYAN}测试 Google 连接...${NC}"
    local result=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" https://www.google.com)
    if [ "$result" = "200" ]; then
        success "Google 连接成功！状态码: $result"
    else
        error "Google 连接失败，状态码: $result"
    fi
    echo ""
}

show_menu() {
    echo -e "${YELLOW}请选择操作:${NC}\n"
    echo -e "  ${GREEN}1.${NC} 安装 WARP (解锁 Gemini、商店等)"
    echo -e "  ${GREEN}2.${NC} 卸载 WARP"
    echo -e "  ${GREEN}3.${NC} 查看状态"
    echo -e "  ${GREEN}0.${NC} 退出\n"
    
    read -p "请输入选项 [0-3]: " choice
    
    case $choice in
        1) do_install ;;
        2) do_uninstall ;;
        3) do_status; do_show_ip; do_test_google ;;
        0) echo -e "\n${GREEN}再见！${NC}\n"; exit 0 ;;
        *) error "无效选项" ;;
    esac
}

main() {
    show_banner
    check_root
    detect_system
    show_current_ip
    show_menu
}

main "$@"
