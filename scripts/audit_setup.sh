#!/bin/bash

# 审计规则部署脚本
# 一键部署 auditd 审计规则集

set -euo pipefail

# --- 默认参数 ---
PROFILE="standard"
PLATFORM="auto"
CATEGORIES="all"
DRY_RUN=0
BACKUP=1

# --- 规则定义 ---

generate_identity_rules() {
    cat <<'EOF'
# identity: 身份认证监控
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/sudoers -p wa -k identity
-w /etc/sudoers.d/ -p wa -k identity
EOF
}

generate_privilege_rules() {
    cat <<EOF
# privilege: 特权命令执行
-a always,exit -F arch=$AUDIT_ARCH -S execve -F euid=0 -F auid!=0 -F auid!=4294967295 -k privilege
-a always,exit -F arch=$AUDIT_ARCH -S setuid -S setgid -S setreuid -S setregid -k privilege_id_change
# exec_cmd: 所有用户命令执行（用于 trace_command_history.sh）
-a always,exit -F arch=$AUDIT_ARCH -S execve -k exec_cmd
# attr_change: 文件属性变更（chmod/chown/chattr）
-a always,exit -F arch=$AUDIT_ARCH -S chmod -S fchmod -S fchmodat -k attr_change
-a always,exit -F arch=$AUDIT_ARCH -S chown -S fchown -S fchownat -S lchown -k owner_change
-a always,exit -F arch=$AUDIT_ARCH -S setxattr -S lsetxattr -S fsetxattr -S removexattr -k xattr_change
EOF
}

generate_fileint_rules() {
    cat <<'EOF'
# file-integrity: 关键文件完整性
-w /etc/ -p wa -k fileint
-w /usr/bin/ -p wa -k fileint
-w /usr/sbin/ -p wa -k fileint
-w /usr/lib/ -p wa -k fileint
-w /usr/lib64/ -p wa -k fileint
-w /boot/ -p wa -k fileint
EOF
}

generate_network_rules() {
    cat <<EOF
# network: 网络活动
-a always,exit -F arch=$AUDIT_ARCH -S connect -S bind -S accept -k network
-w /etc/iptables/ -p wa -k firewall
-w /etc/firewalld/ -p wa -k firewall
EOF
}

generate_process_rules() {
    cat <<EOF
# process: 进程与模块
-a always,exit -F arch=$AUDIT_ARCH -S execve -F dir=/tmp -k process_suspicious
-a always,exit -F arch=$AUDIT_ARCH -S execve -F dir=/dev/shm -k process_suspicious
-a always,exit -F arch=$AUDIT_ARCH -S init_module -S finit_module -S delete_module -k module
EOF
}

generate_config_rules() {
    cat <<EOF
# config: 系统配置
-a always,exit -F arch=$AUDIT_ARCH -S adjtimex -S settimeofday -S clock_settime -k time_change
-a always,exit -F arch=$AUDIT_ARCH -S sethostname -S setdomainname -k hostname_change
-w /etc/resolv.conf -p wa -k dns_change
-w /etc/hosts -p wa -k dns_change
-w /etc/ssh/sshd_config -p wa -k ssh_config
EOF
}

generate_login_rules() {
    cat <<'EOF'
# login: 登录与会话
-w /var/log/lastlog -p wa -k login
-w /var/log/faillog -p wa -k login
-w /var/run/utmp -p wa -k login
-w /var/log/wtmp -p wa -k login
-w /var/log/btmp -p wa -k login
-w /root/.ssh/ -p wa -k ssh_key
# audit_log: 审计日志自身保护
-w /var/log/audit/ -p wa -k audit_log
-w /etc/audit/ -p wa -k audit_config
-w /etc/audisp/ -p wa -k audit_config
EOF
}

generate_selinux_rules() {
    cat <<'EOF'
# selinux: SELinux 事件
-w /etc/selinux/ -p wa -k selinux
-w /usr/share/selinux/ -p wa -k selinux
EOF
}

generate_cron_rules() {
    cat <<'EOF'
# cron: 定时任务
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
EOF
}

generate_media_rules() {
    cat <<EOF
# media: 可移动介质
-a always,exit -F arch=$AUDIT_ARCH -S mount -S umount2 -k media
EOF
}

# --- Profile 规则映射 ---

generate_rules() {
    local profile="$1"
    local categories="$2"

    echo "# 审计规则集 - Profile: $profile"
    echo "# 生成时间: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "# 平台: $PLATFORM"
    echo ""

    if [ "$categories" = "all" ]; then
        case "$profile" in
            basic)
                generate_identity_rules
                echo ""
                generate_privilege_rules
                echo ""
                generate_login_rules
                ;;
            standard)
                generate_identity_rules
                echo ""
                generate_privilege_rules
                echo ""
                generate_fileint_rules
                echo ""
                generate_network_rules
                echo ""
                generate_process_rules
                echo ""
                generate_config_rules
                echo ""
                generate_login_rules
                echo ""
                generate_selinux_rules
                echo ""
                generate_cron_rules
                ;;
            strict)
                generate_identity_rules
                echo ""
                generate_privilege_rules
                echo ""
                generate_fileint_rules
                echo ""
                generate_network_rules
                echo ""
                generate_process_rules
                echo ""
                generate_config_rules
                echo ""
                generate_login_rules
                echo ""
                generate_selinux_rules
                echo ""
                generate_cron_rules
                echo ""
                generate_media_rules
                ;;
        esac
    else
        # 按指定类别生成
        IFS=',' read -ra CATS <<< "$categories"
        for cat in "${CATS[@]}"; do
            case "$cat" in
                identity) generate_identity_rules ;;
                privilege) generate_privilege_rules ;;
                fileint|file-integrity) generate_fileint_rules ;;
                network) generate_network_rules ;;
                process) generate_process_rules ;;
                config) generate_config_rules ;;
                login) generate_login_rules ;;
                selinux) generate_selinux_rules ;;
                cron) generate_cron_rules ;;
                media) generate_media_rules ;;
                *) echo "[警告] 未知类别: $cat" ;;
            esac
            echo ""
        done
    fi

    # 末尾规则：使规则不可变（仅在 strict 模式）
    if [ "$profile" = "strict" ]; then
        echo "# 使规则不可变（需要重启才能修改）"
        echo "# -e 2"
    fi
}

# --- 参数解析 ---

while [ $# -gt 0 ]; do
    case "$1" in
        --profile)
            PROFILE="$2"; shift 2 ;;
        --profile=*)
            PROFILE="${1#*=}"; shift ;;
        --platform)
            PLATFORM="$2"; shift 2 ;;
        --platform=*)
            PLATFORM="${1#*=}"; shift ;;
        --categories)
            CATEGORIES="$2"; shift 2 ;;
        --categories=*)
            CATEGORIES="${1#*=}"; shift ;;
        --dry-run)
            DRY_RUN=1; shift ;;
        --no-backup)
            BACKUP=0; shift ;;
        -h|--help)
            echo "用法: $0 [选项]"
            echo ""
            echo "选项:"
            echo "  --profile <level>     审计级别: basic/standard/strict (默认: standard)"
            echo "  --platform <type>     平台类型: auto/openeuler/fusionos (默认: auto)"
            echo "  --categories <list>   规则类别（逗号分隔）: identity,privilege,fileint,network,process,config,login,selinux,cron,media"
            echo "  --dry-run             仅输出规则，不实际部署"
            echo "  --no-backup           不备份现有规则"
            echo "  -h, --help            显示帮助"
            exit 0
            ;;
        *)
            echo "[错误] 未知参数: $1"; exit 1 ;;
    esac
done

# --- 验证参数 ---

if [[ ! "$PROFILE" =~ ^(basic|standard|strict)$ ]]; then
    echo "[错误] 无效的 profile: $PROFILE (可选: basic/standard/strict)"
    exit 1
fi

# --- 平台检测 ---

if [ "$PLATFORM" = "auto" ]; then
    if [ -f /etc/openEuler-release ]; then
        PLATFORM="openeuler"
    elif [ -f /etc/EulerOS-release ] || [ -f /etc/fusionos-release ]; then
        PLATFORM="fusionos"
    else
        PLATFORM="linux"
    fi
fi

# --- 架构检测 ---

case "$(uname -m)" in
    x86_64|amd64)  AUDIT_ARCH="b64" ;;
    aarch64|arm64) AUDIT_ARCH="aarch64" ;;
    loongarch64)   AUDIT_ARCH="loongarch64" ;;
    *)             AUDIT_ARCH="b64" ;;
esac

echo "=========================================="
echo "  审计规则部署"
echo "=========================================="
echo "Profile: $PROFILE"
echo "Platform: $PLATFORM"
echo "Architecture: $(uname -m) (audit arch=$AUDIT_ARCH)"
echo "Categories: $CATEGORIES"
echo "=========================================="
echo ""

# --- 检查权限 ---

if [ "$(id -u)" -ne 0 ]; then
    echo "[错误] 需要 root 权限运行此脚本"
    exit 1
fi

# --- 检查 auditd ---

if ! command -v auditctl &>/dev/null; then
    echo "[错误] auditctl 未找到，请先安装 audit 包"
    echo "  yum install audit"
    exit 1
fi

# --- 生成规则 ---

RULES_FILE="/etc/audit/rules.d/audit-audit-tracer.rules"
RULES_CONTENT=$(generate_rules "$PROFILE" "$CATEGORIES")

if [ "$DRY_RUN" -eq 1 ]; then
    echo "[Dry Run] 将要部署的规则："
    echo "$RULES_CONTENT"
    exit 0
fi

# --- 备份现有规则 ---

if [ "$BACKUP" -eq 1 ] && [ -f "$RULES_FILE" ]; then
    BACKUP_FILE="${RULES_FILE}.bak.$(date +%Y%m%d_%H%M%S)"
    cp "$RULES_FILE" "$BACKUP_FILE"
    echo "[信息] 已备份现有规则到: $BACKUP_FILE"
fi

# --- 写入规则 ---

echo "$RULES_CONTENT" > "$RULES_FILE"
echo "[信息] 规则已写入: $RULES_FILE"

# --- 加载规则 ---

echo "[信息] 正在加载规则..."
if auditctl -R "$RULES_FILE"; then
    echo "[成功] 审计规则已加载"
else
    echo "[警告] 部分规则加载失败，请检查输出"
fi

# --- 显示统计 ---

RULES_COUNT=$(auditctl -l 2>/dev/null | grep -cv '^No rules' || echo 0)
echo ""
echo "=========================================="
echo "  部署完成"
echo "=========================================="
echo "已加载规则数: $RULES_COUNT"
echo "规则文件: $RULES_FILE"
echo ""
echo "下一步建议："
echo "  1. 验证规则: auditctl -l"
echo "  2. 检查审计日志: tail -f /var/log/audit/audit.log"
echo "  3. 运行健康检查: bash scripts/audit_health_check.sh"
echo "=========================================="
