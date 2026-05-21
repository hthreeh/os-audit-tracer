#!/bin/bash

# 综合异常行为扫描脚本
# 检测认证、文件、进程、网络、配置等异常

set -euo pipefail

# --- 默认参数 ---
DATA_DIR=""
BASELINE_MODE=0

# --- 统计变量 ---
PASS_COUNT=0
WARN_COUNT=0
ALERT_COUNT=0
RISK_SCORE=0

# --- 颜色定义 ---
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

# --- 参数解析 ---

while [ $# -gt 0 ]; do
    case "$1" in
        -d)
            DATA_DIR="$2"; shift 2 ;;
        -d=*)
            DATA_DIR="${1#*=}"; shift ;;
        --baseline)
            BASELINE_MODE=1; shift ;;
        -h|--help)
            echo "用法: $0 [-d <数据目录>] [--baseline]"
            echo ""
            echo "参数:"
            echo "  -d <dir>      数据目录（由 collect_audit_logs.sh 生成）"
            echo "  --baseline    基线检查模式（检查安全配置合规性）"
            exit 0
            ;;
        *)
            echo "[错误] 未知参数: $1"; exit 1 ;;
    esac
done

# --- 辅助函数 ---

print_result() {
    local level="$1"
    local category="$2"
    local message="$3"

    case "$level" in
        PASS)
            echo -e "${GREEN}[PASS]${NC} [$category] $message"
            PASS_COUNT=$((PASS_COUNT + 1))
            ;;
        WARN)
            echo -e "${YELLOW}[WARN]${NC} [$category] $message"
            WARN_COUNT=$((WARN_COUNT + 1))
            RISK_SCORE=$((RISK_SCORE + 10))
            ;;
        ALERT)
            echo -e "${RED}[ALERT]${NC} [$category] $message"
            ALERT_COUNT=$((ALERT_COUNT + 1))
            RISK_SCORE=$((RISK_SCORE + 30))
            ;;
    esac
}

# --- 检测函数 ---

check_auth_anomalies() {
    echo ""
    echo "--- 认证异常检测 ---"

    # 检查暴力破解
    local failed_count=0
    if [ -n "$DATA_DIR" ] && [ -f "$DATA_DIR/secure.log" ]; then
        failed_count=$(grep -c 'Failed password' "$DATA_DIR/secure.log" 2>/dev/null || echo 0)
    elif [ -f /var/log/secure ]; then
        failed_count=$(grep -c 'Failed password' /var/log/secure 2>/dev/null || echo 0)
    elif [ -f /var/log/auth.log ]; then
        failed_count=$(grep -c 'Failed password' /var/log/auth.log 2>/dev/null || echo 0)
    fi

    if [ "$failed_count" -gt 50 ]; then
        print_result "ALERT" "认证" "检测到大量失败登录尝试 ($failed_count 次)，可能存在暴力破解"
    elif [ "$failed_count" -gt 10 ]; then
        print_result "WARN" "认证" "检测到较多失败登录尝试 ($failed_count 次)"
    else
        print_result "PASS" "认证" "失败登录尝试次数正常 ($failed_count 次)"
    fi

    # 检查 root 直接登录
    local root_login=0
    if [ -n "$DATA_DIR" ] && [ -f "$DATA_DIR/secure.log" ]; then
        root_login=$(grep -c 'Accepted.*for root' "$DATA_DIR/secure.log" 2>/dev/null || echo 0)
    elif [ -f /var/log/secure ]; then
        root_login=$(grep -c 'Accepted.*for root' /var/log/secure 2>/dev/null || echo 0)
    fi

    if [ "$root_login" -gt 0 ]; then
        print_result "WARN" "认证" "检测到 root 直接 SSH 登录 ($root_login 次)"
    else
        print_result "PASS" "认证" "未检测到 root 直接 SSH 登录"
    fi

    # 检查空密码账户
    local empty_pass=0
    if [ -f /etc/shadow ]; then
        empty_pass=$(awk -F: '$2 == "" {print $1}' /etc/shadow 2>/dev/null | wc -l)
    fi

    if [ "$empty_pass" -gt 0 ]; then
        print_result "ALERT" "认证" "检测到空密码账户 ($empty_pass 个)"
    else
        print_result "PASS" "认证" "未检测到空密码账户"
    fi
}

check_privilege_anomalies() {
    echo ""
    echo "--- 特权操作检测 ---"

    # 检查 sudo 使用
    local sudo_count=0
    if [ -n "$DATA_DIR" ] && [ -f "$DATA_DIR/secure.log" ]; then
        sudo_count=$(grep -c 'sudo:' "$DATA_DIR/secure.log" 2>/dev/null || echo 0)
    elif [ -f /var/log/secure ]; then
        sudo_count=$(grep -c 'sudo:' /var/log/secure 2>/dev/null || echo 0)
    fi

    if [ "$sudo_count" -gt 50 ]; then
        print_result "ALERT" "特权" "检测到大量 sudo 操作 ($sudo_count 次)，请确认是否正常"
    elif [ "$sudo_count" -gt 20 ]; then
        print_result "WARN" "特权" "检测到较多 sudo 操作 ($sudo_count 次)"
    else
        print_result "PASS" "特权" "sudo 使用频率正常 ($sudo_count 次)"
    fi

    # 检查 UID=0 的非 root 用户
    local uid0_users=0
    if [ -f /etc/passwd ]; then
        uid0_users=$(awk -F: '$3 == 0 && $1 != "root"' /etc/passwd 2>/dev/null | wc -l)
    fi

    if [ "$uid0_users" -gt 0 ]; then
        print_result "ALERT" "特权" "检测到 UID=0 的非 root 用户 ($uid0_users 个)"
    else
        print_result "PASS" "特权" "UID=0 用户正常（仅 root）"
    fi

    # 检查新增 SUID 文件
    local suid_new=0
    if [ -f /etc/passwd ]; then
        suid_new=$(find / -perm -4000 -newer /etc/passwd -type f 2>/dev/null | wc -l)
    fi

    if [ "$suid_new" -gt 0 ]; then
        print_result "ALERT" "特权" "检测到新增 SUID 文件 ($suid_new 个)"
    else
        print_result "PASS" "特权" "未检测到新增 SUID 文件"
    fi
}

check_file_integrity() {
    echo ""
    echo "--- 文件完整性检测 ---"

    # RPM 验证
    if command -v rpm &>/dev/null; then
        local rpm_issues=0
        rpm_issues=$(rpm -Va 2>/dev/null | grep -cE '^[.S5MDLUGTP]' || echo 0)

        if [ "$rpm_issues" -gt 20 ]; then
            print_result "ALERT" "文件" "RPM 验证发现大量异常 ($rpm_issues 个文件)"
        elif [ "$rpm_issues" -gt 5 ]; then
            print_result "WARN" "文件" "RPM 验证发现部分异常 ($rpm_issues 个文件)"
        else
            print_result "PASS" "文件" "RPM 验证正常 ($rpm_issues 个文件有变更)"
        fi
    fi

    # 检查关键文件修改
    local passwd_modified=0
    if [ -f /etc/passwd ]; then
        local mtime
        mtime=$(stat -c %Y /etc/passwd 2>/dev/null || echo 0)
        local now
        now=$(date +%s)
        local diff_hours=$(( (now - mtime) / 3600 ))

        if [ "$diff_hours" -lt 24 ]; then
            print_result "WARN" "文件" "/etc/passwd 在最近 24 小时内被修改"
        else
            print_result "PASS" "文件" "/etc/passwd 未在最近 24 小时内修改"
        fi
    fi
}

check_process_anomalies() {
    echo ""
    echo "--- 进程异常检测 ---"

    # 检查 /tmp 下的可执行文件
    local tmp_exec=0
    tmp_exec=$(find /tmp /dev/shm -type f -executable 2>/dev/null | wc -l)

    if [ "$tmp_exec" -gt 0 ]; then
        print_result "ALERT" "进程" "检测到 /tmp 或 /dev/shm 下的可执行文件 ($tmp_exec 个)"
    else
        print_result "PASS" "进程" "未检测到 /tmp 或 /dev/shm 下的可执行文件"
    fi

    # 检查隐藏进程
    local ps_count
    ps_count=$(ps -e -o pid= 2>/dev/null | wc -l)
    local proc_count
    proc_count=$(ls -1 /proc 2>/dev/null | grep '^[0-9]' | wc -l)
    local diff=$((proc_count - ps_count))

    if [ "$diff" -gt 5 ]; then
        print_result "ALERT" "进程" "检测到可能的隐藏进程 (差异: $diff)"
    else
        print_result "PASS" "进程" "进程列表正常"
    fi

    # 检查高 CPU 进程
    local high_cpu=0
    high_cpu=$(ps aux --sort=-%cpu 2>/dev/null | awk 'NR>1 && $3>80' | wc -l)

    if [ "$high_cpu" -gt 0 ]; then
        print_result "WARN" "进程" "检测到高 CPU 进程 ($high_cpu 个 > 80%)"
    else
        print_result "PASS" "进程" "CPU 使用正常"
    fi
}

check_network_anomalies() {
    echo ""
    echo "--- 网络异常检测 ---"

    # 检查非标准端口外连
    local non_standard=0
    if command -v ss &>/dev/null; then
        non_standard=$(ss -tunap state established 2>/dev/null | awk '$5 !~ /:22$|:80$|:443$|:53$/' | wc -l)
    fi

    if [ "$non_standard" -gt 10 ]; then
        print_result "WARN" "网络" "检测到大量非标准端口外连 ($non_standard 个)"
    elif [ "$non_standard" -gt 0 ]; then
        print_result "WARN" "网络" "检测到非标准端口外连 ($non_standard 个)"
    else
        print_result "PASS" "网络" "网络连接正常"
    fi

    # 检查异常监听端口
    local listening=0
    if command -v ss &>/dev/null; then
        listening=$(ss -tulnp 2>/dev/null | grep -cv '^State' || echo 0)
    fi

    print_result "PASS" "网络" "当前监听端口数: $listening"
}

check_config_tampering() {
    echo ""
    echo "--- 配置篡改检测 ---"

    # 检查 crontab 变更
    local cron_modified=0
    if [ -f /etc/crontab ]; then
        local mtime
        mtime=$(stat -c %Y /etc/crontab 2>/dev/null || echo 0)
        local now
        now=$(date +%s)
        local diff_hours=$(( (now - mtime) / 3600 ))

        if [ "$diff_hours" -lt 24 ]; then
            print_result "WARN" "配置" "/etc/crontab 在最近 24 小时内被修改"
            cron_modified=1
        fi
    fi

    if [ "$cron_modified" -eq 0 ]; then
        print_result "PASS" "配置" "crontab 未在最近 24 小时内修改"
    fi

    # 检查 SSH 配置变更
    local ssh_modified=0
    if [ -f /etc/ssh/sshd_config ]; then
        local mtime
        mtime=$(stat -c %Y /etc/ssh/sshd_config 2>/dev/null || echo 0)
        local now
        now=$(date +%s)
        local diff_hours=$(( (now - mtime) / 3600 ))

        if [ "$diff_hours" -lt 24 ]; then
            print_result "WARN" "配置" "sshd_config 在最近 24 小时内被修改"
            ssh_modified=1
        fi
    fi

    if [ "$ssh_modified" -eq 0 ]; then
        print_result "PASS" "配置" "SSH 配置未在最近 24 小时内修改"
    fi

    # 检查 SSH authorized_keys
    local key_files=0
    local ssh_dirs="/root/.ssh"
    [ -d /home ] && ssh_dirs="$ssh_dirs /home/*/.ssh"
    key_files=$(find $ssh_dirs -name "authorized_keys" -mtime -1 2>/dev/null | wc -l)

    if [ "$key_files" -gt 0 ]; then
        print_result "ALERT" "配置" "检测到最近修改的 SSH authorized_keys ($key_files 个)"
    else
        print_result "PASS" "配置" "SSH 密钥文件未在最近 24 小时内修改"
    fi
}

check_audit_system() {
    echo ""
    echo "--- 审计系统自身检查 ---"

    # 检查 auditd 状态
    if systemctl is-active auditd &>/dev/null; then
        print_result "PASS" "审计" "auditd 正在运行"
    else
        print_result "ALERT" "审计" "auditd 未运行"
    fi

    # 检查审计日志完整性
    if [ -f /var/log/audit/audit.log ]; then
        local size
        size=$(du -sh /var/log/audit/audit.log 2>/dev/null | cut -f1)
        print_result "PASS" "审计" "审计日志存在，大小: $size"
    else
        print_result "ALERT" "审计" "审计日志文件不存在"
    fi

    # 检查审计规则
    local rules_count=0
    if command -v auditctl &>/dev/null; then
        rules_count=$(auditctl -l 2>/dev/null | grep -cv '^No rules' || echo 0)
    fi

    if [ "$rules_count" -eq 0 ]; then
        print_result "WARN" "审计" "未配置审计规则"
    else
        print_result "PASS" "审计" "已配置 $rules_count 条审计规则"
    fi
}

# --- 基线检查模式 ---

check_baseline() {
    echo ""
    echo "=========================================="
    echo "  安全基线检查"
    echo "=========================================="

    # SSH 配置
    echo ""
    echo "--- SSH 安全配置 ---"

    if [ -f /etc/ssh/sshd_config ]; then
        local permit_root
        permit_root=$(grep -E '^PermitRootLogin' /etc/ssh/sshd_config | awk '{print $2}' || echo "not_set")
        if [ "$permit_root" = "no" ]; then
            print_result "PASS" "SSH" "禁止 root 直接登录"
        else
            print_result "WARN" "SSH" "允许 root 直接登录 (PermitRootLogin=$permit_root)"
        fi

        local pass_auth
        pass_auth=$(grep -E '^PasswordAuthentication' /etc/ssh/sshd_config | awk '{print $2}' || echo "not_set")
        if [ "$pass_auth" = "no" ]; then
            print_result "PASS" "SSH" "已禁用密码认证"
        else
            print_result "WARN" "SSH" "密码认证已启用 (PasswordAuthentication=$pass_auth)"
        fi

        local max_auth
        max_auth=$(grep -E '^MaxAuthTries' /etc/ssh/sshd_config | awk '{print $2}' || echo "not_set")
        if [ "$max_auth" != "not_set" ] && [ "$max_auth" -le 4 ]; then
            print_result "PASS" "SSH" "最大认证尝试次数: $max_auth"
        else
            print_result "WARN" "SSH" "最大认证尝试次数未限制或过大 (MaxAuthTries=$max_auth)"
        fi
    fi

    # 密码策略
    echo ""
    echo "--- 密码策略 ---"

    if [ -f /etc/login.defs ]; then
        local pass_max
        pass_max=$(grep -E '^PASS_MAX_DAYS' /etc/login.defs | awk '{print $2}')
        if [ -n "$pass_max" ] && [ "$pass_max" -le 90 ]; then
            print_result "PASS" "密码" "密码最大有效期: ${pass_max} 天"
        else
            print_result "WARN" "密码" "密码最大有效期未限制或过大 (${pass_max:-未设置} 天)"
        fi

        local pass_min
        pass_min=$(grep -E '^PASS_MIN_LEN' /etc/login.defs | awk '{print $2}')
        if [ -n "$pass_min" ] && [ "$pass_min" -ge 8 ]; then
            print_result "PASS" "密码" "密码最小长度: ${pass_min}"
        else
            print_result "WARN" "密码" "密码最小长度不足 (${pass_min:-未设置})"
        fi
    fi

    # SELinux
    echo ""
    echo "--- SELinux 状态 ---"

    if command -v getenforce &>/dev/null; then
        local mode
        mode=$(getenforce 2>/dev/null || echo "unknown")
        if [ "$mode" = "Enforcing" ]; then
            print_result "PASS" "SELinux" "SELinux 为 Enforcing 模式"
        else
            print_result "WARN" "SELinux" "SELinux 不是 Enforcing 模式 ($mode)"
        fi
    fi

    # 防火墙
    echo ""
    echo "--- 防火墙状态 ---"

    if systemctl is-active firewalld &>/dev/null; then
        print_result "PASS" "防火墙" "firewalld 正在运行"
    elif iptables -L -n 2>/dev/null | grep -qv '^Chain'; then
        print_result "PASS" "防火墙" "iptables 已配置规则"
    else
        print_result "WARN" "防火墙" "防火墙未启用"
    fi
}

# --- 主流程 ---

echo "=========================================="
echo "  综合异常行为扫描"
echo "=========================================="
echo "扫描时间: $(date '+%Y-%m-%d %H:%M:%S')"
if [ -n "$DATA_DIR" ]; then
    echo "数据目录: $DATA_DIR"
fi
echo "=========================================="

check_auth_anomalies
check_privilege_anomalies
check_file_integrity
check_process_anomalies
check_network_anomalies
check_config_tampering
check_audit_system

if [ "$BASELINE_MODE" -eq 1 ]; then
    check_baseline
fi

# --- 输出汇总 ---

echo ""
echo "=========================================="
echo "  [SUMMARY] 扫描结果汇总"
echo "=========================================="
echo -e "通过: ${GREEN}${PASS_COUNT}${NC}"
echo -e "警告: ${YELLOW}${WARN_COUNT}${NC}"
echo -e "告警: ${RED}${ALERT_COUNT}${NC}"
echo ""
# 归一化风险评分到 0-100
if [ "$RISK_SCORE" -gt 100 ]; then
    RISK_SCORE=100
fi
echo "风险评分: $RISK_SCORE / 100"
echo ""

if [ "$RISK_SCORE" -ge 60 ]; then
    echo -e "${RED}[CRITICAL] 系统存在严重安全风险，建议立即响应${NC}"
elif [ "$RISK_SCORE" -ge 30 ]; then
    echo -e "${YELLOW}[HIGH] 系统存在安全风险，建议尽快调查${NC}"
elif [ "$RISK_SCORE" -ge 10 ]; then
    echo -e "${YELLOW}[MEDIUM] 系统存在轻微风险，建议计划性排查${NC}"
else
    echo -e "${GREEN}[LOW] 系统安全状态良好${NC}"
fi

echo "=========================================="
