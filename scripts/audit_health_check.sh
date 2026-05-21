#!/bin/bash

# 审计系统健康检查脚本
# 检查 auditd 状态、日志完整性、存储空间等

set -euo pipefail

# --- 颜色定义 ---
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

# --- 统计变量 ---
PASS_COUNT=0
WARN_COUNT=0
ALERT_COUNT=0

# --- 辅助函数 ---

print_result() {
    local level="$1"
    local check="$2"
    local message="$3"

    case "$level" in
        PASS)
            echo -e "${GREEN}[PASS]${NC} $check: $message"
            PASS_COUNT=$((PASS_COUNT + 1))
            ;;
        WARN)
            echo -e "${YELLOW}[WARN]${NC} $check: $message"
            WARN_COUNT=$((WARN_COUNT + 1))
            ;;
        ALERT)
            echo -e "${RED}[ALERT]${NC} $check: $message"
            ALERT_COUNT=$((ALERT_COUNT + 1))
            ;;
    esac
}

# --- 检查函数 ---

check_auditd_installed() {
    if command -v auditd &>/dev/null || [ -f /usr/sbin/auditd ]; then
        print_result "PASS" "auditd 安装" "auditd 已安装"
    else
        print_result "ALERT" "auditd 安装" "auditd 未安装，请执行: yum install audit"
    fi
}

check_auditd_running() {
    if systemctl is-active auditd &>/dev/null; then
        print_result "PASS" "auditd 运行" "auditd 正在运行"
    else
        print_result "ALERT" "auditd 运行" "auditd 未运行，请执行: systemctl start auditd"
    fi
}

check_auditd_enabled() {
    if systemctl is-enabled auditd &>/dev/null; then
        print_result "PASS" "auditd 自启" "auditd 已设置开机自启"
    else
        print_result "WARN" "auditd 自启" "auditd 未设置开机自启，请执行: systemctl enable auditd"
    fi
}

check_audit_rules() {
    local rules_count
    rules_count=$(auditctl -l 2>/dev/null | grep -cv '^No rules' || echo 0)

    if [ "$rules_count" -eq 0 ]; then
        print_result "ALERT" "审计规则" "未配置审计规则，请运行 audit_setup.sh"
    elif [ "$rules_count" -lt 10 ]; then
        print_result "WARN" "审计规则" "审计规则较少（${rules_count} 条），建议检查完整性"
    else
        print_result "PASS" "审计规则" "已配置 ${rules_count} 条审计规则"
    fi
}

check_audit_log_exists() {
    local log_file="/var/log/audit/audit.log"
    if [ -f "$log_file" ]; then
        local size
        size=$(du -sh "$log_file" 2>/dev/null | cut -f1)
        print_result "PASS" "审计日志" "审计日志存在，大小: $size"
    else
        print_result "ALERT" "审计日志" "审计日志文件不存在: $log_file"
    fi
}

check_audit_log_size() {
    local log_file="/var/log/audit/audit.log"
    if [ ! -f "$log_file" ]; then
        return
    fi

    local size_mb
    size_mb=$(du -m "$log_file" 2>/dev/null | cut -f1)

    if [ "$size_mb" -gt 500 ]; then
        print_result "ALERT" "日志大小" "审计日志过大（${size_mb}MB），建议轮转"
    elif [ "$size_mb" -gt 100 ]; then
        print_result "WARN" "日志大小" "审计日志较大（${size_mb}MB），建议关注"
    else
        print_result "PASS" "日志大小" "审计日志大小正常（${size_mb}MB）"
    fi
}

check_log_disk_space() {
    local log_dir="/var/log/audit"
    if [ ! -d "$log_dir" ]; then
        return
    fi

    local usage
    usage=$(df -h "$log_dir" | tail -1 | awk '{print $5}' | tr -d '%')

    if [ "$usage" -gt 90 ]; then
        print_result "ALERT" "磁盘空间" "/var/log 所在分区使用率 ${usage}%，空间严重不足"
    elif [ "$usage" -gt 80 ]; then
        print_result "WARN" "磁盘空间" "/var/log 所在分区使用率 ${usage}%，空间紧张"
    else
        print_result "PASS" "磁盘空间" "/var/log 所在分区使用率 ${usage}%"
    fi
}

check_auditd_config() {
    local config_file="/etc/audit/auditd.conf"
    if [ -f "$config_file" ]; then
        # 检查关键配置
        local max_log_file
        max_log_file=$(grep '^max_log_file' "$config_file" | awk -F= '{print $2}' | tr -d ' ')

        local num_logs
        num_logs=$(grep '^num_logs' "$config_file" | awk -F= '{print $2}' | tr -d ' ')

        if [ -n "$max_log_file" ] && [ -n "$num_logs" ]; then
            print_result "PASS" "auditd 配置" "max_log_file=${max_log_file}MB, num_logs=${num_logs}"
        else
            print_result "WARN" "auditd 配置" "配置文件格式异常，请检查 $config_file"
        fi
    else
        print_result "ALERT" "auditd 配置" "配置文件不存在: $config_file"
    fi
}

check_selinux() {
    if command -v getenforce &>/dev/null; then
        local mode
        mode=$(getenforce 2>/dev/null || echo "unknown")
        case "$mode" in
            Enforcing)
                print_result "PASS" "SELinux" "SELinux 为 Enforcing 模式"
                ;;
            Permissive)
                print_result "WARN" "SELinux" "SELinux 为 Permissive 模式（仅记录不拒绝）"
                ;;
            Disabled)
                print_result "WARN" "SELinux" "SELinux 已禁用"
                ;;
            *)
                print_result "WARN" "SELinux" "无法获取 SELinux 状态"
                ;;
        esac
    fi
}

check_logrotate() {
    if [ -f /etc/logrotate.d/audit ]; then
        print_result "PASS" "日志轮转" "audit 日志轮转已配置"
    else
        print_result "WARN" "日志轮转" "未配置 audit 日志轮转，建议创建 /etc/logrotate.d/audit"
    fi
}

check_recent_activity() {
    local log_file="/var/log/audit/audit.log"
    if [ ! -f "$log_file" ]; then
        return
    fi

    local last_modified
    last_modified=$(stat -c %Y "$log_file" 2>/dev/null || echo 0)
    local now
    now=$(date +%s)
    local diff_hours=$(( (now - last_modified) / 3600 ))

    if [ "$diff_hours" -gt 24 ]; then
        print_result "WARN" "日志活跃度" "审计日志最后更新于 ${diff_hours} 小时前，可能无新事件"
    else
        print_result "PASS" "日志活跃度" "审计日志在 ${diff_hours} 小时内有更新"
    fi
}

# --- 主流程 ---

echo "=========================================="
echo "  审计系统健康检查"
echo "=========================================="
echo "检查时间: $(date '+%Y-%m-%d %H:%M:%S')"
echo "=========================================="
echo ""

check_auditd_installed
check_auditd_running
check_auditd_enabled
check_audit_rules
check_audit_log_exists
check_audit_log_size
check_log_disk_space
check_auditd_config
check_selinux
check_logrotate
check_recent_activity

echo ""
echo "=========================================="
echo "  检查结果汇总"
echo "=========================================="
echo -e "通过: ${GREEN}${PASS_COUNT}${NC}"
echo -e "警告: ${YELLOW}${WARN_COUNT}${NC}"
echo -e "告警: ${RED}${ALERT_COUNT}${NC}"
echo "=========================================="

if [ "$ALERT_COUNT" -gt 0 ]; then
    echo ""
    echo "[建议] 存在告警项，请优先处理以确保审计系统正常运行。"
    exit 1
elif [ "$WARN_COUNT" -gt 0 ]; then
    echo ""
    echo "[建议] 存在警告项，建议在合适时机处理。"
    exit 0
else
    echo ""
    echo "[正常] 审计系统状态良好。"
    exit 0
fi
