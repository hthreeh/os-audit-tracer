#!/bin/bash

# 平台检测脚本
# 检测操作系统类型（openEuler / FusionOS / 其他 Linux）
# 输出平台标识和审计环境信息

set -euo pipefail

# --- 输出变量 ---
PLATFORM="unknown"
VERSION="unknown"
ARCH=$(uname -m)
AUDITD_STATUS="unknown"
SELINUX_STATUS="unknown"
AUDIT_RULES_COUNT=0

# --- 平台检测 ---

# 检查 FusionOS（优先，因为 FusionOS 可能也包含 openEuler 标识）
if [ -f /etc/EulerOS-release ] || [ -f /etc/fusionos-release ]; then
    PLATFORM="fusionos"
    if [ -f /etc/EulerOS-release ]; then
        VERSION=$(cat /etc/EulerOS-release | head -1)
    else
        VERSION=$(cat /etc/fusionos-release | head -1)
    fi
elif [ -f /etc/openEuler-release ]; then
    PLATFORM="openeuler"
    VERSION=$(cat /etc/openEuler-release | head -1)
elif [ -f /etc/os-release ]; then
    . /etc/os-release
    case "$ID" in
        openEuler)
            PLATFORM="openeuler"
            VERSION="${VERSION_ID:-unknown}"
            ;;
        euler|fusionos)
            PLATFORM="fusionos"
            VERSION="${VERSION_ID:-unknown}"
            ;;
        centos|rhel)
            PLATFORM="centos"
            VERSION="${VERSION_ID:-unknown}"
            ;;
        ubuntu|debian)
            PLATFORM="debian"
            VERSION="${VERSION_ID:-unknown}"
            ;;
        *)
            PLATFORM="other"
            VERSION="${VERSION_ID:-unknown}"
            ;;
    esac
fi

# --- auditd 状态检测 ---

if command -v auditd &>/dev/null || [ -f /usr/sbin/auditd ]; then
    if systemctl is-active auditd &>/dev/null; then
        AUDITD_STATUS="active"
    elif systemctl is-enabled auditd &>/dev/null; then
        AUDITD_STATUS="enabled_but_inactive"
    else
        AUDITD_STATUS="installed_but_disabled"
    fi
else
    AUDITD_STATUS="not_installed"
fi

# --- 审计规则计数 ---

if command -v auditctl &>/dev/null; then
    AUDIT_RULES_COUNT=$(auditctl -l 2>/dev/null | grep -cv '^No rules' || echo 0)
fi

# --- SELinux 状态检测 ---

if command -v getenforce &>/dev/null; then
    SELINUX_STATUS=$(getenforce 2>/dev/null || echo "unknown")
elif [ -f /etc/selinux/config ]; then
    SELINUX_STATUS=$(grep '^SELINUX=' /etc/selinux/config | cut -d= -f2)
else
    SELINUX_STATUS="not_available"
fi

# --- 架构标准化 ---

case "$ARCH" in
    x86_64|amd64)
        ARCH="x86_64"
        AUDIT_ARCH="b64"
        ;;
    aarch64|arm64)
        ARCH="aarch64"
        AUDIT_ARCH="aarch64"
        ;;
    riscv64)
        ARCH="riscv64"
        AUDIT_ARCH="b64"
        ;;
    loongarch64)
        ARCH="loongarch64"
        AUDIT_ARCH="loongarch64"
        ;;
    *)
        AUDIT_ARCH="b64"
        ;;
esac

# --- 输出结果 ---

echo "=========================================="
echo "  平台检测结果"
echo "=========================================="
echo "PLATFORM=$PLATFORM"
echo "VERSION=$VERSION"
echo "ARCH=$ARCH"
echo "AUDIT_ARCH=$AUDIT_ARCH"
echo "AUDITD_STATUS=$AUDITD_STATUS"
echo "SELINUX_STATUS=$SELINUX_STATUS"
echo "AUDIT_RULES_COUNT=$AUDIT_RULES_COUNT"
echo "=========================================="

# --- 环境建议 ---

echo ""
echo "环境评估："

if [ "$AUDITD_STATUS" = "not_installed" ]; then
    echo "[严重] auditd 未安装，请先安装："
    echo "  yum install audit       # openEuler/FusionOS/CentOS"
    echo "  apt install auditd      # Ubuntu/Debian"
elif [ "$AUDITD_STATUS" != "active" ]; then
    echo "[警告] auditd 未运行，请启动："
    echo "  systemctl start auditd"
    echo "  systemctl enable auditd"
else
    echo "[正常] auditd 已运行"
fi

if [ "$SELINUX_STATUS" = "Disabled" ]; then
    echo "[警告] SELinux 已禁用，建议启用以增强安全性"
elif [ "$SELINUX_STATUS" = "Permissive" ]; then
    echo "[提示] SELinux 为 Permissive 模式（仅记录不拒绝）"
    echo "  生产环境建议切换到 Enforcing 模式"
elif [ "$SELINUX_STATUS" = "Enforcing" ]; then
    echo "[正常] SELinux 为 Enforcing 模式"
fi

if [ "$AUDIT_RULES_COUNT" -eq 0 ]; then
    echo "[警告] 未配置审计规则，建议运行 audit_setup.sh 部署规则"
elif [ "$AUDIT_RULES_COUNT" -lt 10 ]; then
    echo "[提示] 审计规则较少（$AUDIT_RULES_COUNT 条），建议检查规则完整性"
else
    echo "[正常] 已配置 $AUDIT_RULES_COUNT 条审计规则"
fi
