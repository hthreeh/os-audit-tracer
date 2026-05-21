#!/bin/bash

# eBPF 实时监控入口脚本
# 自动检测 eBPF 可用性并启动监控

set -euo pipefail

# --- 默认参数 ---
MODE="all"
CHECK_ONLY=0
DURATION=0

# --- 脚本目录 ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- 参数解析 ---

while [ $# -gt 0 ]; do
    case "$1" in
        --mode)
            MODE="$2"; shift 2 ;;
        --mode=*)
            MODE="${1#*=}"; shift ;;
        --check)
            CHECK_ONLY=1; shift ;;
        --duration)
            DURATION="$2"; shift 2 ;;
        --duration=*)
            DURATION="${1#*=}"; shift ;;
        -h|--help)
            echo "用法: $0 [选项]"
            echo ""
            echo "选项:"
            echo "  --mode <type>      监控模式: all/process/file/network/privilege (默认: all)"
            echo "  --check            仅检查 eBPF 环境，不启动监控"
            echo "  --duration <sec>   监控持续时间（秒），0 表示持续监控 (默认: 0)"
            echo "  -h, --help         显示帮助"
            echo ""
            echo "监控模式:"
            echo "  process     进程执行追踪"
            echo "  file        敏感文件访问监控"
            echo "  network     网络连接追踪"
            echo "  privilege   提权行为检测"
            echo "  all         所有监控（默认）"
            exit 0
            ;;
        *)
            echo "[错误] 未知参数: $1"; exit 1 ;;
    esac
done

# --- 颜色定义 ---
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

# --- 环境检查函数 ---

check_kernel_version() {
    echo "--- 内核版本检查 ---"

    local kernel_version
    kernel_version=$(uname -r)
    echo "内核版本: $kernel_version"

    local major
    major=$(echo "$kernel_version" | cut -d. -f1)
    local minor
    minor=$(echo "$kernel_version" | cut -d. -f2)

    if [ "$major" -gt 5 ] || { [ "$major" -eq 5 ] && [ "$minor" -ge 10 ]; }; then
        echo -e "${GREEN}[PASS]${NC} 内核版本 >= 5.10，支持 eBPF"
        return 0
    elif [ "$major" -ge 4 ]; then
        echo -e "${YELLOW}[WARN]${NC} 内核版本可能支持部分 eBPF 功能（建议 >= 5.10）"
        return 0
    else
        echo -e "${RED}[FAIL]${NC} 内核版本过低，eBPF 可能不可用"
        return 1
    fi
}

check_btf() {
    echo ""
    echo "--- BTF 支持检查 ---"

    if [ -f /sys/kernel/btf/vmlinux ]; then
        echo -e "${GREEN}[PASS]${NC} BTF (BPF Type Format) 已启用"
        return 0
    else
        echo -e "${YELLOW}[WARN]${NC} BTF 未启用，部分 bpftrace 功能可能受限"
        return 0
    fi
}

check_bpftrace() {
    echo ""
    echo "--- bpftrace 检查 ---"

    if command -v bpftrace &>/dev/null; then
        local version
        version=$(bpftrace --version 2>&1 | head -1)
        echo -e "${GREEN}[PASS]${NC} bpftrace 已安装: $version"
        return 0
    else
        echo -e "${RED}[FAIL]${NC} bpftrace 未安装"
        echo "  安装方法:"
        echo "    yum install bpftrace       # openEuler/FusionOS"
        echo "    apt install bpftrace        # Ubuntu/Debian"
        return 1
    fi
}

check_bcc_tools() {
    echo ""
    echo "--- bcc-tools 检查 ---"

    if command -v execsnoop-bpfcc &>/dev/null || command -v execsnoop &>/dev/null; then
        echo -e "${GREEN}[PASS]${NC} bcc-tools 已安装"
        return 0
    else
        echo -e "${YELLOW}[WARN]${NC} bcc-tools 未安装（可选）"
        echo "  安装方法:"
        echo "    yum install bcc-tools       # openEuler/FusionOS"
        return 0
    fi
}

check_root() {
    echo ""
    echo "--- 权限检查 ---"

    if [ "$(id -u)" -eq 0 ]; then
        echo -e "${GREEN}[PASS]${NC} 具有 root 权限"
        return 0
    else
        echo -e "${RED}[FAIL]${NC} 需要 root 权限运行 eBPF 监控"
        echo "  请使用: sudo $0"
        return 1
    fi
}

check_kernel_modules() {
    echo ""
    echo "--- 内核模块检查 ---"

    local modules=("bpf" "tracepoint" "kprobe")
    for mod in "${modules[@]}"; do
        if lsmod | grep -q "$mod" || [ -d "/sys/kernel/btf" ]; then
            echo -e "${GREEN}[PASS]${NC} $mod 支持可用"
        fi
    done
}

# --- 监控启动函数 ---

start_process_trace() {
    local output_file="${1:-/dev/stdout}"
    echo "[PROCESS] 启动进程执行追踪..." >> "$output_file"
    local script="$SCRIPT_DIR/ebpf_process_trace.bt"
    if [ -f "$script" ]; then
        if [ "$DURATION" -gt 0 ]; then
            timeout "$DURATION" bpftrace "$script" 2>&1 | sed 's/^/[PROCESS] /' >> "$output_file" || true
        else
            bpftrace "$script" 2>&1 | sed 's/^/[PROCESS] /' >> "$output_file"
        fi
    else
        echo "[PROCESS] [错误] 脚本不存在: $script" >> "$output_file"
    fi
}

start_file_monitor() {
    local output_file="${1:-/dev/stdout}"
    echo "[FILE] 启动敏感文件访问监控..." >> "$output_file"
    local script="$SCRIPT_DIR/ebpf_file_access.bt"
    if [ -f "$script" ]; then
        if [ "$DURATION" -gt 0 ]; then
            timeout "$DURATION" bpftrace "$script" 2>&1 | sed 's/^/[FILE] /' >> "$output_file" || true
        else
            bpftrace "$script" 2>&1 | sed 's/^/[FILE] /' >> "$output_file"
        fi
    else
        echo "[FILE] [错误] 脚本不存在: $script" >> "$output_file"
    fi
}

start_network_trace() {
    local output_file="${1:-/dev/stdout}"
    echo "[NET] 启动网络连接追踪..." >> "$output_file"
    local script="$SCRIPT_DIR/ebpf_network_connect.bt"
    if [ -f "$script" ]; then
        if [ "$DURATION" -gt 0 ]; then
            timeout "$DURATION" bpftrace "$script" 2>&1 | sed 's/^/[NET] /' >> "$output_file" || true
        else
            bpftrace "$script" 2>&1 | sed 's/^/[NET] /' >> "$output_file"
        fi
    else
        echo "[NET] [错误] 脚本不存在: $script" >> "$output_file"
    fi
}

start_privilege_monitor() {
    local output_file="${1:-/dev/stdout}"
    echo "[PRIV] 启动提权行为检测..." >> "$output_file"
    local script="$SCRIPT_DIR/ebpf_privilege_escalation.bt"
    if [ -f "$script" ]; then
        if [ "$DURATION" -gt 0 ]; then
            timeout "$DURATION" bpftrace "$script" 2>&1 | sed 's/^/[PRIV] /' >> "$output_file" || true
        else
            bpftrace "$script" 2>&1 | sed 's/^/[PRIV] /' >> "$output_file"
        fi
    else
        echo "[PRIV] [错误] 脚本不存在: $script" >> "$output_file"
    fi
}

# --- 主流程 ---

echo "=========================================="
echo "  eBPF 实时监控"
echo "=========================================="
echo "检查时间: $(date '+%Y-%m-%d %H:%M:%S')"
echo "=========================================="

# 环境检查
check_kernel_version
check_btf
check_bpftrace
check_root
check_kernel_modules

if [ "$CHECK_ONLY" -eq 1 ]; then
    echo ""
    echo "=========================================="
    echo "  环境检查完成"
    echo "=========================================="
    exit 0
fi

# 启动监控
echo ""
echo "=========================================="
echo "  启动监控 (模式: $MODE)"
echo "=========================================="
echo "按 Ctrl+C 停止监控"
echo ""

case "$MODE" in
    process)
        start_process_trace "/dev/stdout"
        ;;
    file)
        start_file_monitor "/dev/stdout"
        ;;
    network)
        start_network_trace "/dev/stdout"
        ;;
    privilege)
        start_privilege_monitor "/dev/stdout"
        ;;
    all)
        # 使用独立日志文件避免输出混杂
        LOG_DIR="/tmp/ebpf-monitor-$(date +%Y%m%d_%H%M%S)"
        mkdir -p "$LOG_DIR"
        echo "日志目录: $LOG_DIR"
        echo ""

        start_process_trace "$LOG_DIR/process.log" &
        PID1=$!
        start_file_monitor "$LOG_DIR/file.log" &
        PID2=$!
        start_network_trace "$LOG_DIR/network.log" &
        PID3=$!
        start_privilege_monitor "$LOG_DIR/privilege.log" &
        PID4=$!

        # 合并输出并带标签显示
        tail -f "$LOG_DIR"/*.log 2>/dev/null &
        TAIL_PID=$!

        # 等待用户中断
        trap "kill $PID1 $PID2 $PID3 $PID4 $TAIL_PID 2>/dev/null; echo ''; echo '日志保存在: $LOG_DIR'; exit 0" INT TERM
        wait
        ;;
    *)
        echo "[错误] 未知模式: $MODE"
        echo "可用模式: all/process/file/network/privilege"
        exit 1
        ;;
esac
