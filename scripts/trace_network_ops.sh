#!/bin/bash

# 网络操作追溯脚本
# 追踪外连、监听端口、防火墙变更等网络活动

set -euo pipefail

# --- 默认参数 ---
START_TIME=""
END_TIME=""
TARGET_IP=""
TARGET_PORT=""
OUTPUT_DIR="./net-trace-$(date +%Y%m%d_%H%M%S)"
DATA_DIR=""
INCLUDE_LIVE=0

# --- 颜色定义 ---
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

# --- 参数解析 ---

show_help() {
    echo "用法: $0 -S <起始时间> [-E <结束时间>] [-d <目标IP>] [-p <端口>] [--live] [-o <输出目录>]"
    echo ""
    echo "追溯网络操作和连接活动。"
    echo ""
    echo "参数:"
    echo "  -S <time>    起始时间（必需），格式: 'YYYY-MM-DD HH:MM:SS' 或 epoch"
    echo "  -E <time>    结束时间（可选），默认为当前时间"
    echo "  -d <ip>      过滤特定目标 IP 地址（可选）"
    echo "  -p <port>    过滤特定端口（可选）"
    echo "  --live       包含当前实时网络状态（ss 输出）"
    echo "  -o <dir>     输出目录（可选）"
    echo "  -h           显示此帮助信息"
    echo ""
    echo "数据来源:"
    echo "  - ausearch -k network"
    echo "  - ss（当前 socket 状态）"
    echo "  - journalctl（防火墙日志）"
    echo ""
    echo "检测事件:"
    echo "  - 出站网络连接"
    echo "  - 监听端口"
    echo "  - 防火墙规则变更"
    echo "  - 网络配置文件修改"
    echo ""
    echo "示例:"
    echo "  $0 -S '2026-05-20 00:00:00'"
    echo "  $0 -S '2026-05-20 00:00:00' -d 10.0.0.5 -p 443"
    echo "  $0 -S '2026-05-20 00:00:00' --live"
}

while [ $# -gt 0 ]; do
    case "$1" in
        -S)
            START_TIME="$2"; shift 2 ;;
        -S=*)
            START_TIME="${1#*=}"; shift ;;
        -E)
            END_TIME="$2"; shift 2 ;;
        -E=*)
            END_TIME="${1#*=}"; shift ;;
        -d)
            TARGET_IP="$2"; shift 2 ;;
        -d=*)
            TARGET_IP="${1#*=}"; shift ;;
        -p)
            TARGET_PORT="$2"; shift 2 ;;
        -p=*)
            TARGET_PORT="${1#*=}"; shift ;;
        --live)
            INCLUDE_LIVE=1; shift ;;
        -o)
            OUTPUT_DIR="$2"; shift 2 ;;
        -o=*)
            OUTPUT_DIR="${1#*=}"; shift ;;
        -h|--help)
            show_help; exit 0 ;;
        *)
            echo -e "${RED}[错误]${NC} 未知参数: $1"
            echo "使用 -h 查看帮助"
            exit 1 ;;
    esac
done

if [ -z "$START_TIME" ]; then
    echo -e "${RED}[错误]${NC} 必须指定起始时间 (-S)"
    echo "使用 -h 查看帮助"
    exit 1
fi

if [ -z "$END_TIME" ]; then
    END_TIME=$(date '+%Y-%m-%d %H:%M:%S')
fi

# --- 创建输出目录 ---

mkdir -p "$OUTPUT_DIR"
RESULTS_FILE="$OUTPUT_DIR/network_ops.log"
TMPFILE=$(mktemp)
trap 'rm -f "$TMPFILE"' EXIT

# --- 解析 auditd 网络事件 ---

parse_audit_network() {
    if ! command -v ausearch &>/dev/null; then
        echo -e "${YELLOW}[跳过]${NC} ausearch 不可用"
        return
    fi

    echo "[1/5] 解析 auditd 网络事件 (key=network)..."

    local ausearch_args=(-k network -ts "$START_TIME" -te "$END_TIME" --input-logs --no-pager)
    ausearch "${ausearch_args[@]}" 2>/dev/null | while IFS= read -r line; do
        local epoch_ts readable_ts
        epoch_ts=$(echo "$line" | grep -oP 'msg=audit\(\K[0-9.]+' || echo "")
        if [ -z "$epoch_ts" ]; then continue; fi
        readable_ts=$(date -d "@${epoch_ts%%.*}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$epoch_ts")

        local syscall auid exe comm saddr
        syscall=$(echo "$line" | grep -oP 'syscall=\K\S+' || echo "-")
        auid=$(echo "$line" | grep -oP 'auid=\K\S+' || echo "-")
        exe=$(echo "$line" | grep -oP 'exe="[^"]*"' | head -1 | cut -d'"' -f2 || echo "-")
        comm=$(echo "$line" | grep -oP 'comm="[^"]*"' | head -1 | cut -d'"' -f2 || echo "-")

        echo "$readable_ts|NET_AUDIT|MEDIUM|auid=$auid|exe=$exe comm=$comm syscall=$syscall"
    done >> "$TMPFILE"

    echo "  auditd 网络事件解析完成"
}

# --- 解析 auditd connect 系统调用 ---

parse_connect_syscalls() {
    if ! command -v ausearch &>/dev/null; then
        echo -e "${YELLOW}[跳过]${NC} ausearch 不可用"
        return
    fi

    echo "[2/5] 解析 connect 系统调用..."

    local ausearch_args=(-sc connect -ts "$START_TIME" -te "$END_TIME" --input-logs --no-pager)
    ausearch "${ausearch_args[@]}" 2>/dev/null | while IFS= read -r line; do
        local epoch_ts readable_ts
        epoch_ts=$(echo "$line" | grep -oP 'msg=audit\(\K[0-9.]+' || echo "")
        if [ -z "$epoch_ts" ]; then continue; fi
        readable_ts=$(date -d "@${epoch_ts%%.*}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$epoch_ts")

        local auid exe comm saddr
        auid=$(echo "$line" | grep -oP 'auid=\K\S+' || echo "-")
        exe=$(echo "$line" | grep -oP 'exe="[^"]*"' | head -1 | cut -d'"' -f2 || echo "-")
        comm=$(echo "$line" | grep -oP 'comm="[^"]*"' | head -1 | cut -d'"' -f2 || echo "-")
        saddr=$(echo "$line" | grep -oP 'saddr=\K\S+' || echo "-")

        # 尝试解析 sockaddr 提取 IP 和端口
        local dest_ip dest_port
        if echo "$saddr" | grep -qP '0200[0-9A-Fa-f]{4}'; then
            # IPv4 sockaddr: 0200 + port(hex) + ip(hex)
            dest_port=$(echo "$saddr" | grep -oP '0200\K[0-9A-Fa-f]{4}')
            dest_port=$((16#$dest_port)) 2>/dev/null || dest_port="?"
            local ip_hex
            ip_hex=$(echo "$saddr" | grep -oP '0200[0-9A-Fa-f]{4}\K[0-9A-Fa-f]{8}')
            if [ -n "$ip_hex" ]; then
                dest_ip=$(printf "%d.%d.%d.%d" \
                    "0x${ip_hex:0:2}" "0x${ip_hex:2:2}" "0x${ip_hex:4:2}" "0x${ip_hex:6:2}" 2>/dev/null || echo "?")
            else
                dest_ip="?"
            fi
        else
            dest_ip="?"
            dest_port="?"
        fi

        # 应用过滤器
        if [ -n "$TARGET_IP" ] && [ "$dest_ip" != "$TARGET_IP" ]; then continue; fi
        if [ -n "$TARGET_PORT" ] && [ "$dest_port" != "$TARGET_PORT" ]; then continue; fi

        local risk="LOW"
        # 连接到非标准端口风险更高
        if [ "$dest_port" != "?" ]; then
            case "$dest_port" in
                22|80|443|53|5353) ;;  # 标准端口：SSH/HTTP/HTTPS/DNS/mDNS
                *) risk="MEDIUM" ;;
            esac
        fi

        echo "$readable_ts|CONNECT|$risk|auid=$auid|dest=$dest_ip:$dest_port exe=$exe comm=$comm"
    done >> "$TMPFILE"

    echo "  connect 系统调用解析完成"
}

# --- 解析防火墙日志 ---

parse_firewall_log() {
    echo "[3/5] 解析防火墙日志..."

    if ! command -v journalctl &>/dev/null; then
        echo -e "${YELLOW}[跳过]${NC} journalctl 不可用"
        return
    fi

    # firewalld 变更日志
    journalctl --since "$START_TIME" --until "$END_TIME" -u firewalld --no-pager 2>/dev/null | while IFS= read -r line; do
        if echo "$line" | grep -qE 'ACCEPT|REJECT|DROP|rule|zone|service|port'; then
            local ts detail
            ts=$(echo "$line" | awk '{print $1, $2, $3}')
            detail=$(echo "$line" | cut -d: -f3- | sed 's/^ *//')
            echo "$ts|FIREWALL|MEDIUM|firewalld|$detail"
        fi
    done >> "$TMPFILE"

    # iptables 变更（通过 audit 日志）
    if command -v ausearch &>/dev/null; then
        ausearch -ts "$START_TIME" -te "$END_TIME" --input-logs --no-pager 2>/dev/null | \
        grep -E 'comm="(iptables|ip6tables|nft)"' | while IFS= read -r line; do
            local epoch_ts readable_ts
            epoch_ts=$(echo "$line" | grep -oP 'msg=audit\(\K[0-9.]+' || echo "")
            if [ -z "$epoch_ts" ]; then continue; fi
            readable_ts=$(date -d "@${epoch_ts%%.*}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$epoch_ts")

            local exe comm auid
            exe=$(echo "$line" | grep -oP 'exe="[^"]*"' | head -1 | cut -d'"' -f2 || echo "-")
            comm=$(echo "$line" | grep -oP 'comm="[^"]*"' | head -1 | cut -d'"' -f2 || echo "-")
            auid=$(echo "$line" | grep -oP 'auid=\K\S+' || echo "-")

            echo "$readable_ts|FIREWALL|HIGH|auid=$auid|comm=$comm exe=$exe"
        done >> "$TMPFILE"
    fi

    echo "  防火墙日志解析完成"
}

# --- 解析网络配置文件变更 ---

parse_network_config_changes() {
    echo "[4/5] 检查网络配置文件变更..."

    local start_epoch
    start_epoch=$(date -d "$START_TIME" +%s 2>/dev/null || echo 0)
    local now_epoch
    now_epoch=$(date +%s)

    local net_config_files=(
        "/etc/hosts"
        "/etc/resolv.conf"
        "/etc/sysconfig/network-scripts/"
        "/etc/NetworkManager/"
        "/etc/nftables.conf"
        "/etc/firewalld/"
        "/etc/iptables/"
    )

    for filepath in "${net_config_files[@]}"; do
        if [[ "$filepath" == */ ]]; then
            if [ -d "$filepath" ]; then
                find "$filepath" -maxdepth 2 -type f -newermt "$START_TIME" 2>/dev/null | while read -r f; do
                    local mtime
                    mtime=$(stat -c %Y "$f" 2>/dev/null || echo 0)
                    if [ "$mtime" -ge "$start_epoch" ] && [ "$mtime" -le "$now_epoch" ]; then
                        local readable_ts
                        readable_ts=$(date -d "@$mtime" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$mtime")
                        echo "$readable_ts|NET_CONFIG|HIGH|$f|网络配置文件被修改"
                    fi
                done >> "$TMPFILE"
            fi
        else
            if [ -f "$filepath" ]; then
                local mtime
                mtime=$(stat -c %Y "$filepath" 2>/dev/null || echo 0)
                if [ "$mtime" -ge "$start_epoch" ] && [ "$mtime" -le "$now_epoch" ]; then
                    local readable_ts
                    readable_ts=$(date -d "@$mtime" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$mtime")
                    echo "$readable_ts|NET_CONFIG|HIGH|$filepath|网络配置文件被修改"
                fi
            fi
        fi
    done

    echo "  网络配置变更检查完成"
}

# --- 采集当前网络状态 ---

collect_live_state() {
    if [ "$INCLUDE_LIVE" -eq 0 ]; then
        echo "[5/5] 当前网络状态（已跳过，使用 --live 启用）"
        return
    fi

    echo "[5/5] 采集当前网络状态..."

    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S')

    # 监听端口
    if command -v ss &>/dev/null; then
        echo ""
        echo "--- 当前监听端口 ---"
        ss -tulnp 2>/dev/null | while IFS= read -r line; do
            if echo "$line" | grep -qE 'LISTEN|UNCONN'; then
                local addr process
                addr=$(echo "$line" | awk '{print $5}')
                process=$(echo "$line" | grep -oP 'users:\(\("\K[^"]+' || echo "-")
                local port
                port=$(echo "$addr" | grep -oP ':\K[0-9]+$' || echo "?")

                # 端口过滤
                if [ -n "$TARGET_PORT" ] && [ "$port" != "$TARGET_PORT" ]; then continue; fi

                echo "$ts|LISTEN|LOW|-|addr=$addr process=$process"
            fi
        done >> "$TMPFILE"

        echo ""
        echo "--- 当前已建立连接 ---"
        ss -tunap state established 2>/dev/null | while IFS= read -r line; do
            local remote_addr process
            remote_addr=$(echo "$line" | awk '{print $5}')
            process=$(echo "$line" | grep -oP 'users:\(\("\K[^"]+' || echo "-")

            local dest_ip dest_port
            dest_ip=$(echo "$remote_addr" | rev | cut -d: -f2- | rev)
            dest_port=$(echo "$remote_addr" | grep -oP ':\K[0-9]+$' || echo "?")

            # 过滤器
            if [ -n "$TARGET_IP" ] && [ "$dest_ip" != "$TARGET_IP" ]; then continue; fi
            if [ -n "$TARGET_PORT" ] && [ "$dest_port" != "$TARGET_PORT" ]; then continue; fi

            # 排除本地回环
            if [ "$dest_ip" = "127.0.0.1" ] || [ "$dest_ip" = "::1" ]; then continue; fi

            local risk="LOW"
            # 非标准端口风险更高
            case "$dest_port" in
                22|80|443|53) ;;
                *) risk="MEDIUM" ;;
            esac

            echo "$ts|ESTABLISHED|$risk|-|dest=$remote_addr process=$process"
        done >> "$TMPFILE"
    fi

    echo "  网络状态采集完成"
}

# --- 格式化输出 ---

print_results() {
    echo ""
    echo "--- 网络活动时间线 ---"
    echo ""
    printf "%-20s %-15s %-10s %-15s %s\n" "时间" "事件类型" "风险" "来源" "详情"
    printf "%-20s %-15s %-10s %-15s %s\n" "----" "--------" "----" "----" "----"

    while IFS='|' read -r ts etype risk source detail; do
        local risk_mark=""
        case "$risk" in
            HIGH)   risk_mark="${RED}HIGH${NC}" ;;
            MEDIUM) risk_mark="${YELLOW}MED${NC}" ;;
            LOW)    risk_mark="${GREEN}LOW${NC}" ;;
        esac
        printf "%-20s %-15s %b %-15s %s\n" "$ts" "$etype" "$risk_mark" "$source" "$detail"
    done < "$RESULTS_FILE"
}

# --- 主流程 ---

echo "=========================================="
echo "  网络操作追溯"
echo "=========================================="
echo "时间范围: $START_TIME ~ $END_TIME"
if [ -n "$TARGET_IP" ]; then echo "目标 IP:  $TARGET_IP"; fi
if [ -n "$TARGET_PORT" ]; then echo "目标端口: $TARGET_PORT"; fi
echo "输出目录: $OUTPUT_DIR"
echo "=========================================="
echo ""

> "$TMPFILE"

parse_audit_network
parse_connect_syscalls
parse_firewall_log
parse_network_config_changes
collect_live_state

# 排序并写入结果文件
if [ -s "$TMPFILE" ]; then
    sort -t'|' -k1 -o "$TMPFILE" "$TMPFILE"
    cp "$TMPFILE" "$RESULTS_FILE"
    print_results
else
    > "$RESULTS_FILE"
    echo -e "${YELLOW}[提示]${NC} 未发现匹配的网络活动"
fi

# --- 统计汇总 ---

TOTAL_EVENTS=$(wc -l < "$RESULTS_FILE" 2>/dev/null || echo 0)
CONNECT_COUNT=$(grep -c '|CONNECT|' "$RESULTS_FILE" 2>/dev/null || echo 0)
FIREWALL_COUNT=$(grep -c '|FIREWALL|' "$RESULTS_FILE" 2>/dev/null || echo 0)
CONFIG_COUNT=$(grep -c '|NET_CONFIG|' "$RESULTS_FILE" 2>/dev/null || echo 0)
LISTEN_COUNT=$(grep -c '|LISTEN|' "$RESULTS_FILE" 2>/dev/null || echo 0)
HIGH_RISK=$(grep -c '|HIGH|' "$RESULTS_FILE" 2>/dev/null || echo 0)

echo ""
echo "=========================================="
echo "  网络操作汇总"
echo "=========================================="
echo -e "总事件数:        $TOTAL_EVENTS"
echo -e "出站连接:        $CONNECT_COUNT"
echo -e "防火墙变更:      ${RED}$FIREWALL_COUNT${NC}"
echo -e "网络配置变更:    ${RED}$CONFIG_COUNT${NC}"
echo -e "监听端口:        $LISTEN_COUNT"
echo -e "高风险事件:      ${RED}$HIGH_RISK${NC}"
echo ""
echo "详细结果: $RESULTS_FILE"
echo ""

if [ "$FIREWALL_COUNT" -gt 0 ]; then
    echo -e "${RED}[WARNING] 检测到防火墙规则变更，请确认是否为授权操作${NC}"
fi
if [ "$CONFIG_COUNT" -gt 0 ]; then
    echo -e "${RED}[WARNING] 检测到网络配置文件变更${NC}"
fi
if [ "$HIGH_RISK" -eq 0 ] && [ "$FIREWALL_COUNT" -eq 0 ]; then
    echo -e "${GREEN}[OK] 网络活动未发现明显异常${NC}"
fi

echo ""
echo "下一步建议:"
echo "  1. 检查高风险事件:   grep 'HIGH' $RESULTS_FILE"
echo "  2. 追溯认证事件:     bash scripts/trace_auth_events.sh -S '$START_TIME'"
echo "  3. 综合异常扫描:     bash scripts/anomaly_scanner.sh"
echo "=========================================="
