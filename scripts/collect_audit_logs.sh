#!/bin/bash

# 审计日志收集脚本
# 收集指定时间范围内的所有审计相关日志

set -euo pipefail

# --- 默认参数 ---
START_TIME=""
END_TIME=""
TARGET_USER=""
OUTPUT_DIR="./audit-logs-$(date +%Y%m%d_%H%M%S)"

# --- 参数解析 ---

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
        -u)
            TARGET_USER="$2"; shift 2 ;;
        -u=*)
            TARGET_USER="${1#*=}"; shift ;;
        -o)
            OUTPUT_DIR="$2"; shift 2 ;;
        -o=*)
            OUTPUT_DIR="${1#*=}"; shift ;;
        -h|--help)
            echo "用法: $0 -S <起始时间> [-E <结束时间>] [-u <用户>] [-o <输出目录>]"
            echo ""
            echo "参数:"
            echo "  -S <time>    起始时间（必需），格式: 'YYYY-MM-DD HH:MM:SS' 或 'YYYY-MM-DD'"
            echo "  -E <time>    结束时间（可选），默认为当前时间"
            echo "  -u <user>    过滤特定用户（可选）"
            echo "  -o <dir>     输出目录（可选）"
            echo ""
            echo "示例:"
            echo "  $0 -S '2024-01-15 14:00:00' -E '2024-01-15 15:00:00'"
            echo "  $0 -S '2024-01-15' -u admin"
            exit 0
            ;;
        *)
            echo "[错误] 未知参数: $1"; exit 1 ;;
    esac
done

if [ -z "$START_TIME" ]; then
    echo "[错误] 必须指定起始时间 (-S)"
    echo "使用 -h 查看帮助"
    exit 1
fi

if [ -z "$END_TIME" ]; then
    END_TIME=$(date '+%Y-%m-%d %H:%M:%S')
fi

# --- 创建输出目录 ---

mkdir -p "$OUTPUT_DIR"
echo "=========================================="
echo "  审计日志收集"
echo "=========================================="
echo "时间范围: $START_TIME ~ $END_TIME"
if [ -n "$TARGET_USER" ]; then
    echo "目标用户: $TARGET_USER"
fi
echo "输出目录: $OUTPUT_DIR"
echo "=========================================="
echo ""

# --- 收集函数 ---

collect_audit_log() {
    local output_file="$OUTPUT_DIR/audit.log"
    echo "[1/6] 收集 audit.log..."

    if [ ! -f /var/log/audit/audit.log ]; then
        echo "  [跳过] /var/log/audit/audit.log 不存在"
        return
    fi

    if command -v ausearch &>/dev/null; then
        local -a ausearch_args=(-ts "$START_TIME" -te "$END_TIME" --input-logs --no-pager)
        if [ -n "$TARGET_USER" ]; then
            ausearch_args=(-ua "$TARGET_USER" -ts "$START_TIME" -te "$END_TIME" --input-logs --no-pager)
        fi
        ausearch "${ausearch_args[@]}" > "$output_file" 2>/dev/null || true
    else
        cp /var/log/audit/audit.log "$output_file" 2>/dev/null || true
    fi

    local lines
    lines=$(wc -l < "$output_file" 2>/dev/null || echo 0)
    echo "  收集完成: $lines 行"
}

collect_secure_log() {
    local output_file="$OUTPUT_DIR/secure.log"
    echo "[2/6] 收集 secure 日志..."

    local secure_file=""
    if [ -f /var/log/secure ]; then
        secure_file="/var/log/secure"
    elif [ -f /var/log/auth.log ]; then
        secure_file="/var/log/auth.log"
    else
        echo "  [跳过] secure/auth 日志不存在"
        return
    fi

    # 按时间范围过滤（覆盖 sshd, sudo, su, pam 等所有认证来源）
    if command -v journalctl &>/dev/null; then
        # 合并多个服务的日志（兼容旧版 journalctl，不使用 + 操作符）
        {
            journalctl _COMM=sshd --since "$START_TIME" --until "$END_TIME" --no-pager 2>/dev/null || true
            journalctl _COMM=sudo --since "$START_TIME" --until "$END_TIME" --no-pager 2>/dev/null || true
            journalctl _COMM=su --since "$START_TIME" --until "$END_TIME" --no-pager 2>/dev/null || true
            journalctl _COMM=login --since "$START_TIME" --until "$END_TIME" --no-pager 2>/dev/null || true
        } | sort -t' ' -k1,3 > "$output_file" 2>/dev/null || true
        # 如果 journalctl 输出为空，回退到直接 grep 原始文件
        if [ ! -s "$output_file" ]; then
            local start_epoch end_epoch
            start_epoch=$(date -d "$START_TIME" +%s 2>/dev/null || echo 0)
            end_epoch=$(date -d "$END_TIME" +%s 2>/dev/null || echo 9999999999)
            grep -E 'sshd|sudo|su:|pam_unix' "$secure_file" 2>/dev/null | while IFS= read -r line; do
                local line_epoch
                line_epoch=$(date -d "$(echo "$line" | awk '{print $1, $2, $3}')" +%s 2>/dev/null || echo 0)
                if [ "$line_epoch" -ge "$start_epoch" ] && [ "$line_epoch" -le "$end_epoch" ]; then
                    echo "$line"
                fi
            done > "$output_file" 2>/dev/null || true
        fi
    else
        cp "$secure_file" "$output_file" 2>/dev/null || true
    fi

    local lines
    lines=$(wc -l < "$output_file" 2>/dev/null || echo 0)
    echo "  收集完成: $lines 行"
}

collect_messages_log() {
    local output_file="$OUTPUT_DIR/messages.log"
    echo "[3/6] 收集 messages 日志..."

    if command -v journalctl &>/dev/null; then
        journalctl --since "$START_TIME" --until "$END_TIME" --no-pager > "$output_file" 2>/dev/null || true
    elif [ -f /var/log/messages ]; then
        cp /var/log/messages "$output_file" 2>/dev/null || true
    else
        echo "  [跳过] messages 日志不可用"
        return
    fi

    local lines
    lines=$(wc -l < "$output_file" 2>/dev/null || echo 0)
    echo "  收集完成: $lines 行"
}

collect_cron_log() {
    local output_file="$OUTPUT_DIR/cron.log"
    echo "[4/6] 收集 cron 日志..."

    if command -v journalctl &>/dev/null; then
        journalctl _COMM=cron --since "$START_TIME" --until "$END_TIME" --no-pager > "$output_file" 2>/dev/null || true
    elif [ -f /var/log/cron ]; then
        cp /var/log/cron "$output_file" 2>/dev/null || true
    else
        echo "  [跳过] cron 日志不可用"
        return
    fi

    local lines
    lines=$(wc -l < "$output_file" 2>/dev/null || echo 0)
    echo "  收集完成: $lines 行"
}

collect_login_records() {
    echo "[5/6] 收集登录记录..."

    # wtmp - 按时间范围过滤
    if [ -f /var/log/wtmp ]; then
        # last -s/-t 需要 YYYYMMDDHHMMSS 格式
        local last_start last_end
        last_start=$(echo "$START_TIME" | sed 's/[-: ]//g;s/^\([0-9]\{14\}\).*/\1/')
        last_end=$(echo "$END_TIME" | sed 's/[-: ]//g;s/^\([0-9]\{14\}\).*/\1/')
        last -s "$last_start" -t "$last_end" > "$OUTPUT_DIR/last.log" 2>/dev/null || \
        last > "$OUTPUT_DIR/last.log" 2>/dev/null || true
        echo "  last.log 收集完成"
    fi

    # btmp - 按时间范围过滤
    if [ -f /var/log/btmp ]; then
        local last_start last_end
        last_start=$(echo "$START_TIME" | sed 's/[-: ]//g;s/^\([0-9]\{14\}\).*/\1/')
        last_end=$(echo "$END_TIME" | sed 's/[-: ]//g;s/^\([0-9]\{14\}\).*/\1/')
        lastb -s "$last_start" -t "$last_end" > "$OUTPUT_DIR/lastb.log" 2>/dev/null || \
        lastb > "$OUTPUT_DIR/lastb.log" 2>/dev/null || true
        echo "  lastb.log 收集完成"
    fi

    # lastlog
    lastlog > "$OUTPUT_DIR/lastlog.log" 2>/dev/null || true
    echo "  lastlog.log 收集完成"

    # who
    who > "$OUTPUT_DIR/who.log" 2>/dev/null || true
    echo "  who.log 收集完成"
}

collect_system_state() {
    echo "[6/6] 收集系统状态..."

    {
        echo "=== 日期 ==="
        date '+%Y-%m-%d %H:%M:%S'
        echo ""
        echo "=== uname ==="
        uname -a
        echo ""
        echo "=== uptime ==="
        uptime
        echo ""
        echo "=== ps auxf ==="
        ps auxf 2>/dev/null || ps aux
        echo ""
        echo "=== ss -tunap ==="
        ss -tunap 2>/dev/null || netstat -tulnp
        echo ""
        echo "=== auditctl -l ==="
        auditctl -l 2>/dev/null || echo "auditctl not available"
        echo ""
        echo "=== getenforce ==="
        getenforce 2>/dev/null || echo "SELinux not available"
    } > "$OUTPUT_DIR/system_state.log" 2>/dev/null

    echo "  系统状态收集完成"
}

# --- 执行收集 ---

collect_audit_log
collect_secure_log
collect_messages_log
collect_cron_log
collect_login_records
collect_system_state

# --- 生成汇总 ---

echo ""
echo "=========================================="
echo "  收集完成"
echo "=========================================="
echo "输出目录: $OUTPUT_DIR"
echo ""
echo "文件列表:"
ls -lh "$OUTPUT_DIR/"
echo ""
echo "下一步建议:"
echo "  1. 构建时间线: bash scripts/build_timeline.sh -S '$START_TIME' -E '$END_TIME' -d '$OUTPUT_DIR'"
echo "  2. 异常扫描: bash scripts/anomaly_scanner.sh -d '$OUTPUT_DIR'"
echo "  3. 事件追溯: bash scripts/trace_auth_events.sh -S '$START_TIME' -E '$END_TIME'"
echo "=========================================="
