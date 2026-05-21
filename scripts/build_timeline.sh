#!/bin/bash

# 时间线构建脚本
# 将多源日志统一解析为时间线格式，支持跨日志源排序

set -euo pipefail

# --- 默认参数 ---
START_TIME=""
END_TIME=""
DATA_DIR=""
OUTPUT_DIR="./audit-timeline-$(date +%Y%m%d_%H%M%S)"
TARGET_USER=""

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
        -d)
            DATA_DIR="$2"; shift 2 ;;
        -d=*)
            DATA_DIR="${1#*=}"; shift ;;
        -u)
            TARGET_USER="$2"; shift 2 ;;
        -u=*)
            TARGET_USER="${1#*=}"; shift ;;
        -o)
            OUTPUT_DIR="$2"; shift 2 ;;
        -o=*)
            OUTPUT_DIR="${1#*=}"; shift ;;
        -h|--help)
            echo "用法: $0 -S <起始时间> [-E <结束时间>] [-d <数据目录>] [-u <用户>] [-o <输出目录>]"
            echo ""
            echo "参数:"
            echo "  -S <time>    起始时间（必需）"
            echo "  -E <time>    结束时间（可选），默认为当前时间"
            echo "  -d <dir>     数据目录（由 collect_audit_logs.sh 生成）"
            echo "  -u <user>    过滤特定用户（可选）"
            echo "  -o <dir>     输出目录（可选）"
            exit 0
            ;;
        *)
            echo "[错误] 未知参数: $1"; exit 1 ;;
    esac
done

if [ -z "$START_TIME" ]; then
    echo "[错误] 必须指定起始时间 (-S)"
    exit 1
fi

if [ -z "$END_TIME" ]; then
    END_TIME=$(date '+%Y-%m-%d %H:%M:%S')
fi

# --- 创建输出目录 ---

mkdir -p "$OUTPUT_DIR"
TIMELINE_FILE="$OUTPUT_DIR/timeline.log"
TMPFILE=$(mktemp)
trap 'rm -f "$TMPFILE"' EXIT

echo "=========================================="
echo "  时间线构建"
echo "=========================================="
echo "时间范围: $START_TIME ~ $END_TIME"
echo "=========================================="
echo ""

# --- 辅助函数 ---

# 将 epoch 时间戳转换为 YYYY-MM-DD HH:MM:SS
epoch_to_readable() {
    local epoch="$1"
    date -d "@${epoch%%.*}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$epoch"
}

# 将 "Mon DD HH:MM:SS" 格式转换为 "YYYY-MM-DD HH:MM:SS"
syslog_to_readable() {
    local syslog_ts="$1"
    local year
    year=$(date '+%Y')
    local parsed
    parsed=$(date -d "$syslog_ts $year" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "")
    if [ -z "$parsed" ]; then
        echo "$syslog_ts"
    else
        # 检查是否跨年（如果解析出的时间比当前时间大很多，可能是去年的）
        echo "$parsed"
    fi
}

# --- 解析 audit.log ---

parse_audit_log() {
    local source_file=""

    if [ -n "$DATA_DIR" ] && [ -f "$DATA_DIR/audit.log" ]; then
        source_file="$DATA_DIR/audit.log"
    elif [ -f /var/log/audit/audit.log ]; then
        source_file="/var/log/audit/audit.log"
    fi

    if [ -z "$source_file" ]; then
        echo "[跳过] audit.log 不可用"
        return
    fi

    echo "[1/4] 解析 audit.log..."

    local ausearch_args=(-ts "$START_TIME" -te "$END_TIME" --input-logs --no-pager)
    if [ -n "$TARGET_USER" ]; then
        ausearch_args=(-ua "$TARGET_USER" -ts "$START_TIME" -te "$END_TIME" --input-logs --no-pager)
    fi

    ausearch "${ausearch_args[@]}" 2>/dev/null | while IFS= read -r line; do
        local epoch_ts
        epoch_ts=$(echo "$line" | grep -oP 'msg=audit\(\K[0-9.]+' || echo "")
        if [ -z "$epoch_ts" ]; then continue; fi

        local readable_time
        readable_time=$(epoch_to_readable "$epoch_ts")

        local event_type="AUDIT"
        local detail=""

        if echo "$line" | grep -q 'type=SYSCALL'; then
            event_type="EXEC"
            local comm exe uid auid
            comm=$(echo "$line" | grep -oP 'comm="[^"]+"' | head -1 || echo "")
            exe=$(echo "$line" | grep -oP 'exe="[^"]+"' | head -1 || echo "")
            uid=$(echo "$line" | grep -oP ' uid=\K\S+' || echo "-")
            auid=$(echo "$line" | grep -oP 'auid=\K\S+' || echo "-")
            detail="uid=$uid auid=$auid $comm $exe"

        elif echo "$line" | grep -q 'type=EXECVE'; then
            event_type="EXECVE"
            local exe auid args
            exe=$(echo "$line" | grep -oP 'exe="[^"]+"' | head -1 || echo "")
            auid=$(echo "$line" | grep -oP 'auid=\K\S+' || echo "-")
            args=$(echo "$line" | grep -oP 'a[0-9]+="[^"]*"' | cut -d'"' -f2 | tr '\n' ' ' || echo "")
            detail="auid=$auid $exe args=[$args]"

        elif echo "$line" | grep -q 'type=USER_AUTH'; then
            event_type="AUTH"
            local acct addr res
            acct=$(echo "$line" | grep -oP 'acct="[^"]*"' | head -1 | cut -d'"' -f2 || echo "unknown")
            addr=$(echo "$line" | grep -oP 'addr="[^"]*"' | head -1 | cut -d'"' -f2 || echo "-")
            res=$(echo "$line" | grep -oP 'res=\K\S+' || echo "unknown")
            detail="acct=$acct addr=$addr res=$res"

        elif echo "$line" | grep -q 'type=USER_LOGIN'; then
            event_type="LOGIN"
            local acct addr res
            acct=$(echo "$line" | grep -oP 'acct="[^"]*"' | head -1 | cut -d'"' -f2 || echo "unknown")
            addr=$(echo "$line" | grep -oP 'addr="[^"]*"' | head -1 | cut -d'"' -f2 || echo "-")
            res=$(echo "$line" | grep -oP 'res=\K\S+' || echo "unknown")
            detail="acct=$acct addr=$addr res=$res"

        elif echo "$line" | grep -q 'type=USER_CHAUTHTOK'; then
            event_type="PASSWD"
            local acct
            acct=$(echo "$line" | grep -oP 'acct="[^"]*"' | head -1 | cut -d'"' -f2 || echo "unknown")
            detail="acct=$acct password/token change"

        elif echo "$line" | grep -q 'type=ADD_USER\|type=ADD_GROUP'; then
            event_type="USER_ADD"
            local acct uid
            acct=$(echo "$line" | grep -oP 'acct="[^"]*"' | head -1 | cut -d'"' -f2 || echo "unknown")
            uid=$(echo "$line" | grep -oP ' uid=\K\S+' || echo "-")
            detail="uid=$uid acct=$acct"

        elif echo "$line" | grep -q 'type=DEL_USER\|type=DEL_GROUP'; then
            event_type="USER_DEL"
            local acct uid
            acct=$(echo "$line" | grep -oP 'acct="[^"]*"' | head -1 | cut -d'"' -f2 || echo "unknown")
            uid=$(echo "$line" | grep -oP ' uid=\K\S+' || echo "-")
            detail="uid=$uid acct=$acct"

        elif echo "$line" | grep -q 'type=PATH'; then
            event_type="FILE"
            local name nametype
            name=$(echo "$line" | grep -oP 'name="[^"]*"' | head -1 | cut -d'"' -f2 || echo "-")
            nametype=$(echo "$line" | grep -oP 'nametype=\K\S+' || echo "-")
            detail="$nametype $name"

        elif echo "$line" | grep -q 'type=AVC'; then
            event_type="SELINUX"
            detail=$(echo "$line" | grep -oP 'avc: denied \{[^}]+\}.*' || echo "$line")

        elif echo "$line" | grep -q 'type=SOCKADDR'; then
            event_type="NET"
            local saddr
            saddr=$(echo "$line" | grep -oP 'saddr=\S+' || echo "-")
            detail="$saddr"

        elif echo "$line" | grep -q 'type=CWD'; then
            event_type="CWD"
            local cwd
            cwd=$(echo "$line" | grep -oP 'cwd="[^"]*"' | head -1 | cut -d'"' -f2 || echo "-")
            detail="$cwd"
        fi

        if [ -n "$detail" ]; then
            echo "$readable_time|$event_type|$detail"
        fi
    done >> "$TMPFILE"

    echo "  audit.log 解析完成"
}

# --- 解析 secure 日志 ---

parse_secure_log() {
    local source_file=""

    if [ -n "$DATA_DIR" ] && [ -f "$DATA_DIR/secure.log" ]; then
        source_file="$DATA_DIR/secure.log"
    elif [ -f /var/log/secure ]; then
        source_file="/var/log/secure"
    elif [ -f /var/log/auth.log ]; then
        source_file="/var/log/auth.log"
    fi

    if [ -z "$source_file" ]; then
        echo "[跳过] secure 日志不可用"
        return
    fi

    echo "[2/4] 解析 secure 日志..."

    local start_epoch end_epoch
    start_epoch=$(date -d "$START_TIME" +%s 2>/dev/null || echo 0)
    end_epoch=$(date -d "$END_TIME" +%s 2>/dev/null || echo 9999999999)

    grep -E 'Failed password|Accepted|sudo:|su:' "$source_file" 2>/dev/null | while IFS= read -r line; do
        # 解析 syslog 时间戳并转换为标准格式
        local syslog_ts
        syslog_ts=$(echo "$line" | awk '{print $1, $2, $3}')
        local readable_ts
        readable_ts=$(syslog_to_readable "$syslog_ts")

        # 时间范围过滤
        local line_epoch
        line_epoch=$(date -d "$readable_ts" +%s 2>/dev/null || echo 0)
        if [ "$line_epoch" -lt "$start_epoch" ] || [ "$line_epoch" -gt "$end_epoch" ]; then
            continue
        fi

        local event_type="AUTH"
        local detail=""

        if echo "$line" | grep -q 'Failed password'; then
            event_type="AUTH_FAIL"
            local ip user
            ip=$(echo "$line" | grep -oP 'from \K[0-9.]+' || echo "unknown")
            user=$(echo "$line" | grep -oP 'for (invalid user )?\K\S+' || echo "unknown")
            detail="user=$user from=$ip"
        elif echo "$line" | grep -q 'Accepted'; then
            event_type="AUTH_OK"
            local ip user method
            ip=$(echo "$line" | grep -oP 'from \K[0-9.]+' || echo "unknown")
            user=$(echo "$line" | grep -oP 'for \K\S+' || echo "unknown")
            method=$(echo "$line" | grep -oP 'Accepted \K\S+' || echo "unknown")
            detail="user=$user from=$ip method=$method"
        elif echo "$line" | grep -q 'sudo:'; then
            event_type="SUDO"
            detail=$(echo "$line" | cut -d: -f4- | sed 's/^ *//')
        elif echo "$line" | grep -q 'su:'; then
            event_type="SU"
            detail=$(echo "$line" | cut -d: -f4- | sed 's/^ *//')
        fi

        if [ -n "$detail" ]; then
            echo "$readable_ts|$event_type|$detail"
        fi
    done >> "$TMPFILE"

    echo "  secure 日志解析完成"
}

# --- 解析 messages 日志 ---

parse_messages_log() {
    local source_file=""

    if [ -n "$DATA_DIR" ] && [ -f "$DATA_DIR/messages.log" ]; then
        source_file="$DATA_DIR/messages.log"
    elif [ -f /var/log/messages ]; then
        source_file="/var/log/messages"
    fi

    if [ -z "$source_file" ]; then
        echo "[跳过] messages 日志不可用"
        return
    fi

    echo "[3/4] 解析 messages 日志..."

    local start_epoch end_epoch
    start_epoch=$(date -d "$START_TIME" +%s 2>/dev/null || echo 0)
    end_epoch=$(date -d "$END_TIME" +%s 2>/dev/null || echo 9999999999)

    grep -iE 'error|warning|critical|alert|emergency|segfault|oom|panic|denied|killed' "$source_file" 2>/dev/null | while IFS= read -r line; do
        local syslog_ts
        syslog_ts=$(echo "$line" | awk '{print $1, $2, $3}')
        local readable_ts
        readable_ts=$(syslog_to_readable "$syslog_ts")

        # 时间范围过滤
        local line_epoch
        line_epoch=$(date -d "$readable_ts" +%s 2>/dev/null || echo 0)
        if [ "$line_epoch" -lt "$start_epoch" ] || [ "$line_epoch" -gt "$end_epoch" ]; then
            continue
        fi

        local event_type="SYS"
        local detail=""

        if echo "$line" | grep -qi 'oom.*kill\|out of memory'; then
            event_type="OOM"
            detail=$(echo "$line" | cut -d: -f4- | sed 's/^ *//' | head -c 200)
        elif echo "$line" | grep -qi 'segfault\|kernel panic'; then
            event_type="CRASH"
            detail=$(echo "$line" | cut -d: -f4- | sed 's/^ *//' | head -c 200)
        elif echo "$line" | grep -qi 'denied'; then
            event_type="DENY"
            detail=$(echo "$line" | cut -d: -f4- | sed 's/^ *//' | head -c 200)
        elif echo "$line" | grep -qi 'error'; then
            event_type="SYS_ERR"
            detail=$(echo "$line" | cut -d: -f4- | sed 's/^ *//' | head -c 200)
        elif echo "$line" | grep -qi 'warning'; then
            event_type="SYS_WARN"
            detail=$(echo "$line" | cut -d: -f4- | sed 's/^ *//' | head -c 200)
        fi

        if [ -n "$detail" ]; then
            echo "$readable_ts|$event_type|$detail"
        fi
    done >> "$TMPFILE"

    echo "  messages 日志解析完成"
}

# --- 排序和去重 ---

sort_timeline() {
    echo "[4/4] 排序时间线..."

    if [ -s "$TMPFILE" ]; then
        # 统一格式为 YYYY-MM-DD HH:MM:SS|TYPE|DETAIL，按时间排序
        sort -t'|' -k1 "$TMPFILE" | uniq > "$TIMELINE_FILE"
        local total_lines
        total_lines=$(wc -l < "$TIMELINE_FILE")
        echo "  时间线构建完成: $total_lines 条事件"
    else
        > "$TIMELINE_FILE"
        echo "  [警告] 时间线为空"
    fi
}

# --- 执行 ---

> "$TMPFILE"

parse_audit_log
parse_secure_log
parse_messages_log
sort_timeline

# --- 输出汇总 ---

echo ""
echo "=========================================="
echo "  时间线构建完成"
echo "=========================================="
echo "输出文件: $TIMELINE_FILE"
echo ""

if [ -s "$TIMELINE_FILE" ]; then
    # 事件类型统计
    echo "事件类型分布:"
    awk -F'|' '{print $2}' "$TIMELINE_FILE" | sort | uniq -c | sort -rn | head -10
    echo ""

    echo "时间线预览（前 20 条）:"
    head -20 "$TIMELINE_FILE"
    echo ""
    echo "时间线预览（后 10 条）:"
    tail -10 "$TIMELINE_FILE"
fi

echo ""
echo "下一步建议:"
echo "  1. 异常扫描: bash scripts/anomaly_scanner.sh"
echo "  2. 认证追溯: bash scripts/trace_auth_events.sh -S '$START_TIME' -E '$END_TIME'"
echo "  3. 生成证据链: bash scripts/generate_evidence_chain.sh -d '$OUTPUT_DIR'"
echo "=========================================="
