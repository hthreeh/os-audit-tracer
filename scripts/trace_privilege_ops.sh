#!/bin/bash

# 特权操作追溯脚本
# 追踪 sudo、su、setuid 执行、UID 变更等特权操作

set -euo pipefail

# --- 默认参数 ---
START_TIME=""
END_TIME=""
TARGET_USER=""
OUTPUT_DIR="./priv-trace-$(date +%Y%m%d_%H%M%S)"
DATA_DIR=""

# --- 颜色定义 ---
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

# --- 参数解析 ---

show_help() {
    echo "用法: $0 -S <起始时间> [-E <结束时间>] [-u <用户>] [-d <数据目录>] [-o <输出目录>]"
    echo ""
    echo "追溯特权操作（sudo、su、setuid、UID 变更）。"
    echo ""
    echo "参数:"
    echo "  -S <time>    起始时间（必需），格式: 'YYYY-MM-DD HH:MM:SS' 或 epoch"
    echo "  -E <time>    结束时间（可选），默认为当前时间"
    echo "  -u <user>    过滤特定用户（可选）"
    echo "  -d <dir>     数据目录（由 collect_audit_logs.sh 生成的离线数据）"
    echo "  -o <dir>     输出目录（可选）"
    echo "  -h           显示此帮助信息"
    echo ""
    echo "数据来源:"
    echo "  - ausearch -k privilege"
    echo "  - /var/log/secure sudo 条目"
    echo "  - ausearch -m USER_CHAUTHTOK,ADD_USER,DEL_USER,ADD_GROUP,DEL_GROUP"
    echo ""
    echo "检测事件:"
    echo "  - sudo 命令执行（含具体命令和参数）"
    echo "  - su 用户切换"
    echo "  - setuid/setgid 程序执行"
    echo "  - UID/GID 变更"
    echo "  - 用户/组的添加和删除"
    echo ""
    echo "示例:"
    echo "  $0 -S '2026-05-20 00:00:00'"
    echo "  $0 -S '2026-05-20 00:00:00' -u admin"
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
        -u)
            TARGET_USER="$2"; shift 2 ;;
        -u=*)
            TARGET_USER="${1#*=}"; shift ;;
        -d)
            DATA_DIR="$2"; shift 2 ;;
        -d=*)
            DATA_DIR="${1#*=}"; shift ;;
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
RESULTS_FILE="$OUTPUT_DIR/privilege_ops.log"
TMPFILE=$(mktemp)
trap 'rm -f "$TMPFILE"' EXIT

# --- 确定日志源 ---

get_secure_log() {
    if [ -n "$DATA_DIR" ] && [ -f "$DATA_DIR/secure.log" ]; then
        echo "$DATA_DIR/secure.log"
    elif [ -f /var/log/secure ]; then
        echo "/var/log/secure"
    elif [ -f /var/log/auth.log ]; then
        echo "/var/log/auth.log"
    else
        echo ""
    fi
}

# --- 解析 sudo 操作（secure 日志）---

parse_sudo_from_secure() {
    local log_file
    log_file=$(get_secure_log)

    if [ -z "$log_file" ]; then
        echo -e "${YELLOW}[跳过]${NC} secure/auth 日志不可用"
        return
    fi

    echo "[1/5] 解析 sudo 操作（secure 日志）..."

    grep 'sudo:' "$log_file" 2>/dev/null | while IFS= read -r line; do
        local user ts detail command
        user=$(echo "$line" | grep -oP ': \K\S+' | head -1 || echo "unknown")
        ts=$(echo "$line" | awk '{print $1, $2, $3}')
        detail=$(echo "$line" | cut -d: -f4- | sed 's/^ *//')

        if [ -n "$TARGET_USER" ] && [ "$user" != "$TARGET_USER" ]; then continue; fi

        command=$(echo "$detail" | grep -oP 'COMMAND=\K.*' || echo "$detail")
        local risk="MEDIUM"
        if echo "$command" | grep -qE 'passwd|useradd|userdel|visudo|chmod.*777|chown.*root'; then
            risk="HIGH"
        fi

        echo "$ts|SUDO|$risk|$user|command=$command"
    done >> "$TMPFILE"

    echo "  sudo 操作解析完成"
}

# --- 解析 su 切换 ---

parse_su_from_secure() {
    local log_file
    log_file=$(get_secure_log)

    if [ -z "$log_file" ]; then return; fi

    echo "[2/5] 解析 su 切换..."

    grep 'su:' "$log_file" 2>/dev/null | while IFS= read -r line; do
        local user ts detail target_user
        user=$(echo "$line" | grep -oP ': \K\S+' | head -1 || echo "unknown")
        ts=$(echo "$line" | awk '{print $1, $2, $3}')
        detail=$(echo "$line" | cut -d: -f4- | sed 's/^ *//')
        target_user=$(echo "$detail" | grep -oP 'to \K\S+' || echo "unknown")

        if [ -n "$TARGET_USER" ] && [ "$user" != "$TARGET_USER" ] && [ "$target_user" != "$TARGET_USER" ]; then continue; fi

        local risk="MEDIUM"
        if [ "$target_user" = "root" ]; then risk="HIGH"; fi

        echo "$ts|SU_SWITCH|$risk|$user|target=$target_user detail=$detail"
    done >> "$TMPFILE"

    echo "  su 切换解析完成"
}

# --- 解析 auditd 特权审计事件 ---

parse_audit_privilege() {
    if ! command -v ausearch &>/dev/null; then
        echo -e "${YELLOW}[跳过]${NC} ausearch 不可用"
        return
    fi

    echo "[3/5] 解析 auditd 特权事件 (key=privilege)..."

    local ausearch_args=(-k privilege -ts "$START_TIME" -te "$END_TIME" --input-logs --no-pager)
    ausearch "${ausearch_args[@]}" 2>/dev/null | while IFS= read -r line; do
        local epoch_ts readable_ts
        epoch_ts=$(echo "$line" | grep -oP 'msg=audit\(\K[0-9.]+' || echo "")
        if [ -z "$epoch_ts" ]; then continue; fi
        readable_ts=$(date -d "@${epoch_ts%%.*}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$epoch_ts")

        local uid auid exe comm
        uid=$(echo "$line" | grep -oP ' uid=\K\S+' || echo "-")
        auid=$(echo "$line" | grep -oP ' auid=\K\S+' || echo "-")
        exe=$(echo "$line" | grep -oP 'exe="[^"]*"' | head -1 | cut -d'"' -f2 || echo "-")
        comm=$(echo "$line" | grep -oP 'comm="[^"]*"' | head -1 | cut -d'"' -f2 || echo "-")

        if [ -n "$TARGET_USER" ]; then
            local target_uid
            target_uid=$(id -u "$TARGET_USER" 2>/dev/null || echo "")
            if [ -n "$target_uid" ] && [ "$auid" != "$target_uid" ]; then continue; fi
        fi

        local risk="MEDIUM"
        echo "$readable_ts|PRIV_AUDIT|$risk|auid=$auid uid=$uid|exe=$exe comm=$comm"
    done >> "$TMPFILE"

    echo "  auditd 特权事件解析完成"
}

# --- 解析 setuid/setgid 执行 ---

parse_setuid_exec() {
    if ! command -v ausearch &>/dev/null; then
        echo -e "${YELLOW}[跳过]${NC} ausearch 不可用"
        return
    fi

    echo "[4/5] 解析 setuid/setgid 程序执行..."

    local ausearch_args=(-m EXECVE -ts "$START_TIME" -te "$END_TIME" --input-logs --no-pager)
    ausearch "${ausearch_args[@]}" 2>/dev/null | while IFS= read -r line; do
        local epoch_ts readable_ts
        epoch_ts=$(echo "$line" | grep -oP 'msg=audit\(\K[0-9.]+' || echo "")
        if [ -z "$epoch_ts" ]; then continue; fi

        # 只关注 setuid/setgid 标记
        if ! echo "$line" | grep -qE 'S_ISUID|S_ISGID|suid|sgid'; then continue; fi

        readable_ts=$(date -d "@${epoch_ts%%.*}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$epoch_ts")

        local uid auid exe comm
        uid=$(echo "$line" | grep -oP ' uid=\K\S+' || echo "-")
        auid=$(echo "$line" | grep -oP ' auid=\K\S+' || echo "-")
        exe=$(echo "$line" | grep -oP 'exe="[^"]*"' | head -1 | cut -d'"' -f2 || echo "-")
        comm=$(echo "$line" | grep -oP 'comm="[^"]*"' | head -1 | cut -d'"' -f2 || echo "-")

        if [ -n "$TARGET_USER" ]; then
            local target_uid
            target_uid=$(id -u "$TARGET_USER" 2>/dev/null || echo "")
            if [ -n "$target_uid" ] && [ "$auid" != "$target_uid" ]; then continue; fi
        fi

        echo "$readable_ts|SETUID|HIGH|auid=$auid uid=$uid|exe=$exe comm=$comm"
    done >> "$TMPFILE"

    echo "  setuid/setgid 解析完成"
}

# --- 解析用户/组变更 ---

parse_user_changes() {
    if ! command -v ausearch &>/dev/null; then
        echo -e "${YELLOW}[跳过]${NC} ausearch 不可用"
        return
    fi

    echo "[5/5] 解析用户/组变更 (ADD_USER, DEL_USER, ADD_GROUP, DEL_GROUP)..."

    local ausearch_args=(-m ADD_USER,DEL_USER,ADD_GROUP,DEL_GROUP,USER_CHAUTHTOK -ts "$START_TIME" -te "$END_TIME" --input-logs --no-pager)
    ausearch "${ausearch_args[@]}" 2>/dev/null | while IFS= read -r line; do
        local epoch_ts readable_ts
        epoch_ts=$(echo "$line" | grep -oP 'msg=audit\(\K[0-9.]+' || echo "")
        if [ -z "$epoch_ts" ]; then continue; fi
        readable_ts=$(date -d "@${epoch_ts%%.*}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$epoch_ts")

        local event_type auid exe
        event_type=$(echo "$line" | grep -oP 'type=\K\S+' | head -1 || echo "USER_CHANGE")
        auid=$(echo "$line" | grep -oP 'auid=\K\S+' || echo "-")
        exe=$(echo "$line" | grep -oP 'exe="[^"]*"' | head -1 | cut -d'"' -f2 || echo "-")

        if [ -n "$TARGET_USER" ]; then
            local target_uid
            target_uid=$(id -u "$TARGET_USER" 2>/dev/null || echo "")
            if [ -n "$target_uid" ] && [ "$auid" != "$target_uid" ]; then continue; fi
        fi

        echo "$readable_ts|$event_type|HIGH|auid=$auid|exe=$exe"
    done >> "$TMPFILE"

    echo "  用户/组变更解析完成"
}

# --- 格式化输出 ---

print_results() {
    echo ""
    echo "--- 特权操作时间线 ---"
    echo ""
    printf "%-20s %-15s %-12s %-15s %s\n" "时间" "事件类型" "风险" "用户" "详情"
    printf "%-20s %-15s %-12s %-15s %s\n" "----" "--------" "----" "----" "----"

    while IFS='|' read -r ts etype risk user detail; do
        local risk_mark=""
        case "$risk" in
            HIGH)   risk_mark="${RED}HIGH${NC}" ;;
            MEDIUM) risk_mark="${YELLOW}MEDIUM${NC}" ;;
            LOW)    risk_mark="${GREEN}LOW${NC}" ;;
        esac
        printf "%-20s %-15s %b %-15s %s\n" "$ts" "$etype" "$risk_mark" "$user" "$detail"
    done < "$RESULTS_FILE"
}

# --- 主流程 ---

echo "=========================================="
echo "  特权操作追溯"
echo "=========================================="
echo "时间范围: $START_TIME ~ $END_TIME"
if [ -n "$TARGET_USER" ]; then echo "目标用户: $TARGET_USER"; fi
echo "输出目录: $OUTPUT_DIR"
echo "=========================================="
echo ""

> "$TMPFILE"

parse_sudo_from_secure
parse_su_from_secure
parse_audit_privilege
parse_setuid_exec
parse_user_changes

# 排序并写入结果文件
if [ -s "$TMPFILE" ]; then
    sort -t'|' -k1 -o "$TMPFILE" "$TMPFILE"
    cp "$TMPFILE" "$RESULTS_FILE"
    print_results
else
    > "$RESULTS_FILE"
    echo -e "${YELLOW}[提示]${NC} 未发现匹配的特权操作"
fi

# --- 统计汇总 ---

TOTAL_EVENTS=$(wc -l < "$RESULTS_FILE" 2>/dev/null || echo 0)
SUDO_COUNT=$(grep -c '|SUDO|' "$RESULTS_FILE" 2>/dev/null || echo 0)
SU_COUNT=$(grep -c '|SU_SWITCH|' "$RESULTS_FILE" 2>/dev/null || echo 0)
SETUID_COUNT=$(grep -c '|SETUID|' "$RESULTS_FILE" 2>/dev/null || echo 0)
USER_CHANGE_COUNT=$(grep -cE 'ADD_USER|DEL_USER|ADD_GROUP|DEL_GROUP|USER_CHAUTHTOK' "$RESULTS_FILE" 2>/dev/null || echo 0)
HIGH_RISK=$(grep -c '|HIGH|' "$RESULTS_FILE" 2>/dev/null || echo 0)

echo ""
echo "=========================================="
echo "  特权操作汇总"
echo "=========================================="
echo -e "总事件数:        $TOTAL_EVENTS"
echo -e "sudo 操作:       $SUDO_COUNT"
echo -e "su 切换:         $SU_COUNT"
echo -e "setuid 执行:     $SETUID_COUNT"
echo -e "用户/组变更:     $USER_CHANGE_COUNT"
echo -e "高风险事件:      ${RED}$HIGH_RISK${NC}"
echo ""
echo "详细结果: $RESULTS_FILE"
echo ""

if [ "$HIGH_RISK" -ge 5 ]; then
    echo -e "${RED}[CRITICAL] 检测到大量高风险特权操作，建议立即排查${NC}"
elif [ "$HIGH_RISK" -ge 1 ]; then
    echo -e "${YELLOW}[WARNING] 检测到高风险特权操作，请确认是否为授权操作${NC}"
else
    echo -e "${GREEN}[OK] 特权操作未发现明显异常${NC}"
fi

echo ""
echo "下一步建议:"
echo "  1. 检查高风险操作:   grep 'HIGH' $RESULTS_FILE"
echo "  2. 追溯文件变更:     bash scripts/trace_file_changes.sh -S '$START_TIME'"
echo "  3. 追溯认证事件:     bash scripts/trace_auth_events.sh -S '$START_TIME'"
echo "=========================================="
