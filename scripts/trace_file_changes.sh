#!/bin/bash

# 文件变更追溯脚本
# 追踪关键文件修改、权限变更、新增 SUID 文件等

set -euo pipefail

# --- 默认参数 ---
START_TIME=""
END_TIME=""
TARGET_FILE=""
OUTPUT_DIR="./file-trace-$(date +%Y%m%d_%H%M%S)"
DATA_DIR=""
RPM_CHECK=0

# --- 颜色定义 ---
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

# --- 参数解析 ---

show_help() {
    echo "用法: $0 -S <起始时间> [-E <结束时间>] [-f <文件路径>] [-d <数据目录>] [--rpm] [-o <输出目录>]"
    echo ""
    echo "追溯文件系统变更事件。"
    echo ""
    echo "参数:"
    echo "  -S <time>    起始时间（必需），格式: 'YYYY-MM-DD HH:MM:SS' 或 epoch"
    echo "  -E <time>    结束时间（可选），默认为当前时间"
    echo "  -f <path>    过滤特定文件路径（可选）"
    echo "  -d <dir>     数据目录（由 collect_audit_logs.sh 生成的离线数据）"
    echo "  --rpm        执行 RPM 完整性验证（较慢）"
    echo "  -o <dir>     输出目录（可选）"
    echo "  -h           显示此帮助信息"
    echo ""
    echo "数据来源:"
    echo "  - ausearch -k fileint（文件完整性审计规则触发的事件）"
    echo "  - ausearch -f <path>（特定文件的审计事件）"
    echo "  - rpm -Va（RPM 包完整性验证）"
    echo ""
    echo "检测事件:"
    echo "  - 关键文件内容修改（/etc/passwd, /etc/shadow, /etc/sudoers 等）"
    echo "  - 文件权限/所有者变更"
    echo "  - 新增 SUID/SGID 文件"
    echo "  - RPM 包文件被篡改"
    echo ""
    echo "注意: 使用此脚本前建议先部署审计规则："
    echo "  bash scripts/audit_setup.sh"
    echo ""
    echo "示例:"
    echo "  $0 -S '2026-05-20 00:00:00'"
    echo "  $0 -S '2026-05-20 00:00:00' -f /etc/passwd"
    echo "  $0 -S '2026-05-20 00:00:00' --rpm"
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
        -f)
            TARGET_FILE="$2"; shift 2 ;;
        -f=*)
            TARGET_FILE="${1#*=}"; shift ;;
        -d)
            DATA_DIR="$2"; shift 2 ;;
        -d=*)
            DATA_DIR="${1#*=}"; shift ;;
        --rpm)
            RPM_CHECK=1; shift ;;
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
RESULTS_FILE="$OUTPUT_DIR/file_changes.log"
TMPFILE=$(mktemp)
trap 'rm -f "$TMPFILE"' EXIT

# --- 关键文件列表 ---
CRITICAL_FILES=(
    "/etc/passwd"
    "/etc/shadow"
    "/etc/group"
    "/etc/gshadow"
    "/etc/sudoers"
    "/etc/ssh/sshd_config"
    "/etc/crontab"
    "/etc/hosts"
    "/etc/resolv.conf"
    "/etc/ld.so.conf"
    "/etc/profile"
    "/etc/bashrc"
    "/etc/pam.d/"
    "/etc/security/limits.conf"
)

# --- 解析 auditd 文件完整性事件 ---

parse_audit_fileint() {
    if ! command -v ausearch &>/dev/null; then
        echo -e "${YELLOW}[跳过]${NC} ausearch 不可用"
        return
    fi

    echo "[1/4] 解析 auditd 文件完整性事件 (key=fileint)..."

    local ausearch_args=(-k fileint -ts "$START_TIME" -te "$END_TIME" --input-logs --no-pager)
    ausearch "${ausearch_args[@]}" 2>/dev/null | while IFS= read -r line; do
        local epoch_ts readable_ts
        epoch_ts=$(echo "$line" | grep -oP 'msg=audit\(\K[0-9.]+' || echo "")
        if [ -z "$epoch_ts" ]; then continue; fi
        readable_ts=$(date -d "@${epoch_ts%%.*}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$epoch_ts")

        local name exe auid syscall
        name=$(echo "$line" | grep -oP 'name="[^"]*"' | head -1 | cut -d'"' -f2 || echo "-")
        exe=$(echo "$line" | grep -oP 'exe="[^"]*"' | head -1 | cut -d'"' -f2 || echo "-")
        auid=$(echo "$line" | grep -oP 'auid=\K\S+' || echo "-")
        syscall=$(echo "$line" | grep -oP 'syscall=\K\S+' || echo "-")

        if [ -n "$TARGET_FILE" ] && [ "$name" != "$TARGET_FILE" ]; then continue; fi

        local risk="MEDIUM"
        # 关键文件变更风险更高
        for crit in "${CRITICAL_FILES[@]}"; do
            if [ "$name" = "$crit" ] || [[ "$name" == "$crit"* ]]; then
                risk="HIGH"
                break
            fi
        done

        echo "$readable_ts|FILEINT|$risk|$name|auid=$auid exe=$exe syscall=$syscall"
    done >> "$TMPFILE"

    echo "  文件完整性事件解析完成"
}

# --- 解析特定文件的审计事件 ---

parse_audit_file_specific() {
    if ! command -v ausearch &>/dev/null; then
        echo -e "${YELLOW}[跳过]${NC} ausearch 不可用"
        return
    fi

    if [ -z "$TARGET_FILE" ]; then
        echo "[2/4] 未指定目标文件，跳过特定文件审计"
        return
    fi

    echo "[2/4] 解析特定文件审计事件 (-f $TARGET_FILE)..."

    local ausearch_args=(-f "$TARGET_FILE" -ts "$START_TIME" -te "$END_TIME" --input-logs --no-pager)
    ausearch "${ausearch_args[@]}" 2>/dev/null | while IFS= read -r line; do
        local epoch_ts readable_ts
        epoch_ts=$(echo "$line" | grep -oP 'msg=audit\(\K[0-9.]+' || echo "")
        if [ -z "$epoch_ts" ]; then continue; fi
        readable_ts=$(date -d "@${epoch_ts%%.*}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$epoch_ts")

        local event_type auid exe comm
        event_type=$(echo "$line" | grep -oP 'type=\K\S+' | head -1 || echo "AUDIT")
        auid=$(echo "$line" | grep -oP 'auid=\K\S+' || echo "-")
        exe=$(echo "$line" | grep -oP 'exe="[^"]*"' | head -1 | cut -d'"' -f2 || echo "-")
        comm=$(echo "$line" | grep -oP 'comm="[^"]*"' | head -1 | cut -d'"' -f2 || echo "-")

        echo "$readable_ts|$event_type|MEDIUM|$TARGET_FILE|auid=$auid exe=$exe comm=$comm"
    done >> "$TMPFILE"

    echo "  特定文件审计完成"
}

# --- 检查近期关键文件变更 ---

check_critical_file_changes() {
    echo "[3/4] 检查近期关键文件变更..."

    local now_epoch
    now_epoch=$(date +%s)
    local start_epoch
    start_epoch=$(date -d "$START_TIME" +%s 2>/dev/null || echo 0)

    for filepath in "${CRITICAL_FILES[@]}"; do
        # 处理目录
        if [[ "$filepath" == */ ]]; then
            if [ -d "$filepath" ]; then
                find "$filepath" -maxdepth 1 -type f 2>/dev/null | while read -r f; do
                    local mtime
                    mtime=$(stat -c %Y "$f" 2>/dev/null || echo 0)
                    if [ "$mtime" -ge "$start_epoch" ] && [ "$mtime" -le "$now_epoch" ]; then
                        local readable_ts
                        readable_ts=$(date -d "@$mtime" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$mtime")
                        echo "$readable_ts|MTIME_CHANGE|HIGH|$f|关键文件在目标时间范围内被修改"
                    fi
                done >> "$TMPFILE"
            fi
            continue
        fi

        if [ -f "$filepath" ]; then
            local mtime
            mtime=$(stat -c %Y "$filepath" 2>/dev/null || echo 0)
            if [ "$mtime" -ge "$start_epoch" ] && [ "$mtime" -le "$now_epoch" ]; then
                local readable_ts
                readable_ts=$(date -d "@$mtime" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$mtime")
                echo "$readable_ts|MTIME_CHANGE|HIGH|$filepath|关键文件在目标时间范围内被修改"
            fi
        fi
    done

    echo "  关键文件变更检查完成"
}

# --- RPM 完整性验证 ---

check_rpm_integrity() {
    if [ "$RPM_CHECK" -eq 0 ]; then
        echo "[4/4] RPM 完整性验证（已跳过，使用 --rpm 启用）"
        return
    fi

    if ! command -v rpm &>/dev/null; then
        echo -e "${YELLOW}[跳过]${NC} rpm 不可用"
        return
    fi

    echo "[4/4] RPM 完整性验证（可能需要较长时间）..."

    rpm -Va 2>/dev/null | grep -v '^$' | while IFS= read -r line; do
        local flags filepath
        flags=$(echo "$line" | awk '{print $1}')
        filepath=$(echo "$line" | awk '{print $2}')

        # 过滤常见的预期变更（如文档、配置文件）
        if echo "$filepath" | grep -qE '/usr/share/doc|/usr/share/man|/usr/share/licenses'; then
            continue
        fi

        local risk="MEDIUM"
        # 5 = MD5/size changed, ..5.T = config file changed
        if echo "$flags" | grep -q '5'; then
            risk="HIGH"
        fi
        # S = size changed, T = timestamp changed, M = mode changed
        if echo "$flags" | grep -q 'M'; then
            risk="HIGH"
        fi

        echo "$(date '+%Y-%m-%d %H:%M:%S')|RPM_VERIFY|$risk|$filepath|flags=$flags"
    done >> "$TMPFILE"

    echo "  RPM 验证完成"
}

# --- 格式化输出 ---

print_results() {
    echo ""
    echo "--- 文件变更时间线 ---"
    echo ""
    printf "%-20s %-15s %-10s %-30s %s\n" "时间" "事件类型" "风险" "文件路径" "详情"
    printf "%-20s %-15s %-10s %-30s %s\n" "----" "--------" "----" "--------" "----"

    while IFS='|' read -r ts etype risk filepath detail; do
        local risk_mark=""
        case "$risk" in
            HIGH)   risk_mark="${RED}HIGH${NC}" ;;
            MEDIUM) risk_mark="${YELLOW}MED${NC}" ;;
            LOW)    risk_mark="${GREEN}LOW${NC}" ;;
        esac
        # 截断过长的路径
        local display_path="$filepath"
        if [ ${#display_path} -gt 30 ]; then
            display_path="...${display_path: -27}"
        fi
        printf "%-20s %-15s %b %-30s %s\n" "$ts" "$etype" "$risk_mark" "$display_path" "$detail"
    done < "$RESULTS_FILE"
}

# --- 主流程 ---

echo "=========================================="
echo "  文件变更追溯"
echo "=========================================="
echo "时间范围: $START_TIME ~ $END_TIME"
if [ -n "$TARGET_FILE" ]; then echo "目标文件: $TARGET_FILE"; fi
echo "输出目录: $OUTPUT_DIR"
echo "=========================================="
echo ""

> "$TMPFILE"

parse_audit_fileint
parse_audit_file_specific
check_critical_file_changes
check_rpm_integrity

# 排序并写入结果文件
if [ -s "$TMPFILE" ]; then
    sort -t'|' -k1 -o "$TMPFILE" "$TMPFILE"
    cp "$TMPFILE" "$RESULTS_FILE"
    print_results
else
    > "$RESULTS_FILE"
    echo -e "${YELLOW}[提示]${NC} 未发现匹配的文件变更事件"
fi

# --- 统计汇总 ---

TOTAL_EVENTS=$(wc -l < "$RESULTS_FILE" 2>/dev/null || echo 0)
FILEINT_COUNT=$(grep -c '|FILEINT|' "$RESULTS_FILE" 2>/dev/null || echo 0)
MTIME_COUNT=$(grep -c '|MTIME_CHANGE|' "$RESULTS_FILE" 2>/dev/null || echo 0)
RPM_COUNT=$(grep -c '|RPM_VERIFY|' "$RESULTS_FILE" 2>/dev/null || echo 0)
HIGH_RISK=$(grep -c '|HIGH|' "$RESULTS_FILE" 2>/dev/null || echo 0)

echo ""
echo "=========================================="
echo "  文件变更汇总"
echo "=========================================="
echo -e "总事件数:        $TOTAL_EVENTS"
echo -e "审计规则触发:    $FILEINT_COUNT"
echo -e "关键文件变更:    ${RED}$MTIME_COUNT${NC}"
echo -e "RPM 篡改:        ${RED}$RPM_COUNT${NC}"
echo -e "高风险事件:      ${RED}$HIGH_RISK${NC}"
echo ""
echo "详细结果: $RESULTS_FILE"
echo ""

if [ "$MTIME_COUNT" -gt 0 ]; then
    echo -e "${RED}[WARNING] 检测到关键配置文件变更，请确认是否为授权修改${NC}"
fi
if [ "$RPM_COUNT" -gt 5 ]; then
    echo -e "${RED}[CRITICAL] 检测到大量 RPM 文件篡改，系统完整性可能已被破坏${NC}"
elif [ "$RPM_COUNT" -gt 0 ]; then
    echo -e "${YELLOW}[WARNING] 检测到 RPM 文件变更，请确认是否为预期更新${NC}"
fi
if [ "$HIGH_RISK" -eq 0 ]; then
    echo -e "${GREEN}[OK] 文件变更未发现明显异常${NC}"
fi

echo ""
echo "下一步建议:"
echo "  1. 检查高风险变更:   grep 'HIGH' $RESULTS_FILE"
echo "  2. 部署审计规则:     bash scripts/audit_setup.sh"
echo "  3. 追溯执行命令:     bash scripts/trace_command_history.sh -S '$START_TIME'"
echo "=========================================="
