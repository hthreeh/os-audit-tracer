#!/bin/bash

# 命令执行历史追溯脚本
# 追踪用户执行的所有命令，检测可疑操作

set -euo pipefail

# --- 默认参数 ---
START_TIME=""
END_TIME=""
TARGET_USER=""
KEYWORD=""
OUTPUT_DIR="./cmd-trace-$(date +%Y%m%d_%H%M%S)"
DATA_DIR=""

# --- 颜色定义 ---
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

# --- 可疑命令模式 ---
SUSPICIOUS_PATTERNS=(
    'curl.*\|.*sh'
    'wget.*\|.*sh'
    'wget.*\|.*bash'
    'curl.*-o.*/tmp'
    'wget.*-O.*/tmp'
    '/tmp/.*\.sh'
    '/dev/shm/'
    'base64.*-d'
    'python.*-c.*import'
    'nc.*-e'
    'ncat.*-e'
    'socat'
    'rm[[:space:]]+.*-rf[[:space:]]+/\*'
    'rm[[:space:]]+.*-rf[[:space:]]+/boot'
    'rm[[:space:]]+.*-rf[[:space:]]+/etc'
    'rm[[:space:]]+.*-rf[[:space:]]+/usr'
    'rm[[:space:]]+.*-rf[[:space:]]+/lib'
    'rm[[:space:]]+.*-rf[[:space:]]+/bin'
    'rm[[:space:]]+.*-rf[[:space:]]+/sbin'
    'rm[[:space:]]+.*-rf[[:space:]]+~'
    'rm[[:space:]]+.*-rf[[:space:]]+\$HOME'
    'mkfs\.'
    'dd.*of=/dev/'
    'chmod.*777'
    'chown.*root'
    'useradd'
    'userdel'
    'groupadd'
    'visudo'
    'crontab'
    'iptables.*-F'
    'iptables.*--flush'
    'setenforce.*0'
    'systemctl.*stop.*firewalld'
    'history.*-c'
    'rm.*\.bash_history'
    'unset.*HISTFILE'
    'export.*HISTSIZE=0'
    '>/var/log/'
    '>/etc/'
)

# --- 参数解析 ---

show_help() {
    echo "用法: $0 -S <起始时间> [-E <结束时间>] [-u <用户>] [-k <关键词>] [-d <数据目录>] [-o <输出目录>]"
    echo ""
    echo "追溯命令执行历史，检测可疑操作。"
    echo ""
    echo "参数:"
    echo "  -S <time>    起始时间（必需），格式: 'YYYY-MM-DD HH:MM:SS' 或 epoch"
    echo "  -E <time>    结束时间（可选），默认为当前时间"
    echo "  -u <user>    过滤特定用户（可选）"
    echo "  -k <keyword> 过滤特定命令关键词（可选，支持正则）"
    echo "  -d <dir>     数据目录（由 collect_audit_logs.sh 生成的离线数据）"
    echo "  -o <dir>     输出目录（可选）"
    echo "  -h           显示此帮助信息"
    echo ""
    echo "数据来源:"
    echo "  - ausearch -k exec_cmd（需审计规则支持）"
    echo "  - ausearch -m EXECVE"
    echo "  - 用户 .bash_history 文件"
    echo ""
    echo "检测事件:"
    echo "  - 所有经审计记录的命令执行"
    echo "  - 可疑命令（反弹 shell、下载执行、日志清除等）"
    echo "  - 从临时目录执行的命令"
    echo ""
    echo "示例:"
    echo "  $0 -S '2026-05-20 00:00:00'"
    echo "  $0 -S '2026-05-20 00:00:00' -u admin -k 'docker'"
    echo "  $0 -S '2026-05-20 00:00:00' -k 'rm.*-rf'"
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
        -k)
            KEYWORD="$2"; shift 2 ;;
        -k=*)
            KEYWORD="${1#*=}"; shift ;;
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
RESULTS_FILE="$OUTPUT_DIR/command_history.log"
SUSPICIOUS_FILE="$OUTPUT_DIR/suspicious_commands.log"
TMPFILE=$(mktemp)
SUSPFILE=$(mktemp)
SORTED_TMPFILE=$(mktemp)
trap 'rm -f "$TMPFILE" "$SUSPFILE" "$SORTED_TMPFILE"' EXIT

# --- 解析 auditd 命令执行（key=exec_cmd）---

parse_audit_exec_cmd() {
    if ! command -v ausearch &>/dev/null; then
        echo -e "${YELLOW}[跳过]${NC} ausearch 不可用"
        return
    fi

    echo "[1/4] 解析 auditd 命令执行 (key=exec_cmd)..."

    local ausearch_args=(-k exec_cmd -ts "$START_TIME" -te "$END_TIME" --input-logs --no-pager)
    if [ -n "$TARGET_USER" ]; then
        ausearch_args+=(-ua "$TARGET_USER")
    fi

    ausearch "${ausearch_args[@]}" 2>/dev/null | while IFS= read -r line; do
        local epoch_ts readable_ts
        epoch_ts=$(echo "$line" | grep -oP 'msg=audit\(\K[0-9.]+' || echo "")
        if [ -z "$epoch_ts" ]; then continue; fi
        readable_ts=$(date -d "@${epoch_ts%%.*}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$epoch_ts")

        local exe comm auid uid
        exe=$(echo "$line" | grep -oP 'exe="[^"]*"' | head -1 | cut -d'"' -f2 || echo "-")
        comm=$(echo "$line" | grep -oP 'comm="[^"]*"' | head -1 | cut -d'"' -f2 || echo "-")
        auid=$(echo "$line" | grep -oP 'auid=\K\S+' || echo "-")
        uid=$(echo "$line" | grep -oP ' uid=\K\S+' || echo "-")

        # 关键词过滤
        if [ -n "$KEYWORD" ]; then
            if ! echo "$line" | grep -qE "$KEYWORD"; then continue; fi
        fi

        local risk="LOW"
        local suspicious=""

        # 检查临时目录执行
        if echo "$exe" | grep -qE '^/tmp/|^/dev/shm/|^/var/tmp/'; then
            risk="HIGH"
            suspicious="从临时目录执行"
        fi

        # 检查可疑命令模式
        for pattern in "${SUSPICIOUS_PATTERNS[@]}"; do
            if echo "$line" | grep -qE "$pattern"; then
                risk="HIGH"
                suspicious="匹配可疑模式: $pattern"
                break
            fi
        done

        echo "$readable_ts|EXEC_CMD|$risk|auid=$auid uid=$uid|exe=$exe comm=$comm $suspicious"
    done >> "$TMPFILE"

    echo "  exec_cmd 解析完成"
}

# --- 解析 EXECVE 事件 ---

parse_audit_execve() {
    if ! command -v ausearch &>/dev/null; then
        echo -e "${YELLOW}[跳过]${NC} ausearch 不可用"
        return
    fi

    echo "[2/4] 解析 EXECVE 事件..."

    local ausearch_args=(-m EXECVE -ts "$START_TIME" -te "$END_TIME" --input-logs --no-pager)
    if [ -n "$TARGET_USER" ]; then
        ausearch_args+=(-ua "$TARGET_USER")
    fi

    ausearch "${ausearch_args[@]}" 2>/dev/null | while IFS= read -r line; do
        local epoch_ts readable_ts
        epoch_ts=$(echo "$line" | grep -oP 'msg=audit\(\K[0-9.]+' || echo "")
        if [ -z "$epoch_ts" ]; then continue; fi
        readable_ts=$(date -d "@${epoch_ts%%.*}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$epoch_ts")

        # 提取命令参数
        local exe auid uid comm
        exe=$(echo "$line" | grep -oP 'exe="[^"]*"' | head -1 | cut -d'"' -f2 || echo "-")
        comm=$(echo "$line" | grep -oP 'comm="[^"]*"' | head -1 | cut -d'"' -f2 || echo "-")
        auid=$(echo "$line" | grep -oP 'auid=\K\S+' || echo "-")
        uid=$(echo "$line" | grep -oP ' uid=\K\S+' || echo "-")

        # 提取命令行参数 (EXECVE 中的 a0, a1, a2...)
        local args=""
        local arg_matches
        arg_matches=$(echo "$line" | grep -oP 'a[0-9]+="[^"]*"' || echo "")
        if [ -n "$arg_matches" ]; then
            args=$(echo "$arg_matches" | cut -d'"' -f2 | tr '\n' ' ')
        fi

        # 关键词过滤
        if [ -n "$KEYWORD" ]; then
            if ! echo "$exe $comm $args" | grep -qE "$KEYWORD"; then continue; fi
        fi

        local risk="LOW"
        local suspicious=""

        # 检查临时目录执行
        if echo "$exe" | grep -qE '^/tmp/|^/dev/shm/|^/var/tmp/'; then
            risk="HIGH"
            suspicious="[从临时目录执行]"
        fi

        # 检查可疑模式
        for pattern in "${SUSPICIOUS_PATTERNS[@]}"; do
            if echo "$exe $args" | grep -qE "$pattern"; then
                risk="HIGH"
                suspicious="[可疑: $pattern]"
                break
            fi
        done

        echo "$readable_ts|EXECVE|$risk|auid=$auid uid=$uid|exe=$exe comm=$comm args=[$args] $suspicious"
    done >> "$TMPFILE"

    echo "  EXECVE 事件解析完成"
}

# --- 解析 .bash_history ---

parse_bash_history() {
    echo "[3/4] 解析 .bash_history 文件..."

    local start_epoch
    start_epoch=$(date -d "$START_TIME" +%s 2>/dev/null || echo 0)
    local end_epoch
    end_epoch=$(date -d "$END_TIME" +%s 2>/dev/null || echo 0)

    # 确定要扫描的用户列表
    local users=()
    if [ -n "$TARGET_USER" ]; then
        users=("$TARGET_USER")
    else
        # 扫描所有有主目录的用户
        while IFS=: read -r user _ _ _ _ home _; do
            if [ -d "$home" ] && [ "$home" != "/" ]; then
                users+=("$user")
            fi
        done < /etc/passwd
    fi

    for user in "${users[@]}"; do
        local home_dir
        home_dir=$(eval echo "~$user" 2>/dev/null || echo "")
        if [ -z "$home_dir" ] || [ ! -d "$home_dir" ]; then continue; fi

        local hist_file="$home_dir/.bash_history"
        if [ ! -f "$hist_file" ]; then continue; fi

        # bash_history 可能包含时间戳（HISTTIMEFORMAT 设置后格式为 #epoch\ncommand）
        local line_num=0
        local hist_ts="N/A"
        while IFS= read -r cmd; do
            line_num=$((line_num + 1))
            [ -z "$cmd" ] && continue
            # 检测时间戳行（#epoch 格式，如 #1705312985）
            if [[ "$cmd" =~ ^#([0-9]{10,})$ ]]; then
                hist_ts=$(date -d "@${BASH_REMATCH[1]}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "N/A")
                continue
            fi
            # 跳过其他注释行
            [[ "$cmd" == \#* ]] && continue

            # 关键词过滤
            if [ -n "$KEYWORD" ]; then
                if ! echo "$cmd" | grep -qE "$KEYWORD"; then continue; fi
            fi

            local risk="LOW"
            local suspicious=""

            # 检查可疑模式
            for pattern in "${SUSPICIOUS_PATTERNS[@]}"; do
                if echo "$cmd" | grep -qE "$pattern"; then
                    risk="HIGH"
                    suspicious="[可疑: $pattern]"
                    break
                fi
            done

            # 检查是否操作临时目录
            if echo "$cmd" | grep -qE '/tmp/|/dev/shm/'; then
                risk="MEDIUM"
                if [ -z "$suspicious" ]; then
                    suspicious="[操作临时目录]"
                fi
            fi

            echo "$hist_ts|BASH_HISTORY|$risk|user=$user|cmd=$cmd $suspicious"
        done < "$hist_file"
    done >> "$TMPFILE"

    echo "  .bash_history 解析完成"
}

# --- 检测可疑命令 ---

detect_suspicious() {
    echo "[4/4] 检测可疑命令模式..."

    if [ ! -s "$RESULTS_FILE" ]; then
        echo "  无数据，跳过检测"
        return
    fi

    # 提取可疑命令
    grep '|HIGH|' "$RESULTS_FILE" > "$SUSPFILE" 2>/dev/null || true

    local susp_count
    susp_count=$(wc -l < "$SUSPFILE" 2>/dev/null || echo 0)

    if [ "$susp_count" -gt 0 ]; then
        echo ""
        echo "--- 可疑命令详情 ---"
        echo ""
        while IFS='|' read -r ts etype risk user detail; do
            echo -e "${RED}[SUSPICIOUS]${NC} [$ts] $user $detail"
        done < "$SUSPFILE"

        echo ""
        echo "--- 可疑命令分类统计 ---"

        # 临时目录执行
        local tmp_exec
        tmp_exec=$(grep -c '临时目录' "$SUSPFILE" 2>/dev/null || echo 0)
        if [ "$tmp_exec" -gt 0 ]; then
            echo -e "${RED}  从临时目录执行:     $tmp_exec 次${NC}"
        fi

        # 下载并执行
        local download_exec
        download_exec=$(grep -cE 'curl.*\|.*sh|wget.*\|.*sh|wget.*\|.*bash' "$SUSPFILE" 2>/dev/null || echo 0)
        if [ "$download_exec" -gt 0 ]; then
            echo -e "${RED}  下载并执行:         $download_exec 次${NC}"
        fi

        # 日志清除
        local log_clear
        log_clear=$(grep -cE 'history.*-c|\.bash_history|HISTFILE|HISTSIZE=0|>/var/log/' "$SUSPFILE" 2>/dev/null || echo 0)
        if [ "$log_clear" -gt 0 ]; then
            echo -e "${RED}  日志/历史清除:      $log_clear 次${NC}"
        fi

        # 权限/用户变更
        local priv_change
        priv_change=$(grep -cE 'useradd|userdel|chmod.*777|visudo' "$SUSPFILE" 2>/dev/null || echo 0)
        if [ "$priv_change" -gt 0 ]; then
            echo -e "${RED}  权限/用户变更:      $priv_change 次${NC}"
        fi
    fi
}

# --- 格式化输出 ---

print_results() {
    echo ""
    echo "--- 命令执行时间线 ---"
    echo ""
    printf "%-20s %-15s %-10s %-20s %s\n" "时间" "来源" "风险" "用户" "命令/详情"
    printf "%-20s %-15s %-10s %-20s %s\n" "----" "----" "----" "----" "----------"

    while IFS='|' read -r ts etype risk user detail; do
        local risk_mark=""
        case "$risk" in
            HIGH)   risk_mark="${RED}HIGH${NC}" ;;
            MEDIUM) risk_mark="${YELLOW}MED${NC}" ;;
            LOW)    risk_mark="${GREEN}LOW${NC}" ;;
        esac
        printf "%-20s %-15s %b %-20s %s\n" "$ts" "$etype" "$risk_mark" "$user" "$detail"
    done < "$RESULTS_FILE"
}

# --- 主流程 ---

echo "=========================================="
echo "  命令执行历史追溯"
echo "=========================================="
echo "时间范围: $START_TIME ~ $END_TIME"
if [ -n "$TARGET_USER" ]; then echo "目标用户: $TARGET_USER"; fi
if [ -n "$KEYWORD" ]; then echo "关键词:   $KEYWORD"; fi
echo "输出目录: $OUTPUT_DIR"
echo "=========================================="
echo ""

> "$TMPFILE"
> "$SUSPFILE"

parse_audit_exec_cmd
parse_audit_execve
parse_bash_history

# 排序并写入结果文件（排除无时间戳的 bash_history 条目放在末尾）
if [ -s "$TMPFILE" ]; then
    # 分离有时间戳和无时间戳的条目
    grep -v '^N/A|' "$TMPFILE" 2>/dev/null | sort -t'|' -k1 > "$SORTED_TMPFILE" || true
    grep '^N/A|' "$TMPFILE" 2>/dev/null >> "$SORTED_TMPFILE" || true
    mv "$SORTED_TMPFILE" "$RESULTS_FILE"
    print_results
else
    > "$RESULTS_FILE"
    echo -e "${YELLOW}[提示]${NC} 未发现匹配的命令执行记录"
fi

detect_suspicious

# --- 统计汇总 ---

TOTAL_EVENTS=$(wc -l < "$RESULTS_FILE" 2>/dev/null || echo 0)
EXEC_CMD_COUNT=$(grep -c '|EXEC_CMD|' "$RESULTS_FILE" 2>/dev/null || echo 0)
EXECVE_COUNT=$(grep -c '|EXECVE|' "$RESULTS_FILE" 2>/dev/null || echo 0)
BASH_HIST_COUNT=$(grep -c '|BASH_HISTORY|' "$RESULTS_FILE" 2>/dev/null || echo 0)
HIGH_RISK=$(grep -c '|HIGH|' "$RESULTS_FILE" 2>/dev/null || echo 0)

echo ""
echo "=========================================="
echo "  命令执行汇总"
echo "=========================================="
echo -e "总事件数:        $TOTAL_EVENTS"
echo -e "审计记录 (key):  $EXEC_CMD_COUNT"
echo -e "审计记录 (EXECVE): $EXECVE_COUNT"
echo -e "bash_history:    $BASH_HIST_COUNT"
echo -e "高风险事件:      ${RED}$HIGH_RISK${NC}"
echo ""
echo "详细结果: $RESULTS_FILE"
if [ -s "$SUSPFILE" ]; then
    echo "可疑命令: $SUSPICIOUS_FILE"
    cp "$SUSPFILE" "$SUSPICIOUS_FILE"
fi
echo ""

if [ "$HIGH_RISK" -ge 10 ]; then
    echo -e "${RED}[CRITICAL] 检测到大量可疑命令执行，系统可能已被入侵${NC}"
elif [ "$HIGH_RISK" -ge 1 ]; then
    echo -e "${RED}[WARNING] 检测到可疑命令执行，请确认是否为授权操作${NC}"
else
    echo -e "${GREEN}[OK] 命令执行记录未发现明显异常${NC}"
fi

echo ""
echo "下一步建议:"
echo "  1. 检查可疑命令:     grep 'HIGH' $RESULTS_FILE"
echo "  2. 追溯特权操作:     bash scripts/trace_privilege_ops.sh -S '$START_TIME'"
echo "  3. 追溯文件变更:     bash scripts/trace_file_changes.sh -S '$START_TIME'"
echo "  4. 综合异常扫描:     bash scripts/anomaly_scanner.sh"
echo "=========================================="
