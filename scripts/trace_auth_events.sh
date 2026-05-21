#!/bin/bash

# 认证事件追溯脚本
# 追踪登录、sudo、su 等认证相关事件，生成带风险标记的时间线

set -euo pipefail

# --- 默认参数 ---
START_TIME=""
END_TIME=""
TARGET_USER=""
TARGET_IP=""
OUTPUT_DIR="./auth-trace-$(date +%Y%m%d_%H%M%S)"
DATA_DIR=""

# --- 颜色定义 ---
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

# --- 参数解析 ---

show_help() {
    echo "用法: $0 -S <起始时间> [-E <结束时间>] [-u <用户>] [-i <IP地址>] [-d <数据目录>] [-o <输出目录>]"
    echo ""
    echo "追溯认证相关安全事件，生成带风险标记的时间线。"
    echo ""
    echo "参数:"
    echo "  -S <time>    起始时间（必需），格式: 'YYYY-MM-DD HH:MM:SS' 或 epoch"
    echo "  -E <time>    结束时间（可选），默认为当前时间"
    echo "  -u <user>    过滤特定用户（可选）"
    echo "  -i <ip>      过滤特定源 IP 地址（可选）"
    echo "  -d <dir>     数据目录（由 collect_audit_logs.sh 生成的离线数据）"
    echo "  -o <dir>     输出目录（可选），默认 ./auth-trace-<timestamp>"
    echo "  -h           显示此帮助信息"
    echo ""
    echo "数据来源:"
    echo "  - /var/log/secure 或 /var/log/auth.log"
    echo "  - ausearch -m USER_AUTH, USER_LOGIN"
    echo ""
    echo "检测事件:"
    echo "  - 失败登录（SSH 密码错误、无效用户）"
    echo "  - 成功登录（SSH 密钥、密码认证成功）"
    echo "  - sudo 命令执行"
    echo "  - su 切换用户"
    echo ""
    echo "示例:"
    echo "  $0 -S '2026-05-20 00:00:00'"
    echo "  $0 -S '2026-05-20 00:00:00' -E '2026-05-20 23:59:59' -u admin"
    echo "  $0 -S '2026-05-20 00:00:00' -i 192.168.1.100"
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
        -i)
            TARGET_IP="$2"; shift 2 ;;
        -i=*)
            TARGET_IP="${1#*=}"; shift ;;
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
RESULTS_FILE="$OUTPUT_DIR/auth_events.log"
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

# --- 解析 secure/auth 日志 ---

parse_secure_log() {
    local log_file
    log_file=$(get_secure_log)

    if [ -z "$log_file" ]; then
        echo -e "${YELLOW}[跳过]${NC} secure/auth 日志不可用"
        return
    fi

    echo "[1/3] 解析 $log_file ..."

    # 失败登录
    grep 'Failed password' "$log_file" 2>/dev/null | while IFS= read -r line; do
        local ip user
        ip=$(echo "$line" | grep -oP 'from \K[0-9.]+' || echo "unknown")
        user=$(echo "$line" | grep -oP 'for (invalid user )?\K\S+' || echo "unknown")

        if [ -n "$TARGET_USER" ] && [ "$user" != "$TARGET_USER" ]; then continue; fi
        if [ -n "$TARGET_IP" ] && [ "$ip" != "$TARGET_IP" ]; then continue; fi

        local ts detail
        ts=$(echo "$line" | awk '{print $1, $2, $3}')
        detail="密码认证失败"
        if echo "$line" | grep -q 'invalid user'; then
            detail="密码认证失败（无效用户）"
        fi

        echo "$ts|AUTH_FAIL|HIGH|$user|$ip|$detail"
    done >> "$TMPFILE"

    # 成功登录
    grep 'Accepted' "$log_file" 2>/dev/null | while IFS= read -r line; do
        local ip user method
        ip=$(echo "$line" | grep -oP 'from \K[0-9.]+' || echo "unknown")
        user=$(echo "$line" | grep -oP 'for \K\S+' || echo "unknown")
        method=$(echo "$line" | grep -oP 'Accepted \K\S+' || echo "unknown")

        if [ -n "$TARGET_USER" ] && [ "$user" != "$TARGET_USER" ]; then continue; fi
        if [ -n "$TARGET_IP" ] && [ "$ip" != "$TARGET_IP" ]; then continue; fi

        local ts
        ts=$(echo "$line" | awk '{print $1, $2, $3}')
        echo "$ts|AUTH_OK|LOW|$user|$ip|$method 认证成功"
    done >> "$TMPFILE"

    # sudo 操作
    grep 'sudo:' "$log_file" 2>/dev/null | while IFS= read -r line; do
        local user ts detail
        user=$(echo "$line" | grep -oP ': \K\S+' | head -1 || echo "unknown")
        ts=$(echo "$line" | awk '{print $1, $2, $3}')
        detail=$(echo "$line" | cut -d: -f4- | sed 's/^ *//')

        if [ -n "$TARGET_USER" ] && [ "$user" != "$TARGET_USER" ]; then continue; fi

        local risk="MEDIUM"
        if [ "$user" = "root" ]; then risk="LOW"; fi
        if echo "$detail" | grep -q 'NOPASSWD'; then risk="HIGH"; fi

        echo "$ts|SUDO|$risk|$user|-|$detail"
    done >> "$TMPFILE"

    # su 切换
    grep 'su:' "$log_file" 2>/dev/null | while IFS= read -r line; do
        local user ts detail target_user
        user=$(echo "$line" | grep -oP ': \K\S+' | head -1 || echo "unknown")
        ts=$(echo "$line" | awk '{print $1, $2, $3}')
        detail=$(echo "$line" | cut -d: -f4- | sed 's/^ *//')
        target_user=$(echo "$detail" | grep -oP 'to \K\S+' || echo "unknown")

        if [ -n "$TARGET_USER" ] && [ "$user" != "$TARGET_USER" ] && [ "$target_user" != "$TARGET_USER" ]; then continue; fi

        local risk="MEDIUM"
        if [ "$target_user" = "root" ]; then risk="HIGH"; fi

        echo "$ts|SU|$risk|$user|-|$detail"
    done >> "$TMPFILE"

    echo "  secure/auth 日志解析完成"
}

# --- 解析 auditd 认证事件 ---

parse_audit_auth() {
    if ! command -v ausearch &>/dev/null; then
        echo -e "${YELLOW}[跳过]${NC} ausearch 不可用"
        return
    fi

    echo "[2/3] 解析 auditd 认证事件 (USER_AUTH, USER_LOGIN) ..."

    local ausearch_args=(-m USER_AUTH,USER_LOGIN -ts "$START_TIME" -te "$END_TIME" --input-logs --no-pager)
    if [ -n "$TARGET_USER" ]; then
        ausearch_args+=(-ua "$TARGET_USER")
    fi

    ausearch "${ausearch_args[@]}" 2>/dev/null | while IFS= read -r line; do
        local epoch_ts readable_ts
        epoch_ts=$(echo "$line" | grep -oP 'msg=audit\(\K[0-9.]+' || echo "")
        if [ -z "$epoch_ts" ]; then continue; fi
        readable_ts=$(date -d "@${epoch_ts%%.*}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$epoch_ts")

        local acct addr res exe
        acct=$(echo "$line" | grep -oP 'acct="[^"]*"' | head -1 | cut -d'"' -f2 || echo "unknown")
        addr=$(echo "$line" | grep -oP 'addr="[^"]*"' | head -1 | cut -d'"' -f2 || echo "-")
        res=$(echo "$line" | grep -oP 'res=\K\S+' || echo "unknown")
        exe=$(echo "$line" | grep -oP 'exe="[^"]*"' | head -1 | cut -d'"' -f2 || echo "unknown")

        if [ -n "$TARGET_IP" ] && [ "$addr" != "$TARGET_IP" ]; then continue; fi

        local event_type="AUTH" risk="LOW"
        if echo "$line" | grep -q 'type=USER_AUTH'; then
            if [ "$res" = "success" ]; then
                event_type="AUTH_OK"
            else
                event_type="AUTH_FAIL"
                risk="HIGH"
            fi
        elif echo "$line" | grep -q 'type=USER_LOGIN'; then
            event_type="LOGIN"
            if [ "$res" != "success" ]; then risk="HIGH"; fi
        fi

        echo "$readable_ts|$event_type|$risk|$acct|$addr|exe=$exe res=$res"
    done >> "$TMPFILE"

    echo "  auditd 认证事件解析完成"
}

# --- 暴力破解检测 ---

detect_brute_force() {
    echo "[3/3] 暴力破解检测 ..."

    if [ ! -s "$RESULTS_FILE" ]; then
        echo "  无事件数据，跳过检测"
        return
    fi

    # 按 IP 统计失败次数
    local brute_ips
    brute_ips=$(grep 'AUTH_FAIL' "$RESULTS_FILE" | awk -F'|' '{print $5}' | sort | uniq -c | sort -rn || true)

    if [ -n "$brute_ips" ]; then
        echo ""
        echo "--- 暴力破解嫌疑 IP ---"
        echo "$brute_ips" | while read -r count ip; do
            if [ "$count" -ge 10 ]; then
                echo -e "${RED}[HIGH RISK]${NC} IP: $ip  失败次数: $count"
            elif [ "$count" -ge 5 ]; then
                echo -e "${YELLOW}[MEDIUM]${NC}     IP: $ip  失败次数: $count"
            fi
        done
    fi

    # 按用户统计失败次数
    local brute_users
    brute_users=$(grep 'AUTH_FAIL' "$RESULTS_FILE" | awk -F'|' '{print $4}' | sort | uniq -c | sort -rn || true)

    if [ -n "$brute_users" ]; then
        echo ""
        echo "--- 被攻击目标用户 ---"
        echo "$brute_users" | head -10 | while read -r count user; do
            if [ "$count" -ge 10 ]; then
                echo -e "${RED}[HIGH RISK]${NC} 用户: $user  被攻击次数: $count"
            elif [ "$count" -ge 5 ]; then
                echo -e "${YELLOW}[MEDIUM]${NC}     用户: $user  被攻击次数: $count"
            fi
        done
    fi

    # 检查成功登录前有多次失败（撞库后成功）
    echo ""
    echo "--- 成功登录前有失败记录的 IP（疑似撞库成功）---"
    local success_ips
    success_ips=$(grep 'AUTH_OK' "$RESULTS_FILE" | awk -F'|' '{print $5}' | sort -u || true)
    local found_compromise=0
    for ip in $success_ips; do
        if [ "$ip" = "-" ] || [ "$ip" = "unknown" ]; then continue; fi
        local fail_count
        fail_count=$(grep 'AUTH_FAIL' "$RESULTS_FILE" | awk -F'|' -v ip="$ip" '$5 == ip' | wc -l)
        if [ "$fail_count" -gt 0 ]; then
            echo -e "${RED}[CRITICAL]${NC} IP: $ip  失败 $fail_count 次后成功登录"
            found_compromise=1
        fi
    done
    if [ "$found_compromise" -eq 0 ]; then
        echo -e "${GREEN}[正常]${NC} 未发现撞库成功迹象"
    fi
}

# --- 格式化输出 ---

print_results() {
    echo ""
    echo "--- 事件时间线 ---"
    echo ""

    while IFS='|' read -r ts etype risk user ip detail; do
        local risk_mark=""
        case "$risk" in
            HIGH)   risk_mark="${RED}[HIGH RISK]${NC}" ;;
            MEDIUM) risk_mark="${YELLOW}[MEDIUM]${NC}" ;;
            LOW)    risk_mark="${GREEN}[LOW]${NC}" ;;
        esac
        printf "[%s] [%-10s] %b %-10s %-18s %s\n" "$ts" "$etype" "$risk_mark" "$user" "$ip" "$detail"
    done < "$RESULTS_FILE"
}

# --- 主流程 ---

echo "=========================================="
echo "  认证事件追溯"
echo "=========================================="
echo "时间范围: $START_TIME ~ $END_TIME"
if [ -n "$TARGET_USER" ]; then echo "目标用户: $TARGET_USER"; fi
if [ -n "$TARGET_IP" ]; then echo "目标 IP:  $TARGET_IP"; fi
echo "输出目录: $OUTPUT_DIR"
echo "=========================================="
echo ""

# 初始化
> "$TMPFILE"

parse_secure_log
parse_audit_auth

# 排序并写入结果文件
if [ -s "$TMPFILE" ]; then
    sort -t'|' -k1 -o "$TMPFILE" "$TMPFILE"
    cp "$TMPFILE" "$RESULTS_FILE"
    # 生成带颜色的终端输出
    print_results
else
    > "$RESULTS_FILE"
    echo -e "${YELLOW}[提示]${NC} 未发现匹配的认证事件"
fi

detect_brute_force

# --- 统计汇总 ---

TOTAL_EVENTS=$(wc -l < "$RESULTS_FILE" 2>/dev/null || echo 0)
FAILED_LOGINS=$(grep -c 'AUTH_FAIL' "$RESULTS_FILE" 2>/dev/null || echo 0)
SUCCESS_LOGINS=$(grep -c 'AUTH_OK' "$RESULTS_FILE" 2>/dev/null || echo 0)
SUDO_EVENTS=$(grep -c 'SUDO' "$RESULTS_FILE" 2>/dev/null || echo 0)
SU_EVENTS=$(grep -c '|SU|' "$RESULTS_FILE" 2>/dev/null || echo 0)
HIGH_RISK=$(grep -c '|HIGH|' "$RESULTS_FILE" 2>/dev/null || echo 0)

echo ""
echo "=========================================="
echo "  认证事件汇总"
echo "=========================================="
echo -e "总事件数:        $TOTAL_EVENTS"
echo -e "失败登录:        ${RED}$FAILED_LOGINS${NC}"
echo -e "成功登录:        ${GREEN}$SUCCESS_LOGINS${NC}"
echo -e "sudo 操作:       $SUDO_EVENTS"
echo -e "su 切换:         $SU_EVENTS"
echo -e "高风险事件:      ${RED}$HIGH_RISK${NC}"
echo ""
echo "详细结果: $RESULTS_FILE"
echo ""

if [ "$HIGH_RISK" -ge 10 ]; then
    echo -e "${RED}[CRITICAL] 检测到大量高风险认证事件，系统可能已被入侵${NC}"
elif [ "$HIGH_RISK" -ge 3 ]; then
    echo -e "${RED}[WARNING] 检测到多个高风险认证事件，建议立即排查${NC}"
elif [ "$FAILED_LOGINS" -ge 20 ]; then
    echo -e "${YELLOW}[NOTICE] 失败登录次数较多，可能存在暴力破解攻击${NC}"
else
    echo -e "${GREEN}[OK] 认证事件数量在正常范围内${NC}"
fi

echo ""
echo "下一步建议:"
echo "  1. 检查高风险 IP:     grep 'HIGH' $RESULTS_FILE"
echo "  2. 追溯特权操作:      bash scripts/trace_privilege_ops.sh -S '$START_TIME'"
echo "  3. 综合异常扫描:      bash scripts/anomaly_scanner.sh"
echo "=========================================="
