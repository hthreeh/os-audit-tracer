#!/bin/bash

# generate_audit_report.sh - 审计报告生成
# 根据数据目录中的审计数据生成结构化报告
# 报告结构参考 assets/ 下的模板文件（Handlebars 格式仅作结构参考）

set -euo pipefail

# --- 默认参数 ---
REPORT_TYPE="audit"
DATA_DIR=""
OUTPUT_FILE=""
TEMPLATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../assets" && pwd)"

# --- 参数解析 ---
while [ $# -gt 0 ]; do
    case "$1" in
        --type)
            REPORT_TYPE="$2"; shift 2 ;;
        --type=*)
            REPORT_TYPE="${1#*=}"; shift ;;
        -d|--data)
            DATA_DIR="$2"; shift 2 ;;
        -d=*|--data=*)
            DATA_DIR="${1#*=}"; shift ;;
        -o|--output)
            OUTPUT_FILE="$2"; shift 2 ;;
        -o=*|--output=*)
            OUTPUT_FILE="${1#*=}"; shift ;;
        -h|--help)
            echo "用法: $0 [选项]"
            echo ""
            echo "选项:"
            echo "  --type <type>    报告类型: audit/incident/compliance (默认: audit)"
            echo "  -d, --data <dir> 数据目录（包含审计日志和分析结果）"
            echo "  -o, --output <f> 输出文件路径"
            echo "  -h, --help       显示帮助"
            echo ""
            echo "报告类型:"
            echo "  audit       通用审计报告"
            echo "  incident    安全事件追溯报告"
            echo "  compliance  合规审计报告"
            exit 0
            ;;
        *)
            echo "[错误] 未知参数: $1"; exit 1 ;;
    esac
done

# --- 颜色定义 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# --- 验证参数 ---
if [ -z "$DATA_DIR" ]; then
    echo -e "${RED}[错误]${NC} 请指定数据目录 (-d)"
    exit 1
fi

if [ ! -d "$DATA_DIR" ]; then
    echo -e "${RED}[错误]${NC} 数据目录不存在: $DATA_DIR"
    exit 1
fi

if [ -z "$OUTPUT_FILE" ]; then
    OUTPUT_FILE="$DATA_DIR/report_${REPORT_TYPE}_$(date +%Y%m%d_%H%M%S).md"
fi

# --- 辅助函数 ---

get_hostname() {
    hostname 2>/dev/null || echo "unknown"
}

get_os_version() {
    cat /etc/os-release 2>/dev/null | grep "PRETTY_NAME" | cut -d'"' -f2 || echo "unknown"
}

get_ip_address() {
    ip -4 addr show 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v "127.0.0.1" | head -1 || echo "unknown"
}

count_anomalies() {
    local file="$1"
    local level="$2"
    if [ -f "$file" ]; then
        grep -ci "$level" "$file" 2>/dev/null || echo "0"
    else
        echo "0"
    fi
}

# --- 报告生成函数 ---

generate_audit_report() {
    echo -e "${CYAN}[INFO]${NC} 生成通用审计报告..."

    local report=""
    report+="# 通用审计报告\n\n"

    # 1. 审计概况（与模板对齐）
    report+="## 1. 审计概况\n\n"
    report+="| 项目 | 内容 |\n"
    report+="|------|------|\n"
    report+="| 审计标题 | 系统安全审计 |\n"
    report+="| 主机名 | $(get_hostname) |\n"
    report+="| 操作系统 | $(get_os_version) |\n"
    report+="| IP 地址 | $(get_ip_address) |\n"
    report+="| 审计时间 | $(date '+%Y-%m-%d %H:%M:%S') |\n"
    report+="| 数据目录 | $DATA_DIR |\n\n"

    # 2. 系统安全状态评估（与模板对齐）
    report+="## 2. 系统安全状态评估\n\n"

    local auditd_status
    auditd_status=$(systemctl is-active auditd 2>/dev/null || echo "unknown")
    local rule_count
    rule_count=$(auditctl -l 2>/dev/null | grep -cv "^No rules" || echo "0")

    report+="### 2.1 审计系统状态\n\n"
    report+="- auditd 状态: $auditd_status\n"
    report+="- 审计规则数: $rule_count\n\n"

    # 异常事件统计
    report+="### 2.2 异常事件统计\n\n"
    if [ -f "$DATA_DIR/anomaly_results.txt" ]; then
        local critical high medium low
        critical=$(count_anomalies "$DATA_DIR/anomaly_results.txt" "CRITICAL")
        high=$(count_anomalies "$DATA_DIR/anomaly_results.txt" "HIGH")
        medium=$(count_anomalies "$DATA_DIR/anomaly_results.txt" "MEDIUM")
        low=$(count_anomalies "$DATA_DIR/anomaly_results.txt" "LOW")

        report+="| 风险等级 | 数量 |\n"
        report+="|----------|------|\n"
        report+="| CRITICAL | $critical |\n"
        report+="| HIGH | $high |\n"
        report+="| MEDIUM | $medium |\n"
        report+="| LOW | $low |\n\n"
    else
        report+="未发现异常事件数据。\n\n"
    fi

    # 3. 异常事件列表（与模板对齐）
    report+="## 3. 异常事件列表\n\n"
    if [ -f "$DATA_DIR/timeline.txt" ]; then
        report+="| 时间 | 类型 | 风险 | 详情 |\n"
        report+="|------|------|------|------|\n"
        while IFS= read -r line; do
            local time etype risk detail
            time=$(echo "$line" | grep -oP '^\[\K[^\]]+' || echo "")
            etype=$(echo "$line" | grep -oP '\[\K[A-Z]+(?=\])' || echo "")
            risk=$(echo "$line" | grep -oP 'HIGH|CRITICAL|MEDIUM|LOW' | head -1 || echo "-")
            detail=$(echo "$line" | sed 's/^\[[^]]*\]\s*\[[^]]*\]\s*//' || echo "$line")
            if [ -n "$time" ]; then
                report+="| $time | $etype | $risk | $detail |\n"
            fi
        done < <(head -50 "$DATA_DIR/timeline.txt")
        report+="\n"
        local total_events
        total_events=$(wc -l < "$DATA_DIR/timeline.txt")
        if [ "$total_events" -gt 50 ]; then
            report+="*（仅显示前 50 条，共 $total_events 条事件）*\n\n"
        fi
    else
        report+="未发现时间线数据。\n\n"
    fi

    # 4. 证据链（与模板对齐）
    report+="## 4. 证据链\n\n"
    if [ -f "$DATA_DIR/evidence_chain.md" ]; then
        report+="$(cat "$DATA_DIR/evidence_chain.md")\n\n"
    else
        report+="未生成证据链。\n\n"
    fi

    # 5. 修复建议（与模板对齐）
    report+="## 5. 修复建议\n\n"
    report+="### 紧急修复（立即执行）\n\n"
    report+="1. 确保 auditd 服务正常运行并配置合适的审计规则\n"
    report+="2. 处理所有 CRITICAL 和 HIGH 级别的异常事件\n\n"
    report+="### 短期修复（一周内）\n\n"
    report+="3. 定期检查系统异常行为\n"
    report+="4. 及时安装安全补丁\n\n"
    report+="### 长期改进\n\n"
    report+="5. 加强访问控制和身份鉴别\n"
    report+="6. 部署文件完整性监控\n"

    echo -e "$report"
}

generate_incident_report() {
    echo -e "${CYAN}[INFO]${NC} 生成安全事件追溯报告..."

    local report=""
    report+="# 安全事件追溯报告\n\n"

    # 1. 事件概述（与模板对齐）
    report+="## 1. 事件概述\n\n"
    report+="| 项目 | 内容 |\n"
    report+="|------|------|\n"
    report+="| 事件标题 | 安全事件追溯 |\n"
    report+="| 主机名 | $(get_hostname) |\n"
    report+="| 操作系统 | $(get_os_version) |\n"
    report+="| IP 地址 | $(get_ip_address) |\n"
    report+="| 报告时间 | $(date '+%Y-%m-%d %H:%M:%S') |\n"
    report+="| 数据目录 | $DATA_DIR |\n\n"

    # 2. 事件时间线（与模板对齐）
    report+="## 2. 事件时间线\n\n"
    if [ -f "$DATA_DIR/timeline.txt" ]; then
        report+="| 时间 | 事件 | 类型 | 详情 |\n"
        report+="|------|------|------|------|\n"
        while IFS= read -r line; do
            local time type detail
            time=$(echo "$line" | grep -oP '^\[\K[^\]]+' || echo "")
            type=$(echo "$line" | grep -oP '\[\K[A-Z]+(?=\])' || echo "")
            detail=$(echo "$line" | sed 's/^\[[^]]*\]\s*\[[^]]*\]\s*//' || echo "$line")
            if [ -n "$time" ]; then
                report+="| $time | - | $type | $detail |\n"
            fi
        done < "$DATA_DIR/timeline.txt"
        report+="\n"
    else
        report+="未发现时间线数据。\n\n"
    fi

    # 3. 攻击链还原（与模板对齐）
    report+="## 3. 攻击链还原\n\n"
    if [ -f "$DATA_DIR/attack_chain.txt" ]; then
        report+="\`\`\`\n"
        report+="$(cat "$DATA_DIR/attack_chain.txt")\n"
        report+="\`\`\`\n\n"
    elif [ -f "$DATA_DIR/evidence_chain.md" ]; then
        report+="基于证据链的攻击链分析：\n\n"
        report+="$(cat "$DATA_DIR/evidence_chain.md")\n\n"
    else
        report+="需要手动分析攻击链。\n\n"
    fi

    # 4. 证据链（与模板对齐）
    report+="## 4. 证据链\n\n"
    if [ -f "$DATA_DIR/evidence_chain.md" ]; then
        report+="$(cat "$DATA_DIR/evidence_chain.md")\n\n"
    else
        report+="未生成证据链。\n\n"
    fi

    # 5. 影响评估（与模板对齐）
    report+="## 5. 影响评估\n\n"
    if [ -f "$DATA_DIR/anomaly_results.txt" ]; then
        local critical high
        critical=$(count_anomalies "$DATA_DIR/anomaly_results.txt" "CRITICAL")
        high=$(count_anomalies "$DATA_DIR/anomaly_results.txt" "HIGH")

        report+="| 影响项 | 状态 | 详情 |\n"
        report+="|--------|------|------|\n"
        if [ "$critical" -gt 0 ]; then
            report+="| 综合风险 | CRITICAL | 发现 $critical 个严重风险项，$high 个高风险项 |\n"
        elif [ "$high" -gt 0 ]; then
            report+="| 综合风险 | HIGH | 发现 $high 个高风险项 |\n"
        else
            report+="| 综合风险 | MEDIUM/LOW | 未发现严重异常 |\n"
        fi
    else
        report+="需要手动评估影响范围。\n\n"
    fi

    # 6. 处置建议（与模板对齐）
    report+="\n## 6. 处置建议\n\n"
    report+="### 6.1 紧急处置（立即执行）\n\n"
    report+="- [ ] 隔离受感染主机\n"
    report+="- [ ] 封锁攻击源 IP\n"
    report+="- [ ] 禁用后门账户\n"
    report+="- [ ] 撤销被植入的 SSH 密钥\n\n"
    report+="### 6.2 短期修复（一周内）\n\n"
    report+="- [ ] 重置受影响用户密码\n"
    report+="- [ ] 修复被篡改的配置文件\n"
    report+="- [ ] 清除恶意 cron 任务和服务\n"
    report+="- [ ] 更新系统补丁\n\n"
    report+="### 6.3 长期预防\n\n"
    report+="- [ ] 部署审计规则（audit_setup.sh）\n"
    report+="- [ ] 启用 AIDE 文件完整性监控\n"
    report+="- [ ] 配置 fail2ban 防暴力破解\n"
    report+="- [ ] 加强 SSH 安全配置\n"

    echo -e "$report"
}

generate_compliance_report() {
    echo -e "${CYAN}[INFO]${NC} 生成合规审计报告..."

    # 如果有 compliance_check 的输出，解析它
    if [ -f "$DATA_DIR/compliance_results.txt" ]; then
        cat "$DATA_DIR/compliance_results.txt"
    elif [ -f "$DATA_DIR/compliance_results.md" ]; then
        cat "$DATA_DIR/compliance_results.md"
    else
        echo -e "${CYAN}[INFO]${NC} 未找到合规检查结果，运行 compliance_check.sh..."
        local script_dir
        script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        if [ -f "$script_dir/compliance_check.sh" ]; then
            bash "$script_dir/compliance_check.sh" --format markdown -o "$OUTPUT_FILE"
            return
        else
            echo -e "${RED}[错误]${NC} 未找到 compliance_check.sh"
            exit 1
        fi
    fi
}

# --- 主流程 ---

echo "=========================================="
echo "  审计报告生成"
echo "=========================================="
echo "报告类型: $REPORT_TYPE"
echo "数据目录: $DATA_DIR"
echo "输出文件: $OUTPUT_FILE"
echo "=========================================="

# 生成报告
report_content=""
case "$REPORT_TYPE" in
    audit)
        report_content=$(generate_audit_report)
        ;;
    incident)
        report_content=$(generate_incident_report)
        ;;
    compliance)
        generate_compliance_report
        echo ""
        echo "报告已保存到: $OUTPUT_FILE"
        exit 0
        ;;
    *)
        echo -e "${RED}[错误]${NC} 未知报告类型: $REPORT_TYPE"
        echo "可用类型: audit, incident, compliance"
        exit 1
        ;;
esac

# 写入文件
printf '%s\n' "$report_content" > "$OUTPUT_FILE"

echo ""
echo -e "${GREEN}[完成]${NC} 报告已生成: $OUTPUT_FILE"
echo "=========================================="
