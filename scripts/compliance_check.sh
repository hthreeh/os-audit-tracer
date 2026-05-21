#!/bin/bash

# compliance_check.sh - 等保核心项合规检查
# 针对 GB/T 22239 三级要求，自动化检查 30 项核心技术检查项

set -euo pipefail

# --- 默认参数 ---
FORMAT="text"
OUTPUT_FILE=""
VERBOSE=0

# --- 参数解析 ---
while [ $# -gt 0 ]; do
    case "$1" in
        --format)
            FORMAT="$2"; shift 2 ;;
        --format=*)
            FORMAT="${1#*=}"; shift ;;
        -o|--output)
            OUTPUT_FILE="$2"; shift 2 ;;
        -o=*|--output=*)
            OUTPUT_FILE="${1#*=}"; shift ;;
        -v|--verbose)
            VERBOSE=1; shift ;;
        -h|--help)
            echo "用法: $0 [选项]"
            echo ""
            echo "选项:"
            echo "  --format <type>   输出格式: text/markdown/json (默认: text)"
            echo "  -o, --output <f>  输出文件路径"
            echo "  -v, --verbose     详细输出"
            echo "  -h, --help        显示帮助"
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
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# --- 计数器 ---
TOTAL=0
PASS=0
FAIL=0
WARN=0
NA=0

# --- 结果收集 ---
declare -a RESULTS=()

# --- 辅助函数 ---

log_result() {
    local id="$1"
    local category="$2"
    local item="$3"
    local status="$4"
    local detail="$5"
    local evidence="${6:-}"

    TOTAL=$((TOTAL + 1))

    case "$status" in
        PASS)
            PASS=$((PASS + 1))
            [ "$FORMAT" = "text" ] && echo -e "${GREEN}[PASS]${NC} $id $item"
            ;;
        FAIL)
            FAIL=$((FAIL + 1))
            [ "$FORMAT" = "text" ] && echo -e "${RED}[FAIL]${NC} $id $item - $detail"
            ;;
        WARN)
            WARN=$((WARN + 1))
            [ "$FORMAT" = "text" ] && echo -e "${YELLOW}[WARN]${NC} $id $item - $detail"
            ;;
        NA)
            NA=$((NA + 1))
            [ "$FORMAT" = "text" ] && echo -e "${CYAN}[N/A]${NC} $id $item - $detail"
            ;;
    esac

    RESULTS+=("$id|$category|$item|$status|$detail|$evidence")
}

output_results() {
    local output=""

    case "$FORMAT" in
        text)
            output=$(generate_text_report)
            ;;
        markdown)
            output=$(generate_markdown_report)
            ;;
        json)
            output=$(generate_json_report)
            ;;
    esac

    if [ -n "$OUTPUT_FILE" ]; then
        echo "$output" > "$OUTPUT_FILE"
        echo ""
        echo "报告已保存到: $OUTPUT_FILE"
    else
        echo ""
        echo "$output"
    fi
}

generate_text_report() {
    local report=""
    report+="==========================================\n"
    report+="  等保三级合规检查报告\n"
    report+="==========================================\n"
    report+="检查时间: $(date '+%Y-%m-%d %H:%M:%S')\n"
    report+="主机名: $(hostname)\n"
    report+="操作系统: $(cat /etc/os-release 2>/dev/null | grep "PRETTY_NAME" | cut -d'"' -f2)\n"
    report+="==========================================\n\n"

    report+="检查结果汇总:\n"
    report+="  总计: $TOTAL\n"
    report+="  通过: $PASS\n"
    report+="  未通过: $FAIL\n"
    report+="  警告: $WARN\n"
    report+="  不适用: $NA\n"
    report+="  合规率: $(( PASS * 100 / (TOTAL - NA > 0 ? TOTAL - NA : 1) ))%\n"

    echo -e "$report"
}

generate_markdown_report() {
    local report=""
    report+="# 等保三级合规检查报告\n\n"
    report+="## 审计概况\n\n"
    report+="- **审计标准**: GB/T 22239-2019\n"
    report+="- **安全等级**: 第三级\n"
    report+="- **审计范围**: $(hostname)\n"
    report+="- **审计日期**: $(date '+%Y-%m-%d %H:%M:%S')\n"
    report+="- **操作系统**: $(cat /etc/os-release 2>/dev/null | grep "PRETTY_NAME" | cut -d'"' -f2)\n\n"

    report+="## 检查结果汇总\n\n"
    report+="| 指标 | 数值 |\n"
    report+="|------|------|\n"
    report+="| 总检查项 | $TOTAL |\n"
    report+="| 通过 | $PASS |\n"
    report+="| 未通过 | $FAIL |\n"
    report+="| 警告 | $WARN |\n"
    report+="| 不适用 | $NA |\n"
    report+="| 合规率 | $(( PASS * 100 / (TOTAL - NA > 0 ? TOTAL - NA : 1) ))% |\n\n"

    report+="## 详细检查结果\n\n"
    report+="| 编号 | 类别 | 检查项 | 状态 | 说明 |\n"
    report+="|------|------|--------|------|------|\n"

    for result in "${RESULTS[@]}"; do
        IFS='|' read -r id category item status detail evidence <<< "$result"
        local status_icon
        case "$status" in
            PASS) status_icon="✅ PASS" ;;
            FAIL) status_icon="❌ FAIL" ;;
            WARN) status_icon="⚠️ WARN" ;;
            NA)   status_icon="➖ N/A" ;;
        esac
        report+="| $id | $category | $item | $status_icon | $detail |\n"
    done

    # 未通过项详情
    if [ "$FAIL" -gt 0 ]; then
        report+="\n## 未通过项详情\n\n"
        for result in "${RESULTS[@]}"; do
            IFS='|' read -r id category item status detail evidence <<< "$result"
            if [ "$status" = "FAIL" ]; then
                report+="### $id $item\n\n"
                report+="- **类别**: $category\n"
                report+="- **问题**: $detail\n"
                if [ -n "$evidence" ]; then
                    report+="- **证据**:\n\`\`\`\n$evidence\n\`\`\`\n"
                fi
                report+="\n"
            fi
        done
    fi

    echo -e "$report"
}

generate_json_report() {
    echo "{"
    echo "  \"report_time\": \"$(date '+%Y-%m-%d %H:%M:%S')\","
    echo "  \"hostname\": \"$(hostname)\","
    echo "  \"standard\": \"GB/T 22239-2019\","
    echo "  \"level\": 3,"
    echo "  \"summary\": {"
    echo "    \"total\": $TOTAL,"
    echo "    \"pass\": $PASS,"
    echo "    \"fail\": $FAIL,"
    echo "    \"warn\": $WARN,"
    echo "    \"na\": $NA,"
    echo "    \"compliance_rate\": $(( PASS * 100 / (TOTAL - NA > 0 ? TOTAL - NA : 1) ))"
    echo "  },"
    echo "  \"results\": ["

    local first=1
    for result in "${RESULTS[@]}"; do
        IFS='|' read -r id category item status detail evidence <<< "$result"
        [ "$first" -eq 0 ] && echo ","
        first=0
        echo -n "    {\"id\":\"$id\",\"category\":\"$category\",\"item\":\"$item\",\"status\":\"$status\",\"detail\":\"$detail\"}"
    done

    echo ""
    echo "  ]"
    echo "}"
}

# ============================================================
# 检查函数
# ============================================================

check_identity_auth() {
    echo ""
    echo -e "${BOLD}=== 身份鉴别 ===${NC}"

    # 4.1.1 用户标识唯一性
    local dup_uids
    dup_uids=$(awk -F: '{print $3}' /etc/passwd | sort -n | uniq -d 2>/dev/null || true)
    if [ -z "$dup_uids" ]; then
        log_result "4.1.1" "身份鉴别" "用户标识唯一性" "PASS" "UID 无重复"
    else
        log_result "4.1.1" "身份鉴别" "用户标识唯一性" "FAIL" "存在重复 UID: $dup_uids" "$dup_uids"
    fi

    # 4.1.2 身份鉴别方式
    if grep -q "^PasswordAuthentication yes" /etc/ssh/sshd_config 2>/dev/null || \
       grep -q "^PubkeyAuthentication yes" /etc/ssh/sshd_config 2>/dev/null; then
        log_result "4.1.2" "身份鉴别" "身份鉴别方式" "PASS" "SSH 配置了认证方式"
    else
        log_result "4.1.2" "身份鉴别" "身份鉴别方式" "WARN" "SSH 认证配置不明确"
    fi

    # 4.1.3 登录失败处理
    if grep -rq "pam_faillock\|pam_tally2\|pam_faildelay" /etc/pam.d/ 2>/dev/null; then
        log_result "4.1.3" "身份鉴别" "登录失败处理" "PASS" "配置了登录失败锁定策略"
    else
        log_result "4.1.3" "身份鉴别" "登录失败处理" "FAIL" "未配置登录失败锁定策略" "grep -r 'pam_faillock\\|pam_tally2' /etc/pam.d/"
    fi

    # 4.1.4 远程管理加密
    local ssh_protocol
    ssh_protocol=$(grep "^Protocol" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    if [ -z "$ssh_protocol" ] || [ "$ssh_protocol" = "2" ]; then
        log_result "4.1.4" "身份鉴别" "远程管理加密" "PASS" "使用 SSH v2 协议"
    else
        log_result "4.1.4" "身份鉴别" "远程管理加密" "FAIL" "SSH 协议版本不安全: $ssh_protocol"
    fi

    # 4.1.5 密码复杂度
    if grep -rq "pam_pwquality\|pam_cracklib\|pam_passwdqc" /etc/pam.d/ 2>/dev/null; then
        log_result "4.1.5" "身份鉴别" "密码复杂度" "PASS" "配置了密码复杂度策略"
    else
        log_result "4.1.5" "身份鉴别" "密码复杂度" "FAIL" "未配置密码复杂度策略" "grep -r 'pam_pwquality\\|pam_cracklib' /etc/pam.d/"
    fi

    # 4.1.6 密码有效期
    local max_days
    max_days=$(grep "^PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
    max_days=${max_days:-99999}
    if [ "$max_days" -le 90 ]; then
        log_result "4.1.6" "身份鉴别" "密码有效期" "PASS" "密码最长有效期: ${max_days}天"
    else
        log_result "4.1.6" "身份鉴别" "密码有效期" "FAIL" "密码最长有效期过长: ${max_days}天（应≤90天）" "PASS_MAX_DAYS=$max_days"
    fi

    # 4.1.7 默认账户处理
    local nologin_accounts
    nologin_accounts=$(awk -F: '$3 < 1000 && $7 != "/sbin/nologin" && $7 != "/bin/false" && $1 != "root" {print $1}' /etc/passwd 2>/dev/null || true)
    if [ -z "$nologin_accounts" ]; then
        log_result "4.1.7" "身份鉴别" "默认账户处理" "PASS" "默认账户已禁用"
    else
        log_result "4.1.7" "身份鉴别" "默认账户处理" "WARN" "部分系统账户有交互 shell: $nologin_accounts" "$nologin_accounts"
    fi
}

check_access_control() {
    echo ""
    echo -e "${BOLD}=== 访问控制 ===${NC}"

    # 4.2.1 root 远程登录
    local permit_root
    permit_root=$(grep -i "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    if [ "$permit_root" = "no" ] || [ "$permit_root" = "prohibit-password" ]; then
        log_result "4.2.1" "访问控制" "root 远程登录限制" "PASS" "PermitRootLogin=$permit_root"
    else
        log_result "4.2.1" "访问控制" "root 远程登录限制" "FAIL" "PermitRootLogin=${permit_root:-yes}（应设为 no）" "grep PermitRootLogin /etc/ssh/sshd_config"
    fi

    # 4.2.2 sudo 配置
    local nopasswd_count
    nopasswd_count=$(grep -rc "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | awk -F: '{sum+=$2} END{print sum+0}')
    if [ "$nopasswd_count" -le 1 ]; then
        log_result "4.2.2" "访问控制" "sudo 最小权限" "PASS" "NOPASSWD 配置合理"
    else
        log_result "4.2.2" "访问控制" "sudo 最小权限" "WARN" "发现 $nopasswd_count 处 NOPASSWD 配置" "grep -rn 'NOPASSWD' /etc/sudoers /etc/sudoers.d/"
    fi

    # 4.2.3 默认 umask
    local umask_val
    umask_val=$(umask)
    if [ "$umask_val" = "0027" ] || [ "$umask_val" = "0077" ]; then
        log_result "4.2.3" "访问控制" "默认权限" "PASS" "umask=$umask_val"
    else
        log_result "4.2.3" "访问控制" "默认权限" "WARN" "umask=$umask_val（建议 0027 或 0077）"
    fi

    # 4.2.4 敏感文件权限
    local passwdd_perm shadow_perm
    passwdd_perm=$(stat -c '%a' /etc/passwd 2>/dev/null)
    shadow_perm=$(stat -c '%a' /etc/shadow 2>/dev/null)
    if [ "$passwdd_perm" = "644" ] && { [ "$shadow_perm" = "0" ] || [ "$shadow_perm" = "600" ] || [ "$shadow_perm" = "640" ]; }; then
        log_result "4.2.4" "访问控制" "敏感文件权限" "PASS" "/etc/passwd=$passwdd_perm /etc/shadow=$shadow_perm"
    else
        log_result "4.2.4" "访问控制" "敏感文件权限" "FAIL" "/etc/passwd=$passwdd_perm /etc/shadow=$shadow_perm" "ls -la /etc/passwd /etc/shadow"
    fi

    # 4.2.5 审计目录权限
    local audit_perm
    audit_perm=$(stat -c '%a' /var/log/audit/ 2>/dev/null || echo "不存在")
    if [ "$audit_perm" = "700" ] || [ "$audit_perm" = "750" ]; then
        log_result "4.2.5" "访问控制" "审计目录权限" "PASS" "/var/log/audit/ 权限: $audit_perm"
    elif [ "$audit_perm" = "不存在" ]; then
        log_result "4.2.5" "访问控制" "审计目录权限" "NA" "审计目录不存在"
    else
        log_result "4.2.5" "访问控制" "审计目录权限" "WARN" "/var/log/audit/ 权限: $audit_perm（建议 700）"
    fi
}

check_audit() {
    echo ""
    echo -e "${BOLD}=== 安全审计 ===${NC}"

    # 4.3.1 审计策略覆盖
    local rule_count
    rule_count=$(auditctl -l 2>/dev/null | grep -cv "^No rules" || echo "0")
    if [ "$rule_count" -ge 10 ]; then
        log_result "4.3.1" "安全审计" "审计策略覆盖" "PASS" "审计规则数: $rule_count"
    elif [ "$rule_count" -gt 0 ]; then
        log_result "4.3.1" "安全审计" "审计策略覆盖" "WARN" "审计规则数较少: $rule_count（建议≥10）"
    else
        log_result "4.3.1" "安全审计" "审计策略覆盖" "FAIL" "未配置审计规则" "auditctl -l"
    fi

    # 4.3.2 审计日志保护
    if [ -f /var/log/audit/audit.log ]; then
        local log_perm
        log_perm=$(stat -c '%a' /var/log/audit/audit.log)
        if [ "$log_perm" = "600" ] || [ "$log_perm" = "640" ]; then
            log_result "4.3.2" "安全审计" "审计日志保护" "PASS" "audit.log 权限: $log_perm"
        else
            log_result "4.3.2" "安全审计" "审计日志保护" "WARN" "audit.log 权限: $log_perm（建议 600）"
        fi
    else
        log_result "4.3.2" "安全审计" "审计日志保护" "NA" "审计日志文件不存在"
    fi

    # 4.3.3 审计日志存储
    local audit_space
    audit_space=$(df -BG /var/log/audit/ 2>/dev/null | tail -1 | awk '{print $4}' | tr -d 'G')
    if [ -n "$audit_space" ] && [ "$audit_space" -ge 5 ]; then
        log_result "4.3.3" "安全审计" "审计日志存储" "PASS" "可用空间: ${audit_space}G"
    elif [ -n "$audit_space" ]; then
        log_result "4.3.3" "安全审计" "审计日志存储" "WARN" "可用空间不足: ${audit_space}G（建议≥5G）"
    else
        log_result "4.3.3" "安全审计" "审计日志存储" "NA" "无法检查存储空间"
    fi

    # 4.3.4 审计日志备份
    if grep -q "rotate\|backup\|archive" /etc/audit/auditd.conf 2>/dev/null || \
       [ -f /etc/logrotate.d/audit ]; then
        log_result "4.3.4" "安全审计" "审计日志备份" "PASS" "配置了日志轮转/备份策略"
    else
        log_result "4.3.4" "安全审计" "审计日志备份" "WARN" "未发现明确的备份策略"
    fi

    # 4.3.5 审计日志保留
    if [ -f /etc/logrotate.d/audit ]; then
        local rotate_conf
        rotate_conf=$(cat /etc/logrotate.d/audit)
        if echo "$rotate_conf" | grep -qE "rotate\s+[5-9][0-9]*|rotate\s+[1-9][0-9]{2,}"; then
            log_result "4.3.5" "安全审计" "审计日志保留" "PASS" "日志保留策略满足 6 个月要求"
        else
            log_result "4.3.5" "安全审计" "审计日志保留" "WARN" "日志保留策略可能不足 6 个月" "$rotate_conf"
        fi
    else
        log_result "4.3.5" "安全审计" "审计日志保留" "WARN" "未配置 audit 日志轮转"
    fi
}

check_intrusion_prevention() {
    echo ""
    echo -e "${BOLD}=== 入侵防范 ===${NC}"

    # 4.4.1 最小安装
    local pkg_count
    pkg_count=$(rpm -qa 2>/dev/null | wc -l || echo "0")
    if [ "$pkg_count" -le 500 ]; then
        log_result "4.4.1" "入侵防范" "最小安装" "PASS" "已安装包数: $pkg_count"
    elif [ "$pkg_count" -le 1000 ]; then
        log_result "4.4.1" "入侵防范" "最小安装" "WARN" "已安装包数较多: $pkg_count"
    else
        log_result "4.4.1" "入侵防范" "最小安装" "WARN" "已安装包数过多: $pkg_count（建议精简）"
    fi

    # 4.4.2 服务最小化
    local running_services
    running_services=$(systemctl list-units --type=service --state=running --no-pager 2>/dev/null | grep "running" | wc -l || echo "0")
    if [ "$running_services" -le 30 ]; then
        log_result "4.4.2" "入侵防范" "服务最小化" "PASS" "运行中服务数: $running_services"
    else
        log_result "4.4.2" "入侵防范" "服务最小化" "WARN" "运行中服务数较多: $running_services（建议精简）"
    fi

    # 4.4.3 安全补丁
    if command -v yum &>/dev/null; then
        local updates
        updates=$(yum check-update --security 2>/dev/null | grep -c "^[a-zA-Z]" || echo "0")
        if [ "$updates" -eq 0 ]; then
            log_result "4.4.3" "入侵防范" "安全补丁" "PASS" "安全补丁已更新"
        else
            log_result "4.4.3" "入侵防范" "安全补丁" "WARN" "有 $updates 个安全更新待安装"
        fi
    else
        log_result "4.4.3" "入侵防范" "安全补丁" "NA" "非 yum 包管理器"
    fi

    # 4.4.4 网络连接限制
    local listening_ports
    listening_ports=$(ss -tlnp 2>/dev/null | grep -cv "^State" || echo "0")
    if [ "$listening_ports" -le 15 ]; then
        log_result "4.4.4" "入侵防范" "网络连接限制" "PASS" "监听端口数: $listening_ports"
    else
        log_result "4.4.4" "入侵防范" "网络连接限制" "WARN" "监听端口数较多: $listening_ports（建议精简）" "ss -tlnp"
    fi
}

check_malware() {
    echo ""
    echo -e "${BOLD}=== 恶意代码防范 ===${NC}"

    # 4.5.1 防病毒软件
    if rpm -qa 2>/dev/null | grep -qiE "clamav|avast|sophos|avg|eset|kaspersky"; then
        log_result "4.5.1" "恶意代码防范" "防病毒软件" "PASS" "已安装防病毒软件"
    else
        log_result "4.5.1" "恶意代码防范" "防病毒软件" "WARN" "未检测到防病毒软件"
    fi

    # 4.5.2 AIDE 文件完整性
    if command -v aide &>/dev/null; then
        log_result "4.5.2" "恶意代码防范" "文件完整性检测" "PASS" "AIDE 已安装"
    elif rpm -qa 2>/dev/null | grep -q "aide"; then
        log_result "4.5.2" "恶意代码防范" "文件完整性检测" "PASS" "AIDE 已安装"
    else
        log_result "4.5.2" "恶意代码防范" "文件完整性检测" "WARN" "未安装 AIDE 文件完整性检测工具"
    fi
}

check_data_integrity() {
    echo ""
    echo -e "${BOLD}=== 数据完整性 ===${NC}"

    # 4.6.1 关键文件完整性
    local rpm_verify
    rpm_verify=$(rpm -Va 2>/dev/null | grep -cE "^..5|^S\.|^\.M" || echo "0")
    if [ "$rpm_verify" -eq 0 ]; then
        log_result "4.6.1" "数据完整性" "关键文件完整性" "PASS" "RPM 验证无异常"
    else
        log_result "4.6.1" "数据完整性" "关键文件完整性" "WARN" "RPM 验证发现 $rpm_verify 个文件变更" "rpm -Va | head -10"
    fi

    # 4.6.2 数据备份
    if [ -d /backup ] || [ -d /data/backup ] || crontab -l 2>/dev/null | grep -qi "backup\|dump\|rsync"; then
        log_result "4.6.2" "数据完整性" "数据备份" "PASS" "检测到备份配置"
    else
        log_result "4.6.2" "数据完整性" "数据备份" "WARN" "未检测到备份配置"
    fi
}

check_data_confidentiality() {
    echo ""
    echo -e "${BOLD}=== 数据保密性 ===${NC}"

    # 4.7.1 传输加密
    if ss -tlnp 2>/dev/null | grep -qE ":443|:8443"; then
        log_result "4.7.1" "数据保密性" "传输加密" "PASS" "检测到 HTTPS 服务"
    else
        log_result "4.7.1" "数据保密性" "传输加密" "NA" "未发现 HTTPS 服务（可能由负载均衡器提供）"
    fi

    # 4.7.2 存储加密
    if lsblk -o FSTYPE 2>/dev/null | grep -q "crypt\|luks"; then
        log_result "4.7.2" "数据保密性" "存储加密" "PASS" "检测到加密分区"
    else
        log_result "4.7.2" "数据保密性" "存储加密" "WARN" "未检测到磁盘加密"
    fi

    # 4.7.3 国密算法支持（FusionOS 特有）
    if openssl engine -t 2>/dev/null | grep -qi "sm\|gmssl\|tongsuo"; then
        log_result "4.7.3" "数据保密性" "国密算法支持" "PASS" "支持国密算法"
    elif [ -f /etc/fusionos-release ] || [ -f /etc/EulerOS-release ]; then
        log_result "4.7.3" "数据保密性" "国密算法支持" "WARN" "FusionOS 环境但未检测到国密引擎"
    else
        log_result "4.7.3" "数据保密性" "国密算法支持" "NA" "非 FusionOS 环境"
    fi
}

check_selinux() {
    echo ""
    echo -e "${BOLD}=== SELinux 安全模块 ===${NC}"

    local selinux_status
    selinux_status=$(getenforce 2>/dev/null || echo "Disabled")
    case "$selinux_status" in
        Enforcing)
            log_result "SEL.1" "安全模块" "SELinux 状态" "PASS" "SELinux 处于强制模式"
            ;;
        Permissive)
            log_result "SEL.1" "安全模块" "SELinux 状态" "WARN" "SELinux 处于宽容模式（建议强制模式）"
            ;;
        *)
            log_result "SEL.1" "安全模块" "SELinux 状态" "FAIL" "SELinux 已禁用" "getenforce"
            ;;
    esac
}

check_firewall() {
    echo ""
    echo -e "${BOLD}=== 防火墙配置 ===${NC}"

    # 检查 iptables
    local iptables_rules
    iptables_rules=$(iptables -L -n 2>/dev/null | grep -cv "^Chain\|^target\|^$" || echo "0")

    # 检查 firewalld
    local firewalld_active=0
    if systemctl is-active firewalld &>/dev/null; then
        firewalld_active=1
    fi

    if [ "$iptables_rules" -gt 0 ] || [ "$firewalld_active" -eq 1 ]; then
        log_result "FW.1" "防火墙" "防火墙状态" "PASS" "防火墙已启用（iptables 规则: $iptables_rules）"
    else
        log_result "FW.1" "防火墙" "防火墙状态" "FAIL" "防火墙未启用或无规则" "iptables -L -n"
    fi

    # 检查默认策略
    local input_policy
    input_policy=$(iptables -L INPUT -n 2>/dev/null | head -1 | awk '{print $4}' | tr -d ')')
    if [ "$input_policy" = "DROP" ] || [ "$input_policy" = "REJECT" ]; then
        log_result "FW.2" "防火墙" "默认入站策略" "PASS" "INPUT 默认策略: $input_policy"
    else
        log_result "FW.2" "防火墙" "默认入站策略" "WARN" "INPUT 默认策略: ${input_policy:-ACCEPT}（建议 DROP）"
    fi
}

check_kernel_security() {
    echo ""
    echo -e "${BOLD}=== 内核安全参数 ===${NC}"

    # IP 转发（非路由器应禁用）
    local ip_forward
    ip_forward=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "unknown")
    if [ "$ip_forward" = "0" ]; then
        log_result "KS.1" "内核参数" "IP 转发" "PASS" "net.ipv4.ip_forward=0"
    else
        log_result "KS.1" "内核参数" "IP 转发" "WARN" "net.ipv4.ip_forward=$ip_forward（非路由器应设为 0）"
    fi

    # ICMP 重定向接受
    local accept_redirects
    accept_redirects=$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null || echo "unknown")
    if [ "$accept_redirects" = "0" ]; then
        log_result "KS.2" "内核参数" "ICMP 重定向" "PASS" "accept_redirects=0"
    else
        log_result "KS.2" "内核参数" "ICMP 重定向" "WARN" "accept_redirects=$accept_redirects（建议设为 0）"
    fi

    # 源路由
    local accept_source_route
    accept_source_route=$(sysctl -n net.ipv4.conf.all.accept_source_route 2>/dev/null || echo "unknown")
    if [ "$accept_source_route" = "0" ]; then
        log_result "KS.3" "内核参数" "源路由" "PASS" "accept_source_route=0"
    else
        log_result "KS.3" "内核参数" "源路由" "WARN" "accept_source_route=$accept_source_route（建议设为 0）"
    fi

    # SYN Cookie
    local syncookies
    syncookies=$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null || echo "unknown")
    if [ "$syncookies" = "1" ]; then
        log_result "KS.4" "内核参数" "SYN Cookie" "PASS" "tcp_syncookies=1"
    else
        log_result "KS.4" "内核参数" "SYN Cookie" "WARN" "tcp_syncookies=$syncookies（建议设为 1）"
    fi

    # 反向路径过滤
    local rp_filter
    rp_filter=$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null || echo "unknown")
    if [ "$rp_filter" = "1" ]; then
        log_result "KS.5" "内核参数" "反向路径过滤" "PASS" "rp_filter=1"
    else
        log_result "KS.5" "内核参数" "反向路径过滤" "WARN" "rp_filter=$rp_filter（建议设为 1）"
    fi

    # ASLR
    local aslr
    aslr=$(sysctl -n kernel.randomize_va_space 2>/dev/null || echo "unknown")
    if [ "$aslr" = "2" ]; then
        log_result "KS.6" "内核参数" "ASLR" "PASS" "randomize_va_space=2"
    else
        log_result "KS.6" "内核参数" "ASLR" "WARN" "randomize_va_space=$aslr（建议设为 2）"
    fi

    # dmesg 限制
    local dmesg_restrict
    dmesg_restrict=$(sysctl -n kernel.dmesg_restrict 2>/dev/null || echo "unknown")
    if [ "$dmesg_restrict" = "1" ]; then
        log_result "KS.7" "内核参数" "dmesg 访问限制" "PASS" "dmesg_restrict=1"
    else
        log_result "KS.7" "内核参数" "dmesg 访问限制" "WARN" "dmesg_restrict=$dmesg_restrict（建议设为 1）"
    fi
}

check_time_sync() {
    echo ""
    echo -e "${BOLD}=== 时间同步 ===${NC}"

    # 检查 NTP/chrony 服务
    local time_sync="none"
    if systemctl is-active chronyd &>/dev/null; then
        time_sync="chronyd"
    elif systemctl is-active ntpd &>/dev/null; then
        time_sync="ntpd"
    elif systemctl is-active systemd-timesyncd &>/dev/null; then
        time_sync="systemd-timesyncd"
    fi

    if [ "$time_sync" != "none" ]; then
        log_result "TS.1" "时间同步" "时间同步服务" "PASS" "时间同步服务运行中: $time_sync"
    else
        log_result "TS.1" "时间同步" "时间同步服务" "FAIL" "未检测到时间同步服务（chronyd/ntpd/systemd-timesyncd）" "systemctl status chronyd"
    fi

    # 检查时区
    local timezone
    timezone=$(timedatectl show --property=Timezone --value 2>/dev/null || date +%Z)
    log_result "TS.2" "时间同步" "时区配置" "PASS" "当前时区: $timezone"
}

# ============================================================
# 主流程
# ============================================================

echo "=========================================="
echo "  等保三级合规检查"
echo "=========================================="
echo "检查时间: $(date '+%Y-%m-%d %H:%M:%S')"
echo "主机名: $(hostname)"
echo "=========================================="

# 执行所有检查
check_identity_auth
check_access_control
check_audit
check_intrusion_prevention
check_malware
check_data_integrity
check_data_confidentiality
check_selinux
check_firewall
check_kernel_security
check_time_sync

# 输出汇总
echo ""
echo "=========================================="
echo -e "  检查完成"
echo "=========================================="
echo -e "总计: $TOTAL  ${GREEN}通过: $PASS${NC}  ${RED}未通过: $FAIL${NC}  ${YELLOW}警告: $WARN${NC}  不适用: $NA"
if [ $((TOTAL - NA)) -gt 0 ]; then
    echo -e "合规率: ${BOLD}$(( PASS * 100 / (TOTAL - NA) ))%${NC}"
fi
echo "=========================================="

# 输出报告
output_results
