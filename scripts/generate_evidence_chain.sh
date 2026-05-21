#!/usr/bin/env bash
# ============================================================================
# generate_evidence_chain.sh
# 从审计日志数据中生成结构化安全事件证据链
# 适用于 openEuler / FusionOS (Linux)
# ============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# 颜色定义
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ---------------------------------------------------------------------------
# 全局变量
# ---------------------------------------------------------------------------
DATA_DIR=""
OUTPUT_DIR=""
OUTPUT_FILE=""
HOSTNAME_TAG="$(hostname 2>/dev/null || echo 'unknown')"

# 临时文件目录
WORK_DIR=""
EVIDENCE_ENTRIES_FILE=""
UNIQUE_USERS_FILE=""
UNIQUE_TYPES_FILE=""

# 统计
TOTAL_EVENTS=0
TIME_RANGE_START=""
TIME_RANGE_END=""

# ---------------------------------------------------------------------------
# 辅助函数
# ---------------------------------------------------------------------------
log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }
log_step()  { echo -e "${CYAN}[STEP]${NC}  ${BOLD}$*${NC}"; }

cleanup() {
    if [[ -n "${WORK_DIR}" && -d "${WORK_DIR}" ]]; then
        rm -rf "${WORK_DIR}"
    fi
}
trap cleanup EXIT

usage() {
    cat <<'USAGE'
用法: generate_evidence_chain.sh -d <数据目录> -o <输出目录> [-h]

从 collect_audit_logs.sh 采集的审计数据中生成结构化安全事件证据链。

选项:
  -d <目录>   数据目录 (collect_audit_logs.sh 的输出目录，必需)
  -o <目录>   输出目录 (存放生成的 Markdown 证据链文件，必需)
  -h          显示此帮助信息

数据目录中应包含以下文件 (至少需要一个):
  audit.log       - auditd 审计日志
  secure.log      - SSH/PAM 认证日志
  messages.log    - 系统消息日志
  timeline.log    - 合并时间线日志

示例:
  ./generate_evidence_chain.sh -d /tmp/audit-collect-20260520 -o /tmp/evidence-out
USAGE
    exit 0
}

# ---------------------------------------------------------------------------
# 参数解析
# ---------------------------------------------------------------------------
parse_args() {
    while getopts "d:o:h" opt; do
        case "${opt}" in
            d) DATA_DIR="${OPTARG}" ;;
            o) OUTPUT_DIR="${OPTARG}" ;;
            h) usage ;;
            *) log_error "未知选项: -${OPTARG}"; usage ;;
        esac
    done

    if [[ -z "${DATA_DIR}" ]]; then
        log_error "缺少必需参数: -d <数据目录>"
        usage
    fi
    if [[ -z "${OUTPUT_DIR}" ]]; then
        log_error "缺少必需参数: -o <输出目录>"
        usage
    fi

    DATA_DIR="$(realpath "${DATA_DIR}" 2>/dev/null || echo "${DATA_DIR}")"

    if [[ ! -d "${DATA_DIR}" ]]; then
        log_error "数据目录不存在: ${DATA_DIR}"
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# 初始化
# ---------------------------------------------------------------------------
init() {
    log_step "初始化..."

    # 创建输出目录
    mkdir -p "${OUTPUT_DIR}"

    # 创建临时工作目录
    WORK_DIR="$(mktemp -d /tmp/evidence-chain.XXXXXX)"
    EVIDENCE_ENTRIES_FILE="${WORK_DIR}/evidence_entries.tsv"
    UNIQUE_USERS_FILE="${WORK_DIR}/unique_users.txt"
    UNIQUE_TYPES_FILE="${WORK_DIR}/unique_types.txt"
    touch "${EVIDENCE_ENTRIES_FILE}"

    # 确定输出文件名
    local timestamp
    timestamp="$(date +%Y%m%d_%H%M%S)"
    OUTPUT_FILE="${OUTPUT_DIR}/evidence_chain_${timestamp}.md"

    log_info "数据目录: ${DATA_DIR}"
    log_info "输出文件: ${OUTPUT_FILE}"
    log_info "工作目录: ${WORK_DIR}"
}

# ---------------------------------------------------------------------------
# 检查可用的日志源
# ---------------------------------------------------------------------------
detect_sources() {
    log_step "检测可用的日志源..."

    local sources=()
    local missing=()

    for logfile in audit.log secure.log messages.log timeline.log; do
        local path="${DATA_DIR}/${logfile}"
        if [[ -f "${path}" && -s "${path}" ]]; then
            local size
            size="$(wc -l < "${path}" 2>/dev/null || echo 0)"
            sources+=("${logfile} (${size} 行)")
            log_info "  发现: ${logfile} (${size} 行)"
        else
            missing+=("${logfile}")
        fi
    done

    if [[ ${#sources[@]} -eq 0 ]]; then
        log_error "数据目录中未找到任何可用的日志文件"
        exit 1
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_warn "  缺少: ${missing[*]}"
    fi
}

# ---------------------------------------------------------------------------
# 从 audit.log 提取事件
# ---------------------------------------------------------------------------
extract_audit_events() {
    local audit_log="${DATA_DIR}/audit.log"
    [[ -f "${audit_log}" && -s "${audit_log}" ]] || return 0

    log_step "解析 audit.log..."

    local count=0

    # 使用 ausearch 解析 (如果可用)，否则用 awk 解析
    if command -v ausearch &>/dev/null; then
        # 尝试使用 ausearch 解析
        extract_audit_via_ausearch "${audit_log}"
        count=$?
    fi

    # 无论 ausearch 是否成功，都用 awk 做补充解析
    extract_audit_via_awk "${audit_log}" && count=$((count + 1))

    log_info "  从 audit.log 提取了事件"
}

extract_audit_via_ausearch() {
    local audit_log="$1"
    local tmpfile="${WORK_DIR}/ausearch_out.tmp"

    # ausearch 解析多种事件类型
    local event_types=("USER_AUTH" "USER_LOGIN" "USER_LOGOUT" "USER_ACCT"
                       "EXECVE" "SYSCALL" "PATH" "OPEN"
                       "SOCKADDR" "NETFILTER_CFG"
                       "CONFIG_CHANGE" "ANOM_ABEND" "ANOM_LOGIN_FAILURES"
                       "ADD_USER" "DEL_USER" "ADD_GROUP" "DEL_GROUP"
                       "USER_CHAUTHTOK" "ROLE_ASSIGN" "ROLE_REMOVE")

    for etype in "${event_types[@]}"; do
        if ausearch -if "${audit_log}" -ts recent -m "${etype}" 2>/dev/null > "${tmpfile}"; then
            while IFS= read -r line; do
                parse_audit_line "${line}" "${etype}"
            done < "${tmpfile}"
        fi
    done

    return 0
}

extract_audit_via_awk() {
    local audit_log="$1"

    # 直接用 awk 解析 audit.log 格式:
    # type=XXX msg=audit(EPOCH.SERIAL:NUM): ...
    awk '
    /^type=/ {
        # 提取 type
        etype = ""
        for (i = 1; i <= NF; i++) {
            if ($i ~ /^type=/) {
                split($i, a, "=")
                etype = a[2]
                break
            }
        }

        # 提取 msg=audit(EPOCH.SERIAL:NUM)
        ts_raw = ""
        audit_id = ""
        match($0, /msg=audit\(([0-9]+)\.([0-9]+):([0-9]+)\)/, m)
        if (RSTART > 0) {
            ts_raw = m[1]
            audit_id = m[1] "." m[2] ":" m[3]
        }

        # 提取关键字段
        uid_val = ""; auid_val = ""; pid_val = ""; exe_val = ""
        comm_val = ""; key_val = ""; acct_val = ""; terminal_val = ""
        success_val = ""; res_val = ""

        for (i = 1; i <= NF; i++) {
            if ($i ~ /^uid=/)        { split($i, a, "="); uid_val = a[2] }
            if ($i ~ /^auid=/)       { split($i, a, "="); auid_val = a[2] }
            if ($i ~ /^pid=/)        { split($i, a, "="); pid_val = a[2] }
            if ($i ~ /^exe=/)        { split($i, a, "="); exe_val = a[2] }
            if ($i ~ /^comm=/)       { split($i, a, "="); comm_val = a[2] }
            if ($i ~ /^key=/)        { split($i, a, "="); key_val = a[2] }
            if ($i ~ /^acct=/)       { split($i, a, "="); acct_val = a[2] }
            if ($i ~ /^terminal=/)   { split($i, a, "="); terminal_val = a[2] }
            if ($i ~ /^success=/)    { split($i, a, "="); success_val = a[2] }
            if ($i ~ /^res=/)        { split($i, a, "="); res_val = a[2] }
        }

        # 过滤：只保留有意义的事件类型
        meaningful = 0
        if (etype == "USER_AUTH" || etype == "USER_LOGIN" || etype == "USER_LOGOUT" ||
            etype == "USER_ACCT" || etype == "USER_CHAUTHTOK" ||
            etype == "EXECVE" || etype == "SYSCALL" ||
            etype == "SOCKADDR" || etype == "NETFILTER_CFG" ||
            etype == "CONFIG_CHANGE" || etype == "ADD_USER" || etype == "DEL_USER" ||
            etype == "ADD_GROUP" || etype == "DEL_GROUP" ||
            etype == "ANOM_ABEND" || etype == "ANOM_LOGIN_FAILURES" ||
            etype == "ROLE_ASSIGN" || etype == "ROLE_REMOVE" ||
            etype == "PATH" || etype == "OPEN")
            meaningful = 1

        if (meaningful && ts_raw != "") {
            # 转换 epoch 时间
            cmd = "date -d @" ts_raw " +\"%Y-%m-%d %H:%M:%S\" 2>/dev/null"
            cmd | getline ts_human
            close(cmd)

            # 确定事件类别
            category = "OTHER"
            if (etype ~ /USER_AUTH|USER_LOGIN|USER_LOGOUT|USER_ACCT|USER_CHAUTHTOK|ROLE_ASSIGN|ROLE_REMOVE/)
                category = "AUTH"
            else if (etype ~ /EXECVE|SYSCALL/)
                category = "EXEC"
            else if (etype ~ /PATH|OPEN/)
                category = "FILE"
            else if (etype ~ /SOCKADDR|NETFILTER_CFG/)
                category = "NET"
            else if (etype ~ /CONFIG_CHANGE|ADD_USER|DEL_USER|ADD_GROUP|DEL_GROUP/)
                category = "CONFIG"
            else if (etype ~ /ANOM/)
                category = "ANOMALY"

            # 构造用户信息
            user_info = "unknown"
            if (acct_val != "") user_info = acct_val
            else if (auid_val != "" && auid_val != "4294967295") user_info = "auid=" auid_val
            if (uid_val != "" && uid_val != "4294967295") user_info = user_info " (uid=" uid_val ")"

            # 构造详情
            detail = etype
            if (comm_val != "") detail = detail " comm=" comm_val
            if (exe_val != "")  detail = detail " exe=" exe_val
            if (key_val != "")  detail = detail " key=" key_val
            if (success_val != "") detail = detail " success=" success_val
            if (res_val != "")  detail = detail " res=" res_val

            # TSV 输出: timestamp \t category \t user_info \t source \t audit_id \t detail \t raw_line
            print ts_human "\t" category "\t" user_info "\t" "audit.log\t" audit_id "\t" detail "\t" $0
        }
    }
    ' "${audit_log}" >> "${EVIDENCE_ENTRIES_FILE}"
}

parse_audit_line() {
    # 由 ausearch 路径使用的简单解析
    local line="$1"
    local etype="$2"

    local ts_raw audit_id uid_val auid_val acct_val detail category user_info ts_human

    if [[ "${line}" =~ msg=audit\(([0-9]+)\.([0-9]+):([0-9]+)\) ]]; then
        ts_raw="${BASH_REMATCH[1]}"
        audit_id="${ts_raw}.${BASH_REMATCH[2]}:${BASH_REMATCH[3]}"
        ts_human="$(date -d "@${ts_raw}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "${ts_raw}")"
    else
        return 0
    fi

    # 提取字段
    uid_val="$(echo "${line}" | grep -oP 'uid=\K[0-9]+' | head -1 || true)"
    auid_val="$(echo "${line}" | grep -oP 'auid=\K[0-9]+' | head -1 || true)"
    acct_val="$(echo "${line}" | grep -oP 'acct=\K"[^"]*"|acct=\K[^ ]+' | head -1 | tr -d '"' || true)"

    # 分类
    case "${etype}" in
        USER_AUTH|USER_LOGIN|USER_LOGOUT|USER_ACCT|USER_CHAUTHTOK|ROLE_ASSIGN|ROLE_REMOVE) category="AUTH" ;;
        EXECVE|SYSCALL)    category="EXEC" ;;
        PATH|OPEN)         category="FILE" ;;
        SOCKADDR|NETFILTER_CFG) category="NET" ;;
        CONFIG_CHANGE|ADD_USER|DEL_USER|ADD_GROUP|DEL_GROUP) category="CONFIG" ;;
        *)                 category="OTHER" ;;
    esac

    user_info="${acct_val:-unknown}"
    [[ -n "${auid_val}" && "${auid_val}" != "4294967295" ]] && user_info="${user_info} (auid=${auid_val})"
    [[ -n "${uid_val}" && "${uid_val}" != "4294967295" ]] && user_info="${user_info} (uid=${uid_val})"

    detail="${etype}"

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "${ts_human}" "${category}" "${user_info}" "audit.log" "${audit_id}" "${detail}" "${line}" \
        >> "${EVIDENCE_ENTRIES_FILE}"
}

# ---------------------------------------------------------------------------
# 从 secure.log 提取事件
# ---------------------------------------------------------------------------
extract_secure_events() {
    local secure_log="${DATA_DIR}/secure.log"
    [[ -f "${secure_log}" && -s "${secure_log}" ]] || return 0

    log_step "解析 secure.log..."

    # secure.log 格式:
    # Mon DD HH:MM:SS hostname sshd[PID]: ...
    # Mon DD HH:MM:SS hostname su[PID]: ...
    # Mon DD HH:MM:SS hostname sudo[PID]: ...
    # Mon DD HH:MM:SS hostname login[PID]: ...
    # Mon DD HH:MM:SS hostname polkitd[PID]: ...

    local current_year
    current_year="$(date +%Y)"

    awk -v year="${current_year}" '
    BEGIN {
        # 安全日志相关关键字及类别
    }
    {
        # 解析时间戳: Mon DD HH:MM:SS
        ts_raw = $1 " " $2 " " $3
        hostname_val = $4
        service_raw = $5

        # 提取进程名
        proc_name = ""
        match(service_raw, /^([^\[]+)\[/, pm)
        if (RSTART > 0) proc_name = pm[1]

        # 提取 PID
        pid_val = ""
        match(service_raw, /\[([0-9]+)\]/, pm)
        if (RSTART > 0) pid_val = pm[1]

        # 将时间标准化
        cmd = "date -d \"" year " " ts_raw "\" +\"%Y-%m-%d %H:%M:%S\" 2>/dev/null"
        cmd | getline ts_human
        close(cmd)
        if (ts_human == "") next

        # 提取冒号后的消息部分
        msg = ""
        idx = index($0, ": ")
        if (idx > 0) msg = substr($0, idx + 2)

        # 判断事件类型
        category = ""
        user_info = ""
        detail = ""
        etype = ""

        if (proc_name == "sshd") {
            if (msg ~ /Accepted password for/ || msg ~ /Accepted publickey for/) {
                category = "AUTH"
                etype = "SSH_LOGIN_SUCCESS"
                match(msg, /for (\S+)/, um)
                user_info = um[1]
                detail = msg
            } else if (msg ~ /Failed password for/ || msg ~ /Failed publickey for/) {
                category = "AUTH"
                etype = "SSH_LOGIN_FAILURE"
                match(msg, /for (\S+)/, um)
                user_info = um[1]
                detail = msg
            } else if (msg ~ /Invalid user/) {
                category = "AUTH"
                etype = "SSH_INVALID_USER"
                match(msg, /Invalid user (\S+)/, um)
                user_info = um[1]
                detail = msg
            } else if (msg ~ /session opened/) {
                category = "AUTH"
                etype = "SSH_SESSION_OPEN"
                match(msg, /for user (\S+)/, um)
                user_info = um[1]
                detail = msg
            } else if (msg ~ /session closed/) {
                category = "AUTH"
                etype = "SSH_SESSION_CLOSE"
                match(msg, /for user (\S+)/, um)
                user_info = um[1]
                detail = msg
            } else if (msg ~ /Received disconnect/) {
                category = "AUTH"
                etype = "SSH_DISCONNECT"
                detail = msg
            } else if (msg ~ /POSSIBLE BREAK-IN ATTEMPT/) {
                category = "ANOMALY"
                etype = "SSH_BREAKIN_ATTEMPT"
                detail = msg
            } else {
                next
            }
        } else if (proc_name == "su" || proc_name == "su:") {
            if (msg ~ /FAILED su/ || msg ~ /authentication failure/) {
                category = "AUTH"
                etype = "SU_FAILURE"
                detail = msg
            } else if (msg ~ /Successful su/) {
                category = "AUTH"
                etype = "SU_SUCCESS"
                detail = msg
            } else {
                next
            }
        } else if (proc_name == "sudo") {
            category = "AUTH"
            etype = "SUDO"
            match(msg, /USER=([^\s;]+)/, um)
            user_info = um[1]
            if (msg ~ /authentication failure/) {
                etype = "SUDO_FAILURE"
            } else if (msg ~ /NOT in sudoers/) {
                etype = "SUDO_NOT_ALLOWED"
            }
            detail = msg
        } else if (proc_name == "login" || proc_name == "login:") {
            category = "AUTH"
            etype = "LOGIN"
            match(msg, /LOGIN ON ([^\s]+) BY ([^\s]+)/, lm)
            user_info = lm[2]
            detail = msg
        } else if (proc_name == "polkitd") {
            if (msg ~ /Authentication failure/) {
                category = "AUTH"
                etype = "POLKIT_FAILURE"
                detail = msg
            } else {
                next
            }
        } else if (proc_name == "passwd") {
            category = "AUTH"
            etype = "PASSWD_CHANGE"
            detail = msg
        } else if (proc_name == "useradd" || proc_name == "userdel" || proc_name == "usermod") {
            category = "CONFIG"
            etype = toupper(proc_name)
            detail = msg
        } else if (proc_name == "groupadd" || proc_name == "groupdel" || proc_name == "groupmod") {
            category = "CONFIG"
            etype = toupper(proc_name)
            detail = msg
        } else {
            next
        }

        if (user_info == "") user_info = "unknown"

        # TSV 输出
        print ts_human "\t" category "\t" user_info "\t" "secure.log\t-\t" etype ": " detail "\t" $0
    }
    ' "${secure_log}" >> "${EVIDENCE_ENTRIES_FILE}"

    log_info "  secure.log 解析完成"
}

# ---------------------------------------------------------------------------
# 从 messages.log 提取事件
# ---------------------------------------------------------------------------
extract_messages_events() {
    local messages_log="${DATA_DIR}/messages.log"
    [[ -f "${messages_log}" && -s "${messages_log}" ]] || return 0

    log_step "解析 messages.log..."

    local current_year
    current_year="$(date +%Y)"

    awk -v year="${current_year}" '
    {
        ts_raw = $1 " " $2 " " $3
        hostname_val = $4
        service_raw = $5

        proc_name = ""
        match(service_raw, /^([^\[]+)\[/, pm)
        if (RSTART > 0) proc_name = pm[1]
        if (proc_name == "") proc_name = service_raw

        cmd = "date -d \"" year " " ts_raw "\" +\"%Y-%m-%d %H:%M:%S\" 2>/dev/null"
        cmd | getline ts_human
        close(cmd)
        if (ts_human == "") next

        idx = index($0, ": ")
        msg = ""
        if (idx > 0) msg = substr($0, idx + 2)

        category = ""
        etype = ""

        # 内核安全事件
        if (proc_name == "kernel") {
            if (msg ~ /segfault/ || msg ~ /Oops/ || msg ~ /BUG/) {
                category = "ANOMALY"
                etype = "KERNEL_FAULT"
            } else if (msg ~ /audit/ || msg ~ /SELinux/ || msg ~ /AppArmor/) {
                category = "CONFIG"
                etype = "KERNEL_SECURITY"
            } else if (msg ~ /nf_conntrack/ || msg ~ /iptables/ || msg ~ /nftables/) {
                category = "NET"
                etype = "NETFILTER"
            } else {
                next
            }
        }
        # OOM killer
        else if (msg ~ /Out of memory/ || msg ~ /oom-kill/ || msg ~ /OOM/) {
            category = "ANOMALY"
            etype = "OOM_KILL"
        }
        # systemd 相关
        else if (proc_name == "systemd") {
            if (msg ~ /Failed to start/ || msg ~ /failed/) {
                category = "ANOMALY"
                etype = "SERVICE_FAILURE"
            } else if (msg ~ /Started/ || msg ~ /Stopped/) {
                category = "CONFIG"
                etype = "SERVICE_CHANGE"
            } else {
                next
            }
        }
        # 内存/硬件错误
        else if (msg ~ /MCE/ || msg ~ /hardware error/ || msg ~ /EDAC/) {
            category = "ANOMALY"
            etype = "HW_ERROR"
        }
        # 磁盘错误
        else if (msg ~ /I\/O error/ || msg ~ /EXT4-fs error/ || msg ~ /xfs_error/ || msg ~ /disk error/) {
            category = "ANOMALY"
            etype = "DISK_ERROR"
        }
        # 网络相关
        else if (proc_name == "NetworkManager" || proc_name == "firewalld") {
            category = "NET"
            etype = toupper(proc_name)
            if (msg ~ /reject|drop|block/) etype = etype "_BLOCK"
        }
        # crond 任务变更
        else if (proc_name == "crond" || proc_name == "cron") {
            if (msg ~ /CMD/ || msg ~ /RELOAD/) {
                category = "CONFIG"
                etype = "CRON_CHANGE"
            } else {
                next
            }
        }
        # PAM 相关
        else if (msg ~ /pam_/) {
            if (msg ~ /authentication failure/ || msg ~ /could not open/ || msg ~ /denied/) {
                category = "AUTH"
                etype = "PAM_FAILURE"
            } else {
                next
            }
        }
        else {
            next
        }

        detail = proc_name ": " msg

        print ts_human "\t" category "\t" "system\t" "messages.log\t-\t" etype ": " detail "\t" $0
    }
    ' "${messages_log}" >> "${EVIDENCE_ENTRIES_FILE}"

    log_info "  messages.log 解析完成"
}

# ---------------------------------------------------------------------------
# 从 timeline.log 提取事件 (如果存在且不同于其他日志)
# ---------------------------------------------------------------------------
extract_timeline_events() {
    local timeline_log="${DATA_DIR}/timeline.log"
    [[ -f "${timeline_log}" && -s "${timeline_log}" ]] || return 0

    # 如果 timeline.log 和 audit.log 内容完全一样，跳过
    local audit_log="${DATA_DIR}/audit.log"
    if [[ -f "${audit_log}" ]]; then
        local tl_hash al_hash
        tl_hash="$(md5sum "${timeline_log}" 2>/dev/null | awk '{print $1}')"
        al_hash="$(md5sum "${audit_log}" 2>/dev/null | awk '{print $1}')"
        if [[ "${tl_hash}" == "${al_hash}" ]]; then
            log_info "  timeline.log 与 audit.log 相同，跳过"
            return 0
        fi
    fi

    log_step "解析 timeline.log..."

    local current_year
    current_year="$(date +%Y)"

    # timeline.log 可能是已经格式化的日志，尝试通用解析
    awk -v year="${current_year}" '
    {
        # 尝试解析标准 syslog 格式
        ts_raw = $1 " " $2 " " $3
        cmd = "date -d \"" year " " ts_raw "\" +\"%Y-%m-%d %H:%M:%S\" 2>/dev/null"
        cmd | getline ts_human
        close(cmd)
        if (ts_human == "") next

        # 尝试提取进程信息
        hostname_val = $4
        service_raw = $5
        proc_name = ""
        match(service_raw, /^([^\[]+)\[/, pm)
        if (RSTART > 0) proc_name = pm[1]

        idx = index($0, ": ")
        msg = ""
        if (idx > 0) msg = substr($0, idx + 2)

        # 宽泛匹配安全相关事件
        category = "OTHER"
        etype = "TIMELINE_EVENT"

        if ($0 ~ /auth|login|sudo|su |pam_|sshd|password/)
            category = "AUTH"
        else if ($0 ~ /exec|syscall|fork|clone/)
            category = "EXEC"
        else if ($0 ~ /open|read|write|chmod|chown|unlink|rename/)
            category = "FILE"
        else if ($0 ~ /connect|bind|accept|listen|socket|iptables|firewall/)
            category = "NET"
        else if ($0 ~ /config|create.*user|delete.*user|passwd|group/)
            category = "CONFIG"
        else
            next

        detail = proc_name ": " msg
        print ts_human "\t" category "\t" "unknown\t" "timeline.log\t-\t" etype ": " detail "\t" $0
    }
    ' "${timeline_log}" >> "${EVIDENCE_ENTRIES_FILE}"

    log_info "  timeline.log 解析完成"
}

# ---------------------------------------------------------------------------
# 排序、去重、关联事件
# ---------------------------------------------------------------------------
sort_and_correlate() {
    log_step "排序与关联事件..."

    local sorted_file="${WORK_DIR}/sorted_entries.tsv"

    # 按时间排序 (第1列)
    sort -t$'\t' -k1,1 "${EVIDENCE_ENTRIES_FILE}" > "${sorted_file}" 2>/dev/null || \
        cp "${EVIDENCE_ENTRIES_FILE}" "${sorted_file}"

    # 去重 (基于时间+类型+详情的前80字符)
    awk -F'\t' '!seen[$1 substr($6, 1, 80)]++' "${sorted_file}" > "${EVIDENCE_ENTRIES_FILE}"

    # 提取统计信息
    TOTAL_EVENTS="$(wc -l < "${EVIDENCE_ENTRIES_FILE}" | tr -d ' ')"

    if [[ "${TOTAL_EVENTS}" -gt 0 ]]; then
        TIME_RANGE_START="$(head -1 "${EVIDENCE_ENTRIES_FILE}" | cut -f1)"
        TIME_RANGE_END="$(tail -1 "${EVIDENCE_ENTRIES_FILE}" | cut -f1)"
    fi

    # 提取去重用户和类型列表
    cut -f3 "${EVIDENCE_ENTRIES_FILE}" | sort -u > "${UNIQUE_USERS_FILE}" 2>/dev/null || true
    cut -f2 "${EVIDENCE_ENTRIES_FILE}" | sort -u > "${UNIQUE_TYPES_FILE}" 2>/dev/null || true

    log_info "  总事件数: ${TOTAL_EVENTS}"
    if [[ "${TOTAL_EVENTS}" -gt 0 ]]; then
        log_info "  时间范围: ${TIME_RANGE_START} ~ ${TIME_RANGE_END}"
    fi
}

# ---------------------------------------------------------------------------
# 关联事件分析
# ---------------------------------------------------------------------------
find_related_events() {
    local ts="$1"
    local user="$2"
    local idx="$3"
    local total="$4"

    local related=()
    local window_seconds=300  # 前后5分钟

    # 将当前事件时间转为 epoch
    local ts_epoch
    ts_epoch="$(date -d "${ts}" '+%s' 2>/dev/null || echo 0)"
    [[ "${ts_epoch}" -eq 0 ]] && { echo ""; return; }

    local lower=$((ts_epoch - window_seconds))
    local upper=$((ts_epoch + window_seconds))

    # 在排序后的文件中查找时间窗口内的其他事件
    while IFS=$'\t' read -r ets ecategory euser esource eaudit_id edetail eraw; do
        local e_epoch
        e_epoch="$(date -d "${ets}" '+%s' 2>/dev/null || echo 0)"
        [[ "${e_epoch}" -eq 0 ]] && continue

        if [[ "${e_epoch}" -ge "${lower}" && "${e_epoch}" -le "${upper}" ]]; then
            # 排除自身
            local ets_idx="${ets}:${edetail:0:40}"
            if [[ "${ets_idx}" != "${ts}:${3}" ]]; then
                related+=("${ets} [${ecategory}] ${edetail:0:60}")
            fi
        fi
    done < "${EVIDENCE_ENTRIES_FILE}"

    # 最多返回5个关联事件
    local result=""
    local count=0
    for r in "${related[@]+"${related[@]}"}"; do
        [[ -z "${r}" ]] && continue
        if [[ -z "${result}" ]]; then
            result="${r}"
        else
            result="${result}<br>${r}"
        fi
        count=$((count + 1))
        [[ ${count} -ge 5 ]] && break
    done

    echo "${result}"
}

# ---------------------------------------------------------------------------
# 风险评估
# ---------------------------------------------------------------------------
assess_risk() {
    local risk_score=0
    local findings=()

    # 统计各类事件数量
    local auth_failures=0
    local auth_success=0
    local anom_count=0
    local config_count=0
    local net_count=0
    local exec_count=0

    while IFS=$'\t' read -r ts category user source audit_id detail raw; do
        case "${category}" in
            AUTH)
                if [[ "${detail}" =~ FAILURE|FAILED|failure|failed|denied|Invalid ]]; then
                    auth_failures=$((auth_failures + 1))
                else
                    auth_success=$((auth_success + 1))
                fi
                ;;
            ANOMALY) anom_count=$((anom_count + 1)) ;;
            CONFIG) config_count=$((config_count + 1)) ;;
            NET) net_count=$((net_count + 1)) ;;
            EXEC) exec_count=$((exec_count + 1)) ;;
        esac
    done < "${EVIDENCE_ENTRIES_FILE}"

    # 风险评分规则
    if [[ ${auth_failures} -gt 10 ]]; then
        risk_score=$((risk_score + 30))
        findings+=("检测到 ${auth_failures} 次认证失败，可能存在暴力破解攻击")
    elif [[ ${auth_failures} -gt 5 ]]; then
        risk_score=$((risk_score + 15))
        findings+=("检测到 ${auth_failures} 次认证失败")
    fi

    if [[ ${anom_count} -gt 0 ]]; then
        risk_score=$((risk_score + 25))
        findings+=("检测到 ${anom_count} 个异常事件 (内核错误/OOM/硬件故障等)")
    fi

    if [[ ${config_count} -gt 3 ]]; then
        risk_score=$((risk_score + 20))
        findings+=("检测到 ${config_count} 个配置变更事件，需确认是否为授权操作")
    fi

    if [[ ${net_count} -gt 5 ]]; then
        risk_score=$((risk_score + 10))
        findings+=("检测到 ${net_count} 个网络相关事件")
    fi

    if [[ ${exec_count} -gt 0 ]]; then
        risk_score=$((risk_score + 5))
    fi

    # SSH 暴力破解特征: 短时间内大量失败
    local ssh_fail_pattern_count
    ssh_fail_pattern_count="$(grep -cE 'SSH_LOGIN_FAILURE|SSH_INVALID_USER|FAILED su|SUDO_FAILURE' "${EVIDENCE_ENTRIES_FILE}" 2>/dev/null || echo 0)"
    if [[ ${ssh_fail_pattern_count} -gt 20 ]]; then
        risk_score=$((risk_score + 20))
        findings+=("检测到大量 SSH/认证失败 (${ssh_fail_pattern_count} 次)，高度疑似暴力破解")
    fi

    # 检查非工作时间活动 (22:00-06:00)
    local off_hours_count
    off_hours_count="$(awk -F'\t' '{
        split($1, t, " ")
        if (length(t) >= 2) {
            split(t[2], hm, ":")
            h = hm[1] + 0
            if (h >= 22 || h < 6) print
        }
    }' "${EVIDENCE_ENTRIES_FILE}" | wc -l | tr -d ' ')"

    if [[ ${off_hours_count} -gt 0 ]]; then
        risk_score=$((risk_score + 10))
        findings+=("检测到 ${off_hours_count} 个非工作时间 (22:00-06:00) 的事件")
    fi

    # 上限 100
    [[ ${risk_score} -gt 100 ]] && risk_score=100

    # 风险等级
    local risk_level
    if [[ ${risk_score} -ge 70 ]]; then
        risk_level="高 (HIGH)"
    elif [[ ${risk_score} -ge 40 ]]; then
        risk_level="中 (MEDIUM)"
    elif [[ ${risk_score} -ge 15 ]]; then
        risk_level="低 (LOW)"
    else
        risk_level="信息 (INFO)"
    fi

    # 输出
    echo "${risk_score}|${risk_level}"
    for f in "${findings[@]+"${findings[@]}"}"; do
        [[ -n "${f}" ]] && echo "FINDING:${f}"
    done
    echo "STATS:auth_failures=${auth_failures} auth_success=${auth_success} anomalies=${anom_count} config=${config_count} net=${net_count} exec=${exec_count}"
}

# ---------------------------------------------------------------------------
# 生成 Markdown 输出
# ---------------------------------------------------------------------------
generate_markdown() {
    log_step "生成 Markdown 证据链..."

    local analysis_time
    analysis_time="$(date '+%Y-%m-%d %H:%M:%S %Z')"

    # 获取风险评估结果
    local risk_output
    risk_output="$(assess_risk)"
    local risk_line
    risk_line="$(echo "${risk_output}" | head -1)"
    local risk_score="${risk_line%%|*}"
    local risk_level="${risk_line#*|}"
    local findings
    findings="$(echo "${risk_output}" | grep '^FINDING:' | sed 's/^FINDING://')"
    local stats_line
    stats_line="$(echo "${risk_output}" | grep '^STATS:' | sed 's/^STATS://')"

    # --- 开始写入 Markdown ---
    {
        cat <<EOF
# 安全事件证据链

> 主机: ${HOSTNAME_TAG}
> 生成工具: generate_evidence_chain.sh

## 概要

| 项目 | 值 |
|------|-----|
| **分析时间** | ${analysis_time} |
| **数据来源** | ${DATA_DIR} |
| **时间范围** | ${TIME_RANGE_START:-N/A} ~ ${TIME_RANGE_END:-N/A} |
| **事件总数** | ${TOTAL_EVENTS} |
| **风险评分** | ${risk_score}/100 |
| **风险等级** | ${risk_level} |

EOF

        # 事件类型分布
        echo "### 事件类型分布"
        echo ""
        echo "| 类型 | 数量 |"
        echo "|------|------|"
        while IFS= read -r t; do
            [[ -z "${t}" ]] && continue
            local cnt
            cnt="$(grep -c $'\t'"${t}"$'\t' "${EVIDENCE_ENTRIES_FILE}" 2>/dev/null || echo 0)"
            echo "| ${t} | ${cnt} |"
        done < "${UNIQUE_TYPES_FILE}"
        echo ""

        # 用户分布
        echo "### 涉及用户"
        echo ""
        local user_list=""
        while IFS= read -r u; do
            [[ -z "${u}" ]] && continue
            [[ -z "${user_list}" ]] && user_list="${u}" || user_list="${user_list}, ${u}"
        done < "${UNIQUE_USERS_FILE}"
        echo "${user_list:-N/A}"
        echo ""

        # --- 证据链主体 ---
        echo "## 证据链"
        echo ""

        local event_num=0
        while IFS=$'\t' read -r ts category user source audit_id detail raw; do
            event_num=$((event_num + 1))

            # 截断过长的详情
            local short_detail="${detail:0:120}"
            [[ ${#detail} -gt 120 ]] && short_detail="${short_detail}..."

            # 类别中文标签
            local category_label
            case "${category}" in
                AUTH)     category_label="AUTH - 认证鉴权" ;;
                EXEC)     category_label="EXEC - 进程执行" ;;
                FILE)     category_label="FILE - 文件操作" ;;
                NET)      category_label="NET - 网络活动" ;;
                CONFIG)   category_label="CONFIG - 配置变更" ;;
                ANOMALY)  category_label="ANOMALY - 异常事件" ;;
                *)        category_label="${category}" ;;
            esac

            echo "### 事件 ${event_num}: ${short_detail}"
            echo ""
            echo "- **时间**: ${ts}"
            echo "- **类型**: ${category_label}"
            echo "- **用户**: ${user}"
            echo "- **证据来源**: ${source}"
            echo "- **audit ID**: ${audit_id}"
            echo "- **详情**: \`${detail}\`"

            # 关联事件 (仅对前50个事件做关联，避免性能问题)
            if [[ ${TOTAL_EVENTS} -le 200 || ${event_num} -le 50 ]]; then
                local related
                related="$(find_related_events "${ts}" "${user}" "${event_num}" "${TOTAL_EVENTS}" 2>/dev/null || true)"
                if [[ -n "${related}" ]]; then
                    echo "- **关联事件**:"
                    echo "${related}" | while IFS= read -r rline; do
                        [[ -n "${rline}" ]] && echo "  - ${rline}"
                    done
                fi
            fi

            echo ""
        done < "${EVIDENCE_ENTRIES_FILE}"

        # --- 时间线摘要 ---
        echo "## 时间线摘要"
        echo ""
        echo "| 序号 | 时间 | 类型 | 用户 | 概要 |"
        echo "|------|------|------|------|------|"
        local idx=0
        while IFS=$'\t' read -r ts category user source audit_id detail raw; do
            idx=$((idx + 1))
            local short="${detail:0:80}"
            [[ ${#detail} -gt 80 ]] && short="${short}..."
            echo "| ${idx} | ${ts} | ${category} | ${user} | ${short} |"
        done < "${EVIDENCE_ENTRIES_FILE}"
        echo ""

        # --- 风险评估 ---
        echo "## 风险评估"
        echo ""
        echo "- **评分**: ${risk_score}/100"
        echo "- **等级**: ${risk_level}"
        echo ""

        if [[ -n "${findings}" ]]; then
            echo "### 发现"
            echo ""
            while IFS= read -r finding; do
                [[ -n "${finding}" ]] && echo "- ${finding}"
            done <<< "${findings}"
            echo ""
        fi

        # 统计摘要
        echo "### 统计数据"
        echo ""
        echo "\`\`\`"
        echo "${stats_line}" | tr ' ' '\n'
        echo "\`\`\`"
        echo ""

        # 建议
        echo "### 建议"
        echo ""
        if [[ "${risk_score}" -ge 70 ]]; then
            echo "- **[紧急]** 立即排查所有认证失败事件来源 IP"
            echo "- **[紧急]** 检查是否有未授权的配置变更"
            echo "- **[紧急]** 审查异常事件是否涉及系统完整性"
            echo "- 考虑临时封禁可疑 IP 地址"
            echo "- 检查相关用户的操作记录"
        elif [[ "${risk_score}" -ge 40 ]]; then
            echo "- 详细审查认证失败事件"
            echo "- 确认配置变更是否经过授权"
            echo "- 检查非工作时间活动的合理性"
            echo "- 加强相关账户的安全策略"
        elif [[ "${risk_score}" -ge 15 ]]; then
            echo "- 继续监控相关事件"
            echo "- 定期审查安全日志"
        else
            echo "- 当前未发现明显安全风险"
            echo "- 建议保持常规安全监控"
        fi
        echo ""

        # 文件尾部
        echo "---"
        echo ""
        echo "*本证据链由 generate_evidence_chain.sh 自动生成，仅供安全事件调查参考。*"

    } > "${OUTPUT_FILE}"

    log_info "Markdown 证据链已写入: ${OUTPUT_FILE}"
}

# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
main() {
    echo ""
    echo -e "${BOLD}========================================${NC}"
    echo -e "${BOLD}  安全事件证据链生成工具${NC}"
    echo -e "${BOLD}  generate_evidence_chain.sh${NC}"
    echo -e "${BOLD}========================================${NC}"
    echo ""

    parse_args "$@"
    init
    detect_sources

    echo ""
    log_step "开始提取事件..."
    extract_audit_events
    extract_secure_events
    extract_messages_events
    extract_timeline_events

    sort_and_correlate

    if [[ "${TOTAL_EVENTS}" -eq 0 ]]; then
        log_warn "未从日志数据中提取到任何安全相关事件"
        log_info "请确认数据目录中包含有效的日志文件"

        # 生成一个简短的空报告
        OUTPUT_FILE="${OUTPUT_DIR}/evidence_chain_$(date +%Y%m%d_%H%M%S).md"
        cat > "${OUTPUT_FILE}" <<EOF
# 安全事件证据链

## 概要

- **分析时间**: $(date '+%Y-%m-%d %H:%M:%S %Z')
- **数据来源**: ${DATA_DIR}
- **事件总数**: 0
- **风险等级**: 信息 (INFO)

## 说明

未从日志数据中提取到安全相关事件。请确认:
1. 数据目录路径正确
2. 目录中包含有效的日志文件 (audit.log, secure.log, messages.log)
3. 日志文件内容不为空

---
*本证据链由 generate_evidence_chain.sh 自动生成。*
EOF
        log_info "空报告已写入: ${OUTPUT_FILE}"
        exit 0
    fi

    generate_markdown

    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  证据链生成完成${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo -e "  事件总数: ${BOLD}${TOTAL_EVENTS}${NC}"
    echo -e "  时间范围: ${TIME_RANGE_START} ~ ${TIME_RANGE_END}"
    echo -e "  输出文件: ${BOLD}${OUTPUT_FILE}${NC}"
    echo ""
}

main "$@"
