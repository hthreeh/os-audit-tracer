# os-audit-tracer

openEuler / FusionOS 操作审计与异常行为追溯 Skill。

覆盖审计规则部署、多源日志分析、异常行为检测、安全事件追溯、证据链构建与合规报告生成。

## 核心能力

| 能力 | 说明 |
|------|------|
| 审计规则部署 | 一键部署符合等保三级/四级标准的 auditd 规则集，自动适配 x86_64 / aarch64 / loongarch64 |
| 异常行为检测 | 认证异常、提权行为、文件完整性、网络异常、进程异常、配置篡改 六大检测维度 |
| 安全事件追溯 | 基于 ausearch 的认证/特权/文件/网络/命令五大追溯能力，支持时间线构建与证据链生成 |
| 合规审计 | 等保三级核心项自动检查，支持文本 / Markdown / JSON 三种报告格式 |
| eBPF 实时监控 | 基于 bpftrace 的内核级行为监控，覆盖进程执行、文件访问、网络连接、提权检测 |

## 典型工作流

### 场景一：安全巡检

```bash
# 1. 检查审计系统健康状态
bash scripts/audit_health_check.sh

# 2. 扫描异常行为
bash scripts/anomaly_scanner.sh

# 3. 等保合规检查
bash scripts/compliance_check.sh --format markdown -o /tmp/compliance.md
```

### 场景二：安全事件追溯

```bash
# 1. 收集指定时间范围的日志
bash scripts/collect_audit_logs.sh -S "2024-01-15 10:00:00" -E "2024-01-15 18:00:00" -o /tmp/logs

# 2. 构建事件时间线
bash scripts/build_timeline.sh -d /tmp/logs -o /tmp/timeline.txt

# 3. 按维度追溯
bash scripts/trace_auth_events.sh -S "2024-01-15 10:00:00" -E "2024-01-15 18:00:00"
bash scripts/trace_command_history.sh -S "2024-01-15 10:00:00" -E "2024-01-15 18:00:00" -u admin

# 4. 生成证据链
bash scripts/generate_evidence_chain.sh -d /tmp/logs -o /tmp/evidence.md

# 5. 生成事件报告
bash scripts/generate_audit_report.sh --type incident -d /tmp/logs -o /tmp/report.md
```

### 场景三：审计规则部署

```bash
# 1. 检测平台与架构
bash scripts/detect_platform.sh

# 2. 预览将要部署的规则
bash scripts/audit_setup.sh --profile standard --dry-run

# 3. 部署标准级规则（等保三级）
sudo bash scripts/audit_setup.sh --profile standard

# 4. 验证部署结果
bash scripts/audit_health_check.sh
```

### 场景四：eBPF 实时监控

```bash
# 1. 检查 eBPF 环境
bash scripts/ebpf/ebpf_realtime_monitor.sh --check

# 2. 启动全部监控（需要 root）
sudo bash scripts/ebpf/ebpf_realtime_monitor.sh --mode all

# 3. 仅监控进程执行（60 秒）
sudo bash scripts/ebpf/ebpf_realtime_monitor.sh --mode process --duration 60
```

## 快速使用

### 平台检测

```bash
bash scripts/detect_platform.sh
```

### 部署审计规则

```bash
# 标准级规则（等保三级）
bash scripts/audit_setup.sh --profile standard

# 严格规则（等保四级）
bash scripts/audit_setup.sh --profile strict

# 预览规则（不实际部署）
bash scripts/audit_setup.sh --profile standard --dry-run
```

### 异常行为扫描

```bash
bash scripts/anomaly_scanner.sh
```

### 合规检查

```bash
# 文本格式输出
bash scripts/compliance_check.sh

# Markdown 格式报告
bash scripts/compliance_check.sh --format markdown -o /tmp/compliance.md

# JSON 格式输出
bash scripts/compliance_check.sh --format json
```

### 日志收集与时间线

```bash
# 收集指定时间范围的日志
bash scripts/collect_audit_logs.sh -S "2024-01-15" -E "2024-01-16" -o /tmp/logs

# 构建时间线
bash scripts/build_timeline.sh -d /tmp/logs -o /tmp/timeline.txt
```

### 事件追溯

```bash
# 认证事件追溯
bash scripts/trace_auth_events.sh -S "2024-01-15" -E "2024-01-16"

# 文件变更追溯
bash scripts/trace_file_changes.sh -S "2024-01-15" -E "2024-01-16" -f /etc/passwd

# 网络操作追溯
bash scripts/trace_network_ops.sh -S "2024-01-15" -E "2024-01-16"

# 命令历史追溯
bash scripts/trace_command_history.sh -S "2024-01-15" -E "2024-01-16" -u admin

# 特权操作追溯
bash scripts/trace_privilege_ops.sh -S "2024-01-15" -E "2024-01-16"

# 证据链生成
bash scripts/generate_evidence_chain.sh -d /tmp/logs -o /tmp/evidence.md
```

### eBPF 实时监控

```bash
# 检查 eBPF 环境
bash scripts/ebpf/ebpf_realtime_monitor.sh --check

# 启动全部监控
sudo bash scripts/ebpf/ebpf_realtime_monitor.sh --mode all

# 仅监控进程
sudo bash scripts/ebpf/ebpf_realtime_monitor.sh --mode process

# 监控 60 秒
sudo bash scripts/ebpf/ebpf_realtime_monitor.sh --mode all --duration 60
```

## 目录结构

```
os-audit-tracer/
├── SKILL.md                              # 主技能文件
├── README.md                             # 本文件
├── agents/
│   └── manifest.yaml                     # Agent 模型配置
├── assets/
│   ├── audit-report-template.md          # 通用审计报告模板
│   ├── incident-report-template.md       # 安全事件追溯报告模板
│   └── compliance-report-template.md     # 合规审计报告模板
├── evals/
│   └── evals.json                        # 评测用例
├── references/
│   ├── common/
│   │   ├── auditd-configuration.md       # auditd 配置与规则编写指南
│   │   ├── log-sources-catalog.md        # 全量日志源目录
│   │   ├── selinux-audit-guide.md        # SELinux 审计事件解读
│   │   └── command-reference.md          # 审计相关命令速查
│   ├── detection/
│   │   ├── auth-anomaly-patterns.md      # 认证异常检测模式
│   │   ├── privilege-escalation.md       # 提权行为检测模式
│   │   ├── file-integrity-anomaly.md     # 文件完整性异常检测
│   │   ├── network-anomaly-patterns.md   # 网络异常行为检测
│   │   ├── process-anomaly-patterns.md   # 进程异常行为检测
│   │   └── config-tampering.md           # 配置篡改检测模式
│   ├── scenarios/
│   │   ├── intrusion-tracing.md          # 入侵事件追溯流程
│   │   ├── insider-threat.md             # 内部威胁检测与追溯
│   │   └── compliance-audit.md           # 合规审计场景
│   ├── ebpf/
│   │   └── ebpf-audit-guide.md           # eBPF 审计应用指南
│   └── platform/
│       ├── openeuler-specific.md         # openEuler 特有审计能力
│       └── fusionos-specific.md          # FusionOS 特有审计能力
└── scripts/
    ├── detect_platform.sh                # 平台检测
    ├── audit_setup.sh                    # 审计规则部署
    ├── audit_health_check.sh             # 审计系统健康检查
    ├── collect_audit_logs.sh             # 审计日志收集
    ├── build_timeline.sh                 # 时间线构建
    ├── anomaly_scanner.sh                # 异常行为扫描
    ├── trace_auth_events.sh              # 认证事件追溯
    ├── trace_privilege_ops.sh            # 特权操作追溯
    ├── trace_file_changes.sh             # 文件变更追溯
    ├── trace_network_ops.sh              # 网络操作追溯
    ├── trace_command_history.sh          # 命令执行历史追溯
    ├── generate_evidence_chain.sh        # 证据链生成
    ├── generate_audit_report.sh          # 审计报告生成
    ├── compliance_check.sh               # 等保核心项合规检查
    └── ebpf/
        ├── ebpf_process_trace.bt         # 进程执行追踪
        ├── ebpf_file_access.bt           # 敏感文件访问追踪
        ├── ebpf_network_connect.bt       # 网络连接追踪
        ├── ebpf_privilege_escalation.bt  # 提权行为追踪
        └── ebpf_realtime_monitor.sh      # eBPF 实时监控入口
```

## 平台支持

| 平台 | 版本 | 架构 |
|------|------|------|
| openEuler | 22.03+ | x86_64, aarch64 |
| FusionOS | 基于 openEuler | x86_64, aarch64 (Kunpeng) |
| 其他 Linux | 主流发行版 | 基本功能兼容 |

> **架构说明**：审计规则中的 `arch` 值与 CPU 架构一一对应。脚本会自动检测并使用正确的值（x86_64=b64, aarch64=aarch64, loongarch64=loongarch64）。

## 依赖

### 必需

- auditd / audit-libs
- bash 4+
- GNU coreutils（`last`, `date`, `find` 等）

### 可选

- bpftrace >= 0.12（eBPF 实时监控，需要内核 BTF 支持）
- bcc-tools（eBPF 工具集）
- aide（文件完整性检测）
- fail2ban（暴力破解防护）

## 注意事项

- 所有脚本需要 **root 权限** 运行（auditctl / ausearch 需要特权）
- eBPF 功能需要内核编译时启用 `CONFIG_BPF=y`、`CONFIG_BPF_SYSCALL=y`
- 日志时间范围参数格式为 `YYYY-MM-DD HH:MM:SS`
- 合规检查基于 GB/T 22239-2019（等保 2.0）三级标准
