# os-audit-tracer

`os-audit-tracer` 是一个面向 openEuler / FusionOS 操作审计与异常行为追溯的 Skill，覆盖以下场景：

- 审计部署：auditd 规则集生成与部署，自动适配 x86_64 / aarch64 / loongarch64
- 异常检测：认证异常、提权行为、文件完整性、网络异常、进程异常、配置篡改 六大维度
- 事件追溯：基于 ausearch 的多源日志分析、时间线构建、攻击链还原、证据链固化
- 合规审计：等保 2.0 三级核心项自动检查，支持文本 / Markdown / JSON 报告
- 实时监控：基于 bpftrace 的 eBPF 内核级行为监控（进程、文件、网络、提权）

仓库主体是完全遵循格式化声明的通用 AI Skill 模型，**不受任何闭源或开源具体厂商的绑定，只要具备能力调用外部工具链的大语言模型（如 ChatGPT, Claude, Llama, DeepSeek, Qwen 等），皆可无缝挂载。** 同时它也适合作为专家脚本手册被现场运维工程师离线执行。

## 目录结构

- `SKILL.md`: Skill 主说明，定义适用范围、分流逻辑、分析方法与输出规范
- `agents/manifest.yaml`: Agent 模型侧挂载配置与 Prompt
- `assets/`: 报告模板（通用审计、安全事件、合规审计）
- `evals/`: 评测样例
- `references/`: 按主题整理的审计参考资料
  - `common/`: 通用参考（auditd 配置、日志源、SELinux、命令速查）
  - `detection/`: 六类异常检测模式（认证、提权、文件、网络、进程、配置）
  - `scenarios/`: 场景参考（入侵追溯、内部威胁、合规审计）
  - `ebpf/`: eBPF 审计应用指南
  - `platform/`: openEuler / FusionOS 平台特有能力
- `scripts/`: 审计脚本集

## 主要脚本

### 平台与部署

- `scripts/detect_platform.sh`: 平台检测（OS、架构、auditd 状态、SELinux 状态）
- `scripts/audit_setup.sh`: 审计规则集生成与部署（支持 basic / standard / strict 三级 profile）
- `scripts/audit_health_check.sh`: 审计系统健康检查

### 异常检测与扫描

- `scripts/anomaly_scanner.sh`: 综合异常行为扫描（输出 PASS / WARN / ALERT + 风险评分）
- `scripts/compliance_check.sh`: 等保三级核心项合规检查（支持 text / markdown / json 输出）

### 操作追溯

- `scripts/collect_audit_logs.sh`: 多源审计日志收集（audit.log、secure、messages、journalctl、wtmp）
- `scripts/build_timeline.sh`: 事件时间线构建
- `scripts/trace_auth_events.sh`: 认证事件追溯（暴力破解、异常登录、账户枚举）
- `scripts/trace_privilege_ops.sh`: 特权操作追溯（sudo、setuid、用户/组变更）
- `scripts/trace_file_changes.sh`: 文件变更追溯（RPM 验证、SUID 检测、关键文件监控）
- `scripts/trace_network_ops.sh`: 网络操作追溯（连接追踪、SOCKADDR 解析）
- `scripts/trace_command_history.sh`: 命令执行历史追溯（bash_history + audit 联合分析）

### 报告与证据链

- `scripts/generate_evidence_chain.sh`: 证据链生成（时间线 + 因果关系 + 关联事件）
- `scripts/generate_audit_report.sh`: 审计报告生成（通用 / 事件 / 合规三种类型）

### eBPF 实时监控

- `scripts/ebpf/ebpf_realtime_monitor.sh`: eBPF 实时监控入口（环境检查 + 多模式启动）
- `scripts/ebpf/ebpf_process_trace.bt`: 进程执行追踪探针
- `scripts/ebpf/ebpf_file_access.bt`: 敏感文件访问监控探针
- `scripts/ebpf/ebpf_network_connect.bt`: 网络连接追踪探针
- `scripts/ebpf/ebpf_privilege_escalation.bt`: 提权行为检测探针

## 快速使用

### 1. 平台检测与审计部署

```bash
# 检测平台与审计环境
bash scripts/detect_platform.sh

# 预览规则（不实际部署）
bash scripts/audit_setup.sh --profile standard --dry-run

# 部署标准级审计规则（等保三级）
sudo bash scripts/audit_setup.sh --profile standard
```

### 2. 异常检测与合规检查

```bash
# 综合异常扫描
bash scripts/anomaly_scanner.sh

# 等保合规检查（Markdown 报告）
bash scripts/compliance_check.sh --format markdown -o /tmp/compliance.md
```

### 3. 事件追溯

```bash
# 收集指定时间范围的日志
bash scripts/collect_audit_logs.sh -S "2024-01-15 10:00:00" -E "2024-01-15 18:00:00" -o /tmp/logs

# 构建时间线
bash scripts/build_timeline.sh -d /tmp/logs -o /tmp/timeline.txt

# 按维度追溯
bash scripts/trace_auth_events.sh -S "2024-01-15" -E "2024-01-16"
bash scripts/trace_command_history.sh -S "2024-01-15" -E "2024-01-16" -u admin

# 证据链与报告
bash scripts/generate_evidence_chain.sh -d /tmp/logs -o /tmp/evidence.md
bash scripts/generate_audit_report.sh --type incident -d /tmp/logs -o /tmp/report.md
```

### 4. eBPF 实时监控

```bash
# 环境检查
bash scripts/ebpf/ebpf_realtime_monitor.sh --check

# 启动监控（需要 root）
sudo bash scripts/ebpf/ebpf_realtime_monitor.sh --mode all
```

## 平台支持

| 平台 | 版本 | 架构 |
|------|------|------|
| openEuler | 22.03+ | x86_64, aarch64 |
| FusionOS | 基于 openEuler | x86_64, aarch64 (Kunpeng) |
| 其他 Linux | 主流发行版 | 基本功能兼容 |

审计规则的 `arch` 值与 CPU 架构一一对应（x86_64=b64, aarch64=aarch64, loongarch64=loongarch64），脚本会自动检测并使用正确的值。

## 依赖

### 必需

- auditd / audit-libs
- bash 4+
- GNU coreutils

### 可选

- bpftrace >= 0.12（eBPF 实时监控，需要内核 BTF 支持）
- bcc-tools（eBPF 工具集）
- aide（文件完整性检测）

## 已知边界

- eBPF 功能需要内核编译时启用 `CONFIG_BPF=y`、`CONFIG_BPF_SYSCALL=y`
- 没有 `/var/log/audit/audit.log` 访问权限时，追溯能力受限
- 合规检查基于 GB/T 22239-2019 三级标准，未覆盖的检查项通过参考文档指导人工检查
- eBPF 探针仅覆盖本地发起的 TCP 连接，UDP 和入站连接需额外探针

## 适合的仓库定位

这个仓库更适合被当作：

- **大语言模型通用 Skill 插件**（ChatGPT / Claude / 企业内部私有部署的 Agent 模型底座）
- Linux 操作审计结构化知识库
- 安全事件追溯方法论与自动化工具集
- 等保合规检查辅助脚本集合
