---
name: os-audit-tracer
description: >
  openEuler / FusionOS 操作审计与异常行为追溯技能。覆盖审计规则部署、多源日志分析、
  异常行为检测、安全事件追溯、证据链构建与合规报告生成。当用户提到审计、audit、
  操作追溯、行为分析、安全审计、日志分析、入侵检测、异常行为、合规检查、行为溯源、
  操作回放、安全事件追溯等关键词时触发。即使用户只说"帮我查一下谁改了这个文件"
  或"最近有没有异常登录"也要触发本技能。
---

# 操作审计与异常行为追溯

面向 openEuler / FusionOS 的统一操作审计技能入口。覆盖审计规则部署、异常行为检测、操作追溯、eBPF 实时监控和合规审计。

## 使用边界

- 面向 openEuler / FusionOS，兼容主流 Linux 发行版
- 证据优先：没有日志支撑不下结论，区分"观察事实""推论""待验证假设"
- 遵循最小权限原则：审计操作本身不破坏现场
- 没有根因调查不进入修复建议
- 复杂事件使用迭代分析，不要把第一次观察当最终结论

## 平台检测

首先运行平台检测，确定操作系统类型和审计环境：

```bash
bash scripts/detect_platform.sh
```

根据输出的 `PLATFORM`、`VERSION`、`AUDITD_STATUS`、`SELINUX_STATUS` 调整后续操作。

平台差异详见：
- openEuler：`references/platform/openeuler-specific.md`
- FusionOS：`references/platform/fusionos-specific.md`

## 总体分流

先判定用户输入属于哪一类，再进入对应分支：

| 场景 | 典型输入 | 首要操作 |
|------|----------|----------|
| 审计部署 | 配置审计、启用审计、审计规则、auditd 配置 | `audit_setup.sh` |
| 异常检测 | 扫描异常、检查入侵、安全检查、有没有被黑 | `anomaly_scanner.sh` |
| 事件追溯 | 追溯操作、查谁改了、操作回放、谁动了 | 对应 `trace_*.sh` |
| 合规审计 | 等保检查、合规报告、安全评估、基线检查 | `compliance_check.sh` |
| 日志分析 | 分析日志、日志中有何异常、日志时间线 | `collect_audit_logs.sh` + `build_timeline.sh` |
| 实时监控 | 实时监控、实时追踪、eBPF 监控 | `ebpf/ebpf_realtime_monitor.sh` |

如果分类不明确：

1. 先执行 `anomaly_scanner.sh` 快速扫描。
2. 根据扫描结果二次分类。
3. 仍不明确时，明确说明不确定性，并给出下一步最小必要数据。

## 分支 A：审计系统部署与配置

### A1. 平台检测与环境检查

```bash
bash scripts/detect_platform.sh
bash scripts/audit_health_check.sh
```

检查项：
- auditd 是否安装并运行
- audit.rules 是否已配置
- SELinux 状态
- 日志存储空间是否充足
- 架构（x86_64 / aarch64）以确定 audit rules 的 arch 字段

### A2. 审计规则集生成

```bash
bash scripts/audit_setup.sh --profile <level> --platform auto --categories <list>
```

**Profile 级别**：
- `basic`：基础审计（等保 1-2 级）—— 身份认证 + 特权命令
- `standard`：标准审计（等保 3 级）—— 全部 10 类规则
- `strict`：严格审计（等保 4-5 级）—— 全部规则 + 更细粒度

**规则类别**（可通过 `--categories` 选择性启用）：

| 类别 | 关键词 | 监控目标 |
|------|--------|----------|
| identity | identity | /etc/passwd, /etc/shadow, /etc/group, /etc/sudoers |
| privilege | privilege | execve by root/sudo, setuid/setgid |
| file-integrity | fileint | /etc/, /usr/bin/, /usr/sbin/, /usr/lib/ |
| network | network | connect, bind, accept 系统调用 |
| process | process | execve from /tmp,/dev/shm, kernel module |
| config | config | time changes, hostname, DNS, firewall |
| login | login | login 事件, SSH key 变更 |
| selinux | selinux | AVC denials, policy changes |
| cron | cron | /etc/crontab, /var/spool/cron/ |
| media | media | mount, USB 设备 |

### A3. auditd 配置优化

配置文件：`/etc/audit/auditd.conf`

关键参数建议：

| 参数 | basic | standard | strict |
|------|-------|----------|--------|
| max_log_file | 10 | 50 | 100 |
| num_logs | 5 | 10 | 20 |
| max_log_file_action | ROTATE | ROTATE | ROTATE |
| space_left_action | SYSLOG | EMAIL | SUSPEND |
| action_mail_acct | root | root | root |

详细配置参考：`references/common/auditd-configuration.md`

### A4. 日志轮转与存储策略

确保 audit 日志不会因空间不足而丢失：
- 配置 logrotate：`/etc/logrotate.d/audit`
- 建议远程日志转发（rsyslog remote）
- 监控 `/var/log/audit/` 磁盘使用

## 分支 B：异常行为检测

### B1. 综合异常扫描

首先运行综合扫描器获取全局视图：

```bash
bash scripts/anomaly_scanner.sh
```

输出包含每项检测的 PASS / WARN / ALERT 状态和风险评分。

### B2. 认证异常检测

**检测目标**：暴力破解、异常时间登录、异常源 IP、账户枚举

```bash
bash scripts/trace_auth_events.sh -S "2024-01-15" -E "2024-01-16" [-u user] [-i ip]
```

**关键检测规则**：
- 同一 IP 5 分钟内失败登录 >= 5 次 → 暴力破解（ALERT）
- 非工作时间（0:00-6:00）成功登录 → 异常时间（WARN）
- 首次出现的源 IP 成功登录 → 新 IP 登录（WARN）
- root 直接 SSH 登录 → root 远程登录（ALERT）
- 成功登录前有多次失败 → 密码猜测成功（ALERT）

详细检测模式：`references/detection/auth-anomaly-patterns.md`

### B3. 文件完整性检测

**检测目标**：系统文件篡改、SUID 异常、关键配置变更

```bash
bash scripts/trace_file_changes.sh -S "2024-01-15" -E "2024-01-16" [-f /etc/passwd]
```

**关键检测规则**：
- RPM 验证失败（`rpm -Va`）→ 包文件被篡改（ALERT）
- 新增 SUID/SGID 文件 → 权限提升风险（ALERT）
- /etc/passwd, /etc/shadow 修改 → 账户变更（WARN/ALERT）
- /usr/bin/, /usr/sbin/ 修改 → 系统二进制篡改（ALERT）
- SSH authorized_keys 变更 → 密钥注入（ALERT）

详细检测模式：`references/detection/file-integrity-anomaly.md`

### B4. 进程异常检测

**检测目标**：可疑进程、反弹 Shell、挖矿程序、Rootkit

```bash
# 结合 audit 日志和当前进程状态分析
bash scripts/anomaly_scanner.sh  # 包含进程检测
```

**关键检测规则**：
- 进程从 /tmp, /dev/shm 执行 → 可疑执行（ALERT）
- bash -i, /dev/tcp, nc -e 等模式 → 反弹 Shell（ALERT）
- 已知挖矿进程名 / 高 CPU + 可疑进程 → 挖矿（ALERT）
- 隐藏进程（ps 与 /proc 差异）→ Rootkit（ALERT）
- web server 进程 spawn shell → Web Shell（ALERT）

详细检测模式：`references/detection/process-anomaly-patterns.md`

### B5. 网络异常检测

**检测目标**：异常连接、C2 通信、数据外泄、端口扫描

```bash
bash scripts/trace_network_ops.sh -S "2024-01-15" -E "2024-01-16" [-d ip]
```

**关键检测规则**：
- 非标准端口外连（非 22/80/443）→ 异常外连（WARN）
- 大量数据传输 → 数据外泄（WARN）
- 异常 DNS 查询 → DNS 隧道（WARN）
- 监听端口异常增加 → 后门监听（ALERT）
- SSH 隧道 / 端口转发 → 隧道穿透（WARN）

详细检测模式：`references/detection/network-anomaly-patterns.md`

### B6. 配置篡改检测

**检测目标**：定时任务注入、启动项篡改、SSH 配置变更、防火墙规则变更

```bash
bash scripts/trace_file_changes.sh -S "2024-01-15" -E "2024-01-16" -f /etc/crontab
```

**关键检测规则**：
- crontab 新增条目 → 定时任务注入（ALERT）
- systemd 新增 service → 启动项篡改（ALERT）
- sshd_config 变更 → SSH 配置篡改（ALERT）
- firewall 规则变更 → 防火墙篡改（WARN）
- /etc/resolv.conf 变更 → DNS 篡改（ALERT）

详细检测模式：`references/detection/config-tampering.md`

### B7. 综合风险评分

`anomaly_scanner.sh` 输出的 [SUMMARY] 包含：

| 风险等级 | 条件 | 建议动作 |
|----------|------|----------|
| CRITICAL | 任一项 ALERT + 关键系统受影响 | 立即响应，隔离系统 |
| HIGH | 多项 ALERT | 尽快调查，保全证据 |
| MEDIUM | 多项 WARN | 计划性排查 |
| LOW | 仅 PASS 或少量 WARN | 常规关注 |

## 分支 C：操作追溯与事件重建

### C1. 确定追溯目标

明确追溯范围：
- **时间范围**：事件发生的时间段（`-S` 起始，`-E` 结束）
- **用户范围**：特定用户（`-u username`）
- **文件范围**：特定文件或目录（`-f /path`）
- **网络范围**：特定 IP 或端口（`-d ip`, `-p port`）
- **命令范围**：特定命令或关键字

### C2. 多源日志收集

```bash
bash scripts/collect_audit_logs.sh -S "2024-01-15 14:00:00" -E "2024-01-15 15:00:00" -o /tmp/audit-collect
```

收集源优先级：
1. `/var/log/audit/audit.log` —— 最权威的操作审计记录
2. `/var/log/secure` —— 认证与授权事件
3. `/var/log/messages` —— 系统级事件
4. `journalctl` —— 结构化日志（补充）
5. `/var/log/cron` —— 定时任务执行
6. `/var/log/wtmp`, `/var/log/btmp` —— 登录记录

### C3. 时间线构建

```bash
bash scripts/build_timeline.sh -S "2024-01-15 14:00:00" -E "2024-01-15 15:00:00" -o /tmp/audit-timeline
```

输出格式：
```
[2024-01-15 14:23:01] [AUTH] [sshd] Failed password for admin from 192.168.1.100 port 22
[2024-01-15 14:23:05] [AUTH] [sshd] Accepted publickey for admin from 192.168.1.100 port 22
[2024-01-15 14:23:10] [EXEC] [uid=1000] sudo useradd -m backdoor_user
[2024-01-15 14:23:15] [FILE] [uid=0] write /etc/passwd
[2024-01-15 14:23:20] [NET] [pid=12345] connect to 10.0.0.99:4444
```

### C4. 攻击链 / 操作链还原

基于时间线，识别事件之间的因果关系：

1. **入口点**：最初的异常事件（如暴力破解成功）
2. **立足点**：攻击者建立持久化（如 SSH 密钥注入、定时任务）
3. **提权**：获取更高权限（如 sudo 滥用、SUID 利用）
4. **横向移动**：访问其他系统或服务
5. **目标达成**：数据窃取、破坏、后门植入

### C5. 证据链固化

```bash
bash scripts/generate_evidence_chain.sh -d /tmp/audit-collect
```

每条证据必须包含：
- **时间戳**：精确到秒
- **事件类型**：AUTH / EXEC / FILE / NET / CONFIG
- **证据来源**：具体日志文件和行号
- **audit ID**：audit.log 中的事件 ID（如 `audit(1705312985.123:456)`）
- **关联事件**：前后相关的事件

详细追溯流程：
- 入侵事件：`references/scenarios/intrusion-tracing.md`
- 内部威胁：`references/scenarios/insider-threat.md`

## 分支 D：eBPF 实时行为监控（可选增强）

当需要比 auditd 更精细的实时监控时，使用 eBPF 工具。

### D1. 环境检测

```bash
bash scripts/ebpf/ebpf_realtime_monitor.sh --check
```

检查项：
- 内核版本是否支持 eBPF（>= 5.10 或 openEuler 22.03+）
- BTF（BPF Type Format）是否启用
- bpftrace / bcc-tools 是否安装
- 是否有 root 权限

### D2. 实时监控

```bash
# 实时进程执行追踪
sudo bpftrace scripts/ebpf/ebpf_process_trace.bt

# 敏感文件访问监控
sudo bpftrace scripts/ebpf/ebpf_file_access.bt

# 网络连接追踪
sudo bpftrace scripts/ebpf/ebpf_network_connect.bt

# 提权行为检测
sudo bpftrace scripts/ebpf/ebpf_privilege_escalation.bt

# 综合监控入口
bash scripts/ebpf/ebpf_realtime_monitor.sh --mode all
```

### D3. eBPF 与 auditd 配合

- **auditd**：持久化审计记录，适合事后追溯
- **eBPF**：实时监控，适合捕获 auditd 无法覆盖的细粒度行为
- 建议：auditd 作为基础审计，eBPF 作为特定场景的增强监控

详细指南：`references/ebpf/ebpf-audit-guide.md`

## 分支 E：合规审计与报告

### E1. 等保核心项检查

```bash
bash scripts/compliance_check.sh --format markdown -o /tmp/compliance_report.md
```

覆盖 GB/T 22239 等保三级最核心的 30-50 个技术检查项，包括：
- 身份鉴别（密码策略、登录失败锁定、远程管理加密）
- 访问控制（最小权限、默认拒绝、特权用户分离）
- 安全审计（审计开启、审计记录保护、审计日志留存）
- 入侵防范（最小安装、漏洞管理、恶意代码防范）
- 数据完整性（传输校验、存储校验）
- 数据保密性（加密算法、密钥管理）

未覆盖的检查项通过参考文档指导人工检查：`references/scenarios/compliance-audit.md`

### E2. 安全基线扫描

```bash
bash scripts/anomaly_scanner.sh --baseline
```

基于 CIS Benchmark 或等保基线，检查：
- 系统配置是否符合安全基线
- 服务是否最小化
- 文件权限是否合规
- 网络配置是否安全

### E3. 审计报告生成

```bash
bash scripts/generate_audit_report.sh --type <audit|incident|compliance> -d /tmp/audit-data
```

报告类型：
- `audit`：通用审计报告 → `assets/audit-report-template.md`
- `incident`：安全事件追溯报告 → `assets/incident-report-template.md`
- `compliance`：合规审计报告 → `assets/compliance-report-template.md`

## 输出要求

### 简单问题

终端输出应包含：

- 事件类型
- 风险评级（CRITICAL / HIGH / MEDIUM / LOW）
- 关键发现
- 建议动作

### 复杂问题

生成 Markdown 报告，使用对应模板。报告必须包含：

- 时间线（精确到秒）
- 证据链（每步操作的日志证据）
- 因果关系（事件之间的关联）
- 影响评估
- 处置建议

## 迭代分析

复杂事件按四轮推进：

1. **快速扫描**：异常检测，识别可疑事件
2. **定向追溯**：针对可疑事件深入追溯
3. **攻击链重建**：还原完整操作链
4. **报告输出**：证据链固化，生成报告

退出条件：
- 事件链完整，因果关系明确
- 超过 3 轮仍无法确定，则明确说明卡点和缺失数据
- 用户停止，则输出当前最可靠结论和后续建议

## 资源索引

### 通用参考

- `references/common/auditd-configuration.md`：auditd 配置与规则编写指南
- `references/common/log-sources-catalog.md`：全量日志源目录
- `references/common/selinux-audit-guide.md`：SELinux 审计事件解读
- `references/common/command-reference.md`：审计相关命令速查

### 检测模式参考

- `references/detection/auth-anomaly-patterns.md`：认证异常检测
- `references/detection/privilege-escalation.md`：提权行为检测
- `references/detection/file-integrity-anomaly.md`：文件完整性异常
- `references/detection/network-anomaly-patterns.md`：网络异常行为
- `references/detection/process-anomaly-patterns.md`：进程异常行为
- `references/detection/config-tampering.md`：配置篡改检测

### 场景参考

- `references/scenarios/intrusion-tracing.md`：入侵事件追溯
- `references/scenarios/insider-threat.md`：内部威胁检测
- `references/scenarios/compliance-audit.md`：合规审计场景

### eBPF 参考

- `references/ebpf/ebpf-audit-guide.md`：eBPF 审计应用指南

### 平台参考

- `references/platform/openeuler-specific.md`：openEuler 特有审计能力
- `references/platform/fusionos-specific.md`：FusionOS 特有审计能力

### 脚本

- `scripts/detect_platform.sh`：平台检测
- `scripts/audit_setup.sh`：审计规则部署
- `scripts/audit_health_check.sh`：审计系统健康检查
- `scripts/collect_audit_logs.sh`：审计日志收集
- `scripts/build_timeline.sh`：时间线构建
- `scripts/anomaly_scanner.sh`：异常行为扫描
- `scripts/trace_auth_events.sh`：认证事件追溯
- `scripts/trace_privilege_ops.sh`：特权操作追溯
- `scripts/trace_file_changes.sh`：文件变更追溯
- `scripts/trace_network_ops.sh`：网络操作追溯
- `scripts/trace_command_history.sh`：命令执行历史追溯
- `scripts/generate_evidence_chain.sh`：证据链生成
- `scripts/generate_audit_report.sh`：审计报告生成
- `scripts/compliance_check.sh`：等保合规检查
- `scripts/ebpf/ebpf_realtime_monitor.sh`：eBPF 实时监控入口
- `scripts/ebpf/ebpf_process_trace.bt`：eBPF 进程执行追踪探针
- `scripts/ebpf/ebpf_file_access.bt`：eBPF 敏感文件访问监控探针
- `scripts/ebpf/ebpf_network_connect.bt`：eBPF 网络连接追踪探针
- `scripts/ebpf/ebpf_privilege_escalation.bt`：eBPF 提权行为检测探针
