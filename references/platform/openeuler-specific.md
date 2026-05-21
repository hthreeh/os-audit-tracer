# openEuler 特有审计能力

## 1. 平台概述

openEuler 是由华为主导、OpenAtom 基金会托管的开源 Linux 发行版，基于 RHEL/CentOS 生态，使用 RPM、yum/dnf、systemd。

**版本识别**：
```bash
cat /etc/openEuler-release
cat /etc/os-release | grep -E "^NAME|^VERSION"
rpm -q openEuler-release
```

## 2. 审计框架

### auditd 配置

openEuler 使用标准 auditd，配置路径与 RHEL 一致：
- `/etc/audit/auditd.conf`
- `/etc/audit/rules.d/audit.rules`
- `/etc/audit/rules.d/` 下的规则文件

### 默认审计策略

openEuler 默认审计策略相对宽松，建议根据等保要求使用 `audit_setup.sh` 部署增强规则。

### SELinux

openEuler 默认启用 SELinux（targeted 策略），部分版本可能为 Permissive 模式。

```bash
getenforce                        # 查看当前模式
sestatus                          # 详细状态
cat /etc/selinux/config           # 配置文件
```

**注意**：openEuler 的 SELinux 策略可能不如 FusionOS 严格，需要根据合规要求调整。

## 3. 特有工具

### A-Ops

openEuler 的智能运维工具集，提供系统诊断和故障定位能力。

```bash
# 检查是否安装
rpm -q aops-ares aops-zeus

# A-Ops 诊断能力
# - 系统故障诊断
# - 性能分析
# - 安全事件辅助分析
```

**与审计的关系**：A-Ops 可以辅助分析审计日志中的异常模式，但不替代 auditd。

### SecGear

openEuler 的机密计算框架，支持 Intel SGX、ARM TrustZone 等 TEE 技术。

```bash
# 检查是否可用
rpm -q secgear

# 应用场景
# - 敏感数据处理的审计
# - 可信执行环境的日志
```

### iSulad

openEuler 的轻量级容器运行时。

```bash
# 检查是否运行
systemctl status isulad

# 容器审计相关
isula ps                          # 列出容器
isula logs <container>            # 容器日志
isula inspect <container>         # 容器详情
```

**注意**：容器审计不在 v1 范围内，但 iSulad 的日志可作为系统审计的补充。

## 4. 架构支持

openEuler 支持多种架构，审计规则需要适配：

| 架构 | arch 值 | 说明 |
|------|---------|------|
| x86_64 | b64 | Intel/AMD 64 位 |
| aarch64 | aarch64 | ARM 64 位（鲲鹏） |
| RISC-V | b64 | RISC-V 64 位（需确认内核支持） |
| LoongArch | loongarch64 | 龙芯 |

**重要**：`arch` 值必须与目标架构匹配。`b64` 仅对应 x86_64，在 aarch64 上使用 `arch=b64` 的规则将静默匹配不到任何系统调用。

```bash
# 检查当前架构并设置对应的 arch 值
case "$(uname -m)" in
    x86_64)       AUDIT_ARCH="b64" ;;
    aarch64)      AUDIT_ARCH="aarch64" ;;
    loongarch64)  AUDIT_ARCH="loongarch64" ;;
    *)            AUDIT_ARCH="b64" ;;
esac

# 在 audit rules 中使用
-F arch=$AUDIT_ARCH
```

## 5. 日志配置

### 日志路径

openEuler 使用标准日志路径：
- `/var/log/audit/audit.log`
- `/var/log/secure`（也可能在 `/var/log/auth.log`）
- `/var/log/messages`

### journald 配置

```bash
# 查看 journald 配置
cat /etc/systemd/journald.conf

# 持久化日志存储
mkdir -p /var/log/journal
systemd-tmpfiles --create --prefix /var/log/journal
systemctl restart systemd-journald

# 日志大小限制
journalctl --disk-usage
```

## 6. 安全基线

### CIS Benchmark

openEuler 有社区维护的 CIS Benchmark，可作为安全基线参考：

```bash
# 检查关键配置
grep -E "^PermitRootLogin|^PasswordAuthentication|^MaxAuthTries" /etc/ssh/sshd_config
grep -E "^PASS_MAX_DAYS|^PASS_MIN_LEN" /etc/login.defs
```

### 等保合规

openEuler 支持等保 2.0 合规要求，但需要手动配置审计策略。使用 `compliance_check.sh` 可以自动化检查核心项。

## 7. 特有审计场景

### A-Ops 集成审计

当 A-Ops 已安装时，可以结合审计日志进行智能分析：

1. A-Ops 的诊断结果可以作为审计事件的上下文
2. 审计日志中的异常可以触发 A-Ops 诊断
3. 两者结合可以提供更全面的安全视图

### 鲲鹏平台特有

在鲲鹏（ARM64）平台上运行 openEuler 时：

```bash
# 检查鲲鹏特有功能
lscpu | grep -i kunpeng

# NUMA 拓扑（审计性能相关）
numactl --hardware

# 大页配置（影响审计日志存储）
cat /proc/meminfo | grep Huge
```

## 8. 常见问题

### auditd 无法启动

```bash
# 检查内核审计支持
cat /proc/sys/kernel/audit

# 检查 auditd 日志
journalctl -u auditd -n 50

# 检查规则语法
auditctl -R /etc/audit/rules.d/audit.rules
```

### SELinux 阻止审计服务

```bash
# 检查 AVC 拒绝
ausearch -m avc -c auditd --no-pager

# 生成策略模块
ausearch -m avc -c auditd | audit2allow -M auditd_fix
semodule -i auditd_fix.pp
```

### 日志空间不足

```bash
# 检查日志大小
du -sh /var/log/audit/

# 配置日志轮转
vim /etc/logrotate.d/audit

# 手动清理
find /var/log/audit/ -name "*.gz" -mtime +30 -delete
```
