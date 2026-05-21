# auditd 配置与规则编写指南

## 1. auditd 架构概述

```
┌─────────────────────────────────────────────────────────┐
│                    Linux Kernel                          │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │  Audit       │  │  SELinux     │  │  Other        │  │
│  │  Subsystem   │  │  AVC Events  │  │  Subsystems   │  │
│  └──────┬───────┘  └──────┬───────┘  └───────┬───────┘  │
│         └──────────────────┼──────────────────┘          │
│                            ▼                             │
│                    Netlink Socket                         │
└────────────────────────────┬────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────┐
│                    User Space                             │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │  auditd      │  │  audispd     │  │  Plugins      │  │
│  │  (Daemon)    │  │  (Dispatch)  │  │  (syslog,pre) │  │
│  └──────┬───────┘  └──────────────┘  └───────────────┘  │
│         │                                                │
│         ▼                                                │
│  /var/log/audit/audit.log                                │
└─────────────────────────────────────────────────────────┘
```

### 核心组件

| 组件 | 功能 | 配置文件 |
|------|------|----------|
| auditd | 审计守护进程，收集内核审计事件 | `/etc/audit/auditd.conf` |
| auditctl | 运行时控制审计规则 | `/etc/audit/rules.d/audit.rules` |
| audispd | 审计调度守护进程，实时处理事件 | `/etc/audit/audispd.conf`（auditd 3.x）或 `/etc/audisp/audispd.conf`（旧版） |
| ausearch | 搜索审计日志 | - |
| aureport | 生成审计报告 | - |

## 2. auditd.conf 关键参数

### 日志管理

```ini
# 日志文件路径
log_file = /var/log/audit/audit.log

# 单个日志文件最大大小（MB）
max_log_file = 50

# 保留的日志文件数量
num_logs = 10

# 日志文件达到最大大小时的动作
# IGNORE: 不处理
# SYSLOG: 发送 syslog 消息
# SUSPEND: 暂停审计
# ROTATE: 轮转日志
# KEEP_LOGS: 保留所有日志
max_log_file_action = ROTATE
```

### 磁盘空间管理

```ini
# 剩余空间低于此值时的动作（MB）
space_left = 75
space_left_action = SYSLOG

# 剩余空间严重不足时的动作
admin_space_left = 50
admin_space_left_action = SUSPEND

# 完全无空间时的动作
disk_full_action = SUSPEND
disk_error_action = SUSPEND
```

### 通知配置

```ini
action_mail_acct = root
sendmail = /usr/sbin/sendmail
```

### openEuler / FusionOS 差异

| 参数 | openEuler 默认 | FusionOS 默认 |
|------|---------------|---------------|
| max_log_file | 10 | 50 |
| num_logs | 5 | 10 |
| space_left_action | SYSLOG | EMAIL |
| max_log_file_action | ROTATE | ROTATE |

## 3. audit.rules 语法与编写规范

### 规则类型

#### 文件监控规则（-w）

```bash
# 监控文件访问
-w /etc/passwd -p rwxa -k identity

# 参数说明：
# -w: 要监控的文件或目录路径
# -p: 监控的权限类型
#     r = 读取 (read)
#     w = 写入 (write)
#     x = 执行 (execute)
#     a = 属性变更 (attribute change)
# -k: 事件标识键（用于搜索过滤）
```

#### 系统调用规则（-a）

```bash
# 监控系统调用
-a always,exit -F arch=b64 -S execve -k exec_cmd

# 参数说明：
# -a: 规则类型
#     always,exit: 系统调用退出时始终记录
#     always,entry: 系统调用进入时始终记录
#     task: 任务创建时记录
# -F: 过滤条件
#     arch=b64: x86_64 架构（仅适用于 x86 平台）
#     arch=b32: i386 架构（仅适用于 x86 平台）
#     arch=aarch64: ARM64 架构
#     uid=0: root 用户
#     success=1: 成功的操作
# -S: 要监控的系统调用
# -k: 事件标识键
```

#### 架构适配

```bash
# x86_64 系统
-F arch=b64

# ARM64 (aarch64) 系统
-F arch=aarch64

# x86_64 同时监控 32 位和 64 位
-F arch=b64 -S execve -k exec_64
-F arch=b32 -S execve -k exec_32
```

### 规则编写最佳实践

1. **使用有意义的 key**：`-k identity_changes` 而非 `-k rule1`
2. **避免规则冲突**：同一路径不要重复监控
3. **考虑性能影响**：过度监控会影响系统性能
4. **测试规则**：先用 `auditctl` 临时添加测试，确认无误后再写入配置文件
5. **备份规则**：修改前备份 `/etc/audit/rules.d/`

## 4. 标准审计规则集

> **架构说明**：以下规则均以 x86_64 (`arch=b64`) 为例。在 aarch64 系统上需将 `arch=b64` 替换为 `arch=aarch64`。

### identity（身份认证）

```bash
# 监控用户账户文件
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# 监控 sudoers 配置
-w /etc/sudoers -p wa -k identity
-w /etc/sudoers.d/ -p wa -k identity
```

### privilege（特权操作）

```bash
# 监控特权命令执行（euid=0 且非初始登录用户）
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid!=0 -F auid!=4294967295 -k privilege

# 监控 UID/GID 变更
-a always,exit -F arch=b64 -S setuid -S setgid -S setreuid -S setregid -k privilege_id_change

# 所有用户命令执行（用于 trace_command_history.sh）
-a always,exit -F arch=b64 -S execve -k exec_cmd

# 文件属性变更（chmod/chown/chattr）
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -k attr_change
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -k owner_change
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -k xattr_change
```

### file-integrity（文件完整性）

```bash
# 监控关键目录
-w /etc/ -p wa -k fileint
-w /usr/bin/ -p wa -k fileint
-w /usr/sbin/ -p wa -k fileint
-w /usr/lib/ -p wa -k fileint
-w /usr/lib64/ -p wa -k fileint

# 监控启动相关文件
-w /boot/ -p wa -k fileint
-w /etc/grub.d/ -p wa -k fileint
```

### network（网络活动）

```bash
# 监控网络连接
-a always,exit -F arch=b64 -S connect -S bind -S accept -k network

# 监控防火墙规则变更
-w /etc/iptables/ -p wa -k firewall
-w /etc/firewalld/ -p wa -k firewall
```

### process（进程与模块）

```bash
# 监控从临时目录执行
-a always,exit -F arch=b64 -S execve -F dir=/tmp -k process_suspicious
-a always,exit -F arch=b64 -S execve -F dir=/dev/shm -k process_suspicious

# 监控内核模块加载
-a always,exit -F arch=b64 -S init_module -S finit_module -S delete_module -k module
```

### config（系统配置）

```bash
# 监控时间变更
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k time_change

# 监控主机名变更
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k hostname_change

# 监控 DNS 配置
-w /etc/resolv.conf -p wa -k dns_change
-w /etc/hosts -p wa -k dns_change

# 监控 SSH 配置变更
-w /etc/ssh/sshd_config -p wa -k ssh_config
```

### login（登录与会话）

```bash
# 监控登录事件
-w /var/log/lastlog -p wa -k login
-w /var/log/faillog -p wa -k login
-w /var/run/utmp -p wa -k login
-w /var/log/wtmp -p wa -k login
-w /var/log/btmp -p wa -k login

# 监控 SSH 密钥变更
-w /root/.ssh/ -p wa -k ssh_key

# 审计日志自身保护
-w /var/log/audit/ -p wa -k audit_log
-w /etc/audit/ -p wa -k audit_config
-w /etc/audisp/ -p wa -k audit_config
```

### selinux（SELinux 事件）

```bash
# SELinux 策略变更
-w /etc/selinux/ -p wa -k selinux
-w /usr/share/selinux/ -p wa -k selinux
```

### cron（定时任务）

```bash
# 监控定时任务
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
```

### media（可移动介质）

```bash
# 监控挂载操作
-a always,exit -F arch=b64 -S mount -S umount2 -k media
```

## 5. 日志轮转配置

### /etc/logrotate.d/audit

```
/var/log/audit/audit.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0600 root root
    postrotate
        systemctl restart auditd 2>/dev/null || /sbin/service auditd restart 2>/dev/null || true
    endscript
}
```

### 远程日志转发

在 `/etc/rsyslog.conf` 中添加：

```
# 转发审计日志到远程服务器
# @@ 表示 TCP 协议，@ 表示 UDP 协议
local6.* @@logserver.example.com:514
```

或使用 audispd 插件实时转发。

## 6. 常见问题排查

### auditd 启动失败

```bash
# 检查配置语法
auditd -f

# 检查日志
journalctl -u auditd -n 50

# 检查规则文件语法
auditctl -R /etc/audit/rules.d/audit.rules
```

### 规则不生效

```bash
# 查看当前加载的规则
auditctl -l

# 检查规则优先级
# 后加载的规则优先级更高
# 使用 -d 删除冲突规则
auditctl -d -w /etc/passwd -p wa -k identity
```

### 日志空间不足

```bash
# 检查日志大小
du -sh /var/log/audit/

# 手动轮转
systemctl kill -s SIGUSR1 auditd  # systemd 方式
# 或
service auditd rotate  # SysVinit 方式

# 清理旧日志
find /var/log/audit/ -name "*.gz" -mtime +30 -delete
```
