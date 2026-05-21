# eBPF 审计应用指南

## 1. eBPF 在审计中的应用概述

### 什么是 eBPF

eBPF (extended Berkeley Packet Filter) 是 Linux 内核中的一个可编程框架，允许在内核空间安全地运行自定义代码，无需修改内核或加载内核模块。

### eBPF vs auditd

| 维度 | auditd | eBPF |
|------|--------|------|
| 部署方式 | 内核子系统 + 用户空间守护进程 | 内核虚拟机 + 用户空间工具 |
| 性能影响 | 中等（每次事件都写日志） | 低（内核空间过滤） |
| 粒度 | 系统调用级别 | 函数级别、内核探针 |
| 持久化 | 写入日志文件 | 实时流式输出 |
| 适用场景 | 事后追溯、合规审计 | 实时监控、深度分析 |
| 配置复杂度 | 简单（规则文件） | 较高（需要编写脚本） |

### 推荐使用策略

```
┌─────────────────────────────────────────────────────────┐
│                    审计架构                               │
│                                                          │
│  ┌──────────────┐    ┌──────────────┐                   │
│  │   auditd     │    │   eBPF       │                   │
│  │   (基础层)    │    │   (增强层)    │                   │
│  │              │    │              │                   │
│  │ - 持久化记录  │    │ - 实时监控    │                   │
│  │ - 合规审计    │    │ - 深度分析    │                   │
│  │ - 事后追溯    │    │ - 细粒度追踪  │                   │
│  └──────────────┘    └──────────────┘                   │
│         │                   │                            │
│         └───────┬───────────┘                            │
│                 ▼                                        │
│        ┌──────────────┐                                 │
│        │  日志聚合     │                                 │
│        │  时间线构建    │                                 │
│        │  证据链生成    │                                 │
│        └──────────────┘                                 │
└─────────────────────────────────────────────────────────┘
```

**建议**：
- auditd 作为基础审计层，负责持久化记录和合规要求
- eBPF 作为增强层，用于实时监控和深度分析
- 两者结合使用，互补优势

## 2. bpftrace 脚本编写规范

### 基本语法

```bash
#!/usr/bin/env bpftrace

# 探针定义
tracepoint:syscalls:sys_enter_execve {
    printf("exec: %s %s\n", comm, str(args->filename));
}

# kprobe
kprobe:tcp_connect {
    printf("connect: pid=%d comm=%s\n", pid, comm);
}
```

### 常用探针类型

| 探针类型 | 说明 | 示例 |
|----------|------|------|
| tracepoint | 内核静态追踪点 | `tracepoint:syscalls:sys_enter_execve` |
| kprobe | 内核函数入口 | `kprobe:tcp_connect` |
| kretprobe | 内核函数返回 | `kretprobe:tcp_connect` |
| uprobe | 用户空间函数 | `uprobe:/bin/bash:readline` |
| profile | 定时采样 | `profile:hz:99 { ... }` |
| interval | 定时输出 | `interval:s:1 { ... }` |
| BEGIN | 脚本开始 | `BEGIN { ... }` |
| END | 脚本结束 | `END { ... }` |

### 常用内置变量

| 变量 | 说明 |
|------|------|
| `pid` | 当前进程 PID |
| `tid` | 当前线程 TID |
| `uid` | 当前用户 UID |
| `gid` | 当前用户组 GID |
| `comm` | 当前进程名 |
| `nsecs` | 纳秒级时间戳 |
| `elapsed` | 脚本启动后的时间（纳秒） |
| `curtask` | 当前任务结构体指针 |
| `args` | 追踪点参数 |
| `retval` | 函数返回值 |

### 常用内置函数

| 函数 | 说明 | 示例 |
|------|------|------|
| `printf()` | 格式化输出 | `printf("pid=%d\n", pid)` |
| `str()` | 转换为字符串 | `str(args->filename)` |
| `time()` | 格式化时间 | `time("%H:%M:%S")` |
| `strftime()` | 格式化时间 | `strftime("%H:%M:%S", nsecs)` |
| `ntop()` | 网络地址转字符串 | `ntop($sk->__sk_common.skc_daddr)` |
| `ntohs()` | 网络字节序转换 | `ntohs($sk->__sk_common.skc_dport)` |
| `strcontains()` | 字符串包含检查 | `strcontains(str, "pattern")` |
| `kstack()` | 内核栈 | `kstack(10)` |
| `ustack()` | 用户栈 | `ustack(10)` |

## 3. 实时进程追踪

### 基本进程追踪

```bash
# 追踪所有 execve 调用
bpftrace -e 'tracepoint:syscalls:sys_enter_execve {
    printf("%-6d %-16s %s\n", pid, comm, str(args->filename));
}'
```

### 过滤特定进程

```bash
# 追踪特定用户的进程
bpftrace -e 'tracepoint:syscalls:sys_enter_execve /uid == 1000/ {
    printf("%s\n", str(args->filename));
}'

# 排除特定进程
bpftrace -e 'tracepoint:syscalls:sys_enter_execve /comm != "bpftrace"/ {
    printf("%s\n", str(args->filename));
}'
```

### 追踪父子进程关系

```bash
bpftrace -e 'tracepoint:syscalls:sys_enter_execve {
    printf("pid=%d ppid=%d comm=%s exe=%s\n",
           pid, curtask->parent->tgid, comm, str(args->filename));
}'
```

## 4. 文件访问监控

### 监控特定文件

```bash
# 监控 /etc/passwd 访问
bpftrace -e 'tracepoint:syscalls:sys_enter_openat
/str(args->filename) == "/etc/passwd"/ {
    printf("pid=%d comm=%s uid=%d\n", pid, comm, uid);
}'
```

### 监控目录访问

```bash
# 监控 /etc/ 目录下的写操作
bpftrace -e 'tracepoint:syscalls:sys_enter_openat
/strcontains(str(args->filename), "/etc/") &&
 (args->flags & 0x3) != 0/ {
    printf("WRITE: pid=%d file=%s\n", pid, str(args->filename));
}'
```

### 监控敏感文件

```bash
# 监控多个敏感文件
bpftrace -e '
tracepoint:syscalls:sys_enter_openat
/str(args->filename) == "/etc/shadow" ||
 str(args->filename) == "/etc/sudoers" ||
 strcontains(str(args->filename), ".ssh/")/ {
    printf("SENSITIVE: pid=%d comm=%s file=%s\n",
           pid, comm, str(args->filename));
}'
```

## 5. 网络连接监控

### 追踪 TCP 连接

```bash
# 追踪所有 TCP 连接
bpftrace -e 'kprobe:tcp_connect {
    $sk = (struct sock *)arg0;
    $daddr = ntop($sk->__sk_common.skc_daddr);
    $dport = $sk->__sk_common.skc_dport;
    printf("connect: %s -> %s:%d\n", comm, $daddr, ntohs($dport));
}'
```

### 追踪 DNS 查询

```bash
# 追踪 UDP 53 端口（DNS）
bpftrace -e 'kprobe:udp_sendmsg {
    $sk = (struct sock *)arg0;
    $dport = $sk->__sk_common.skc_dport;
    if (ntohs($dport) == 53) {
        printf("DNS query from pid=%d comm=%s\n", pid, comm);
    }
}'
```

### 监控监听端口

```bash
# 监控 bind 调用（新监听端口）
bpftrace -e 'tracepoint:syscalls:sys_enter_bind {
    printf("bind: pid=%d comm=%s\n", pid, comm);
}'
```

## 6. 提权行为检测

### 监控 setuid/setgid

```bash
bpftrace -e '
tracepoint:syscalls:sys_enter_setuid /args->uid == 0/ {
    printf("setuid to root: pid=%d comm=%s old_uid=%d\n", pid, comm, uid);
}
tracepoint:syscalls:sys_enter_setgid /args->gid == 0/ {
    printf("setgid to root: pid=%d comm=%s old_gid=%d\n", pid, comm, gid);
}'
```

### 监控 sudo/su 执行

```bash
bpftrace -e 'tracepoint:syscalls:sys_enter_execve
/strcontains(str(args->filename), "sudo") ||
 strcontains(str(args->filename), "/su")/ {
    printf("priv exec: pid=%d uid=%d exe=%s\n",
           pid, uid, str(args->filename));
}'
```

### 监控内核模块加载

```bash
bpftrace -e '
tracepoint:syscalls:sys_enter_finit_module {
    printf("module load: pid=%d uid=%d comm=%s\n", pid, uid, comm);
}
tracepoint:syscalls:sys_enter_init_module {
    printf("module load: pid=%d uid=%d comm=%s\n", pid, uid, comm);
}'
```

## 7. eBPF 与 auditd 配合使用

### 分工策略

| 场景 | 使用工具 | 原因 |
|------|----------|------|
| 合规审计 | auditd | 需要持久化记录，符合审计标准 |
| 实时告警 | eBPF | 低延迟，可在内核空间过滤 |
| 事后追溯 | auditd | 日志持久化，可回溯分析 |
| 性能分析 | eBPF | 低开销，支持高频事件 |
| 入侵检测 | 两者结合 | auditd 记录 + eBPF 实时检测 |

### 数据关联

```bash
# eBPF 检测到异常时，记录 audit ID 以便关联
bpftrace -e 'tracepoint:syscalls:sys_enter_execve
/strcontains(str(args->filename), "/tmp/")/ {
    printf("[%s] SUSPICIOUS EXEC: pid=%d uid=%d exe=%s\n",
           strftime("%Y-%m-%d %H:%M:%S", nsecs),
           pid, uid, str(args->filename));
    printf("  -> Use: ausearch -ts %s -k process_suspicious\n",
           strftime("%H:%M:%S", nsecs));
}'
```

## 8. openEuler / FusionOS 的 eBPF 支持差异

### openEuler

- **版本要求**：22.03+（kernel 5.10+）默认内核配置支持 eBPF，具体功能取决于内核编译选项
- **BTF 支持**：默认启用（/sys/kernel/btf/vmlinux）
- **安装方法**：`yum install bpftrace bcc-tools`
- **A-Ops 集成**：A-Ops 项目使用 eBPF 进行系统诊断

### FusionOS

- **版本要求**：基于 openEuler 内核，同级支持
- **BTF 支持**：默认启用
- **安装方法**：`yum install bpftrace bcc-tools`
- **安全增强**：可能有更严格的 eBPF 权限控制

### 兼容性检查

```bash
# 检查内核版本
uname -r

# 检查 BTF 支持
ls -la /sys/kernel/btf/vmlinux

# 检查 bpftrace
bpftrace --version

# 检查 bcc-tools
execsnoop-bpfcc --help 2>/dev/null || execsnoop --help 2>/dev/null
```

## 9. 性能考虑

### 开销评估

| 监控类型 | CPU 开销 | 适用场景 |
|----------|----------|----------|
| 进程追踪 | 低 | 持续监控 |
| 文件监控 | 中 | 关键文件 |
| 网络追踪 | 低 | 持续监控 |
| 提权检测 | 低 | 持续监控 |

### 最佳实践

1. **过滤条件**：在内核空间过滤，减少用户空间开销
2. **采样频率**：对于高频事件，使用采样而非全量追踪
3. **输出限制**：避免大量 printf 输出影响性能
4. **持续时间**：根据需要设置监控持续时间
5. **资源监控**：监控 bpftrace 进程本身的资源使用

## 10. 安全注意事项

1. **权限控制**：eBPF 需要 root 权限，确保脚本来源可信
2. **脚本审查**：使用前审查 bpftrace 脚本内容
3. **避免干扰**：不要在生产环境使用可能影响性能的复杂脚本
4. **日志记录**：eBPF 输出建议同时记录到文件
5. **合规性**：eBPF 监控记录可能不满足某些合规审计要求，需配合 auditd
