# 全量日志源目录

## 1. 日志源总览

| 日志源 | 路径 | 格式 | 内容 | 优先级 |
|--------|------|------|------|--------|
| 审计日志 | `/var/log/audit/audit.log` | 二进制/文本 | 所有 auditd 事件 | 最高 |
| 安全日志 | `/var/log/secure` | 文本 | 认证、授权事件 | 高 |
| 系统日志 | `/var/log/messages` | 文本 | 系统级事件、内核消息 | 高 |
| 定时任务 | `/var/log/cron` | 文本 | cron 任务执行 | 中 |
| 启动日志 | `/var/log/boot.log` | 文本 | 启动时消息 | 中 |
| 最后登录 | `/var/log/lastlog` | 二进制 | 每用户最后登录时间 | 中 |
| 登录记录 | `/var/log/wtmp` | 二进制 | 成功登录历史 | 高 |
| 失败登录 | `/var/log/btmp` | 二进制 | 失败登录尝试 | 高 |
| systemd 日志 | `/var/log/journal/` 或 `/run/log/journal/` | 二进制 | 结构化日志 | 高 |
| 防火墙 | `/var/log/firewalld` 或 via journal | 文本 | 防火墙规则命中 | 中 |
| SELinux | via audit.log (avc type) | 二进制 | SELinux 策略决策 | 高 |

## 2. audit.log 字段解析

### 事件类型

| 类型 | 说明 | 关键字段 |
|------|------|----------|
| SYSCALL | 系统调用事件 | syscall, arch, success, exit, a0-a3, ppid, pid, uid, comm, exe, key |
| PATH | 文件路径信息 | name, inode, dev, mode, ouid, ogid |
| EXECVE | 命令执行详情 | argc, a0, a1, a2, ... |
| CWD | 当前工作目录 | cwd |
| SOCKADDR | 网络地址信息 | saddr_fam, laddr, lport, raddr, rport |
| USER_AUTH | 用户认证 | op, acct, addr, hostname, terminal |
| USER_ACCT | 用户账户操作 | op, acct, addr |
| LOGIN | 登录事件 | pid, uid, subj, acct |
| AVC | SELinux 拒绝 | avc, denied, scontext, tcontext, tclass |
| CONFIG_CHANGE | 配置变更 | op, key, list, res |
| SYSCALL_EXECVE | execve 详情 | comm, exe, key |

### SYSCALL 事件示例

```
type=SYSCALL msg=audit(1705312985.123:456): arch=c000003e syscall=59 success=yes exit=0 
a0=7ffd12345678 a1=7ffd12345690 a2=7ffd12345700 a3=0 items=2 ppid=1000 pid=12345 
auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 
comm="useradd" exe="/usr/sbin/useradd" key="privilege"
```

**字段说明**：
- `arch=c000003e`: x86_64 架构（c0000028 = aarch64）
- `syscall=59`: execve 系统调用
- `success=yes`: 操作成功
- `auid=1000`: 审计 UID（登录时的原始用户）
- `uid=0`: 实际 UID（root）
- `euid=0`: 有效 UID
- `comm="useradd"`: 命令名
- `exe="/usr/sbin/useradd"`: 可执行文件路径
- `key="privilege"`: 审计规则标识键

### PATH 事件示例

```
type=PATH msg=audit(1705312985.123:456): item=0 name="/usr/sbin/useradd" 
inode=123456 dev=08:02 mode=0100755 ouid=0 ogid=0 rdev=00:00
```

### EXECVE 事件示例

```
type=EXECVE msg=audit(1705312985.123:456): argc=3 a0="useradd" a1="-m" a2="backdoor_user"
```

### SOCKADDR 事件示例

```
type=SOCKADDR msg=audit(1705312985.123:456): saddr_fam=inet laddr=192.168.1.10 lport=22 
raddr=192.168.1.100 rport=54321
```

### AVC 事件示例

```
type=AVC msg=audit(1705312985.123:456): avc: denied { read } for pid=12345 
comm="httpd" name="index.html" dev="sda1" ino=789 
scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file
```

## 3. /var/log/secure 字段解析

### 事件格式

```
Jan 15 14:23:01 hostname sshd[12345]: Failed password for admin from 192.168.1.100 port 22 ssh2
Jan 15 14:23:05 hostname sshd[12345]: Accepted publickey for admin from 192.168.1.100 port 22 ssh2
Jan 15 14:23:10 hostname sudo: admin : TTY=pts0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/useradd -m backdoor_user
Jan 15 14:23:15 hostname su: admin to root on /dev/pts/0
```

### 关键事件模式

| 模式 | 事件类型 | 风险级别 |
|------|----------|----------|
| `Failed password for (.+) from (.+)` | 密码认证失败 | 中 |
| `Accepted publickey for (.+) from (.+)` | 密钥认证成功 | 低 |
| `Accepted password for (.+) from (.+)` | 密码认证成功 | 低 |
| `Failed password for invalid user (.+)` | 无效用户尝试 | 高 |
| `sudo:.+COMMAND=` | sudo 命令执行 | 中 |
| `su:.+to root` | su 切换到 root | 中 |
| `session opened for user (.+)` | 会话打开 | 低 |
| `session closed for user (.+)` | 会话关闭 | 低 |
| `authentication failure` | 认证失败 | 中 |
| `pam_unix.+authentication failure` | PAM 认证失败 | 中 |

## 4. journalctl 过滤技巧

### 按服务过滤

```bash
journalctl -u sshd                    # SSH 服务日志
journalctl -u auditd                  # auditd 服务日志
journalctl -u firewalld               # 防火墙日志
```

### 按时间过滤

```bash
journalctl --since "2024-01-15 14:00:00" --until "2024-01-15 15:00:00"
journalctl --since "1 hour ago"
journalctl --since today
```

### 按优先级过滤

```bash
journalctl -p err                     # 错误及以上
journalctl -p warning                 # 警告及以上
journalctl -p crit                    # 严重及以上
```

### 按用户过滤

```bash
journalctl _UID=0                     # root 用户
journalctl _UID=1000                  # 特定 UID
```

### 按进程过滤

```bash
journalctl _PID=12345                 # 特定 PID
journalctl _COMM=sshd                 # 特定命令名
```

### 内核消息

```bash
journalctl -k                         # 内核消息
journalctl -k -p err                  # 内核错误
```

### 组合过滤

```bash
journalctl -u sshd --since today -p warning
journalctl _COMM=sudo --since "2024-01-15" --until "2024-01-16"
```

## 5. 二进制日志读取方法

### wtmp（成功登录记录）

```bash
# 查看登录历史
last -20

# 查看特定用户
last username

# 查看特定时间段
last -s "2024-01-15" -t "2024-01-16"

# 查看重启记录
last reboot

# 查看关机记录
last shutdown
```

### btmp（失败登录记录）

```bash
# 查看失败登录
lastb -20

# 查看特定用户
lastb username

# 统计失败登录次数
lastb | wc -l
```

### lastlog（最后登录）

```bash
# 查看所有用户最后登录
lastlog

# 查看特定用户
lastlog -u username

# 查看从未登录的用户
lastlog | grep Never
```

## 6. 日志关联分析

### 跨日志源关联

当分析一个安全事件时，需要关联多个日志源：

1. **时间关联**：以时间戳为基准，对齐不同日志源的事件
2. **用户关联**：通过 UID / username 关联不同日志中的同一用户
3. **进程关联**：通过 PID / command 关联进程行为
4. **网络关联**：通过 IP / port 关联网络活动

### 关联示例

```
[secure]     Jan 15 14:23:05 sshd: Accepted publickey for admin from 192.168.1.100
[audit.log]  type=SYSCALL ... pid=12345 uid=1000 comm="sshd" key="login"
[audit.log]  type=USER_AUTH ... acct="admin" addr=192.168.1.100
[messages]   Jan 15 14:23:06 systemd: Started session 1234 of user admin
```

这三个日志条目描述了同一个登录事件，通过时间（14:23:05-06）和用户（admin）关联。
