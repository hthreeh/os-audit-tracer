# 提权行为检测模式

## 检测目标

识别本地权限提升行为，包括 SUID/SGID 滥用、capability 利用、内核漏洞利用、容器逃逸等。

---

## 1. SUID/SGID 文件异常

### 检测原理

SUID 文件以文件所有者权限运行，SGID 以文件所属组权限运行。异常的 SUID/SGID 文件是常见的提权手段。

### 检测命令

```bash
# 查找所有 SUID 文件
find / -perm -4000 -type f 2>/dev/null

# 查找所有 SGID 文件
find / -perm -2000 -type f 2>/dev/null

# 与基线对比（检测新增 SUID 文件）
find / -perm -4000 -type f 2>/dev/null | sort > /tmp/suid_current.txt
diff /tmp/suid_baseline.txt /tmp/suid_current.txt

# 检查非标准路径下的 SUID 文件
find / -perm -4000 -type f 2>/dev/null | grep -vE "^/(usr/)?(bin|sbin)/"

# 检查 SUID 文件的修改时间
find / -perm -4000 -type f -exec stat --format="%n %y" {} \; 2>/dev/null
```

### auditd 规则

```bash
# 监控 SUID/SGID 位设置（注意：arch=b64 仅适用于 x86_64，aarch64 需改为 arch=aarch64）
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F a1&04000 -k suid_change
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F a1&02000 -k sgid_change

# 监控 /usr/bin 和 /usr/sbin 下文件属性变更
-w /usr/bin -p x -k bin_exec
-w /usr/sbin -p x -k sbin_exec
```

### 判定阈值

| 条件 | 风险等级 | 说明 |
|------|----------|------|
| /tmp 或 /dev/shm 下出现 SUID 文件 | CRITICAL | 典型提权后门 |
| /home 下出现 SUID 文件 | HIGH | 用户级提权尝试 |
| 新增非标准 SUID 文件 | HIGH | 可能后门植入 |
| 已知工具 SUID 化（nmap/python/perl） | CRITICAL | 经典提权手法 |
| /usr/bin 下 SUID 文件被替换 | CRITICAL | 系统工具篡改 |

### 常见提权 SUID 工具

```
nmap, python, perl, ruby, php, bash, sh, dash, vim, find, awk, env, less, more
```

---

## 2. Capability 滥用

### 检测原理

Linux capability 将 root 权限细分为多个独立能力。异常 capability 可用于提权。

### 检测命令

```bash
# 查找所有带 capability 的文件
getcap -r / 2>/dev/null

# 检查关键 capability
getcap -r / 2>/dev/null | grep -E "cap_setuid|cap_setgid|cap_sys_admin|cap_dac_override|cap_net_raw"

# 与基线对比
getcap -r / 2>/dev/null | sort > /tmp/cap_current.txt
diff /tmp/cap_baseline.txt /tmp/cap_current.txt
```

### 判定阈值

| 条件 | 风险等级 | 说明 |
|------|----------|------|
| cap_setuid 在非标准文件上 | CRITICAL | 可直接提权 |
| cap_sys_admin 在用户工具上 | HIGH | 可绕过权限检查 |
| cap_dac_override | HIGH | 绕过文件权限 |
| /tmp 下文件带 capability | CRITICAL | 恶意利用 |

---

## 3. sudo 配置审计

### 检测原理

sudoers 配置不当可导致提权，如允许执行特定命令的用户利用命令特性获取 shell。

### 检测命令

```bash
# 检查 sudoers 语法
visudo -c

# 检查 NOPASSWD 配置
grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/

# 检查危险命令授权
grep -rE "(ALL|!/)" /etc/sudoers /etc/sudoers.d/ | grep -v "^#"

# 检查 sudoers 文件权限
ls -la /etc/sudoers /etc/sudoers.d/

# 检查 sudo 版本漏洞
sudo --version | head -1
```

### 常见提权场景

```bash
# 1. vim 提权
sudo vim -c ':!/bin/bash'

# 2. find 提权
sudo find / -exec /bin/bash \;

# 3. awk 提权
sudo awk 'BEGIN {system("/bin/bash")}'

# 4. less/more 提权
sudo less /etc/passwd
# 在 less 中输入: !/bin/bash

# 5. nmap NSE 脚本提权（--interactive 已在 nmap 5.10+ 移除）
sudo nmap --script=<malicious-script>
```

### 判定阈值

| 条件 | 风险等级 | 说明 |
|------|----------|------|
| NOPASSWD + 危险命令 | CRITICAL | 可直接提权 |
| sudoers 文件权限 > 0440 | HIGH | 可能被篡改 |
| ALL=(ALL) 授权给非 wheel 用户 | HIGH | 完整 root 权限 |
| 允许编辑 sudoers 的用户 | HIGH | 可添加任意规则 |

---

## 4. 内核模块与 eBPF 提权

### 检测命令

```bash
# 检查内核模块加载
lsmod | tail -20
dmesg | grep -i "module"

# 监控模块加载（注意：arch=b64 仅适用于 x86_64，aarch64 需改为 arch=aarch64）
auditctl -a always,exit -F arch=b64 -S init_module -S finit_module -k module_load

# 检查 eBPF 程序
bpftool prog list 2>/dev/null
```

### 判定阈值

| 条件 | 风险等级 | 说明 |
|------|----------|------|
| 非预期的内核模块加载 | HIGH | 可能 rootkit |
| /tmp 下的 .ko 文件 | CRITICAL | 恶意模块 |
| eBPF 程序注入 | HIGH | 内核级代码执行 |

---

## 5. ptrace 进程注入

### 检测原理

ptrace 系统调用可附加到其他进程，注入代码执行。

### 检测命令

```bash
# 监控 ptrace 调用（注意：arch=b64 仅适用于 x86_64，aarch64 需改为 arch=aarch64）
auditctl -a always,exit -F arch=b64 -S ptrace -k ptrace_use

# 检查 ptrace 使用
ausearch -k ptrace_use -ts recent
```

### 判定阈值

| 条件 | 风险等级 | 说明 |
|------|----------|------|
| ptrace 附加到特权进程 | CRITICAL | 进程注入提权 |
| ptrace 从非标准路径 | HIGH | 可能恶意行为 |

---

## 6. cron/at 提权

### 检测原理

通过修改 cron 任务或 at 队列，以 root 权限执行任意命令。

### 检测命令

```bash
# 监控 cron 文件变更
auditctl -w /etc/crontab -p wa -k cron_change
auditctl -w /var/spool/cron -p wa -k cron_change
auditctl -w /etc/cron.d -p wa -k cron_change

# 检查 cron 中的 root 任务
crontab -l -u root 2>/dev/null
cat /etc/crontab
ls -la /etc/cron.d/

# 检查 cron 文件权限
find /var/spool/cron -type f -exec ls -la {} \;
```

### 判定阈值

| 条件 | 风险等级 | 说明 |
|------|----------|------|
| 非 root 用户修改 root cron | CRITICAL | 直接提权路径 |
| cron 文件权限异常 | HIGH | 可能被篡改 |
| cron 执行 /tmp 下脚本 | CRITICAL | 恶意脚本执行 |

---

## 7. 计划任务提权（systemd timer）

### 检测命令

```bash
# 检查 systemd timer
systemctl list-timers --all

# 检查 service 文件变更
find /etc/systemd/system -newer /etc/passwd -type f
find /usr/lib/systemd/system -newer /etc/passwd -type f

# 监控 service 文件
auditctl -w /etc/systemd/system -p wa -k systemd_change
```

### 判定阈值

| 条件 | 风险等级 | 说明 |
|------|----------|------|
| 新增 root 权限 service | HIGH | 可能后门服务 |
| service 文件权限异常 | MEDIUM | 检查所有者 |
| ExecStart 指向 /tmp | CRITICAL | 恶意执行 |

---

## 8. Docker/容器提权

### 检测命令

```bash
# 检查特权容器
docker ps --format '{{.Names}}' | while read c; do
  docker inspect "$c" --format '{{.HostConfig.Privileged}}' | grep -q true && echo "PRIVILEGED: $c"
done

# 检查 docker.sock 暴露
ls -la /var/run/docker.sock

# 检查容器内 root 用户映射
docker ps --format '{{.Names}}' | while read c; do
  echo "$c: $(docker exec "$c" whoami 2>/dev/null)"
done
```

### 判定阈值

| 条件 | 风险等级 | 说明 |
|------|----------|------|
| 特权容器运行 | HIGH | 可逃逸到宿主机 |
| docker.sock 可被非 root 访问 | CRITICAL | 完全控制 Docker |
| 容器内映射宿主机敏感目录 | HIGH | 文件系统逃逸 |

---

## 综合检测流程

```
提权行为检测
    │
    ├─ 1. SUID/SGID 异常扫描
    │     └─ 新增/异常 SUID → ALERT
    │
    ├─ 2. Capability 滥用检查
    │     └─ 非标准 capability → ALERT
    │
    ├─ 3. sudo 配置审计
    │     └─ NOPASSWD + 危险命令 → ALERT
    │
    ├─ 4. 内核模块检查
    │     └─ 非预期模块 → ALERT
    │
    ├─ 5. ptrace 注入检查
    │     └─ 特权进程注入 → ALERT
    │
    ├─ 6. cron 提权检查
    │     └─ root cron 被篡改 → ALERT
    │
    └─ 7. 容器提权检查
          └─ 特权容器/sock 暴露 → ALERT
```
