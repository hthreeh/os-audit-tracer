# 进程异常行为检测

## 检测目标

识别可疑进程、隐藏进程、异常父子关系、挖矿程序、后门进程等。

---

## 1. 可疑进程路径检测

### 检测原理

正常进程通常位于 /usr/bin、/usr/sbin 等标准路径。从 /tmp、/dev/shm、/var/tmp 等目录执行的进程高度可疑。

### 检测命令

```bash
# 从临时目录执行的进程
ps -eo pid,ppid,user,args | grep -E "/tmp/|/dev/shm/|/var/tmp/"

# 检查 /proc 中的可执行文件链接
ls -la /proc/*/exe 2>/dev/null | grep -E "/tmp/|/dev/shm/|/var/tmp/|\(deleted\)"

# 检查已删除但仍运行的进程（进程注入特征）
ls -la /proc/*/exe 2>/dev/null | grep "(deleted)"

# 检查内存中的进程（无对应文件）
for pid in $(ls /proc | grep -E "^[0-9]+$"); do
  exe=$(readlink /proc/$pid/exe 2>/dev/null)
  if [ -n "$exe" ] && [ ! -f "$exe" ] && [ "$exe" != "(deleted)" ]; then
    echo "NO FILE: pid=$pid exe=$exe"
  fi
done
```

### auditd 规则

```bash
# 监控从 /tmp 执行的程序（注意：arch=b64 仅适用于 x86_64，aarch64 需改为 arch=aarch64）
-a always,exit -F arch=b64 -S execve -F dir=/tmp -k tmp_exec
-a always,exit -F arch=b64 -S execve -F dir=/dev/shm -k shm_exec
-a always,exit -F arch=b64 -S execve -F dir=/var/tmp -k vartmp_exec
```

### 判定阈值

| 条件 | 风险等级 | 说明 |
|------|----------|------|
| /tmp 下执行的程序 | CRITICAL | 高度可疑 |
| /dev/shm 下执行的程序 | CRITICAL | 内存文件系统执行 |
| 已删除文件仍在执行 | HIGH | 可能恶意进程 |
| 无对应文件的进程 | HIGH | 内存注入 |

---

## 2. 异常父子进程关系

### 检测原理

攻击者常通过合法进程（如 web 服务器）启动 shell，形成异常的父子关系。

### 检测命令

```bash
# 完整进程树
ps auxf

# 检查 web 服务器进程下的 shell
ps auxf | grep -B5 -E "bash|sh|dash|zsh" | grep -E "httpd|nginx|apache|tomcat|java"

# 检查数据库进程下的 shell
ps auxf | grep -B5 -E "bash|sh|dash|zsh" | grep -E "mysql|postgres|redis|mongo"

# 检查 cron 下的异常进程
ps auxf | grep -B3 -E "bash|sh|dash" | grep -E "cron|atd"

# 检查异常的进程继承关系
for pid in $(ps -eo pid --no-headers); do
  ppid=$(cat /proc/$pid/stat 2>/dev/null | awk '{print $4}')
  if [ -n "$ppid" ] && [ "$ppid" != "0" ] && [ "$ppid" != "1" ]; then
    parent_name=$(cat /proc/$ppid/comm 2>/dev/null)
    child_name=$(cat /proc/$pid/comm 2>/dev/null)
    # 检查 web 服务器启动 shell
    if echo "$parent_name" | grep -qE "httpd|nginx|apache|tomcat"; then
      if echo "$child_name" | grep -qE "bash|sh|dash|python|perl"; then
        echo "SUSPICIOUS: $parent_name(pid=$ppid) -> $child_name(pid=$pid)"
      fi
    fi
  fi
done
```

### 判定阈值

| 条件 | 风险等级 | 说明 |
|------|----------|------|
| web 服务器 → bash/sh | CRITICAL | webshell 执行 |
| 数据库 → bash/sh | CRITICAL | 数据库提权 |
| cron → 异常命令 | HIGH | cron 后门 |
| init/systemd 之外的孤儿进程 | MEDIUM | 可能逃逸进程 |

---

## 3. 挖矿程序检测

### 检测特征

- 高 CPU 使用率
- 连接到矿池端口（3333, 4444, 5555, 8888, 9999 等）
- 进程名伪装（如 kworker, kthreadd 的仿冒）
- 命令行包含矿池地址

### 检测命令

```bash
# CPU 使用率最高的进程
ps aux --sort=-%cpu | head -20

# 检查矿池连接
ss -tunap | grep -E ":(3333|4444|5555|7777|8888|9999|14433|14444|45560)"

# 检查挖矿关键词
ps aux | grep -iE "xmr|eth|mine|miner|stratum|pool|hashrate|cryptonight|randomx"

# 检查可疑的 kworker 进程（仿冒内核线程）
ps aux | grep "kworker" | grep -v "\["

# 检查 crontab 中的挖矿脚本
crontab -l 2>/dev/null | grep -iE "curl|wget|mine|pool|xmr"

# 检查 /tmp 下的挖矿相关文件
find /tmp -name "*miner*" -o -name "*xmr*" -o -name "*stratum*" 2>/dev/null
```

### 判定阈值

| 条件 | 风险等级 | 说明 |
|------|----------|------|
| 连接到矿池端口 | CRITICAL | 确认挖矿 |
| CPU 使用率 > 90% 持续 10 分钟 | HIGH | 可能挖矿 |
| 命令行含矿池关键词 | CRITICAL | 确认挖矿 |
| 仿冒内核线程名 | HIGH | 隐藏挖矿进程 |
| /tmp 下挖矿文件 | CRITICAL | 挖矿程序 |

---

## 4. 后门进程检测

### 检测命令

```bash
# 检查反弹 Shell（已在网络异常中详述）
ss -tunap | grep -E "bash|sh|dash" | grep ESTAB

# 检查 SSH 反向隧道
ps aux | grep "ssh.*-[LR]" | grep -v grep

# 检查 Web 后门进程
ps aux | grep -iE "webshell|c99|r57|b374k|china chopper|antsword|behinder|godzilla"

# 检查 nc 监听
ss -tlnp | grep "nc\|ncat\|netcat\|socat"

# 检查 Python/Perl/Ruby 后门
ps aux | grep -iE "python.*-c|perl.*-e|ruby.*-e" | grep -v grep

# 检查隐藏进程（/proc 中存在但 ps 中不显示）
diff <(ls /proc | grep -E "^[0-9]+$" | sort -n) <(ps -eo pid --no-headers | awk '{print $1}' | sort -n)
```

### 判定阈值

| 条件 | 风险等级 | 说明 |
|------|----------|------|
| SSH 反向隧道运行中 | CRITICAL | 远程访问后门 |
| nc/ncat 监听端口 | HIGH | 可能后门监听 |
| python -c / perl -e 运行中 | HIGH | 一行命令后门 |
| 隐藏进程（ps 不显示） | CRITICAL | rootkit 隐藏 |
| Web 后门关键词匹配 | CRITICAL | Webshell 进程 |

---

## 5. 进程权限异常

### 检测命令

```bash
# 检查非 root 用户运行的特权进程
ps -eo pid,user,comm | awk '$2 != "root" && $1 > 2' | while read pid user comm; do
  caps=$(cat /proc/$pid/status 2>/dev/null | grep "CapEff" | awk '{print $2}')
  if [ "$caps" != "0000000000000000" ] && [ -n "$caps" ]; then
    echo "CAPS: pid=$pid user=$user comm=$comm caps=$caps"
  fi
done

# 检查 capability 异常的进程
for pid in $(ls /proc | grep -E "^[0-9]+$"); do
  cap=$(getpcaps $pid 2>/dev/null | grep -v "=")
  if [ -n "$cap" ]; then
    user=$(stat -c '%U' /proc/$pid 2>/dev/null)
    echo "pid=$pid user=$user caps=$cap"
  fi
done

# 检查进程的命名空间（容器逃逸检测）
ls -la /proc/1/ns/
for pid in $(ls /proc | grep -E "^[0-9]+$"); do
  if [ -d "/proc/$pid/ns" ]; then
    pid_ns=$(readlink /proc/$pid/ns/pid 2>/dev/null)
    init_ns=$(readlink /proc/1/ns/pid 2>/dev/null)
    if [ "$pid_ns" != "$init_ns" ]; then
      echo "DIFFERENT NS: pid=$pid"
    fi
  fi
done
```

### 判定阈值

| 条件 | 风险等级 | 说明 |
|------|----------|------|
| 非 root 进程有异常 capability | HIGH | 提权后进程 |
| 进程命名空间异常 | HIGH | 容器逃逸 |
| 进程运行在 init ns 外 | MEDIUM | 容器进程 |

---

## 6. 进程隐藏检测

### 检测命令

```bash
# 方法 1: 对比 /proc 和 ps 输出
proc_pids=$(ls /proc | grep -E "^[0-9]+$" | sort -n)
ps_pids=$(ps -eo pid --no-headers | awk '{print $1}' | sort -n)
echo "Hidden processes:"
comm -23 <(echo "$proc_pids") <(echo "$ps_pids")

# 方法 2: 使用不同方式获取进程列表
ps aux | wc -l
ls /proc | grep -cE "^[0-9]+$"
echo "If counts differ significantly, processes may be hidden"

# 方法 3: 检查 /proc 中进程的 cmdline
for pid in $(ls /proc | grep -E "^[0-9]+$"); do
  cmdline=$(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ')
  if [ -z "$cmdline" ]; then
    comm=$(cat /proc/$pid/comm 2>/dev/null)
    echo "EMPTY CMDLINE: pid=$pid comm=$comm"
  fi
done
```

### 判定阈值

| 条件 | 风险等级 | 说明 |
|------|----------|------|
| /proc 中有但 ps 中无 | CRITICAL | rootkit 隐藏 |
| 空 cmdline 的进程 | HIGH | 可能隐藏恶意进程 |
| 进程数差异 > 5 | HIGH | 大量进程被隐藏 |

---

## 7. 定时任务异常

### 检测命令

```bash
# 所有用户的 crontab
for user in $(cut -d: -f1 /etc/passwd); do
  crontab=$(crontab -l -u "$user" 2>/dev/null)
  if [ -n "$crontab" ]; then
    echo "=== $user ==="
    echo "$crontab"
  fi
done

# 系统级 cron
cat /etc/crontab
ls -la /etc/cron.d/
cat /etc/cron.d/*

# 检查 cron 中的可疑命令
grep -rE "curl|wget|bash|nc|ncat|python|perl|/tmp/|/dev/shm/" \
  /etc/crontab /etc/cron.d/ /var/spool/cron/ 2>/dev/null

# 检查 at 队列
atq

# 检查 systemd timer
systemctl list-timers --all
```

### 判定阈值

| 条件 | 风险等级 | 说明 |
|------|----------|------|
| cron 中有 curl/wget 到外部 | CRITICAL | 持久化后门 |
| cron 中执行 /tmp 下脚本 | CRITICAL | 恶意脚本 |
| 非 root 用户的异常 cron | HIGH | 可能后门 |
| at 队列中的异常任务 | HIGH | 一次性后门 |

---

## 综合检测流程

```
进程异常检测
    │
    ├─ 1. 可疑路径进程
    │     └─ /tmp, /dev/shm 下执行 → CRITICAL
    │
    ├─ 2. 异常父子关系
    │     └─ web/db → shell → CRITICAL
    │
    ├─ 3. 挖矿检测
    │     └─ 矿池连接/高 CPU → ALERT
    │
    ├─ 4. 后门进程检测
    │     └─ 反弹 Shell/隧道/隐藏 → CRITICAL
    │
    ├─ 5. 权限异常检测
    │     └─ 非 root 特权进程 → ALERT
    │
    ├─ 6. 进程隐藏检测
    │     └─ /proc vs ps 差异 → CRITICAL
    │
    └─ 7. 定时任务异常
          └─ cron 中 curl/wget → ALERT
```
