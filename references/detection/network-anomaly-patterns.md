# 网络异常行为检测

## 检测目标

识别异常网络连接、C2 通信、数据外泄、横向移动等网络层面的攻击行为。

---

## 1. 异常外连检测

### 检测命令

```bash
# 当前活动连接
ss -tunap

# 检查非标准端口的外连
ss -tunap | grep ESTAB | awk '{print $5}' | grep -vE ":(22|80|443|53|25|993|995|143|110)" | sort | uniq

# 检查 root 用户的外连
ss -tunap | grep "users:((" | grep "uid:0"

# 检查来自 /tmp 的进程的网络连接
ls -la /proc/*/exe 2>/dev/null | grep "/tmp\|/dev/shm" | while read line; do
  pid=$(echo "$line" | grep -oP '/proc/\K[0-9]+')
  ss -tunap | grep "pid=$pid"
done

# 检查大量连接的目标 IP
ss -tunap | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -20
```

### auditd 规则

```bash
# 监控网络连接
-a always,exit -F arch=b64 -S connect -k network_connect
-a always,exit -F arch=b64 -S accept -k network_accept
-a always,exit -F arch=b64 -S bind -k network_bind
```

### 判定阈值

| 条件 | 风险等级 | 说明 |
|------|----------|------|
| 非标准端口外连（非 22/80/443/53） | MEDIUM | 需进一步确认 |
| /tmp 进程建立网络连接 | CRITICAL | 恶意软件活动 |
| root 用户非预期外连 | HIGH | 可能后门通信 |
| 大量短连接到同一 IP | HIGH | 扫描或 C2 通信 |
| 凌晨时段的异常外连 | MEDIUM | 非工作时间活动 |

---

## 2. 反弹 Shell 检测

### 检测原理

反弹 Shell 是攻击者获取交互式访问的常见手段，通常表现为进程的标准输入/输出重定向到网络连接。

### 检测命令

```bash
# 检查 bash/sh 的网络连接（经典反弹 Shell 特征）
ss -tunap | grep -E "bash|sh|dash|zsh" | grep ESTAB

# 检查 /dev/tcp 连接（bash 内建反弹 Shell）
grep -r "/dev/tcp" /proc/*/cmdline 2>/dev/null

# 检查常见反弹 Shell 命令
ausearch -m EXECVE -ts recent 2>/dev/null | grep -iE "bash -i|nc -e|ncat|socat|python.*socket|perl.*socket|php.*fsockopen|ruby.*TCPSocket"

# 检查进程树中的可疑组合
ps auxf | grep -B5 -A5 -E "bash.*-i|nc.*-e|ncat.*-e"

# 检查 iptables 重定向（端口转发后门）
iptables -t nat -L -n --line-numbers
```

### 判定阈值

| 条件 | 风险等级 | 说明 |
|------|----------|------|
| bash/sh 有 ESTAB 连接 | CRITICAL | 极可能是反弹 Shell |
| /dev/tcp 出现在进程参数中 | CRITICAL | bash 反弹 Shell |
| nc -e / ncat -e 命令 | CRITICAL | netcat 反弹 Shell |
| python/perl/php socket 调用 | HIGH | 脚本语言反弹 Shell |
| iptables NAT 规则异常 | HIGH | 端口转发后门 |

---

## 3. C2 通信检测

### 检测特征

- 周期性心跳连接
- DNS 隧道（高频 TXT 查询）
- 加密通道到异常 IP/域名
- HTTP/HTTPS 通信中的异常 User-Agent

### 检测命令

```bash
# 检查周期性连接（同一 IP 多次出现）
ss -tunap | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn

# 检查 DNS 查询（高频 TXT 记录查询）
tcpdump -i any -n port 53 -c 100 2>/dev/null | grep "TXT\|ANY"

# 检查异常 DNS 域名长度（DNS 隧道特征）
tcpdump -i any -n port 53 -c 100 2>/dev/null | \
  grep -oP '(\S+\.)+\S+' | awk '{if(length($0)>50) print}'

# 检查已知 C2 端口
ss -tunap | grep -E ":(4444|5555|6666|7777|8888|9999|1234|31337|1337)"

# 检查异常 User-Agent
grep -iE "curl|wget|python-requests|Go-http" /var/log/nginx/access.log 2>/dev/null | head -20
```

### 判定阈值

| 条件 | 风险等级 | 说明 |
|------|----------|------|
| 周期性连接到外部 IP | HIGH | 可能 C2 心跳 |
| 高频 DNS TXT 查询 | HIGH | DNS 隧道 |
| 已知 C2 端口通信 | CRITICAL | 确认 C2 通信 |
| 长域名 DNS 查询 | MEDIUM | DNS 隧道特征 |
| 加密通信到异常 IP | MEDIUM | 需威胁情报关联 |

---

## 4. 数据外泄检测

### 检测命令

```bash
# 检查大量数据传输（通过 ss 统计）
ss -tunap | grep ESTAB | while read line; do
  ip=$(echo "$line" | awk '{print $5}' | cut -d: -f1)
  echo "$line"
done

# 检查 scp/sftp/rsync 传输
ausearch -m EXECVE -ts recent 2>/dev/null | grep -iE "scp|sftp|rsync|curl.*-F|wget.*--post"

# 检查压缩后的数据传输（常见外泄手法）
ausearch -m EXECVE -ts recent 2>/dev/null | grep -iE "tar.*\|.*nc|zip.*\|.*curl|gzip.*\|.*ssh"

# 检查 base64 编码传输
ausearch -m EXECVE -ts recent 2>/dev/null | grep -i "base64"

# 检查 iptables 日志（异常出站流量）
grep "IPTABLES" /var/log/messages | grep -i "drop\|reject" | tail -20
```

### 判定阈值

| 条件 | 风险等级 | 说明 |
|------|----------|------|
| tar/zip + 网络传输命令链 | CRITICAL | 数据打包外传 |
| scp/rsync 到非白名单 IP | HIGH | 数据外传 |
| base64 编码 + 网络传输 | HIGH | 混淆数据外传 |
| 大量数据从服务器流出 | HIGH | 数据外泄 |

---

## 5. 横向移动检测

### 检测命令

```bash
# 检查 SSH 跳转（从本机 SSH 到其他机器）
ausearch -m EXECVE -ts recent 2>/dev/null | grep "ssh " | grep -v "sshd"

# 检查内网扫描工具
ausearch -m EXECVE -ts recent 2>/dev/null | grep -iE "nmap|masscan|zmap|fscan|goby"

# 检查代理工具
ausearch -m EXECVE -ts recent 2>/dev/null | grep -iE "proxychains|reGeorg|frp|chisel|ngrok|socat"

# 检查内网连接模式（本机同时连接多个内网 IP）
ss -tunap | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | \
  grep -vE "^(127\.0\.0\.1|0\.0\.0\.0|\*)"

# 检查凭据传递攻击
ausearch -m EXECVE -ts recent 2>/dev/null | grep -iE "psexec|wmiexec|smbexec|atexec|dcomexec"
```

### 判定阈值

| 条件 | 风险等级 | 说明 |
|------|----------|------|
| 内网扫描工具执行 | CRITICAL | 主机被用于横向移动 |
| SSH 到多个内网主机 | HIGH | 跳板行为 |
| 代理工具运行 | CRITICAL | 隧道/代理后门 |
| 凭据传递工具 | CRITICAL | 横向移动攻击 |

---

## 6. DNS 异常检测

### 检测命令

```bash
# 检查 DNS 配置变更
cat /etc/resolv.conf
stat /etc/resolv.conf

# 检查 hosts 文件篡改
cat /etc/hosts
stat /etc/hosts

# 检查异常 DNS 查询频率
tcpdump -i any -n port 53 -c 500 2>/dev/null | wc -l

# 检查 DNS 查询的目标域名长度分布
tcpdump -i any -n port 53 -c 200 2>/dev/null | \
  grep -oP 'A\?\s+\K(\S+)' | awk '{print length, $0}' | sort -rn | head -10
```

### 判定阈值

| 条件 | 风险等级 | 说明 |
|------|----------|------|
| /etc/resolv.conf 被修改 | HIGH | DNS 劫持 |
| /etc/hosts 被篡改 | HIGH | 重定向攻击 |
| 异常高频 DNS 查询 | MEDIUM | DNS 隧道或 DGA |
| 查询非常长域名 | HIGH | DNS 隧道特征 |

---

## 7. 防火墙规则异常

### 检测命令

```bash
# 检查 iptables 规则变更
iptables -L -n --line-numbers
iptables -t nat -L -n --line-numbers
iptables -t mangle -L -n --line-numbers

# 检查 firewalld 变更
firewall-cmd --list-all 2>/dev/null

# 检查规则文件变更
stat /etc/sysconfig/iptables 2>/dev/null
stat /etc/iptables/rules.v4 2>/dev/null

# 检查是否有 ACCEPT ALL 规则
iptables -L | grep "ACCEPT.*anywhere\|0\.0\.0\.0/0"
```

### 判定阈值

| 条件 | 风险等级 | 说明 |
|------|----------|------|
| INPUT 链默认 ACCEPT | HIGH | 防火墙被禁用 |
| 新增 NAT 规则 | HIGH | 端口转发后门 |
| 防火墙规则被清空 | CRITICAL | 完全开放 |
| 允许所有入站流量 | CRITICAL | 防火墙无效 |

---

## 综合检测流程

```
网络异常检测
    │
    ├─ 1. 异常外连扫描
    │     └─ 非标端口/可疑进程 → ALERT
    │
    ├─ 2. 反弹 Shell 检测
    │     └─ bash+网络连接/nc -e → CRITICAL
    │
    ├─ 3. C2 通信检测
    │     └─ 心跳/DNS 隧道/C2 端口 → ALERT
    │
    ├─ 4. 数据外泄检测
    │     └─ 打包+传输/base64 → ALERT
    │
    ├─ 5. 横向移动检测
    │     └─ 扫描工具/代理工具 → ALERT
    │
    ├─ 6. DNS 异常检测
    │     └─ 配置变更/长域名查询 → ALERT
    │
    └─ 7. 防火墙异常检测
          └─ 规则清空/ACCEPT ALL → CRITICAL
```
