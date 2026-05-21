# 配置篡改检测模式

## 检测目标

检测系统配置的未授权修改，包括 SSH 配置、防火墙规则、用户权限、计划任务、启动项等。

---

## 1. SSH 服务配置篡改

### 监控目标

```
/etc/ssh/sshd_config
/etc/ssh/ssh_host_rsa_key
/etc/ssh/ssh_host_ecdsa_key
/etc/ssh/ssh_host_ed25519_key
/home/*/.ssh/authorized_keys
/root/.ssh/authorized_keys
```

### 检测命令

```bash
# 检查 SSH 配置关键项
sshd -T 2>/dev/null | grep -iE "permitroot|passwordauth|pubkeyauth|emptypasswords|maxauthtries|x11forwarding|allowtcpforwarding"

# 检查危险配置
grep -iE "PermitRootLogin\s+yes" /etc/ssh/sshd_config
grep -iE "PasswordAuthentication\s+yes" /etc/ssh/sshd_config
grep -iE "PermitEmptyPasswords\s+yes" /etc/ssh/sshd_config
grep -iE "X11Forwarding\s+yes" /etc/ssh/sshd_config

# 检查 MaxAuthTries（默认应为 3-6）
grep -i "MaxAuthTries" /etc/ssh/sshd_config

# 检查 AllowUsers/AllowGroups（白名单模式）
grep -iE "AllowUsers|AllowGroups|DenyUsers|DenyGroups" /etc/ssh/sshd_config

# 检查 SSH 密钥文件权限
ls -la /etc/ssh/ssh_host_*_key
# 应为 600 (-rw-------)

# 检查 authorized_keys 变更
stat /home/*/.ssh/authorized_keys /root/.ssh/authorized_keys 2>/dev/null

# 检查 SSH 配置语法
sshd -t
```

### 判定阈值

| 条件 | 风险等级 | 说明 |
|------|----------|------|
| PermitRootLogin = yes | HIGH | 允许 root SSH 登录 |
| PasswordAuthentication = yes | MEDIUM | 允许密码登录 |
| PermitEmptyPasswords = yes | CRITICAL | 允许空密码 |
| MaxAuthTries > 6 | LOW | 6 为 OpenSSH 默认值，安全加固建议设为 3-4 |
| SSH 密钥文件权限 > 600 | HIGH | 密钥可能被读取 |
| authorized_keys 被异常修改 | CRITICAL | 可能后门密钥 |
| sshd_config 语法错误 | HIGH | SSH 服务可能异常 |

---

## 2. 防火墙配置篡改

### 检测命令

```bash
# iptables 规则完整性
iptables -L -n --line-numbers
iptables -t nat -L -n --line-numbers

# firewalld 状态
firewall-cmd --state 2>/dev/null
firewall-cmd --list-all 2>/dev/null

# 检查规则文件变更
stat /etc/sysconfig/iptables 2>/dev/null
stat /etc/iptables/rules.v4 2>/dev/null

# 检查是否有全放行规则
iptables -L INPUT -n | grep "ACCEPT.*0.0.0.0/0.*0.0.0.0/0"

# 检查默认策略
iptables -L | grep "Chain.*policy"

# 检查 nftables（新版本可能使用）
nft list ruleset 2>/dev/null
```

### 判定阈值

| 条件 | 风险等级 | 说明 |
|------|----------|------|
| INPUT 默认策略 ACCEPT | HIGH | 入站未过滤 |
| 存在全放行规则 | HIGH | 防火墙无效 |
| 规则被清空 | CRITICAL | 完全开放 |
| 新增 NAT 转发规则 | HIGH | 可能端口映射后门 |
| firewalld 被禁用 | HIGH | 防火墙关闭 |

---

## 3. 用户与权限配置篡改

### 检测命令

```bash
# 检查 UID=0 用户（应只有 root）
awk -F: '$3 == 0 {print $1}' /etc/passwd

# 检查空密码用户
awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow

# 检查 /etc/passwd 文件变更
stat /etc/passwd
ls -la /etc/passwd

# 检查新增用户（UID >= 1000）
awk -F: '$3 >= 1000 && $3 < 65534 {print $1, $3, $7}' /etc/passwd

# 检查 /etc/group 变更
stat /etc/group

# 检查 wheel/sudo 组成员
getent group wheel 2>/dev/null || getent group sudo 2>/dev/null

# 检查系统用户是否有异常 shell
awk -F: '$3 < 1000 && $7 != "/sbin/nologin" && $7 != "/bin/false" {print $1, $7}' /etc/passwd

# 检查 /etc/shells 文件
cat /etc/shells
```

### 判定阈值

| 条件 | 风险等级 | 说明 |
|------|----------|------|
| 多个 UID=0 用户 | CRITICAL | 后门超级用户 |
| 存在空密码用户 | CRITICAL | 未授权访问 |
| 系统用户有交互 shell | HIGH | 可能被利用 |
| 非预期用户加入 wheel 组 | HIGH | 提权后门 |
| /etc/passwd 被异常修改 | CRITICAL | 用户配置篡改 |

---

## 4. 计划任务配置篡改

### 检测命令

```bash
# 系统 crontab
cat /etc/crontab

# cron.d 目录
ls -la /etc/cron.d/
cat /etc/cron.d/*

# 用户 crontab
for user in $(cut -d: -f1 /etc/passwd); do
  crontab -l -u "$user" 2>/dev/null | grep -v "^#" | while read line; do
    [ -n "$line" ] && echo "$user: $line"
  done
done

# 检查 cron 文件权限
ls -la /etc/crontab /etc/cron.d/ /var/spool/cron/

# 检查 at 队列
atq 2>/dev/null

# 检查 anacron
cat /etc/anacrontab 2>/dev/null

# 检查 systemd timer
systemctl list-timers --all 2>/dev/null
```

### 判定阈值

| 条件 | 风险等级 | 说明 |
|------|----------|------|
| /etc/crontab 被修改 | HIGH | 系统级任务篡改 |
| cron 文件权限异常（应为 600/644） | HIGH | 可能被篡改 |
| cron 中有 curl/wget 到外部 | CRITICAL | 持久化后门 |
| cron 中执行 /tmp 下脚本 | CRITICAL | 恶意执行 |
| 新增 systemd timer | MEDIUM | 检查任务内容 |

---

## 5. 启动项配置篡改

### 检测命令

```bash
# 检查 systemd service 文件变更
find /etc/systemd/system -newer /etc/passwd -type f 2>/dev/null
find /usr/lib/systemd/system -newer /etc/passwd -type f 2>/dev/null

# 检查自定义 service
ls -la /etc/systemd/system/*.service

# 检查 rc.local
cat /etc/rc.local 2>/dev/null
cat /etc/rc.d/rc.local 2>/dev/null

# 检查 init.d 脚本
ls -la /etc/init.d/

# 检查 GRUB 配置
cat /etc/default/grub
stat /boot/grub2/grub.cfg 2>/dev/null

# 检查 profile 脚本
cat /etc/profile
cat /etc/bashrc
ls -la /etc/profile.d/

# 检查 LD_PRELOAD
cat /etc/ld.so.preload 2>/dev/null
[ -s /etc/ld.so.preload ] && echo "WARNING: ld.so.preload is not empty"
```

### 判定阈值

| 条件 | 风险等级 | 说明 |
|------|----------|------|
| 新增 systemd service | HIGH | 可能后门服务 |
| rc.local 被修改 | HIGH | 启动后门 |
| profile 脚本被修改 | HIGH | 登录后门 |
| /etc/ld.so.preload 非空 | CRITICAL | 库劫持后门 |
| GRUB 配置被修改 | HIGH | 可能单用户模式后门 |

---

## 6. 日志配置篡改

### 检测命令

```bash
# 检查 auditd 配置
cat /etc/audit/auditd.conf
stat /etc/audit/auditd.conf

# 检查 audit 规则
auditctl -l
stat /etc/audit/rules.d/

# 检查 rsyslog 配置
cat /etc/rsyslog.conf
cat /etc/rsyslog.d/*.conf
stat /etc/rsyslog.conf

# 检查 journal 配置
cat /etc/systemd/journald.conf

# 检查日志文件权限
ls -la /var/log/audit/ /var/log/secure /var/log/messages

# 检查 logrotate 配置
cat /etc/logrotate.d/audit 2>/dev/null
cat /etc/logrotate.conf
```

### 判定阈值

| 条件 | 风险等级 | 说明 |
|------|----------|------|
| auditd 被禁用/停止 | CRITICAL | 审计失效 |
| audit 规则被清空 | CRITICAL | 审计失效 |
| rsyslog 配置被修改 | HIGH | 日志转发可能被篡改 |
| 日志文件权限异常 | HIGH | 日志可能被篡改 |
| logrotate 配置被修改 | MEDIUM | 日志保留策略变更 |

---

## 7. 网络配置篡改

### 检测命令

```bash
# 检查 DNS 配置
cat /etc/resolv.conf
stat /etc/resolv.conf

# 检查 hosts 文件
cat /etc/hosts
stat /etc/hosts

# 检查网络接口配置
ip addr show
ip route show

# 检查 NetworkManager 配置
nmcli con show 2>/dev/null

# 检查 sysctl 网络参数
sysctl net.ipv4.ip_forward
sysctl net.ipv4.conf.all.accept_redirects
sysctl net.ipv4.conf.all.accept_source_route
sysctl net.ipv4.conf.all.rp_filter

# 检查代理配置
env | grep -i proxy
cat /etc/environment | grep -i proxy
```

### 判定阈值

| 条件 | 风险等级 | 说明 |
|------|----------|------|
| /etc/resolv.conf 指向异常 DNS | HIGH | DNS 劫持 |
| /etc/hosts 含异常条目 | HIGH | 重定向攻击 |
| ip_forward=1（非路由器） | HIGH | 转发被启用 |
| accept_redirects=1 | MEDIUM | ICMP 重定向攻击 |
| 代理配置异常 | MEDIUM | 流量劫持 |

---

## 综合检测流程

```
配置篡改检测
    │
    ├─ 1. SSH 配置检查
    │     └─ PermitRoot/空密码/密钥 → ALERT
    │
    ├─ 2. 防火墙配置检查
    │     └─ 全放行/规则清空 → ALERT
    │
    ├─ 3. 用户权限检查
    │     └─ 多 UID=0/空密码/异常 shell → ALERT
    │
    ├─ 4. 计划任务检查
    │     └─ 异常 cron/at/timer → ALERT
    │
    ├─ 5. 启动项检查
    │     └─ 新 service/ld.so.preload → ALERT
    │
    ├─ 6. 日志配置检查
    │     └─ auditd 停用/规则清空 → CRITICAL
    │
    └─ 7. 网络配置检查
          └─ DNS 异常/ip_forward → ALERT
```
