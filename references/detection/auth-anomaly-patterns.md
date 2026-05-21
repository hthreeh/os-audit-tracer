# 认证异常检测模式

## 检测目标

识别认证环节的异常行为，包括暴力破解、异常时间登录、异常源 IP、凭证滥用等。

---

## 1. 暴力破解检测

### 日志特征

**来源**: `/var/log/secure` 或 `/var/log/auth.log`

```
# 失败密码尝试
Failed password for {user} from {ip} port {port} ssh2
Failed password for invalid user {user} from {ip} port {port} ssh2

# PAM 认证失败
authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip}  user={user}

# SSH 密钥拒绝
Connection closed by authenticating user {user} {ip} port {port} [preauth]
```

**来源**: `/var/log/audit/audit.log`

```
type=USER_AUTH msg=audit({timestamp}:{id}): pid={pid} uid=0 res=failed
type=USER_AUTH msg=audit({timestamp}:{id}): pid={pid} uid=0 auid={auid} res=failed
```

### 检测命令

```bash
# 统计每个 IP 的失败登录次数（最近 1 小时）
journalctl --since "1 hour ago" | grep "Failed password" | \
  awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' | sort | uniq -c | sort -rn

# 统计每个用户的失败登录次数
ausearch -m USER_AUTH -ts recent --just-failures 2>/dev/null | \
  grep "acct=" | sed 's/.*acct="([^"]*)".*/\1/' | sort | uniq -c | sort -rn

# 检查短时间内大量失败（5 分钟内超过 5 次）
grep "Failed password" /var/log/secure | \
  awk '{print $1,$2,$3}' | uniq -c | awk '$1 >= 5'
```

### 判定阈值

| 条件 | 风险等级 | 说明 |
|------|----------|------|
| 5 分钟内 ≥5 次失败（同一 IP） | MEDIUM | 可能的暴力破解 |
| 5 分钟内 ≥20 次失败（同一 IP） | HIGH | 确认暴力破解 |
| 1 小时内 ≥100 次失败（全局） | HIGH | 分布式暴力破解 |
| 失败后紧接成功登录 | HIGH | 可能破解成功 |
| 无效用户名尝试 ≥10 次 | MEDIUM | 用户枚举攻击 |

### 误报排除

- 内部监控系统定期 SSH 健康检查（白名单 IP）
- 配置管理工具（Ansible/SaltStack）批量操作
- 密码轮换期间的用户误输入

---

## 2. 异常时间登录

### 日志特征

```
# /var/log/secure
Accepted publickey for {user} from {ip} port {port} ssh2
Accepted password for {user} from {ip} port {port} ssh2

# lastlog / last 输出
{user}  pts/0  {ip}  {timestamp}  still logged in
```

### 检测命令

```bash
# 检查非工作时间（22:00-06:00）的登录
last -ai | awk '
  {
    split($NF, t, ":");
    hour = t[1];
    if (hour >= 22 || hour < 6) print
  }'

# 检查周末登录
last -ai | awk '
  /Sat|Sun/ { print }'

# 检查特定用户的历史登录时间
lastlog -u {user}
```

### 判定阈值

| 条件 | 风险等级 | 说明 |
|------|----------|------|
| 凌晨 02:00-05:00 登录 | MEDIUM | 非常规工作时间 |
| 周末登录（非运维人员） | LOW | 需结合用户角色判断 |
| 节假日登录 | MEDIUM | 需结合运维排班判断 |
| 首次出现的登录时间模式 | MEDIUM | 行为基线偏离 |

### 误报排除

- 运维人员值班排班表
- 自动化任务（cron 触发的 SSH）
- 跨时区团队成员

---

## 3. 异常源 IP 登录

### 日志特征

```
Accepted publickey for {user} from {new_ip} port {port} ssh2
```

### 检测命令

```bash
# 获取用户历史登录 IP
last -ai {user} | awk '{print $NF}' | sort | uniq -c | sort -rn

# 检查首次出现的 IP
comm -23 \
  <(last -ai {user} | awk '{print $NF}' | sort -u) \
  <(last -ai {user} --since "30 days ago" | awk '{print $NF}' | sort -u)

# 检查地理位置异常（需要 GeoIP 数据库）
# 此处简化为检查 IP 段
for ip in $(last -ai | awk '/still logged/{print $NF}'); do
  whois $ip 2>/dev/null | grep -i "country\|org"
done
```

### 判定阈值

| 条件 | 风险等级 | 说明 |
|------|----------|------|
| 首次出现的源 IP | MEDIUM | 可能是新设备或入侵 |
| 境外 IP（如果业务仅限国内） | HIGH | 高度可疑 |
| 内网 IP 段异常 | HIGH | 可能内网横向移动 |
| VPN/代理 IP | MEDIUM | 需确认是否合规 |

---

## 4. SSH 密钥异常

### 日志特征

```
# 新密钥添加
Accepted publickey for {user} from {ip} port {port} ssh2

# authorized_keys 变更
type=SYSCALL ... comm="bash" exe="/usr/bin/bash" ... key="ssh_key_change"
```

### 检测命令

```bash
# 监控 authorized_keys 变更
auditctl -w /home/*/.ssh/authorized_keys -p wa -k ssh_key_change
ausearch -k ssh_key_change -ts recent

# 列出所有 authorized_keys 文件
find /home -name "authorized_keys" -exec ls -la {} \;
find /root -name "authorized_keys" -exec ls -la {} \;

# 检查密钥数量异常
for f in /home/*/.ssh/authorized_keys /root/.ssh/authorized_keys; do
  [ -f "$f" ] && echo "$f: $(wc -l < "$f") keys"
done
```

### 判定阈值

| 条件 | 风险等级 | 说明 |
|------|----------|------|
| 非用户本人添加密钥 | HIGH | 可能后门植入 |
| authorized_keys 文件被异常修改 | HIGH | 检查修改者 UID |
| root 的 authorized_keys 被修改 | CRITICAL | 极高风险 |
| 单用户密钥数量突然增加 | MEDIUM | 可能账户共享 |

---

## 5. sudo/su 提权异常

### 日志特征

```
# /var/log/secure
{timestamp} {host} sudo: {user} : TTY={tty} ; PWD={pwd} ; USER=root ; COMMAND={cmd}
{timestamp} {host} su: pam_unix(su:session): session opened for user root by {user}(uid={uid})

# audit.log
type=USER_CMD ... comm="sudo" exe="/usr/bin/sudo" ... cmd={cmd}
type=CRED_ACQ ... sudo:pam_unix(su:session): session opened
```

### 检测命令

```bash
# 统计 sudo 使用频率
grep "sudo:" /var/log/secure | awk '{print $5}' | sort | uniq -c | sort -rn

# 查找非 wheel 组用户的 sudo 使用
grep "sudo:" /var/log/secure | while read line; do
  user=$(echo "$line" | awk -F'[( ]' '{print $5}')
  if ! id -nG "$user" 2>/dev/null | grep -qw "wheel"; then
    echo "NON-WHEEL SUDO: $line"
  fi
done

# 检查 sudo 命令黑名单
grep "sudo:" /var/log/secure | grep -iE "passwd|useradd|usermod|chmod|chown|visudo|crontab"
```

### 判定阈值

| 条件 | 风险等级 | 说明 |
|------|----------|------|
| 非 wheel 组用户使用 sudo | HIGH | 权限配置不当 |
| sudo 执行 useradd/usermod/passwd | HIGH | 用户管理操作 |
| sudo 执行 chmod 777 | MEDIUM | 不安全权限 |
| sudo 执行网络工具（nc/curl/wget） | HIGH | 可能数据外泄 |
| sudo 频率突增 | MEDIUM | 行为偏离基线 |

---

## 6. PAM 配置异常

### 日志特征

```
pam_unix(sshd:auth): authentication failure
pam_unix(su:auth): check pass; user unknown
PAM [error] /etc/pam.d/{service}: bad config line
```

### 检测命令

```bash
# 检查 PAM 配置文件完整性
rpm -Va | grep pam

# 检查 PAM 模块是否存在
for module in $(grep -rh "pam_" /etc/pam.d/ | awk '{print $2}' | sort -u); do
  [ ! -f "/lib64/security/$module" ] && echo "MISSING: $module"
done

# 检查可疑 PAM 配置
grep -rn "pam_permit\|pam_exec\|pam_script" /etc/pam.d/
```

### 判定阈值

| 条件 | 风险等级 | 说明 |
|------|----------|------|
| PAM 配置文件被修改 | CRITICAL | 可能认证绕过 |
| 出现 pam_permit.so（认证模块） | CRITICAL | 无条件放行 |
| 出现 pam_exec.so | HIGH | 可执行任意命令 |
| PAM 模块文件缺失 | HIGH | 认证可能失败 |

---

## 综合检测流程

```
认证异常检测
    │
    ├─ 1. 暴力破解扫描
    │     └─ 统计失败次数 → 超阈值 → ALERT
    │
    ├─ 2. 异常时间检查
    │     └─ 与基线对比 → 偏离 → WARN
    │
    ├─ 3. 异常 IP 检查
    │     └─ 与历史 IP 对比 → 新 IP → WARN
    │
    ├─ 4. SSH 密钥检查
    │     └─ authorized_keys 变更 → ALERT
    │
    ├─ 5. sudo/su 检查
    │     └─ 非常规用户/命令 → ALERT
    │
    └─ 6. PAM 完整性检查
          └─ 配置变更 → CRITICAL
```
