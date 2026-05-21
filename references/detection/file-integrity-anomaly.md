# 文件完整性异常检测

## 检测目标

检测关键系统文件、配置文件、二进制文件的未授权修改，识别后门植入和篡改行为。

---

## 1. RPM 包完整性验证

### 检测原理

RPM 数据库记录了每个安装文件的预期属性（大小、权限、校验和等）。通过对比可发现篡改。

### 检测命令

```bash
# 验证所有已安装包的完整性
rpm -Va 2>/dev/null

# 验证特定包
rpm -V openssh-server
rpm -V sudo
rpm -V pam

# 仅检查关键包
rpm -Va 2>/dev/null | grep -E "^..5|^.M|S\.|missing"

# 输出字段说明:
# S = 大小变更  5 = MD5 变更  M = 权限变更
# D = 设备号变更  L = 链接变更  U = 属主变更
# G = 属组变更  T = 时间变更  P = capabilities 变更
```

### 判定阈值

| 标记 | 含义 | 风险等级 |
|------|------|----------|
| `S.5` | 大小和校验和变更 | CRITICAL（二进制篡改） |
| `.M` | 权限变更 | HIGH |
| `..T` | 仅时间变更 | LOW（可能是正常更新） |
| `missing` | 文件缺失 | HIGH |

---

## 2. 关键系统文件监控

### 监控目标

```bash
# 用户与认证
/etc/passwd
/etc/shadow
/etc/group
/etc/gshadow
/etc/sudoers
/etc/sudoers.d/

# SSH 配置
/etc/ssh/sshd_config
/etc/ssh/ssh_host_*
/home/*/.ssh/authorized_keys

# 系统配置
/etc/pam.d/
/etc/ld.so.preload
/etc/ld.so.conf.d/
/etc/environment
/etc/profile
/etc/profile.d/
/etc/bashrc

# 启动相关
/etc/systemd/system/
/usr/lib/systemd/system/
/etc/init.d/
/etc/rc.local

# cron 相关
/etc/crontab
/etc/cron.d/
/var/spool/cron/
```

### auditd 规则

```bash
# 用户认证文件
-w /etc/passwd -p wa -k identity_change
-w /etc/shadow -p wa -k identity_change
-w /etc/group -p wa -k identity_change
-w /etc/gshadow -p wa -k identity_change
-w /etc/sudoers -p wa -k sudoers_change
-w /etc/sudoers.d -p wa -k sudoers_change

# SSH 配置
-w /etc/ssh/sshd_config -p wa -k ssh_config_change
-w /etc/ssh/ssh_host_rsa_key -p wa -k ssh_key_change
-w /etc/ssh/ssh_host_ecdsa_key -p wa -k ssh_key_change
-w /etc/ssh/ssh_host_ed25519_key -p wa -k ssh_key_change

# 系统配置
-w /etc/pam.d -p wa -k pam_change
-w /etc/ld.so.preload -p wa -k preload_change
-w /etc/profile -p wa -k profile_change
-w /etc/bashrc -p wa -k profile_change

# 启动项
-w /etc/systemd/system -p wa -k systemd_change
-w /etc/init.d -p wa -k init_change
```

### 检测命令

```bash
# 检查 /etc/passwd 最后修改时间
stat /etc/passwd
ls -la /etc/passwd

# 检查 /etc/passwd 新增用户
awk -F: '$3 >= 1000 {print $1, $3, $7}' /etc/passwd

# 检查 UID=0 用户（应该只有 root）
awk -F: '$3 == 0 {print $1}' /etc/passwd

# 检查空密码用户
awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow

# 检查 /etc/shadow 最后修改
stat /etc/shadow
```

---

## 3. 二进制文件篡改检测

### 检测目标

系统关键二进制文件被替换或篡改（如 ls, ps, netstat, ss 等）。

### 检测命令

```bash
# 使用 RPM 验证关键二进制
rpm -V coreutils procps net-tools iproute openssh-server sudo pam

# 检查常见 rootkit 替换的文件
for f in ls ps netstat ss lsof find top; do
  path=$(which $f 2>/dev/null)
  if [ -n "$path" ]; then
    rpm -qf "$path" >/dev/null 2>&1 && rpm -V "$(rpm -qf "$path")" "$path"
    if [ $? -ne 0 ]; then
      echo "TAMPERED: $path"
    fi
  fi
done

# 检查 ls 命令是否被替换
which ls
rpm -V coreutils

# 检查文件大小异常
ls -la /usr/bin/ls /usr/bin/ps /usr/bin/netstat /usr/bin/ss

# 检查 ld.so.preload（常见 rootkit 手段）
cat /etc/ld.so.preload 2>/dev/null
[ -s /etc/ld.so.preload ] && echo "WARNING: ld.so.preload is not empty"
```

### 判定阈值

| 条件 | 风险等级 | 说明 |
|------|----------|------|
| /etc/ld.so.preload 非空 | CRITICAL | 典型 rootkit 特征 |
| ls/ps/netstat 被替换 | CRITICAL | rootkit 植入 |
| 关键二进制 RPM 验证失败 | CRITICAL | 需立即排查 |
| 新增 SUID 二进制 | HIGH | 可能提权后门 |

---

## 4. AIDE 文件完整性监控

### 检测原理

AIDE (Advanced Intrusion Detection Environment) 通过维护文件属性数据库来检测变更。

### 部署命令

```bash
# 安装 AIDE
yum install aide

# 初始化数据库
aide --init
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

# 执行检查
aide --check

# 更新数据库（在确认变更合法后）
aide --update
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
```

### AIDE 配置要点

```bash
# /etc/aide.conf 关键配置
# 监控 /etc 下所有文件
/etc NORMAL
# 监控二进制目录
/usr/bin NORMAL
/usr/sbin NORMAL
# 监控库文件
/lib NORMAL
/lib64 NORMAL
# 排除动态目录
!/var/log
!/var/spool
!/tmp
!/proc
!/sys
```

---

## 5. 特殊文件属性检查

### 检测命令

```bash
# 检查不可变文件（chattr +i）
lsattr -R / 2>/dev/null | grep "\-i\-"

# 检查 append-only 文件（chattr +a）
lsattr -R / 2>/dev/null | grep "\-\-a\-"

# 检查隐藏文件（以 . 开头的关键目录下）
find /etc /usr/bin /usr/sbin -name ".*" -type f 2>/dev/null

# 检查硬链接异常
find / -type f -links +1 -perm -4000 2>/dev/null
```

### 判定阈值

| 条件 | 风险等级 | 说明 |
|------|----------|------|
| 关键文件 chattr +i 被移除 | HIGH | 可能被篡改 |
| /usr/bin 下出现隐藏文件 | HIGH | 可能后门 |
| SUID 文件有多硬链接 | MEDIUM | 可能绕过检测 |

---

## 6. 库文件劫持检测

### 检测原理

通过修改 LD_PRELOAD 或替换共享库，可在不修改二进制的情况下注入恶意代码。

### 检测命令

```bash
# 检查 LD_PRELOAD
echo $LD_PRELOAD
cat /etc/ld.so.preload 2>/dev/null

# 检查 ld.so.conf 配置
cat /etc/ld.so.conf
ls -la /etc/ld.so.conf.d/

# 验证关键库文件
rpm -V glibc
rpm -V openssl-libs

# 检查新增库文件
find /lib /lib64 /usr/lib /usr/lib64 -newer /etc/passwd -name "*.so*" 2>/dev/null

# 检查 LD_PRELOAD 环境变量注入
grep -r "LD_PRELOAD" /etc/profile /etc/profile.d/ /etc/environment /etc/bashrc 2>/dev/null
```

### 判定阈值

| 条件 | 风险等级 | 说明 |
|------|----------|------|
| /etc/ld.so.preload 非空 | CRITICAL | 库劫持 |
| /etc/ld.so.conf.d/ 新增配置 | HIGH | 可能库劫持 |
| glibc 被替换 | CRITICAL | 系统级后门 |
| 新增未知 .so 文件 | HIGH | 需进一步分析 |

---

## 综合检测流程

```
文件完整性检测
    │
    ├─ 1. RPM 完整性验证
    │     └─ 关键包验证失败 → ALERT
    │
    ├─ 2. 关键文件变更检查
    │     └─ /etc/passwd, shadow 等变更 → ALERT
    │
    ├─ 3. 二进制篡改检测
    │     └─ ld.so.preload 非空 → CRITICAL
    │
    ├─ 4. AIDE 检查（如已部署）
    │     └─ 与基线对比 → 变更项 → ALERT
    │
    ├─ 5. 特殊属性检查
    │     └─ 隐藏文件/异常链接 → WARN
    │
    └─ 6. 库文件劫持检查
          └─ LD_PRELOAD/新 .so → ALERT
```
