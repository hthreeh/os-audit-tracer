# 内部威胁检测与追溯

## 场景描述

怀疑内部人员（员工、外包、合作伙伴）有违规操作或恶意行为，需要检测和追溯。

---

## 威胁类型

| 类型 | 描述 | 典型行为 |
|------|------|----------|
| 数据泄露 | 内部人员窃取敏感数据 | 大量文件下载、U 盘拷贝、邮件外发 |
| 权限滥用 | 超越职责范围的操作 | 访问非授权系统、越权命令执行 |
| 配置篡改 | 恶意修改系统配置 | 创建后门、降低安全设置 |
| 账户共享 | 违规共享账户凭证 | 同一账户多地登录、密码告知他人 |
| 离职风险 | 离职前的数据窃取 | 批量下载、清空操作记录 |

---

## 检测流程

### 阶段 1：确定追溯对象

#### 1.1 确定目标用户

```bash
# 查询用户信息
id {username}
getent passwd {username}

# 查询用户组成员
id -nG {username}

# 查询 sudo 权限
sudo -l -U {username}
```

#### 1.2 确定时间范围

```bash
# 查询用户最后登录
lastlog -u {username}

# 查询用户登录历史
last -ai {username}

# 查询用户最近活动
ausearch -ua {username} -ts this-week 2>/dev/null | head -20
```

---

### 阶段 2：用户行为收集

#### 2.1 命令执行历史

```bash
# 从 audit.log 收集用户命令
ausearch -ua {username} -m EXECVE -ts "$START_TIME" -te "$END_TIME"

# 收集用户 shell 历史
cat /home/{username}/.bash_history
cat /home/{username}/.zsh_history 2>/dev/null

# 收集 sudo 命令
grep "{username}" /var/log/secure | grep "sudo:"

# 收集 su 命令
grep "su:" /var/log/secure | grep "{username}"
```

#### 2.2 文件访问记录

```bash
# 用户打开的文件
ausearch -ua {username} -m OPEN -ts "$START_TIME" -te "$END_TIME"

# 用户修改的文件
ausearch -ua {username} -m PATH -ts "$START_TIME" -te "$END_TIME" | grep "nametype=CREATE\|nametype=NORMAL"

# 用户删除的文件
ausearch -ua {username} -m PATH -ts "$START_TIME" -te "$END_TIME" | grep "nametype=DELETE"
```

#### 2.3 网络活动

```bash
# 用户的网络连接
ausearch -ua {username} -m SOCKADDR -ts "$START_TIME" -te "$END_TIME"

# SSH 出站连接
ausearch -ua {username} -m EXECVE -ts "$START_TIME" -te "$END_TIME" | grep "ssh\|scp\|rsync"

# 数据传输工具使用
ausearch -ua {username} -m EXECVE -ts "$START_TIME" -te "$END_TIME" | grep -iE "curl|wget|scp|rsync|sftp|ftp"
```

#### 2.4 登录行为

```bash
# 登录历史
last -ai {username} --since "$START_TIME"

# 登录来源 IP
last -ai {username} | awk '{print $NF}' | sort | uniq -c | sort -rn

# 异常时间登录
last -ai {username} | awk '{
  split($NF, t, ":");
  hour = t[1];
  if (hour >= 22 || hour < 6) print
}'
```

---

### 阶段 3：异常行为分析

#### 3.1 数据泄露指标

```bash
# 大量文件下载/复制
ausearch -ua {username} -m EXECVE -ts "$START_TIME" -te "$END_TIME" | \
  grep -iE "cp|rsync|scp|tar|zip|gzip" | wc -l

# USB 设备使用
ausearch -m USER_DEVICE -ts "$START_TIME" -te "$END_TIME"

# 邮件附件外发（需邮件日志）
grep "{username}" /var/log/maillog 2>/dev/null | grep -i "attach\|size"

# 压缩打包敏感目录
ausearch -ua {username} -m EXECVE -ts "$START_TIME" -te "$END_TIME" | \
  grep -iE "tar.*(/etc|/home|/var|/opt|/data)"
```

#### 3.2 权限滥用指标

```bash
# 访问非授权文件
ausearch -ua {username} -m OPEN -ts "$START_TIME" -te "$END_TIME" | \
  grep -E "/etc/shadow|/etc/sudoers|\.ssh/|/root/"

# 越权命令执行
ausearch -ua {username} -m EXECVE -ts "$START_TIME" -te "$END_TIME" | \
  grep -iE "useradd|usermod|userdel|passwd|visudo|chmod|chown"

# 尝试提权
ausearch -ua {username} -m EXECVE -ts "$START_TIME" -te "$END_TIME" | \
  grep -iE "sudo|su |setuid|setgid|capsh"
```

#### 3.3 账户共享指标

```bash
# 同一账户多地登录
last -ai {username} | grep "still logged in" | awk '{print $NF}' | sort -u

# 检查同时在线的会话数
who | grep "{username}" | wc -l

# 异常 IP 登录
last -ai {username} | awk '{print $NF}' | sort | uniq -c | sort -rn | head -5
```

#### 3.4 离职风险指标

```bash
# 批量文件操作
ausearch -ua {username} -m EXECVE -ts "$START_TIME" -te "$END_TIME" | \
  grep -iE "cp.*-r|rsync.*-r|tar.*-c|find.*-exec" | wc -l

# 清空历史记录
ausearch -ua {username} -m EXECVE -ts "$START_TIME" -te "$END_TIME" | \
  grep -iE "history -c|rm.*history|>.*history|truncate.*history"

# 删除文件
ausearch -ua {username} -m PATH -ts "$START_TIME" -te "$END_TIME" | grep "nametype=DELETE" | wc -l
```

---

### 阶段 4：时间线与证据

#### 4.1 构建用户行为时间线

```bash
# 收集用户所有审计事件
ausearch -ua {username} -ts "$START_TIME" -te "$END_TIME" > /tmp/user_audit.txt

# 构建时间线
bash scripts/build_timeline.sh -d /tmp -o /tmp/user_timeline.txt

# 过滤特定用户的事件
grep -i "{username}" /tmp/user_timeline.txt
```

#### 4.2 证据收集

```bash
# 命令执行证据
ausearch -ua {username} -m EXECVE -ts "$START_TIME" -te "$END_TIME" -i

# 文件操作证据
ausearch -ua {username} -m PATH -ts "$START_TIME" -te "$END_TIME" -i

# 认证事件证据
ausearch -ua {username} -m USER_AUTH -ts "$START_TIME" -te "$END_TIME" -i

# 生成证据链
bash scripts/generate_evidence_chain.sh -d /tmp -o /tmp/user_evidence.md
```

---

### 阶段 5：报告生成

#### 报告结构

```markdown
# 内部威胁追溯报告

## 1. 概述
- 目标用户: {username} ({uid})
- 用户角色: {role}（如：开发工程师、DBA、运维等）
- 追溯时间: {start_time} 至 {end_time}
- 发现日期: {discovery_date}
- 委托人: {requester}

## 2. 发现经过
（描述如何发现可疑行为）

## 3. 用户行为分析

### 3.1 登录行为
（登录时间、来源 IP、登录频率统计）

### 3.2 命令执行
（执行的命令列表、频率、异常命令）

### 3.3 文件访问
（访问的文件、修改的文件、删除的文件）

### 3.4 网络活动
（网络连接、数据传输、外部通信）

## 4. 异常行为列表
（按时间顺序列出所有异常行为，附证据）

## 5. 风险评估
- 数据泄露风险: 高/中/低
- 权限滥用程度: 高/中/低
- 配置篡改: 是/否
- 持久化后门: 是/否

## 6. 证据链
（每项异常行为的审计证据）

## 7. 建议措施
（处置建议、预防措施）
```

---

## 合规注意事项

1. **法律合规**: 内部调查需符合劳动法、个人信息保护法等法规
2. **授权确认**: 调查前需获得管理层书面授权
3. **隐私保护**: 收集的证据仅用于调查目的，不得泄露
4. **证据保全**: 确保证据链完整，防止篡改
5. **最小影响**: 调查过程不应影响用户正常工作
