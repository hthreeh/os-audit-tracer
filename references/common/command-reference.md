# 审计相关命令速查

## 1. auditd 控制命令

### 服务管理

```bash
# 启动/停止/重启 auditd
systemctl start auditd
systemctl stop auditd
systemctl restart auditd

# 查看状态
systemctl status auditd

# 开机自启
systemctl enable auditd
```

### 规则管理

```bash
# 查看当前加载的规则
auditctl -l

# 添加文件监控规则
auditctl -w /etc/passwd -p wa -k identity

# 添加系统调用规则（arch=b64 仅适用于 x86_64，aarch64 需改为 arch=aarch64）
auditctl -a always,exit -F arch=b64 -S execve -k exec_cmd

# 删除规则
auditctl -d -w /etc/passwd -p wa -k identity

# 删除所有规则
auditctl -D

# 从文件加载规则
auditctl -R /etc/audit/rules.d/audit.rules

# 查看审计系统状态（规则列表用 auditctl -l）
auditctl -s
```

## 2. ausearch 日志搜索

### 按 key 搜索

```bash
ausearch -k identity --no-pager
ausearch -k privilege --no-pager
ausearch -k exec_cmd --no-pager
```

### 按时间搜索

```bash
# 今天
ausearch -ts today --no-pager

# 最近
ausearch -ts recent --no-pager

# 指定时间范围
ausearch -ts '01/15/2024 14:00:00' -te '01/15/2024 15:00:00' --no-pager

# 相对时间
ausearch -ts '2 hours ago' --no-pager
```

### 按用户搜索

```bash
ausearch -ua 1000 --no-pager          # 按 UID
ausearch -ue root --no-pager          # 按用户名
ausearch -auid 1000 --no-pager        # 按审计 UID（登录时的原始用户）
```

### 按文件搜索

```bash
ausearch -f /etc/passwd --no-pager
ausearch -f /etc/shadow --no-pager
```

### 按系统调用搜索

```bash
ausearch -sc execve --no-pager
ausearch -sc connect --no-pager
ausearch -sc open --no-pager
```

### 按事件类型搜索

```bash
ausearch -m SYSCALL --no-pager
ausearch -m EXECVE --no-pager
ausearch -m AVC --no-pager
ausearch -m USER_AUTH --no-pager
ausearch -m USER_LOGIN --no-pager
```

### 按成功/失败搜索

```bash
ausearch -sv yes --no-pager           # 成功的操作
ausearch -sv no --no-pager            # 失败的操作
```

### 组合搜索

```bash
# 特定用户今天的所有操作
ausearch -ua 1000 -ts today --no-pager

# 特定文件的修改操作
ausearch -f /etc/passwd -sc write --no-pager

# 失败的认证尝试
ausearch -m USER_AUTH -sv no --no-pager
```

## 3. aureport 报告生成

### 综合报告

```bash
aureport --summary --no-pager
```

### 专项报告

```bash
# 认证报告
aureport --auth --no-pager

# 登录报告
aureport --login --no-pager

# 失败事件报告
aureport --failed --no-pager

# 文件访问报告
aureport --file --no-pager

# 命令执行报告
aureport -x --no-pager

# 网络连接报告
aureport --net --no-pager

# 用户报告
aureport --user --no-pager

# AVC（SELinux）报告
aureport --avc --no-pager
```

### 时间范围报告

```bash
aureport --auth --ts today --no-pager
aureport --login --ts '01/15/2024' --te '01/16/2024' --no-pager
```

## 4. 登录分析命令

### 当前登录用户

```bash
who                              # 当前登录用户
w                                # 当前登录用户及活动
users                            # 当前登录用户名列表
```

### 登录历史

```bash
last -20                         # 最近 20 条登录记录
last username                    # 特定用户登录历史
last -s "2024-01-15"             # 指定日期之后
last -t "2024-01-16"             # 指定日期之前
last reboot                      # 重启记录
last -i                          # 显示 IP 地址
```

### 失败登录

```bash
lastb -20                        # 最近 20 条失败登录
lastb username                   # 特定用户失败登录
```

### 最后登录

```bash
lastlog                          # 所有用户最后登录
lastlog -u username              # 特定用户
lastlog | grep Never             # 从未登录的用户
```

## 5. 进程分析命令

### 进程列表

```bash
ps auxf                          # 完整进程树
ps aux --sort=-%cpu              # 按 CPU 排序
ps aux --sort=-%mem              # 按内存排序
ps -eo pid,ppid,user,comm,args   # 自定义列
```

### 进程详情

```bash
ls -la /proc/<PID>/exe           # 可执行文件路径
cat /proc/<PID>/cmdline          # 命令行
ls -la /proc/<PID>/fd/           # 打开的文件描述符
cat /proc/<PID>/environ          # 环境变量
ls -la /proc/<PID>/cwd           # 工作目录
cat /proc/<PID>/stack            # 调用栈
cat /proc/<PID>/maps             # 内存映射
```

### 隐藏进程检测

```bash
diff <(ps -e -o pid= | sort -n) <(ls -1 /proc | grep '^[0-9]' | sort -n)
```

## 6. 网络分析命令

### 连接状态

```bash
ss -tunap                        # 所有 TCP/UDP 连接及进程
ss -tunap state established       # 已建立的连接
ss -tunap state listening          # 监听端口
ss -tunap | grep -v ':22\|:80\|:443'  # 非标准端口
```

### 连接统计

```bash
ss -tunap | awk '{print $5}' | sort | uniq -c | sort -rn | head -20
ss -s                            # 连接统计摘要
```

### 路由和接口

```bash
ip route show                    # 路由表
ip addr show                     # 接口地址
netstat -rn                      # 路由表（传统）
```

## 7. 文件完整性命令

### RPM 验证

```bash
rpm -Va                          # 验证所有已安装包
rpm -Va | grep -v '^\.\.\.\.\.\.\.\.  '  # 过滤正常文件
rpm -Vf /usr/bin/ls              # 验证特定文件所属的包
```

### SUID/SGID 扫描

```bash
find / -perm -4000 -type f -ls 2>/dev/null    # SUID 文件
find / -perm -2000 -type f -ls 2>/dev/null    # SGID 文件
find / -perm -4000 -newer /etc/passwd -ls 2>/dev/null  # 新增 SUID
```

### 最近修改的文件

```bash
find / -mtime -1 -type f -ls 2>/dev/null | grep -v '/proc\|/sys\|/run'
find / -newermt '2024-01-15' ! -newermt '2024-01-16' -type f -ls 2>/dev/null
```

### 文件属性

```bash
stat /path/to/file               # 文件详细信息（包含时间戳）
lsattr /path/to/file             # 文件属性（ext4）
getfattr -d -m - /path/to/file   # 扩展属性
```

## 8. 用户和权限命令

### 用户信息

```bash
cat /etc/passwd                  # 用户列表
awk -F: '$3 == 0 && $1 != "root"' /etc/passwd  # UID=0 的非 root 用户
grep -v '/nologin\|/false' /etc/passwd          # 可登录用户
awk -F: '$2 == ""' /etc/shadow                  # 空密码用户
```

### sudo 配置

```bash
visudo -c                        # 检查 sudoers 语法
grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null
grep -r 'ALL' /etc/sudoers /etc/sudoers.d/ 2>/dev/null
```

### SSH 密钥

```bash
for dir in /home/*/ /root/; do
    [ -f "${dir}.ssh/authorized_keys" ] && echo "=== $dir ===" && cat "${dir}.ssh/authorized_keys"
done
```

## 9. 定时任务检查

```bash
# 用户 crontab
for user in $(cut -d: -f1 /etc/passwd); do
    echo "=== $user ==="
    crontab -l -u "$user" 2>/dev/null
done

# 系统 crontab
cat /etc/crontab
ls -la /etc/cron.d/
ls -la /etc/cron.daily/
ls -la /etc/cron.hourly/
ls -la /etc/cron.weekly/
ls -la /etc/cron.monthly/

# systemd 定时器
systemctl list-timers --all --no-pager
```

## 10. 启动项检查

```bash
# systemd 服务
systemctl list-unit-files --type=service --state=enabled --no-pager
systemctl list-units --type=service --state=running --no-pager

# 传统启动项
cat /etc/rc.local 2>/dev/null
cat /etc/rc.d/rc.local 2>/dev/null
ls -la /etc/init.d/
```

## 11. eBPF 工具命令

### bpftrace

```bash
# 列出可用探针
bpftrace -l

# 运行脚本
bpftrace script.bt

# 单行命令
bpftrace -e 'tracepoint:syscalls:sys_enter_execve { printf("%s %s\n", comm, str(args->filename)); }'
```

### bcc-tools

```bash
# 进程追踪
execsnoop

# 文件访问
opensnoop

# 网络连接
tcpconnect

# DNS 查询
gethostlatency
```
