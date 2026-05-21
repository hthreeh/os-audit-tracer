# SELinux 审计事件解读

## 1. SELinux 基础

### 工作模式

| 模式 | 说明 | 查看命令 |
|------|------|----------|
| Enforcing | 强制执行策略，拒绝未授权访问并记录 | `getenforce` |
| Permissive | 不拒绝但记录未授权访问（调试用） | `getenforce` |
| Disabled | 完全禁用 | `sestatus` |

### 安全上下文

每个进程和文件都有安全上下文，格式为：`user:role:type:level`

```
system_u:system_r:httpd_t:s0    # httpd 进程上下文
unconfined_u:object_r:default_t:s0  # 文件上下文
```

**字段说明**：
- `user`: SELinux 用户（如 system_u, unconfined_u）
- `role`: 角色（如 system_r, object_r, unconfined_r）
- `type`: 类型（最重要的字段，策略主要基于类型）
- `level`: MLS/MCS 级别（如 s0, s0-s0:c0.c1023）

## 2. AVC 事件解析

### AVC 拒绝事件格式

```
type=AVC msg=audit(1705312985.123:456): avc: denied { read } for pid=12345 
comm="httpd" name="index.html" dev="sda1" ino=789 
scontext=system_u:system_r:httpd_t:s0 
tcontext=unconfined_u:object_r:default_t:s0 
tclass=file permissive=0
```

**字段说明**：
- `denied { read }`: 被拒绝的操作（read, write, open, create, unlink, execute 等）
- `pid=12345`: 进程 PID
- `comm="httpd"`: 进程命令名
- `name="index.html"`: 目标文件名
- `scontext`: 源上下文（发起操作的进程）
- `tcontext`: 目标上下文（被操作的对象）
- `tclass=file`: 目标类型（file, dir, socket, process 等）
- `permissive=0`: 0=Enforcing, 1=Permissive

### 常见 AVC 拒绝类型

| 操作 | 说明 | 常见原因 |
|------|------|----------|
| { read } | 读取文件 | 文件上下文错误 |
| { write } | 写入文件 | 文件上下文错误 |
| { open } | 打开文件 | 文件上下文错误 |
| { execute } | 执行文件 | 文件上下文错误或布尔值未设置 |
| { create } | 创建文件 | 目录上下文错误 |
| { unlink } | 删除文件 | 目录上下文错误 |
| { getattr } | 获取属性 | 文件上下文错误 |
| { connectto } | 连接套接字 | 布尔值未设置 |
| { name_bind } | 绑定端口 | 端口标签错误 |

## 3. SELinux 审计查询命令

### 查看拒绝日志

```bash
# 查看今天的 AVC 拒绝
ausearch -m avc -ts today --no-pager

# 查看最近的 AVC 拒绝
ausearch -m avc -ts recent --no-pager

# 查看特定服务的拒绝
ausearch -m avc -c httpd --no-pager

# 查看特定时间范围
ausearch -m avc -ts '01/15/2024 14:00:00' -te '01/15/2024 15:00:00' --no-pager
```

### sealert 分析

```bash
# 分析所有 AVC 拒绝并给出修复建议
sealert -a /var/log/audit/audit.log

# 分析特定事件
sealert -l <alert_id>
```

### 查看安全上下文

```bash
# 文件上下文
ls -lZ /path/to/file

# 进程上下文
ps auxZ | grep httpd

# 当前 SELinux 用户
semanage login -l

# 端口标签
semanage port -l

# 文件上下文规则
semanage fcontext -l
```

## 4. 常见问题诊断

### 服务无法访问文件

**症状**：服务返回 403 或 Permission Denied，但文件权限正确。

**诊断**：
```bash
ausearch -m avc -c <service> --no-pager
# 检查 scontext（服务类型）和 tcontext（文件上下文）是否匹配
```

**修复**：
```bash
# 恢复默认上下文
restorecon -Rv /path/to/directory

# 或设置自定义上下文
semanage fcontext -a -t httpd_sys_content_t '/web(/.*)?'
restorecon -Rv /web
```

### 服务无法连接网络

**症状**：服务无法绑定端口或连接外部服务。

**诊断**：
```bash
ausearch -m avc -c <service> --no-pager | grep -E 'connectto|name_bind'
```

**修复**：
```bash
# 设置布尔值
setsebool -P httpd_can_network_connect on

# 或设置端口标签
semanage port -a -t http_port_t -p tcp 8080
```

### 服务无法启动

**症状**：服务启动失败，日志中有 AVC 拒绝。

**诊断**：
```bash
ausearch -m avc -ts recent --no-pager
journalctl -u <service> -n 50
```

**修复**：
```bash
# 查看需要的布尔值
getsebool -a | grep <service>

# 启用所需布尔值
setsebool -P <boolean> on
```

## 5. 策略管理

### 自动生成策略模块

```bash
# 从 AVC 拒绝生成策略模块
ausearch -m avc -ts today | audit2allow -M mypolicy

# 查看生成的策略
cat mypolicy.te

# 安装策略模块
semodule -i mypolicy.pp
```

### 查看策略信息

```bash
# 查看已安装的模块
semodule -l

# 查看类型强制规则
sesearch --allow -t httpd_t

# 查看所有允许 httpd_t 的规则
sesearch --allow -s httpd_t
```

### 布尔值管理

```bash
# 列出所有布尔值
getsebool -a

# 查看特定布尔值
getsebool httpd_can_network_connect

# 临时设置（重启后失效）
setsebool httpd_can_network_connect on

# 永久设置
setsebool -P httpd_can_network_connect on
```

## 6. openEuler / FusionOS SELinux 差异

| 方面 | openEuler | FusionOS |
|------|-----------|----------|
| 默认模式 | Permissive（部分版本） | Enforcing |
| 策略类型 | targeted | targeted（更严格） |
| 自定义策略 | 社区提供 | 华为增强 |
| 合规性 | 通用企业级 | GB/T 22239 合规 |

### FusionOS 特有策略

FusionOS 安全增强版可能包含更严格的 SELinux 策略：
- 限制更多服务的网络访问
- 限制特权进程的文件访问
- 增强容器隔离策略

## 7. 安全最佳实践

1. **保持 Enforcing 模式**：不要因为遇到拒绝就切换到 Permissive
2. **使用 restorecon**：优先使用 `restorecon` 而非 `chcon`（chcon 修改重启后可能丢失）
3. **最小权限原则**：只启用必要的布尔值
4. **定期审计**：定期检查 AVC 拒绝日志
5. **测试后再部署**：在 Permissive 模式下测试策略，确认无误后切换到 Enforcing
6. **备份策略**：修改策略前备份 `/etc/selinux/`
