# 通用审计报告

## 1. 审计概况

| 项目 | 内容 |
|------|------|
| 审计标题 | {{title}} |
| 审计范围 | {{scope}} |
| 审计时间 | {{start_time}} 至 {{end_time}} |
| 主机名 | {{hostname}} |
| 操作系统 | {{os_version}} |
| 审计人员 | {{auditor}} |
| 报告日期 | {{report_date}} |

---

## 2. 系统安全状态评估

### 2.1 综合评分

| 评估维度 | 评分 | 等级 |
|----------|------|------|
| 身份鉴别 | {{auth_score}}/100 | {{auth_level}} |
| 访问控制 | {{access_score}}/100 | {{access_level}} |
| 安全审计 | {{audit_score}}/100 | {{audit_level}} |
| 入侵防范 | {{intrusion_score}}/100 | {{intrusion_level}} |
| 数据保护 | {{data_score}}/100 | {{data_level}} |
| **综合评分** | **{{total_score}}/100** | **{{total_level}}** |

### 2.2 安全状态概要

{{security_summary}}

---

## 3. 异常事件列表

| 序号 | 时间 | 事件类型 | 风险等级 | 描述 |
|------|------|----------|----------|------|
{{#each anomalies}}
| {{@index}} | {{time}} | {{type}} | {{risk}} | {{description}} |
{{/each}}

---

## 4. 详细分析

{{#each event_details}}
### 4.{{@index}}. {{title}}

- **时间**: {{time}}
- **类型**: {{type}}
- **风险等级**: {{risk}}
- **来源**: {{source}}

#### 事件描述

{{description}}

#### 证据链

{{#each evidence}}
- {{this}}
{{/each}}

#### 影响评估

{{impact}}

{{/each}}

---

## 5. 修复建议

### 紧急修复（立即执行）

{{#each urgent_fixes}}
{{@index}}. {{this}}
{{/each}}

### 短期修复（一周内）

{{#each short_term_fixes}}
{{@index}}. {{this}}
{{/each}}

### 长期改进

{{#each long_term_fixes}}
{{@index}}. {{this}}
{{/each}}

---

## 6. 附录

### 附录 A: 审计规则清单

```
{{audit_rules}}
```

### 附录 B: 原始日志片段

{{#each log_snippets}}
#### {{title}}

```
{{content}}
```

{{/each}}

### 附录 C: 检查工具版本

| 工具 | 版本 |
|------|------|
| auditd | {{auditd_version}} |
| bpftrace | {{bpftrace_version}} |
| 内核 | {{kernel_version}} |

---

*报告由 os-audit-tracer 自动生成*
