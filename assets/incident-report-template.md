# 安全事件追溯报告

## 1. 事件概述

| 项目 | 内容 |
|------|------|
| 事件标题 | {{incident_title}} |
| 事件编号 | {{incident_id}} |
| 发现时间 | {{discovery_time}} |
| 事件时间范围 | {{start_time}} 至 {{end_time}} |
| 影响系统 | {{affected_systems}} |
| 影响范围 | {{impact_scope}} |
| 事件状态 | {{status}}（进行中/已控制/已清除） |
| 报告人员 | {{reporter}} |
| 报告日期 | {{report_date}} |

### 事件摘要

{{executive_summary}}

---

## 2. 事件时间线

| 时间 | 事件 | 类型 | 详情 |
|------|------|------|------|
{{#each timeline}}
| {{time}} | {{event}} | {{type}} | {{detail}} |
{{/each}}

---

## 3. 攻击链还原

```
{{attack_chain_diagram}}
```

### 3.1 初始入侵

- **攻击向量**: {{initial_vector}}
- **时间**: {{initial_time}}
- **证据**: {{initial_evidence}}

### 3.2 权限获取

- **提权方式**: {{privilege_method}}
- **时间**: {{privilege_time}}
- **证据**: {{privilege_evidence}}

### 3.3 持久化

- **持久化手段**: {{persistence_method}}
- **时间**: {{persistence_time}}
- **证据**: {{persistence_evidence}}

### 3.4 横向移动

- **移动方式**: {{lateral_method}}
- **目标系统**: {{lateral_targets}}
- **证据**: {{lateral_evidence}}

### 3.5 目标达成

- **攻击目的**: {{objective}}
- **数据泄露**: {{data_breach}}
- **证据**: {{objective_evidence}}

---

## 4. 证据链

{{#each evidence_chain}}
### 事件 {{@index}}: {{title}}

- **时间**: {{time}}
- **类型**: {{type}}
- **用户**: {{user}}
- **来源**: {{source}}
- **审计 ID**: {{audit_id}}

#### 证据详情

{{detail}}

#### 关联事件

{{#each related_events}}
- {{this}}
{{/each}}

{{/each}}

---

## 5. 影响评估

### 5.1 直接影响

| 影响项 | 状态 | 详情 |
|--------|------|------|
| 账户安全 | {{account_status}} | {{account_detail}} |
| 数据泄露 | {{data_status}} | {{data_detail}} |
| 系统完整性 | {{system_status}} | {{system_detail}} |
| 服务可用性 | {{service_status}} | {{service_detail}} |

### 5.2 业务影响

{{business_impact}}

### 5.3 风险评级

| 维度 | 评级 | 说明 |
|------|------|------|
| 机密性 | {{confidentiality}} | {{confidentiality_detail}} |
| 完整性 | {{integrity}} | {{integrity_detail}} |
| 可用性 | {{availability}} | {{availability_detail}} |
| **综合风险** | **{{overall_risk}}** | |

---

## 6. 处置建议

### 6.1 紧急处置（立即执行）

- [ ] {{emergency_1}}
- [ ] {{emergency_2}}
- [ ] {{emergency_3}}

### 6.2 短期修复（一周内）

- [ ] {{short_term_1}}
- [ ] {{short_term_2}}
- [ ] {{short_term_3}}

### 6.3 长期预防

- [ ] {{long_term_1}}
- [ ] {{long_term_2}}
- [ ] {{long_term_3}}

---

## 7. 经验教训

{{lessons_learned}}

---

## 8. 附录

### 附录 A: 原始审计日志

```
{{raw_audit_logs}}
```

### 附录 B: 取证数据清单

| 数据项 | 路径 | 大小 | MD5 |
|--------|------|------|-----|
{{#each forensic_data}}
| {{name}} | {{path}} | {{size}} | {{md5}} |
{{/each}}

### 附录 C: 参与人员

| 角色 | 姓名 | 联系方式 |
|------|------|----------|
| 事件响应负责人 | {{lead}} | {{lead_contact}} |
| 技术分析人员 | {{analyst}} | {{analyst_contact}} |
| 管理层汇报人 | {{manager}} | {{manager_contact}} |

---

*报告由 os-audit-tracer 自动生成*
*本报告包含安全敏感信息，请按机密文件管理*
