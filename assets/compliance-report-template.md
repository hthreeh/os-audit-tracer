# 合规审计报告

## 1. 审计概况

| 项目 | 内容 |
|------|------|
| 审计标准 | {{standard}}（如 GB/T 22239-2019） |
| 安全等级 | 第{{level}}级 |
| 审计范围 | {{scope}} |
| 主机名 | {{hostname}} |
| IP 地址 | {{ip_address}} |
| 操作系统 | {{os_version}} |
| 审计日期 | {{audit_date}} |
| 审计人员 | {{auditor}} |

---

## 2. 检查结果汇总

| 类别 | 检查项数 | 通过 | 未通过 | 警告 | 不适用 | 合规率 |
|------|----------|------|--------|------|--------|--------|
{{#each categories}}
| {{name}} | {{total}} | {{pass}} | {{fail}} | {{warn}} | {{na}} | {{rate}}% |
{{/each}}
| **总计** | **{{total}}** | **{{total_pass}}** | **{{total_fail}}** | **{{total_warn}}** | **{{total_na}}** | **{{total_rate}}%** |

---

## 3. 详细检查结果

### 3.1 身份鉴别

| 编号 | 检查项 | 状态 | 说明 | 证据 |
|------|--------|------|------|------|
{{#each identity_items}}
| {{id}} | {{item}} | {{status}} | {{detail}} | {{evidence}} |
{{/each}}

### 3.2 访问控制

| 编号 | 检查项 | 状态 | 说明 | 证据 |
|------|--------|------|------|------|
{{#each access_items}}
| {{id}} | {{item}} | {{status}} | {{detail}} | {{evidence}} |
{{/each}}

### 3.3 安全审计

| 编号 | 检查项 | 状态 | 说明 | 证据 |
|------|--------|------|------|------|
{{#each audit_items}}
| {{id}} | {{item}} | {{status}} | {{detail}} | {{evidence}} |
{{/each}}

### 3.4 入侵防范

| 编号 | 检查项 | 状态 | 说明 | 证据 |
|------|--------|------|------|------|
{{#each intrusion_items}}
| {{id}} | {{item}} | {{status}} | {{detail}} | {{evidence}} |
{{/each}}

### 3.5 数据保护

| 编号 | 检查项 | 状态 | 说明 | 证据 |
|------|--------|------|------|------|
{{#each data_items}}
| {{id}} | {{item}} | {{status}} | {{detail}} | {{evidence}} |
{{/each}}

---

## 4. 差距分析

{{#each gaps}}
### 4.{{@index}}. {{title}}

- **检查项**: {{check_item}}
- **当前状态**: {{current_state}}
- **要求状态**: {{required_state}}
- **差距描述**: {{gap_description}}
- **风险等级**: {{risk_level}}
- **影响范围**: {{impact}}

{{/each}}

---

## 5. 整改建议

### 5.1 高优先级整改项

{{#each high_priority}}
{{@index}}. **{{title}}**
   - 检查项: {{check_item}}
   - 整改措施: {{measure}}
   - 预期效果: {{expected_effect}}
   - 责任人: {{responsible}}
   - 完成时限: {{deadline}}

{{/each}}

### 5.2 中优先级整改项

{{#each medium_priority}}
{{@index}}. **{{title}}**
   - 检查项: {{check_item}}
   - 整改措施: {{measure}}
   - 预期效果: {{expected_effect}}

{{/each}}

### 5.3 低优先级整改项

{{#each low_priority}}
{{@index}}. {{title}} - {{measure}}
{{/each}}

---

## 6. 合规结论

### 6.1 总体评估

{{overall_assessment}}

### 6.2 合规状态

| 状态 | 说明 |
|------|------|
| 合规 | {{compliant_count}} 项检查通过 |
| 部分合规 | {{partial_count}} 项存在警告 |
| 不合规 | {{non_compliant_count}} 项检查未通过 |

### 6.3 建议

{{recommendations}}

---

## 7. 附录

### 附录 A: 检查工具与方法

| 检查项 | 使用工具 | 检查方法 |
|--------|----------|----------|
{{#each tools}}
| {{item}} | {{tool}} | {{method}} |
{{/each}}

### 附录 B: 参考标准

- GB/T 22239-2019 信息安全技术 网络安全等级保护基本要求
- GB/T 25070-2019 信息安全技术 网络安全等级保护安全设计技术要求
- GB/T 28448-2019 信息安全技术 网络安全等级保护测评要求

### 附录 C: 原始检查数据

```
{{raw_check_data}}
```

---

*报告由 os-audit-tracer 自动生成*
*本报告仅供内部审计使用*
