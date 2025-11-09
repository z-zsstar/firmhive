# HiveMind (FirmHive 实现)

## 概述

**FirmHive** 是一个由 LLM 智能体驱动的自动化固件漏洞分析系统。它采用分层多智能体架构，系统化地分析固件镜像，识别安全漏洞，并生成详细的验证报告。这是我们论文中描述的 HiveMind 架构的实际实现。

### 核心特性

- 🌳 **递归委托引擎 (RDE)**：位于 `agent/core/` 的核心引擎，动态生成智能体树，实现深度和广度自适应的分析。
- 📚 **主动知识中心 (PKH)**：中央知识库（`firmhive/knowagent.py`），使智能体能够存储、查询和主动关联发现，形成集体智能。
- ✅ **两阶段分析（探索与验证）**：首先探索固件以发现广泛的潜在漏洞，然后启动第二次聚焦验证阶段以过滤误报并确认发现。
- 🔧 **可自定义分析蓝图**：分析策略不是硬编码的。您可以在 `firmhive/blueprint.py` 中定义自己的分层工作流、智能体类型、工具和提示词。
- 🤖 **专业化智能体**：`firmhive/assistants.py` 中设计了一套专门用于特定任务的智能体，如目录遍历、文件分析和深度二进制函数追踪。

## 项目结构

```
firmhive/
├── agent/                  # 核心智能体框架（"蜂巢"）
│   ├── base.py            # 核心 LLM/智能体运行时、工具编排、异步任务
│   ├── core/              # 🏠 递归委托引擎 (RDE) 实现
│   └── tools/             # 通用工具执行框架
│
├── firmhive/              # 固件分析的领域特定实现
│   ├── blueprint.py       # 🧬 分析层次结构、智能体配置和系统提示词
│   ├── knowagent.py       # 🧠 主动知识中心 (PKH) 智能体
│   ├── assistants.py      # 🐝 专业化分析智能体（目录、文件、函数）
│   └── tools.py           # 🛠️ 固件分析工具（文件系统、radare2 封装）
│
├── baselines/             # 基线智能体实现（SRA、MAS）
└── scripts/               # 执行分析和基线的脚本
```

## 快速开始

### 前置要求

- Python 3.8+
- [radare2](https://github.com/radareorg/radare2)（用于二进制分析）
- [r2ghidra](https://github.com/radareorg/r2ghidra)（强烈推荐，用于更好的反编译）
- LLM API 访问（例如 DeepSeek、OpenAI）

### 安装配置

```bash
# 安装 radare2（Ubuntu/Debian 示例）
sudo apt-get install radare2

# 安装最新版本，推荐从源码安装
# git clone https://github.com/radareorg/radare2 && cd radare2 && sys/install.sh

# 安装 r2ghidra 以获得更优质的反编译效果
r2pm init
r2pm install r2ghidra

# 安装 Python 依赖
pip install -r requirements.txt

# 配置 LLM API 密钥
cp config.ini.template config.ini
# 编辑 config.ini 并添加您的 API 密钥和其他设置
```

**为什么使用 r2ghidra？** Ghidra 反编译器生成的伪代码可读性更强，这对于帮助 LLM 智能体理解复杂的二进制逻辑至关重要。虽然仅使用 `radare2` 也可以工作，但 `r2ghidra` 能显著提升二进制分析任务的性能。

**关于模型选择**：本系统在开发过程中主要使用 DeepSeek 模型进行测试。作为国产大模型，DeepSeek 理论上对中文的理解能力应该更强，所以在 `hivemind_cn` 分支（中文版本）中*可能*会有更好的表现……但我们并没有做严格的对比实验来验证这一点，纯属作者推测。如果您有兴趣，欢迎测试并分享结果！

### 运行首次分析

```bash
python -u firmhive/blueprint.py \
  --search_dir /path/to/extracted_firmware \
  --output ./output
```

数据集根目录（供脚本使用）：建议通过环境变量设置，避免硬编码

```bash
export KARONTE_DATASET_DIR=/path/to/karonte_dataset
```

## 理解输出结果

分析分为两个主要阶段：**探索** 和 **验证**。输出目录反映了这一点。

### 输出结构

```
output/
├── knowledge_base.jsonl       # 探索阶段的原始候选发现
├── knowledge_base.md          # 初始候选的可读报告
├── verification_results.jsonl # 详细验证结果（每个候选的真/假判断）
├── verification_report.md     # ⭐ 最终报告：确认漏洞的摘要
├── token_usage.jsonl          # LLM API 使用量和成本统计
└── FirmwareMasterAgent_logs/  # 完整详细的消息历史（用于调试）
```

**关键要点**：始终首先阅读 `verification_report.md`。该文件包含系统过滤潜在误报后的最终高置信度发现。

### 运行期间的预期指标

| 指标 | 典型范围 | 说明 |
| :--- | :--- | :--- |
| **分析时间** | 30 分钟 - 2+ 小时 | 很大程度上取决于固件大小和复杂度 |
| **Token 使用量** | 500 万 - 5000 万 tokens | 根据文件数量和分析深度而变化 |
| **成本估算** | $1 - $10 USD | 使用 DeepSeek API。监控 `token_usage.jsonl` |
| **初始发现**| 10 - 100+ 候选| 探索阶段设计为广泛覆盖，会包含误报 |
| **验证后发现**| 约初始候选的 20-50% | 验证阶段将候选过滤为高精度漏洞集 |

## 架构深入解析

### 分层蓝图（完全可自定义）

**当前配置**：FirmHive 配置了三层分析策略作为演示：

1. **目录层**：根智能体调查固件结构
2. **文件层**：专业化智能体分析单个文件（二进制、脚本、配置）
3. **函数层**：二进制分析智能体追踪漏洞代码路径

**灵活设计**：`firmhive/blueprint.py` 中的蓝图完全可自定义。您可以配置：
- 📊 **层数**：2、3、4 层或更多分层级别
- 💬 **系统提示词**：每层的任务特定指令
- 🔄 **最大迭代次数**：每个智能体可以递归的深度（每层控制）
- 🛠️ **工具集**：每层的智能体可以访问哪些工具
- 🎯 **智能体类型**：顺序、并行或混合委托策略

当前的三层设置是一个强大的默认配置，但只是一个示例。您可以通过编辑蓝图中的 `LAYER_CONFIGS` 来适应您的特定分析需求。

### 智能体作用域隔离

每个智能体在受限作用域内运行：
- ✅ 可访问：当前目录及所有子目录（任意深度）
- ❌ 不可访问：父目录、兄弟目录
- 🔄 升级：必须向父智能体报告发现以进行跨作用域分析

### 异步任务执行（实验性）

为了加速分析，FirmHive 支持将任务委托给**后台作业**：

```json
{
  "action": "ParallelDeepFileAnalysisDelegator",
  "action_input": {
    "file_names": ["file1.bin", "file2.sh"],
    "run_in_background": true  // ← 此标志启用异步执行
  }
}
```

**工作原理**：
- 智能体可以委托任务在后台运行
- 父智能体在子智能体分析时继续其他工作
- 异步收集和集成结果
- 减少顺序等待时间，对于分析大型目录至关重要

**⚠️ 实验性功能**：此异步机制尚未经过详尽测试。为了最大稳定性，您可以禁用它。如果遇到挂起，这是首先要检查的地方。

**重要提醒**：如果要完全禁用异步机制，建议从工具定义中移除 `run_in_background` 参数（在 `firmhive/assistants.py` 中），而不是仅仅将其设置为 `false`。仅设置为 `false` 可能会导致 LLM 智能体仍然尝试使用该参数，引发混淆或不可预期的行为。

### 知识中心

智能体主动存储和查询发现：
- **存储**：记录带有结构化元数据的漏洞
- **查询**：跨分析会话搜索相关发现
- **探索**：发现不同发现之间的联系

## 复现评估结果

### 运行基线

```bash
# 在脚本中编辑固件路径
vim scripts/run_hierarchical.sh  # 设置 FIRMWARE_BASE_DIR

# 运行 FirmHive（完整系统）
bash scripts/run_hierarchical.sh

# 运行基线
bash scripts/run_baseline_agent.sh        # SRA（单一 ReAct 智能体）
bash scripts/run_baseline_agent_kb.sh     # SRA + 知识库
bash scripts/run_baseline_pipeline.sh     # MAS（静态多智能体系统）
bash scripts/run_baseline_pipeline_kb.sh  # MAS + 知识库
```

### 结果位置

所有评估输出存储在 `result/` 目录中，按方法组织。论文打包仅包含 `exp/`，本地临时输出 `output/` 与 `result/` 均不提交。

```
results/
├── Hierarchical/              # ✅ FirmHive（我们的系统）
│   └── <任务>/<固件>/
│       ├── knowledge_base.jsonl
│       ├── verification_report.md    # ⭐ 最终验证发现在此
│       └── verification_results.jsonl
├── BaselineAgent/             # 单智能体基线
├── BaselineAgentKB/           # 单智能体 + 知识库
├── BaselinePipeline/          # 静态多智能体流水线（MAS）
└── BaselinePipelineKB/        # 静态多智能体流水线 + 知识库（MAS+KB）
```

**分析提示**：比较结果时，始终使用 FirmHive 的 `verification_report.md` 来查看最终验证的漏洞，而不是初始候选的原始 `knowledge_base.jsonl`。

## 自定义和配置

### LLM API 配置

编辑 `config.ini`：

```ini
[llm]
api_key = your_api_key_here
model = deepseek-chat
base_url = https://api.deepseek.com
temperature = 0.0
```

### 消息过滤（敏感数据脱敏）

为了安全和隐私，您可以添加消息过滤器以防止将机密信息（API 密钥、本地路径）泄露到日志或 LLM 上下文中。智能体运行时通过 `messages_filters` 参数支持简单的查找/替换规则。

```python
# 示例：在 blueprint.py 中构造智能体时附加过滤器
messages_filters = [
    {"from": "YOUR_REAL_API_KEY", "to": "REDACTED_API_KEY"},
    {"from": "/home/username/", "to": "/home/REDACTED/"},
    {"from": "192.168.", "to": "192.REDACTED."}
]
```

这些规则在消息记录或发送到 LLM 之前应用。

### 自定义分析蓝图

整个分层分析工作流定义在 `firmhive/blueprint.py` 中。这是您可以对系统行为施加最大控制的地方。

#### 可自定义内容：
- **系统提示词**（约第 40 行及 `LAYER_CONFIGS` 中）：定义每层的核心目标。
- **层数**：系统不限于 3 层——使用 2、4 层或更多。
- **最大迭代次数**：控制每层智能体递归深度（例如，第 1 层：5 步，第 2 层：15 步）。
- **工具集**：为不同层分配不同工具（例如，只有文件智能体可以使用二进制分析工具）。
- **委托策略**：为子智能体选择 `sequential`（逐个）或 `parallel`（并发）执行。
- **知识中心提示词**：修改 `firmhive/knowagent.py` 中的提示词以改变智能体存储和检索信息的方式。

默认配置针对漏洞搜寻进行了调优。如果您的目标是代码审查、合规性检查或特性提取，您应该调整这些提示词和层定义。

## 输出示例片段

### 初始分析候选（来自 `knowledge_base.jsonl`）

```json
{
  "name": "Hardcoded_Credentials_Admin",
  "location": "etc/config/default_config.xml line 42",
  "description": "在默认配置中发现硬编码的管理员凭据...",
  "code_snippet": "<admin><username>admin</username><password>admin123</password></admin>",
  "risk_score": 9.0,
  "confidence": 9.5,
  "file_path": "etc/config/default_config.xml"
}
```

### 验证结果（来自 `verification_results.jsonl`）

```json
{
  "name": "Hardcoded_Credentials_Admin",
  "is_real_vulnerability": true,
  "risk_level": "Critical",
  "detailed_reason": "已确认：默认凭据 'admin/admin123' 硬编码在默认配置文件中，用于身份验证且没有任何强制更改机制。",
  "verification_duration": 45.2,
  "token_usage": 12450
}
```

**关键区别**：验证结果提供了明确的确认（`is_real_vulnerability: true/false`），应该是您的真相来源。

## 故障排除

### 常见问题

**找不到 radare2**

```bash
# 验证 radare2 安装
r2 -v

# 检查 r2ghidra 安装（推荐）
r2pm -l | grep r2ghidra

# 如果未安装 r2ghidra
r2pm init
r2pm install r2ghidra

# 测试反编译
echo 'int main() { return 0; }' | gcc -x c - -o /tmp/test
r2 -qc 'aa; pdg' /tmp/test
# 应该显示反编译输出
```

**API 速率限制**
- 如果遇到速率限制，在 `agent/llmclient.py` 中添加延迟
- 考虑使用更高级别的 API 计划进行大规模分析

## 重要说明

### 任务适配
此系统目前针对漏洞发现进行了调优。如果您将 FirmHive 用于其他任务（如代码摘要或合规性检查），请确保调整 `firmhive/blueprint.py` 中的系统提示词以匹配您的目标。否则，智能体可能无法识别和保留重要发现。

### 异步执行
`run_in_background` 功能使智能体能够异步委托耗时任务。**这是一个实验性功能**，旨在处理多智能体协作开销。我们尚未在所有场景中彻底测试此机制。如果遇到问题：
- 禁用所有异步机制（建议从 `firmhive/assistants.py` 的工具定义中移除 `run_in_background` 参数，而非仅设置为 `false`）
- 调整智能体配置中的超时值
- 报告任何错误或意外行为以供未来改进

## 免责声明

本工具生成的漏洞报告仅用于教育和研究目的。我们不保证所有发现的准确性或完整性。在采取纠正措施之前，请手动验证任何报告的漏洞。

### 获得最佳结果：

- **首先阅读 `verification_report.md`**：这是最重要的文件。它包含经过过滤和验证的漏洞。从这里开始审查。
- **预期初始误报**：探索阶段设计为广泛撒网。在验证期间过滤掉 50-80% 的初始候选是正常的。
