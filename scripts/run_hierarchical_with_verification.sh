#!/bin/bash
set -e

METHOD_NAME="Hierarchical"

BASE_OUTPUT_DIR="results"

FIRMWARE_BASE_DIR="/media/zxr/Elements/karonte"

# 分析阶段的并发固件数
MAX_CONCURRENT_JOBS=8

# 验证阶段的配置
VERIFICATION_MAX_WORKERS=5  # 每个固件验证时的并发worker数
VERIFICATION_PARALLEL_JOBS=4  # 同时验证多少个固件

# 随机选择固件数量（设置为0表示运行所有固件）
RANDOM_SAMPLE_COUNT=7

ALL_AVAILABLE_TASKS=(
    "T1_HARDCODED_CREDENTIALS"
    "T2_COMPONENT_CVE"
    "T3_NVRAM_INTERACTION"
    "T4_WEB_ATTACK_CHAIN"
    "T5_COMPREHENSIVE_ANALYSIS"
)

declare -a TASKS_TO_RUN=()

# 分析函数
run_analysis() {
    local task_name="$1"
    local firmware_path="$2"
    
    local firmware_dir_name
    firmware_dir_name=$(basename "$firmware_path")
    
    local output_dir="$BASE_OUTPUT_DIR/$METHOD_NAME/$task_name/$firmware_dir_name"
    mkdir -p "$output_dir"

    if [ -f "$output_dir/summary.txt" ]; then
        echo "   [SKIPPING] 分析结果已存在: $firmware_dir_name (任务: $task_name)"
        return
    fi

    echo "=> [开始分析] 方法: $METHOD_NAME, 任务: $task_name, 固件: $firmware_dir_name"
    echo "   输出目录: $output_dir"

    local task_prompt
    task_prompt=$(python3 firmhive/get_task.py "$task_name")
    if [ $? -ne 0 ]; then
        echo "   [错误] 无法从 get_task.py 获取任务 '$task_name'。"
        return 1
    fi

    python3 firmhive/blueprint.py \
        --search_dir "$firmware_path" \
        --output "$output_dir" \
        --mode "analyze" \
        --user_input "$task_prompt"

    echo "<= [完成分析] 方法: $METHOD_NAME, 任务: $task_name, 固件: $firmware_dir_name"
}

# 验证函数
run_verification() {
    local task_name="$1"
    local firmware_path="$2"
    
    local firmware_dir_name
    firmware_dir_name=$(basename "$firmware_path")
    
    local output_dir="$BASE_OUTPUT_DIR/$METHOD_NAME/$task_name/$firmware_dir_name"

    if [ ! -d "$output_dir" ]; then
        echo "   [跳过] 未找到分析结果目录: $output_dir"
        return
    fi

    if [ ! -f "$output_dir/knowledge_base.jsonl" ]; then
        echo "   [跳过] 未找到知识库文件: $firmware_dir_name (任务: $task_name)"
        return
    fi

    if [ -f "$output_dir/verification_results.jsonl" ]; then
        echo "   [跳过] 验证结果已存在: $firmware_dir_name (任务: $task_name)"
        return
    fi

    echo "=> [开始验证] 任务: $task_name, 固件: $firmware_dir_name"
    echo "   验证目录: $output_dir"

    python3 firmhive/blueprint.py \
        --search_dir "$firmware_path" \
        --output "$output_dir" \
        --mode "verify" \
        --concurrent \
        --max_workers "$VERIFICATION_MAX_WORKERS"

    echo "<= [完成验证] 任务: $task_name, 固件: $firmware_dir_name"
}

export -f run_analysis
export -f run_verification
export BASE_OUTPUT_DIR
export METHOD_NAME
export VERIFICATION_MAX_WORKERS

echo "======================================================================="
echo "         FirmHive 分层分析 + 验证 (完整流程)"
echo "======================================================================="
echo ""

# 解析任务参数
ARGS_PARSED_TASKS=false
for arg in "$@"; do
    if [[ "$arg" == --T* ]]; then
        ARGS_PARSED_TASKS=true
        search_prefix="${arg#--}"
        
        FOUND_TASK=false
        for full_task_name in "${ALL_AVAILABLE_TASKS[@]}"; do
            if [[ "$full_task_name" == "$search_prefix" ]] || [[ "$full_task_name" == "${search_prefix}"_* ]]; then
                TASKS_TO_RUN+=("$full_task_name")
                FOUND_TASK=true
                break
            fi
        done
        if ! $FOUND_TASK; then
            echo "警告: 未知任务参数 '$arg'。请检查任务名称。"
        fi
    fi
done

if [ ${#TASKS_TO_RUN[@]} -eq 0 ] && $ARGS_PARSED_TASKS; then
    echo "警告: 未找到有效任务，或所有指定任务无效。"
    echo "错误: 没有要运行的任务。请检查脚本配置或命令行参数。"
    exit 1
elif [ ${#TASKS_TO_RUN[@]} -eq 0 ] && ! $ARGS_PARSED_TASKS; then
    echo "错误: 没有要运行的任务。请使用 --T... 参数指定至少一个任务。"
    echo "示例: bash $0 --T1 --T3 --T5"
    exit 1
fi

echo "将运行以下任务: ${TASKS_TO_RUN[*]}"
echo ""

# 发现固件目标
echo "正在从 ${FIRMWARE_BASE_DIR} 发现固件目标..."
FIRMWARE_TARGETS=$(python3 firmhive/discover.py --base_dir "$FIRMWARE_BASE_DIR")
FIRMWARE_LIST=$(echo "$FIRMWARE_TARGETS" | tail -n +2)
if [ -z "$FIRMWARE_LIST" ]; then
    echo "错误: 未发现固件目标。请检查 FIRMWARE_BASE_DIR 配置。"
    exit 1
fi

# 统计总固件数
TOTAL_FIRMWARE_COUNT=$(echo "$FIRMWARE_LIST" | wc -l)
echo "发现 $TOTAL_FIRMWARE_COUNT 个固件目标"

# 随机采样
if [ "$RANDOM_SAMPLE_COUNT" -gt 0 ]; then
    if [ "$RANDOM_SAMPLE_COUNT" -ge "$TOTAL_FIRMWARE_COUNT" ]; then
        echo "注意: 请求的样本数 ($RANDOM_SAMPLE_COUNT) >= 总固件数 ($TOTAL_FIRMWARE_COUNT)，将使用所有固件"
    else
        echo "随机选择 $RANDOM_SAMPLE_COUNT 个固件进行测试..."
        FIRMWARE_LIST=$(echo "$FIRMWARE_LIST" | shuf | head -n "$RANDOM_SAMPLE_COUNT")
    fi
else
    echo "将运行所有固件..."
fi

echo ""
echo "将运行以下固件目标:"
echo "$FIRMWARE_LIST"
echo ""

# 阶段1: 分析（探索）
for task in "${TASKS_TO_RUN[@]}"; do
    echo "======================================================================="
    echo "    [阶段 1/2: 分析] 开始任务: $task"
    echo "======================================================================="
    
    echo "$FIRMWARE_LIST" | xargs -P "$MAX_CONCURRENT_JOBS" -I {} bash -c "run_analysis '$task' '{}'"
    
    echo ""
    echo "任务 [$task] 的分析阶段已完成所有固件。"
    echo ""
done

echo ""
echo "======================================================================="
echo "             所有任务的分析阶段已完成"
echo "             现在开始验证阶段..."
echo "======================================================================="
echo ""
sleep 2

# 阶段2: 验证
for task in "${TASKS_TO_RUN[@]}"; do
    echo "======================================================================="
    echo "    [阶段 2/2: 验证] 开始任务: $task"
    echo "======================================================================="
    echo "验证配置: 每个固件 $VERIFICATION_MAX_WORKERS 个并发worker，同时验证 $VERIFICATION_PARALLEL_JOBS 个固件"
    echo ""
    
    echo "$FIRMWARE_LIST" | xargs -P "$VERIFICATION_PARALLEL_JOBS" -I {} bash -c "run_verification '$task' '{}'"
    
    echo ""
    echo "任务 [$task] 的验证阶段已完成所有固件。"
    echo ""
done

echo ""
echo "======================================================================="
echo "                  🎉 所有任务已完成！"
echo "======================================================================="
echo "分析结果和验证结果保存在: $BASE_OUTPUT_DIR/$METHOD_NAME/"
echo ""
echo "查看结果示例:"
echo "  - 知识库 (发现的漏洞): results/$METHOD_NAME/<任务名>/<固件名>/knowledge_base.jsonl"
echo "  - 验证结果 (过滤后): results/$METHOD_NAME/<任务名>/<固件名>/verification_results.jsonl"
echo "  - 分析报告: results/$METHOD_NAME/<任务名>/<固件名>/analysis_report.md"
echo "  - 验证报告: results/$METHOD_NAME/<任务名>/<固件名>/verification_report.md"
echo ""

