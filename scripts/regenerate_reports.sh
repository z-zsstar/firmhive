#!/bin/bash
set -e

# 配置
EXPERIMENTS_DIR="experiments/Hierarchical"

# 显示用法
usage() {
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  --task TASK_NAME    指定任务名（例如 T5_COMPREHENSIVE_ANALYSIS）"
    echo "                      如果不指定，将处理所有任务"
    echo "  --experiments DIR   指定实验目录（默认: experiments/Hierarchical）"
    echo ""
    echo "示例:"
    echo "  $0 --task T5_COMPREHENSIVE_ANALYSIS"
    echo "  $0  # 重新生成所有任务的报告"
    exit 1
}

# 解析参数
SPECIFIC_TASK=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --task)
            SPECIFIC_TASK="$2"
            shift 2
            ;;
        --experiments)
            EXPERIMENTS_DIR="$2"
            shift 2
            ;;
        --help|-h)
            usage
            ;;
        *)
            echo "未知选项: $1"
            usage
            ;;
    esac
done

echo "======================================================================="
echo "         FirmHive 报告重新生成工具"
echo "======================================================================="
echo ""

# 检查实验目录是否存在
if [ ! -d "$EXPERIMENTS_DIR" ]; then
    echo "错误：未找到实验目录 '$EXPERIMENTS_DIR'"
    exit 1
fi

# 统计计数器
TOTAL_KB_REGENERATED=0
TOTAL_VR_REGENERATED=0
TOTAL_KB_SKIPPED=0
TOTAL_VR_SKIPPED=0
TOTAL_ERRORS=0

# 重新生成报告的函数
regenerate_reports() {
    local output_dir="$1"
    local firmware_name="$2"
    local task_name="$3"
    
    local kb_regenerated=0
    local vr_regenerated=0
    local kb_skipped=0
    local vr_skipped=0
    local errors=0
    
    # 检查并重新生成知识库报告
    if [ -f "$output_dir/knowledge_base.jsonl" ]; then
        echo "    [转换] 知识库报告: $firmware_name (任务: $task_name)"
        if python3 firmhive/utils/convert2md.py kb "$output_dir/knowledge_base.jsonl" -o knowledge_base.md 2>&1; then
            kb_regenerated=1
        else
            echo "    [错误] 知识库转换失败: $firmware_name"
            errors=1
        fi
    else
        kb_skipped=1
    fi
    
    # 检查并重新生成验证报告
    if [ -f "$output_dir/verification_results.jsonl" ]; then
        echo "    [转换] 验证报告: $firmware_name (任务: $task_name)"
        if python3 firmhive/utils/convert2md.py vr "$output_dir" -o verification_report.md 2>&1; then
            vr_regenerated=1
        else
            echo "    [错误] 验证报告转换失败: $firmware_name"
            errors=1
        fi
    else
        vr_skipped=1
    fi
    
    echo "$kb_regenerated $vr_regenerated $kb_skipped $vr_skipped $errors"
}

export -f regenerate_reports

# 主处理逻辑
if [ -n "$SPECIFIC_TASK" ]; then
    # 处理特定任务
    echo "正在重新生成任务 '$SPECIFIC_TASK' 的报告..."
    echo ""
    
    TASK_DIR="$EXPERIMENTS_DIR/$SPECIFIC_TASK"
    
    if [ ! -d "$TASK_DIR" ]; then
        echo "错误：未找到任务目录 '$TASK_DIR'"
        exit 1
    fi
    
    # 遍历所有固件目录
    for firmware_dir in "$TASK_DIR"/*; do
        if [ ! -d "$firmware_dir" ]; then
            continue
        fi
        
        firmware_name=$(basename "$firmware_dir")
        
        # 重新生成报告
        result=$(regenerate_reports "$firmware_dir" "$firmware_name" "$SPECIFIC_TASK")
        
        # 解析结果
        read kb_regen vr_regen kb_skip vr_skip err <<< "$result"
        TOTAL_KB_REGENERATED=$((TOTAL_KB_REGENERATED + kb_regen))
        TOTAL_VR_REGENERATED=$((TOTAL_VR_REGENERATED + vr_regen))
        TOTAL_KB_SKIPPED=$((TOTAL_KB_SKIPPED + kb_skip))
        TOTAL_VR_SKIPPED=$((TOTAL_VR_SKIPPED + vr_skip))
        TOTAL_ERRORS=$((TOTAL_ERRORS + err))
    done
    
else
    # 处理所有任务
    echo "正在重新生成所有任务的报告..."
    echo ""
    
    # 遍历所有任务
    for task_dir in "$EXPERIMENTS_DIR"/*; do
        if [ ! -d "$task_dir" ]; then
            continue
        fi
        
        task_name=$(basename "$task_dir")
        echo "处理任务: $task_name"
        echo "-------------------------------------------------------------------"
        
        task_kb_count=0
        task_vr_count=0
        
        # 遍历该任务下的所有固件
        for firmware_dir in "$task_dir"/*; do
            if [ ! -d "$firmware_dir" ]; then
                continue
            fi
            
            firmware_name=$(basename "$firmware_dir")
            
            # 重新生成报告
            result=$(regenerate_reports "$firmware_dir" "$firmware_name" "$task_name")
            
            # 解析结果
            read kb_regen vr_regen kb_skip vr_skip err <<< "$result"
            TOTAL_KB_REGENERATED=$((TOTAL_KB_REGENERATED + kb_regen))
            TOTAL_VR_REGENERATED=$((TOTAL_VR_REGENERATED + vr_regen))
            TOTAL_KB_SKIPPED=$((TOTAL_KB_SKIPPED + kb_skip))
            TOTAL_VR_SKIPPED=$((TOTAL_VR_SKIPPED + vr_skip))
            TOTAL_ERRORS=$((TOTAL_ERRORS + err))
            
            task_kb_count=$((task_kb_count + kb_regen))
            task_vr_count=$((task_vr_count + vr_regen))
        done
        
        echo "  任务 $task_name 完成: ${task_kb_count} 个知识库报告, ${task_vr_count} 个验证报告"
        echo ""
    done
fi

echo ""
echo "======================================================================="
echo "                     报告重新生成完成！"
echo "======================================================================="
echo ""
echo "统计信息:"
echo "  - 知识库报告已重新生成: $TOTAL_KB_REGENERATED 个"
echo "  - 验证报告已重新生成: $TOTAL_VR_REGENERATED 个"
echo "  - 知识库报告跳过（无源文件）: $TOTAL_KB_SKIPPED 个"
echo "  - 验证报告跳过（无源文件）: $TOTAL_VR_SKIPPED 个"
if [ $TOTAL_ERRORS -gt 0 ]; then
    echo "  - ⚠️  错误数量: $TOTAL_ERRORS"
    echo ""
    echo "提示：请检查上面的错误信息以了解详情"
else
    echo "  - ✅ 全部成功，无错误"
fi
echo ""
echo "所有 Markdown 报告现在都已使用最新的格式和中文翻译！"
echo "======================================================================="

