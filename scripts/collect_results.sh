#!/bin/bash
set -e

# 配置
EXPERIMENTS_DIR="experiments/Hierarchical"
OUTPUT_DIR="collected_results"

# 显示用法
usage() {
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  --task TASK_NAME    指定任务名（例如 T5_COMPREHENSIVE_ANALYSIS）"
    echo "                      如果不指定，将为每个任务创建单独的结果目录"
    echo "  --output DIR        指定输出目录（默认: collected_results）"
    echo "  --merge             如果指定，将所有任务的结果合并到同一固件目录下"
    echo ""
    echo "示例:"
    echo "  $0 --task T5_COMPREHENSIVE_ANALYSIS"
    echo "  $0 --output my_results"
    echo "  $0 --merge"
    exit 1
}

# 解析参数
SPECIFIC_TASK=""
MERGE_MODE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --task)
            SPECIFIC_TASK="$2"
            shift 2
            ;;
        --output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --merge)
            MERGE_MODE=true
            shift
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
echo "         FirmHive 结果收集工具"
echo "======================================================================="
echo ""

# 检查实验目录是否存在
if [ ! -d "$EXPERIMENTS_DIR" ]; then
    echo "错误：未找到实验目录 '$EXPERIMENTS_DIR'"
    exit 1
fi

# 创建输出目录
mkdir -p "$OUTPUT_DIR"

# 收集结果
if [ -n "$SPECIFIC_TASK" ]; then
    # 收集特定任务的结果
    echo "正在收集任务 '$SPECIFIC_TASK' 的结果..."
    echo ""
    
    TASK_DIR="$EXPERIMENTS_DIR/$SPECIFIC_TASK"
    
    if [ ! -d "$TASK_DIR" ]; then
        echo "错误：未找到任务目录 '$TASK_DIR'"
        exit 1
    fi
    
    # 统计固件数量
    FIRMWARE_COUNT=0
    
    # 遍历所有固件目录
    for firmware_dir in "$TASK_DIR"/*; do
        if [ ! -d "$firmware_dir" ]; then
            continue
        fi
        
        firmware_name=$(basename "$firmware_dir")
        
        # 检查是否有结果文件
        if [ ! -f "$firmware_dir/knowledge_base.jsonl" ]; then
            echo "  [跳过] $firmware_name: 未找到 knowledge_base.jsonl"
            continue
        fi
        
        # 创建固件结果目录
        OUTPUT_FIRMWARE_DIR="$OUTPUT_DIR/$firmware_name"
        mkdir -p "$OUTPUT_FIRMWARE_DIR"
        
        # 复制结果文件
        echo "  [收集] $firmware_name"
        
        [ -f "$firmware_dir/knowledge_base.jsonl" ] && cp "$firmware_dir/knowledge_base.jsonl" "$OUTPUT_FIRMWARE_DIR/"
        [ -f "$firmware_dir/knowledge_base.md" ] && cp "$firmware_dir/knowledge_base.md" "$OUTPUT_FIRMWARE_DIR/"
        [ -f "$firmware_dir/verification_results.jsonl" ] && cp "$firmware_dir/verification_results.jsonl" "$OUTPUT_FIRMWARE_DIR/"
        [ -f "$firmware_dir/verification_report.md" ] && cp "$firmware_dir/verification_report.md" "$OUTPUT_FIRMWARE_DIR/"
        
        FIRMWARE_COUNT=$((FIRMWARE_COUNT + 1))
    done
    
    echo ""
    echo "完成！共收集了 $FIRMWARE_COUNT 个固件的结果"
    echo "结果保存在: $OUTPUT_DIR/"
    
elif $MERGE_MODE; then
    # 合并所有任务的结果到同一固件目录
    echo "正在收集并合并所有任务的结果..."
    echo ""
    
    declare -A firmware_collected
    
    # 遍历所有任务
    for task_dir in "$EXPERIMENTS_DIR"/*; do
        if [ ! -d "$task_dir" ]; then
            continue
        fi
        
        task_name=$(basename "$task_dir")
        echo "处理任务: $task_name"
        
        # 遍历该任务下的所有固件
        for firmware_dir in "$task_dir"/*; do
            if [ ! -d "$firmware_dir" ]; then
                continue
            fi
            
            firmware_name=$(basename "$firmware_dir")
            
            # 检查是否有结果文件
            if [ ! -f "$firmware_dir/knowledge_base.jsonl" ]; then
                continue
            fi
            
            # 创建固件结果目录（如果不存在）
            OUTPUT_FIRMWARE_DIR="$OUTPUT_DIR/$firmware_name"
            mkdir -p "$OUTPUT_FIRMWARE_DIR"
            
            # 复制结果文件，使用任务名作为前缀
            echo "  [收集] $firmware_name (任务: $task_name)"
            
            [ -f "$firmware_dir/knowledge_base.jsonl" ] && cp "$firmware_dir/knowledge_base.jsonl" "$OUTPUT_FIRMWARE_DIR/${task_name}_knowledge_base.jsonl"
            [ -f "$firmware_dir/knowledge_base.md" ] && cp "$firmware_dir/knowledge_base.md" "$OUTPUT_FIRMWARE_DIR/${task_name}_knowledge_base.md"
            [ -f "$firmware_dir/verification_results.jsonl" ] && cp "$firmware_dir/verification_results.jsonl" "$OUTPUT_FIRMWARE_DIR/${task_name}_verification_results.jsonl"
            [ -f "$firmware_dir/verification_report.md" ] && cp "$firmware_dir/verification_report.md" "$OUTPUT_FIRMWARE_DIR/${task_name}_verification_report.md"
            
            firmware_collected[$firmware_name]=1
        done
    done
    
    FIRMWARE_COUNT=${#firmware_collected[@]}
    echo ""
    echo "完成！共收集了 $FIRMWARE_COUNT 个固件的结果（来自多个任务）"
    echo "结果保存在: $OUTPUT_DIR/"
    
else
    # 为每个任务创建单独的结果目录
    echo "正在收集所有任务的结果（按任务分组）..."
    echo ""
    
    # 遍历所有任务
    for task_dir in "$EXPERIMENTS_DIR"/*; do
        if [ ! -d "$task_dir" ]; then
            continue
        fi
        
        task_name=$(basename "$task_dir")
        echo "处理任务: $task_name"
        
        FIRMWARE_COUNT=0
        TASK_OUTPUT_DIR="$OUTPUT_DIR/$task_name"
        mkdir -p "$TASK_OUTPUT_DIR"
        
        # 遍历该任务下的所有固件
        for firmware_dir in "$task_dir"/*; do
            if [ ! -d "$firmware_dir" ]; then
                continue
            fi
            
            firmware_name=$(basename "$firmware_dir")
            
            # 检查是否有结果文件
            if [ ! -f "$firmware_dir/knowledge_base.jsonl" ]; then
                echo "  [跳过] $firmware_name: 未找到 knowledge_base.jsonl"
                continue
            fi
            
            # 创建固件结果目录
            OUTPUT_FIRMWARE_DIR="$TASK_OUTPUT_DIR/$firmware_name"
            mkdir -p "$OUTPUT_FIRMWARE_DIR"
            
            # 复制结果文件
            echo "  [收集] $firmware_name"
            
            [ -f "$firmware_dir/knowledge_base.jsonl" ] && cp "$firmware_dir/knowledge_base.jsonl" "$OUTPUT_FIRMWARE_DIR/"
            [ -f "$firmware_dir/knowledge_base.md" ] && cp "$firmware_dir/knowledge_base.md" "$OUTPUT_FIRMWARE_DIR/"
            [ -f "$firmware_dir/verification_results.jsonl" ] && cp "$firmware_dir/verification_results.jsonl" "$OUTPUT_FIRMWARE_DIR/"
            [ -f "$firmware_dir/verification_report.md" ] && cp "$firmware_dir/verification_report.md" "$OUTPUT_FIRMWARE_DIR/"
            
            FIRMWARE_COUNT=$((FIRMWARE_COUNT + 1))
        done
        
        echo "  任务 $task_name: 收集了 $FIRMWARE_COUNT 个固件"
        echo ""
    done
    
    echo "完成！所有任务的结果已收集"
    echo "结果保存在: $OUTPUT_DIR/"
fi

echo ""
echo "结果目录结构:"
tree -L 2 "$OUTPUT_DIR" 2>/dev/null || find "$OUTPUT_DIR" -maxdepth 2 -type d | head -20

echo ""
echo "======================================================================="
echo "                     收集完成！"
echo "======================================================================="

