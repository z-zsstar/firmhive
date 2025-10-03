#!/bin/bash
set -e

DEFAULT_METHOD="Hierarchical"
DEFAULT_TASK="T5_COMPREHENSIVE_ANALYSIS"
DEFAULT_MAX_WORKERS=10
DEFAULT_PARALLEL_JOBS=8

BASE_OUTPUT_DIR="results"
FIRMWARE_BASE_DIR="/path/to/karonte_dataset"

METHOD="$DEFAULT_METHOD"
TASK="$DEFAULT_TASK"
MAX_WORKERS="$DEFAULT_MAX_WORKERS"
PARALLEL_JOBS="$DEFAULT_PARALLEL_JOBS"

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --method) METHOD="$2"; shift ;;
        --task) TASK="$2"; shift ;;
        --max_workers) MAX_WORKERS="$2"; shift ;;
        --parallel-jobs) PARALLEL_JOBS="$2"; shift ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
    shift
done

echo "======================================================================="
echo "            Starting Verification Process"
echo "-----------------------------------------------------------------------"
echo "  Method:                $METHOD"
echo "  Task:                  $TASK"
echo "  Max Workers per Firmware: $MAX_WORKERS"
echo "  Parallel Firmware Verifications: $PARALLEL_JOBS"
echo "======================================================================="

task_results_dir="$BASE_OUTPUT_DIR/$METHOD/$TASK"
if [ ! -d "$task_results_dir" ]; then
    echo "ERROR: Task results directory not found: $task_results_dir"
    exit 1
fi
echo "Task results directory found: $task_results_dir"
echo ""

echo "Discovering targets from firmware dataset..."
source_firmware_list=$(python3 firmhive/discover.py --base_dir "$FIRMWARE_BASE_DIR" | tail -n +2)

if [ -z "$source_firmware_list" ]; then
    echo "ERROR: Failed to discover any firmware from the dataset via firmhive/discover.py."
    exit 1
fi

target_source_dirs="$source_firmware_list"

echo "Verification will be performed for all discovered target firmwares."
echo ""

echo "Checking for corresponding result directories..."
firmware_result_dirs_array=()
for source_dir in $target_source_dirs; do
    firmware_name=$(basename "$source_dir")
    result_dir_path="$task_results_dir/$firmware_name"
    if [ -d "$result_dir_path" ]; then
        firmware_result_dirs_array+=("$result_dir_path")
        echo "  [FOUND] $result_dir_path"
    else
        echo "  [SKIPPED] Result directory for source firmware '$firmware_name' does not exist in $task_results_dir"
    fi
done

firmware_result_dirs=$(printf "%s\n" "${firmware_result_dirs_array[@]}")

if [ -z "$firmware_result_dirs" ]; then
    echo "No existing, verifiable result directories found among the discovered firmwares."
    exit 0
fi

num_firmware=$(echo "$firmware_result_dirs" | wc -l)
echo "Found ${num_firmware} matching firmware results to verify."

pids=()

for result_dir in $firmware_result_dirs; do
    (
        firmware_name=$(basename "$result_dir")
        
        echo "-----------------------------------------------------------------------"
        echo ">> [START] Processing: $firmware_name"
        
        kb_file="$result_dir/knowledge_base.jsonl"
        if [ ! -s "$kb_file" ]; then
            echo "   [SKIPPING] $firmware_name: Knowledge base file does not exist or is empty: $kb_file"
            exit 0
        fi
        
        echo "   [INFO] $firmware_name: Searching for original firmware path..."
        original_firmware_path=$(find "$FIRMWARE_BASE_DIR" -type d -name "$firmware_name" | head -n 1)
        
        if [ -z "$original_firmware_path" ]; then
            echo "   [WARNING] $firmware_name: Could not find original firmware directory named '$firmware_name' in $FIRMWARE_BASE_DIR, skipping verification."
            exit 0
        fi
        echo "   [INFO] $firmware_name: Original firmware found: $original_firmware_path"
        
        log_file="$result_dir/verification_run.log"
        echo "   [INFO] $firmware_name: Invoking blueprint.py for verification... (Log: $log_file)"
        python3 firmhive/blueprint.py \
            --mode verify \
            --output "$result_dir" \
            --search_dir "$original_firmware_path" \
            --concurrent \
            --max_workers "$MAX_WORKERS" 2>&1 | tee "$log_file"
            
        echo "<< [DONE] Processing complete: $firmware_name"
    ) &
    pids+=($!)

    # 控制并发数：当达到最大并发数时，等待任意一个完成
    if [ ${#pids[@]} -ge "$PARALLEL_JOBS" ]; then
        wait -n  # 等待任意一个后台进程完成
        # 清理已完成的进程ID
        new_pids=()
        for pid in "${pids[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then
                new_pids+=("$pid")
            fi
        done
        pids=("${new_pids[@]}")
    fi
done

wait

echo ""
echo "======================================================================="
echo "All verification tasks completed!"
echo "======================================================================="