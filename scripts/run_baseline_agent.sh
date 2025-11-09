#!/bin/bash
set -e

METHOD_NAME="BaselineAgent"

BASE_OUTPUT_DIR="result"

# Dataset root (anonymized). Override by exporting KARONTE_DATASET_DIR.
FIRMWARE_BASE_DIR="${KARONTE_DATASET_DIR:-/path/to/karonte_dataset}"

MAX_CONCURRENT_JOBS=8

ALL_AVAILABLE_TASKS=(
    "T1_HARDCODED_CREDENTIALS"
    "T2_COMPONENT_CVE"
    "T3_NVRAM_INTERACTION"
    "T4_WEB_ATTACK_CHAIN"
    "T5_COMPREHENSIVE_ANALYSIS"
)

declare -a TASKS_TO_RUN=()

run_analysis() {
    local task_name="$1"
    local firmware_path="$2"
    
    local firmware_dir_name
    firmware_dir_name=$(basename "$firmware_path")
    
    local output_dir_for_script="$BASE_OUTPUT_DIR/$METHOD_NAME/$task_name"
    mkdir -p "$output_dir_for_script"

    local final_output_dir="$output_dir_for_script/$firmware_dir_name"

    echo "=> [START] Method: $METHOD_NAME, Task: $task_name, Firmware: $firmware_dir_name"
    echo "   Output directory: $final_output_dir"

    local task_prompt
    task_prompt=$(python3 firmhive/get_task.py "$task_name")
    if [ $? -ne 0 ]; then
        echo "   [ERROR] Failed to retrieve task '$task_name' from get_task.py."
        return 1
    fi

    python3 eval/baseline_agent.py \
        --search_dir "$firmware_path" \
        --output "$output_dir_for_script" \
        --user_input "$task_prompt"

    echo "<= [DONE] Method: $METHOD_NAME, Task: $task_name, Firmware: $firmware_dir_name"
}

export -f run_analysis
export BASE_OUTPUT_DIR
export METHOD_NAME

echo "Starting analysis process for [${METHOD_NAME}] method..."

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
            echo "WARNING: Unknown task argument '$arg'. Please check the task name."
        fi
    fi
done

if [ ${#TASKS_TO_RUN[@]} -eq 0 ] && $ARGS_PARSED_TASKS; then
    echo "WARNING: No valid tasks found, or all specified tasks are invalid. All available tasks will be run."
elif [ ${#TASKS_TO_RUN[@]} -eq 0 ] && ! $ARGS_PARSED_TASKS; then
    echo "ERROR: No tasks to run. Please specify at least one task using --T... arguments."
fi

if [ ${#TASKS_TO_RUN[@]} -eq 0 ]; then
    echo "ERROR: No tasks to run. Please check the script configuration or command-line arguments."
    exit 1
fi

echo "The following tasks will be run: ${TASKS_TO_RUN[*]}"
echo ""

echo "Discovering firmware targets from karonte dataset..."
FIRMWARE_TARGETS=$(python3 firmhive/discover.py --base_dir "$FIRMWARE_BASE_DIR")
FIRMWARE_LIST=$(echo "$FIRMWARE_TARGETS" | tail -n +2)
if [ -z "$FIRMWARE_LIST" ]; then
    echo "ERROR: No firmware targets discovered. Please check the FIRMWARE_BASE_DIR configuration."
    exit 1
fi
echo "Discovered the following firmware targets:"
echo "$FIRMWARE_LIST"
echo ""

for task in "${TASKS_TO_RUN[@]}"; do
    echo "=================================================="
    echo "             Starting task: $task"
    echo "=================================================="
    
    echo "$FIRMWARE_LIST" | xargs -P "$MAX_CONCURRENT_JOBS" -I {} bash -c "run_analysis '$task' '{}'"
    
    echo "Task [$task] completed for all firmwares."
    echo ""
done

echo "All tasks have been completed!"
