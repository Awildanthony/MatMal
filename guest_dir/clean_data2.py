#
# Example usage: python3 ./clean_data.py out.txt 2 syscalls.json
#          args: <log_file.txt> <interval_len_in_seconds> <list_of_syscalls.json>

import numpy as np
import re
import json
from datetime import datetime, timedelta
import argparse

def parse_logs_to_matrix(log_file, interval_duration, syscalls_file, cpu_log):
    # Load the syscall-to-index mapping from the JSON file.
    with open(syscalls_file, "r") as f:
        syscall_index = json.load(f)

    # Get the total number of syscalls.
    num_syscalls = len(syscall_index)

    # Initialize variables.
    feature_vectors = []

    # Parse logs.
    with open(log_file, "r") as f:
        logs = f.readlines()

    # Parse CPU log data
    with open(cpu_log, "r") as f:
        cpu_logs = f.readlines()

    # Extract first timestamp to calculate intervals.
    first_timestamp = None
    logs_parsed = []

    for line in logs:
        # Attempt to match the updated log pattern.
        match = re.search(r"(\d{2}:\d{2}:\d{2})\s+(\w+)\(", line)

        if match:
            timestamp_str, syscall = match.groups()
            timestamp = datetime.strptime(timestamp_str, "%H:%M:%S")

            if first_timestamp is None:
                first_timestamp = timestamp

            logs_parsed.append((timestamp, syscall))

    if not logs_parsed:
        print("No logs matched the expected format. Exiting...")
        return np.zeros((0, num_syscalls + 2))  # Adjusted for additional features.

    # Create feature vectors for all valid intervals (limit to 10 seconds).
    current_time = first_timestamp
    end_limit_time = first_timestamp + timedelta(seconds=10)  # Limit to 10 seconds.

    while current_time < end_limit_time:  # Stop after 10 seconds.
        start_time = current_time
        end_time = start_time + timedelta(seconds=interval_duration)

        # Create an empty feature vector with space for additional features.
        fv = np.zeros(num_syscalls + 2, dtype=float)  # +2 for CPU usage and variance.

        # Process logs within the interval.
        interval_logs_found = False
        for timestamp, syscall in logs_parsed:
            if start_time <= timestamp < end_time:
                interval_logs_found = True
                if syscall in syscall_index:
                    fv[syscall_index[syscall]] += 1

        # Add CPU usage data from cpu_log for this interval.
        cpu_usage_values = []
        for line in cpu_logs:
            match_cpu = re.search(r"time (\d+) - (\d+) \[(\d+\.\d+)\]", line)
            if match_cpu:
                time_start, time_end, overall_cpu_usage = match_cpu.groups()
                time_start_sec = int(time_start)
                time_end_sec = int(time_end)
                if time_start_sec <= (current_time - first_timestamp).seconds < time_end_sec:
                    fv[-2] = float(overall_cpu_usage)  # Overall CPU usage.

                    # Extract per-process CPU usage and compute variance.
                    process_usages = re.findall(r"cpu usage (\d+\.\d+)", line)
                    process_usages_float = [float(cpu) for cpu in process_usages]
                    if process_usages_float:
                        fv[-1] = np.var(process_usages_float)  # Variance of CPU usage.
                    break

        if not interval_logs_found and fv[-2] == 0:  # No logs or CPU data found.
            break

        feature_vectors.append(fv)
        current_time = end_time

    # Convert list of feature vectors to a numpy array.
    feature_matrix = np.array(feature_vectors)

    return feature_matrix


if __name__ == "__main__":
    # Set up argument parser for command-line arguments.
    parser = argparse.ArgumentParser(description="Process strace logs into feature vectors.")
    parser.add_argument("log_file", type=str, help="Path to the log file.")
    parser.add_argument("cpu_log", type=str, help="Path to the CPU profile log file.")
    parser.add_argument("interval_duration", type=int, help="Interval duration in seconds.")
    parser.add_argument("syscalls_file", type=str, help="Path to the syscalls.json file.")

    args = parser.parse_args()

    # Process the logs.
    feature_matrix = parse_logs_to_matrix(args.log_file, args.interval_duration, args.syscalls_file, args.cpu_log)

    # Output the feature matrix (just to be confident it works).
    print("Feature Matrix:")
    if feature_matrix.size > 0:
        row, col = feature_matrix.shape
        print(f"rows: {row}, cols: {col}")
        print(feature_matrix)
    else:
        print("Feature matrix is empty.")
