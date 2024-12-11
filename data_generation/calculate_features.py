"""
This script processes strace and CPU usage logs to generate feature matrices for analysis.
The extracted features are saved in both .npy and .csv formats.

Usage:
    python3 calculate_features.py <log_file> <cpu_log> <interval_duration> <syscalls_file>

Arguments:
    log_file:         Path to the strace log file.
    cpu_log:          Path to the CPU usage log file.
    interval_duration: Interval duration in seconds for processing the logs.
    syscalls_file:    Path to the syscalls.json file containing the syscall-to-index mapping.

Example:
    python3 calculate_features.py strace.txt cpu_log.txt 1 syscalls.json

Dependencies:
    - Python modules: numpy, json, argparse, datetime, re
"""

import re
import numpy as np
import json
from datetime import datetime, timedelta
import argparse

def extract_cpu_usage_data(log_text):
    time_blocks = log_text.split('time')
    cpu_usage_data = {}

    for block in time_blocks[1:]:  # Skip the initial empty split
        # Extract the time range
        time_range_match = re.search(r'(\d+) - (\d+)', block)
        if not time_range_match:
            continue
        time_start, time_end = map(int, time_range_match.groups())
        time_range = f"{time_start} - {time_end}"

        # Extract overall CPU usage
        overall_match = re.search(r'\[(\d+\.\d+)\]', block)
        overall_usage = float(overall_match.group(1)) if overall_match else 0.0

        # Extract per-process CPU usage values
        cpu_usages = re.findall(r'Proc \d+ cpu usage ([\d.]+)', block)
        cpu_usages = list(map(float, cpu_usages))

        # Calculate variance if there are valid CPU usages
        variance = np.var(cpu_usages) if cpu_usages else 0.0

        cpu_usage_data[time_range] = (overall_usage, variance)

    return cpu_usage_data

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
        cpu_logs = f.read()

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

    # Create feature vectors for all valid intervals (limit to 10 seconds / vectors).
    current_time = first_timestamp
    end_limit_time = first_timestamp + timedelta(seconds=10)  # Limit to 10 seconds.

    # Extract CPU usage data from logs
    cpu_usage_data = extract_cpu_usage_data(cpu_logs)

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

        # Add CPU usage data for this interval.
        interval_key = f"{(current_time - first_timestamp).seconds} - {(current_time - first_timestamp).seconds + interval_duration}"
        if interval_key in cpu_usage_data:
            overall_usage, variance = cpu_usage_data[interval_key]
            fv[-2] = overall_usage  # Overall CPU usage
            fv[-1] = variance  # Variance of CPU usage

        feature_vectors.append(fv)
        current_time = end_time

    # Pad with zeros if necessary
    required_rows = 10 // interval_duration
    while len(feature_vectors) < required_rows:
        feature_vectors.append(np.zeros(num_syscalls + 2, dtype=float))

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

    # Save the feature matrix to both .npy and .csv files
    np.save("feature_matrix.npy", feature_matrix)
    np.savetxt("feature_matrix.csv", feature_matrix, delimiter=",", fmt="%.5f")