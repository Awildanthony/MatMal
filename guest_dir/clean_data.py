#
# Example usage: python3 ./clean_data.py out.txt 2 syscalls.json
#          args: <log_file.txt> <interval_len_in_seconds> <list_of_syscalls.json>

import numpy as np
import re
import json
from datetime import datetime, timedelta
import argparse


def parse_logs_to_matrix(log_file, interval_duration, syscalls_file):
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

    # Extract first timestamp to calculate intervals.
    first_timestamp = None
    logs_parsed = []

    for line in logs:
        # Attempt to match the updated log pattern.
        match = re.search(r"(\d{2}:\d{2}:\d{2})\s+(\w+)\(", line)

        # NOTE: certain log lines featuring "<... some_syscall resumed>" correspond
        #       to previously-called system calls and are therefore ignored.
        if match:
            timestamp_str, syscall = match.groups()
            timestamp = datetime.strptime(timestamp_str, "%H:%M:%S")

            if first_timestamp is None:
                first_timestamp = timestamp

            logs_parsed.append((timestamp, syscall))

    if not logs_parsed:
        print("No logs matched the expected format. Exiting...")
        return np.zeros((0, num_syscalls))

    # Create feature vectors for all valid intervals.
    current_time = first_timestamp
    while True:
        start_time = current_time
        end_time = start_time + timedelta(seconds=interval_duration)

        # Create an empty feature vector.
        fv = np.zeros(num_syscalls, dtype=int)

        # Process logs within the interval.
        interval_logs_found = False
        for timestamp, syscall in logs_parsed:
            if start_time <= timestamp < end_time:
                interval_logs_found = True
                if syscall in syscall_index:
                    fv[syscall_index[syscall]] += 1
                else:
                    # Debug: Print syscalls that are not found in the syscall index.
                    print(f"Unmapped syscall: {syscall}")
        
        # Break if no more logs fall into the current interval.
        if not interval_logs_found:
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
    parser.add_argument("interval_duration", type=int, help="Interval duration in seconds.")
    parser.add_argument("syscalls_file", type=str, help="Path to the syscalls.json file.")

    args = parser.parse_args()

    # Process the logs.
    feature_matrix = parse_logs_to_matrix(args.log_file, args.interval_duration, args.syscalls_file)

    # Output the feature matrix (just to be confident it works).
    print("Feature Matrix:")
    if feature_matrix.size > 0:
        row, col = feature_matrix.shape
        print(f"rows: {row}, cols: {col}")
        nonzero_entry_count_list = []
        for i in range(row):
            nonzero_entry_count_list.append(np.count_nonzero(feature_matrix[i] != 0))
        avg_nonzero_count = sum(nonzero_entry_count_list) // len(nonzero_entry_count_list)
        print(f"Avg. # of non-0 entries in a given row: {avg_nonzero_count}")
        print(feature_matrix)
    else:
        print("Feature matrix is empty.")
