"""
This script automates the process of running malware binaries in isolated Podman containers,
collecting strace and CPU usage logs, and subsequently extracting features into numpy arrays and CSV files.

Usage:
    python3 fingerprint_collection.py <input_directory> <output_directory> <syscalls_file> <script_directory>

Arguments:
    input_directory:    Path to the directory containing binaries to analyze.
    output_directory:   Path to the directory where logs and features will be saved.
    syscalls_file:      Path to the syscalls.json file used for feature extraction.
    script_directory:   Path to the directory containing auxiliary scripts (e.g., collect.py).

Example:
    python3 fingerprint_collection.py ../test_malware/bin ../test_malware/output syscalls.json .

Workflow:
1. Output Collection:
    - Each binary in the input directory is run inside a fresh Podman container.
    - The `collect.py` script generates `strace.txt` and `cpu_log.txt` for each binary in the output directory.
    - Progress is tracked with a progress bar.

2. Fingerprint Extraction:
    - Once all fingerprints are collected, features (fingerprints) are extracted using strace and CPU logs.
    - Features are saved as both `.npy` and `.csv` files in the respective binary's output directory.

Dependencies:
    - Python modules: os, subprocess, argparse, numpy, tqdm
    - Podman with a valid container image (e.g., `straceimg`)
    - Auxiliary scripts: `collect.py` (located in script_directory)
"""

import os
import subprocess
import argparse
import numpy as np
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed

def collect_output(binary_path, output_dir, script_dir):
    """Run a binary in a fresh Podman container and collect strace and CPU logs."""
    # Resolve paths to absolute
    binary_path = os.path.abspath(binary_path)
    output_dir = os.path.abspath(output_dir)
    script_dir = os.path.abspath(script_dir)  # Directory containing all scripts

    # Ensure host paths exist
    os.makedirs(output_dir, exist_ok=True)

    # Podman container execution
    subprocess.run([
        "podman", "run", "--rm", "--cap-add=SYS_PTRACE", "--network", "none",
        "-v", f"{os.path.dirname(binary_path)}:/mnt/working_dir",
        "-v", f"{output_dir}:/mnt/output_dir",
        "-v", f"{script_dir}:/mnt/scripts",  # Mount the directory with scripts
        "straceimg", "bash", "-c",
        f"python3 /mnt/scripts/collect.py /mnt/working_dir /mnt/working_dir/{os.path.basename(binary_path)} /mnt/output_dir"
    ], check=True)

def calculate_features(output_dir, syscalls_file, script_dir):
    """Iterate over all binary output directories and calculate features."""
    for binary_dir in tqdm(os.listdir(output_dir), desc="Feature Calculation", unit="binary"):
        binary_output_path = os.path.join(output_dir, binary_dir)
        if os.path.isdir(binary_output_path):
            strace_file = os.path.join(binary_output_path, "strace.txt")
            cpu_log_file = os.path.join(binary_output_path, "cpu_log.txt")
            feature_matrix_path = os.path.join(binary_output_path, "feature_matrix.npy")
            feature_csv_path = os.path.join(binary_output_path, "feature_matrix.csv")

            # Run feature extraction using calculate_features.py
            subprocess.run([
                "python3", os.path.join(script_dir, "calculate_features.py"),
                strace_file, cpu_log_file, "1", syscalls_file
            ], check=True)

            # Move outputs to appropriate paths
            if os.path.exists("feature_matrix.npy"):
                os.rename("feature_matrix.npy", feature_matrix_path)
            if os.path.exists("feature_matrix.csv"):
                os.rename("feature_matrix.csv", feature_csv_path)

def main(directory, output_dir, syscalls_file, script_dir, num_threads, features_only):
    """Iterate over all binaries in the directory and collect fingerprints and features."""
    directory = os.path.abspath(directory)
    output_dir = os.path.abspath(output_dir)

    if not features_only:
        # Collect fingerprints if not in features-only mode
        binaries = [binary for binary in os.listdir(directory) if os.path.isfile(os.path.join(directory, binary))]

        # Parallelize binary output collection
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            future_to_binary = {
                executor.submit(collect_output, os.path.join(directory, binary), os.path.join(output_dir, binary), script_dir): binary
                for binary in binaries
            }

            for future in tqdm(as_completed(future_to_binary), total=len(future_to_binary), desc="Binary Output Collection", unit="binary"):
                binary = future_to_binary[future]
                try:
                    future.result()
                except Exception as e:
                    print(f"Error processing {binary}: {e}")

    # Calculate features
    calculate_features(output_dir, syscalls_file, script_dir)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", help="Directory containing binaries to analyze")
    parser.add_argument("output_dir", help="Directory to store output files")
    parser.add_argument("syscalls_file", help="Path to the syscalls.json file for feature extraction")
    parser.add_argument("script_dir", help="Path to the directory containing the scripts (e.g., collect.py and calculate_features.py)")
    parser.add_argument("--num-threads", type=int, default=4, help="Number of threads for parallel processing")
    parser.add_argument("--features-only", action="store_true", help="Skip output collection and calculate features only")
    args = parser.parse_args()

    # Limit the number of threads to a max of 4, to avoid overloading EC2 instances
    args.num_threads = min(args.num_threads, 4)

    os.makedirs(args.output_dir, exist_ok=True)
    main(args.directory, args.output_dir, args.syscalls_file, args.script_dir, args.num_threads, args.features_only)
