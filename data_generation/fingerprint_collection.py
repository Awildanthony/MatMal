"""
Fingerprint Collection Script

This script automates the process of running malware binaries in isolated Podman containers,
collecting strace and CPU usage logs, and storing the results in organized directories.

Usage:
    python3 fingerprint_collection.py <input_directory> <output_directory>

Example:
    python3 fingerprint_collection.py ../test_malware/bin ../test_malware/output

This will process each binary in the input directory and save the corresponding logs in the output directory.
"""

import os
import subprocess
import argparse

def collect_fingerprint(binary_path, output_dir):
    """Run a binary in a fresh Podman container and collect strace and CPU logs."""
    # Resolve paths to absolute
    binary_path = os.path.abspath(binary_path)
    output_dir = os.path.abspath(output_dir)
    script_dir = os.path.dirname(os.path.abspath(__file__))  # Directory containing all scripts

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

def main(directory, output_dir):
    """Iterate over all binaries in the directory and collect fingerprints."""
    directory = os.path.abspath(directory)
    output_dir = os.path.abspath(output_dir)

    for binary in os.listdir(directory):
        binary_path = os.path.join(directory, binary)
        if os.path.isfile(binary_path):
            binary_output_dir = os.path.join(output_dir, os.path.basename(binary))
            os.makedirs(binary_output_dir, exist_ok=True)
            print(f"Processing {binary_path}...")
            collect_fingerprint(binary_path, binary_output_dir)
            print(f"Finished processing {binary_path}, output saved to {binary_output_dir}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", help="Directory containing binaries to analyze")
    parser.add_argument("output_dir", help="Directory to store output files")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    main(args.directory, args.output_dir)
