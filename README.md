# MatMal: Malware Detection using Behavioral Fingerprinting and ML

## Background

**MatMal** is a behavior-driven malware detection and classification system that allows for lightweight, dynamic analysis of malware binaries. It runs binaries in sandboxed Podman containers, collects system behavior outputs (namely, `strace` logs and CPU usage metrics), and then converts these into timed-interval behavioral fingerprints (feature matrices). These fingerprints are then used to classify malware families and variants, improving detection accuracy for obfuscated or polymorphic malware.

This repository hosts our dataset, along with the code used to generate it. To find our model training/testing code, please refer to [this Colab notebook](https://colab.research.google.com/drive/1B__2sUCNqvPS7JtjgsBavFaz9ASNFJiI?usp=sharing).

---

## Setup Instructions

Spin up a Linux (Debian-based) virtual machine, ideally in the cloud --- we used EC2. Then, within your instance, execute the commands listed in the `setup.sh` file step by step -- do not run it as a single script. These steps include:
1. Installing dependencies on the virtual machine.
2. Setting up a Fedora-based container using Podman.
3. Committing this container as an image to be reused many times.

Refer to the comments in `setup.sh` for more detailed guidance.

---

## Execution Instructions

### Run `fingerprint_collection.py`
`cd` into the `data_generation` directory to use this script. This script automates running (any amount of malicious or benign) binaries, collecting logs for these binaries, and extracting features.

#### Usage:
```bash
python3 fingerprint_collection.py <input_directory> <output_directory> <syscalls_file> <script_directory> [--num-threads NUM] [--features-only]
```

#### Arguments:
- `input_directory`: Directory containing binaries to analyze.
- `output_directory`: Directory where logs and features will be saved.
- `syscalls_file`: Path to the `syscalls.json` file used for feature extraction.
- `script_directory`: Path to the directory containing auxiliary scripts (e.g., `collect.py`).

#### Optional Arguments:
- `--num-threads NUM`: Number of threads for parallel processing (defaults to 4, limited to 4).
- `--features-only`: Skip output collection and calculate features only, using the existing logs in `output_directory`.

#### Example:
```bash
python3 fingerprint_collection.py ../test_malware/bin ../test_malware/output syscalls.json . --num-threads 4
```

## Repository Structure Overview

### `./`
- **`setup.sh`**: A setup script containing instructions to install dependencies and configure the environment. Follow the commands in this file manually to prepare your EC2 instance / virtual machine for containerization and feature extraction.
- **`.gitignore`**: Specifies files and directories to be excluded from version control (e.g., logs, temporary files).
- **`README.md`**: This file! Explaining the project, setup, and usage instructions.

### `data_generation/`
This folder contains scripts for data collection, feature extraction, and other utilities:
- **`fingerprint_collection.py`**: Automates running binaries in isolated Podman containers, collecting logs (`strace` and CPU usage), and extracting features into `.npy` and `.csv` files.
- **`calculate_features.py`**: Extracts features from logs (e.g., `strace.txt`, `cpu_log.txt`) into structured matrices for further analysis.
- **`collect.py`**: Collects runtime data (e.g., system calls, CPU usage) for binaries executed in containers.
- **`delete_large_dirs.py`**: Utility script for cleaning up large directories (that can't be uploaded to GitHub).
- **`gen_benign_samples.py`**: [Not used] Generates benign sample data for comparison with malware fingerprints.
- **`syscalls.json`**: A JSON file mapping system calls to unique feature vector indices for fingerprint extraction.

### `example_malware_datapoint/`
This folder contains an example of the output generated by the system for a single malware binary:
- **`cpu_log.txt`**: CPU usage log collected during execution.
- **`feature_matrix.csv`**: Extracted feature matrix in CSV format.
- **`feature_matrix.npy`**: Extracted feature matrix in NumPy format.
- **`strace.txt`**: System call trace log collected during execution.

### `test_benign/`
This folder is used for testing benign binaries:
- **`bin/`**: Contains benign binary files to be analyzed.
- **`output/`**: Stores logs and extracted features for benign binaries.
- **`consolidate/`**: Stores feature matrices from `output/` in NumPy format (for easy use in models).
- **`consolidate.py`**: Script to consolidate outputs or results from benign tests.
- **`commands.sh`**: A shell script containing example commands for generating benign binaries.
- **`README.md`**: Documentation for how we found benign binaries.

### `test_malware/`
This folder is used for testing benign binaries:
- **`bin/`**: Contains malware binary files to be analyzed.
- **`output/`**: Stores logs and extracted features for malware binaries.
- **`consolidate/`**: Stores feature matrices from `output/` in NumPy format (for easy use in models).
- **`consolidate.py`**: Script to consolidate outputs or results from malware tests.
- **`README.md`**: Documentation for how we found malware binaries.