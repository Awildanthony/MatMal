import os
import random
import itertools
import time

# Sample list of "benign" syscalls for training (replace with actual syscall names).
# NOTE: These are just syscalls that are trivial and/or safe to execute in isolation.
#       Limiting the pool might also be more efficient and yield the same desired products.
BENIGN_SYSCALLS = [
    "open", "read", "write", "close", "chmod", "stat", "fstat", "lseek", "getpid", "getuid"
]

# Parameters.
N = len(BENIGN_SYSCALLS)
MAX_SYSCALLS = 20    # Maximum k value (this hovers at around 20 for the malware samples).
DURATION = 20        # Duration of each script in seconds.
NUM_SAMPLES = 10     # Number of benign samples to generate.


def generate_syscall_combinations(max_k, num_samples, syscalls):
    combinations = []
    for k in range(1, max_k + 1):
        # Generate all possible k-tuples of syscalls.
        tuples = list(itertools.combinations(syscalls, k))
        # Randomly sample from the k-tuples.
        random_samples = random.sample(tuples, min(num_samples, len(tuples)))
        combinations.extend(random_samples)
    return combinations


def generate_benign_script(syscall_tuple, script_name, duration):
    script_lines = []
    script_lines.append("#!/usr/bin/env python3")
    script_lines.append("import os, time")

    # Create a series of sporadic or repeated calls.
    script_lines.append(f"start_time = time.time()")
    script_lines.append(f"while time.time() - start_time < {duration}:")
    for syscall in syscall_tuple:
        if syscall == "open":
            script_lines.append(f"    with open('/tmp/testfile', 'w') as f: pass")
        elif syscall == "chmod":
            script_lines.append(f"    os.chmod('/tmp/testfile', 0o644)")
        elif syscall == "read" or syscall == "write":
            script_lines.append(f"    with open('/tmp/testfile', 'r+') as f: f.{syscall}(b'test')")
        elif syscall == "getpid":
            script_lines.append(f"    pid = os.getpid()")
        elif syscall == "getuid":
            script_lines.append(f"    uid = os.getuid()")
        elif syscall == "stat" or syscall == "fstat":
            script_lines.append(f"    os.{syscall}('/tmp/testfile')")
        elif syscall == "lseek":
            script_lines.append(f"    with open('/tmp/testfile', 'r') as f: os.lseek(f.fileno(), 0, os.SEEK_SET)")
        script_lines.append(f"    time.sleep(0.5)")    # Add some idle time between syscalls.

    # Write the script to file.
    with open(script_name, "w") as f:
        f.write("\n".join(script_lines))

    # Make script executable.
    os.chmod(script_name, 0o755)


def main():
    # Step 1: Generate syscall combinations.
    syscall_combinations = generate_syscall_combinations(MAX_SYSCALLS, NUM_SAMPLES, BENIGN_SYSCALLS)

    # Step 2: Generate scripts for each combination.
    for i, syscall_tuple in enumerate(syscall_combinations):
        script_name = f"benign_sample_{i + 1}.py"
        print(f"Generating script: {script_name} with syscalls: {syscall_tuple}")
        generate_benign_script(syscall_tuple, script_name, DURATION)


if __name__ == "__main__":
    main()
