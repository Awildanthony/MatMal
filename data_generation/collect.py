# run this script inside the podman container at the /mnt/guest_dir directory

# example usage: python collect.py ../test_malware/bin 00bbe47a7af460fcd2beb72772965e2c3fcff93a91043f0d74ba33c92939fe9d ../test_malware/output > cpu_profile.txt

import os
import signal
import sys
import subprocess
import psutil
import time
import argparse
from datetime import datetime

def get_time_delta(time_difference):
    days = time_difference.days
    seconds = time_difference.seconds
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    remaining_seconds = seconds % 60

    formatted_string = f"{days} days, {hours} hours, {minutes} minutes, {remaining_seconds} seconds"
    return formatted_string

def get_proc_output():
    ret = []
    for process in psutil.process_iter():
        try:
            process_info = process.as_dict(attrs=['pid', 'name', 'cpu_percent', 'memory_percent', 'exe'])
            cpu_usage = process.cpu_percent(interval=0.2)
            process_info['cpu_percent'] = cpu_usage
            start_time = datetime.fromtimestamp(process.create_time())
            process_info['time+'] = get_time_delta(datetime.now() - start_time)
            ret.append(process_info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return ret

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("working_dir", help="Directory where binary should be run from")
    parser.add_argument("binary_path", help="Path to the binary to analyze")
    parser.add_argument("output_dir", help="Directory to store output files")
    args = parser.parse_args()

    # Ensure output directory exists
    os.makedirs(args.output_dir, exist_ok=True)

    malware_bin = os.path.basename(args.binary_path)
    strace_output_path = os.path.join(args.output_dir, "strace.txt")
    cpu_log_output_path = os.path.join(args.output_dir, "cpu_log.txt")

    with open(strace_output_path, "w") as strace_file, open(cpu_log_output_path, "w") as cpu_log_file:
        command = ["strace", "-f", "-t", "-T", "./" + malware_bin]
        proc = subprocess.Popen(command, 
                                stdout=strace_file,
                                stderr=strace_file,
                                cwd=args.working_dir,
                                text=True)
        for i in range(10):
            cpu_log_file.write(f"time {i} - {i+1}\n")
            cpu_usage = psutil.cpu_percent(interval=0, percpu=True)
            cpu_log_file.write(str(cpu_usage) + "\n")
            process_info = get_proc_output()
            for info in process_info:
                cpu_log_file.write(f"Proc {info['pid']} cpu usage {info['cpu_percent']}\n")
            cpu_log_file.write(str(process_info) + "\n")
            cpu_log_file.flush()
            time.sleep(1)
        proc.kill()
