# run this script inside the podman container at the /mnt/guest_dir directory

# example usage: python collect.py test_malware 00bbe47a7af460fcd2beb72772965e2c3fcff93a91043f0d74ba33c92939fe9d > cpu_profile.txt

import os
import signal
import sys
import subprocess
import psutil
import select
from datetime import datetime
from multiprocessing import Pool
import time

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
            print("Proc " + str(process_info['pid']) + " cpu usage " + str(cpu_usage))
            start_time = datetime.fromtimestamp(process.create_time())
            process_info['cpu_percent'] = cpu_usage
            process_info['time+'] = get_time_delta(datetime.now() - start_time)
            ret.append(process_info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return ret

def poll_proc(proc, total_duration, interval, output_file): # not used
    start_time_log = 0

    while start_time_log < total_duration:
        if proc.poll() is not None: # exit if proc exit check succeeds
            break

        ready_to_read, _, _ = select.select([proc.stdout, proc.stderr], [], [], interval)

        for stream in ready_to_read:
            output = os.read(stream.fileno(), 4096).decode('utf-8')
            log_output = "\ntime " + str(start_time_log) + "-" + str(start_time_log+interval) + "\n\n"
            output_file.write(log_output)

            for plog in get_proc_output():
                if malware_bin in plog["name"]:
                    output_file.write(str(plog))
            
            output_file.write("\n\n")
            output_file.write(output)

        time.sleep(interval)
        start_time_log += interval


if __name__ == "__main__":
    d = sys.argv[1]
    malware_bin = sys.argv[2]

    command = ["strace", "-f", "-t", "-T", "./" + malware_bin]
    with open("out.txt", "w") as outfile:
        proc = subprocess.Popen(command, 
            stdout=outfile,
            stderr=outfile,
            cwd=d,
            text=True
        )
        for i in range(10):
            print("time", i, "-", i+1)
            print(psutil.cpu_percent(interval=0, percpu=True))
            print(get_proc_output())
            time.sleep(1)
        proc.kill()




