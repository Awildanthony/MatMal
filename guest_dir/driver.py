import os 

with open('commands.sh') as f:
    lines = f.readlines()
    lines = [line.strip() for line in lines]

directory_path = 'linux_binaries'
files = [f for f in os.listdir(directory_path) if os.path.isfile(os.path.join(directory_path, f))]

cleaned_commands = []

for l in lines:
    bi = l.split()[0].strip()
    if bi in files:
        new_cmd = "./" + l
        cleaned_commands.append(new_cmd.strip())

print(cleaned_commands)


# need to cd into mnt/guest_dir