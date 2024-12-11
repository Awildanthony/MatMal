#!/bin/bash

# Install Podman on EC2
sudo apt update && sudo apt install -y podman

# Pull Fedora base image if not already available
podman pull fedora

# Install dependencies in the container
podman run --name fedora_temp fedora bash -c "
    dnf update -y &&
    dnf install -y strace htop python3 python3-pip psutil
"

# Get the most recently created container ID and commit it to an image
container_id=$(podman ps -a --format "{{.ID}}" --sort created | tail -n 1)
podman commit "$container_id" straceimg

# Run the malware-isolated container with the created image
podman run -it \
    --cap-add=SYS_PTRACE \
    --network none \
    -v $(pwd):/mnt/ \
    straceimg bash


# Old version below in case you want to do this manually instead:

# # install podman on ec2
# sudo apt install podman

# # install dependencies on container
# podman run -it fedora bash
# dnf update -y
# dnf install -y strace htop python3 python3-pip
# exit

# # commit it to an image after install 
# podman container ls -a
# podman commit <container_id> straceimg

# # get malware isolated container container
# podman run -it \
#     --cap-add=SYS_PTRACE \
#     --network none \
#     -v $(pwd):/mnt/ \
#     straceimg bash