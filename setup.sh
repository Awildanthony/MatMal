# Perform these steps manually:

# install podman on ec2
sudo apt install podman python3 python3-pip
pip install numpy tqdm

# install dependencies in container
podman run -it fedora bash
dnf update -y
dnf install -y strace htop python3 python3-pip
pip install psutil
exit

# commit container to an image after install 
podman container ls -a
podman commit <container_id> straceimg

# [OPTIONAL] open an isolated container to test any malware individually
podman run -it \
    --cap-add=SYS_PTRACE \
    --network none \
    -v $(pwd):/mnt/ \
    straceimg bash