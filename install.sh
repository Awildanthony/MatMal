# install podman on ec2
sudo apt install podman

# install dependencies on container
podman run -it fedora bash
dnf update -y
dnf install -y strace htop python3 python3-pip
exit

# commit it to an image after install 
podman container ls -a
podman commit <container_id> straceimg

# get malware isolated container container
podman run -it \
    --cap-add=SYS_PTRACE \
    --network none \
    -v $(pwd):/mnt/ \
    straceimg bash