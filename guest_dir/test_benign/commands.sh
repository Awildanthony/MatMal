ls
ls -l
ls -la
ls -lh
ls -ltr
tree
tree -L 2
pwd
du
du -h
du -sh *
df
df -h
cd /
cd ..
cd ~
cd /tmp
find / -name "*.conf" 2>/dev/null
find . -type f -size +10M
find /var -type d
touch testfile
mkdir testdir
rmdir testdir
cat /etc/passwd
cat /etc/hostname
cat /etc/os-release
head /etc/passwd
tail /etc/passwd
wc -l /etc/passwd
wc -w /etc/passwd
uname -a
uname -r
uname -s
cat /proc/cpuinfo
cat /proc/meminfo
lscpu
lsblk
free
free -h
uptime
hostname
hostnamectl
whoami
who
w
id
env
printenv
date
cal
df -h
du -h
stat /etc/passwd
ifconfig
ip addr
ip link
ip route
ping 8.8.8.8
ping -c 4 google.com
traceroute google.com
nslookup google.com
dig google.com
netstat -tuln
netstat -anp
ss
ss -tuln
curl http://example.com
wget http://example.com
curl -I http://example.com
wget -O - http://example.com
host google.com
arp -a
nmcli
nmcli device
nmcli connection
apt list --installed
apt-cache search ssh
apt-cache show bash
yum list installed
yum search nginx
dnf list installed
dnf search python
zypper se apache
pacman -Q
pacman -Ss vim
snap list
flatpak list
ps
ps aux
ps -ef
top
htop
kill -l
jobs
bg
fg
pgrep bash
pkill -l
fdisk -l
lsblk
blkid
df -h
mount
umount
cat /etc/fstab
cat /proc/partitions
dmesg
dmesg | tail
journalctl
journalctl -b
journalctl --since "1 hour ago"
tail -f /var/log/syslog
tail -f /var/log/messages
cat /var/log/auth.log
less /var/log/dmesg
echo "Hello, world!"
cat /etc/passwd
cat /etc/hostname
head /etc/passwd
tail /etc/passwd
grep root /etc/passwd
grep -i bash /etc/passwd
cut -d: -f1 /etc/passwd
awk -F: '{print $1}' /etc/passwd
sort /etc/passwd
uniq /etc/passwd
wc -l /etc/passwd
wc -w /etc/passwd
wc -c /etc/passwd
yes "I love Linux!"
cowsay "Hello, world!"
fortune
fortune | cowsay
sl
cmatrix
toilet "Linux!"
lolcat /etc/hostname
factor 42
echo "scale=10; 22/7" | bc
rev <<< "linux"
lsmod
modinfo loop
lsusb
lspci
uptime
whoami
users
id
groups
last
lastlog
cat /etc/passwd
cat /etc/group
cat /etc/shadow 2>/dev/null
getent passwd
getent group
id
groups
who
w
last
ssh-keygen -l -f ~/.ssh/id_rsa.pub
cat ~/.ssh/id_rsa.pub
ssh localhost
scp file.txt user@remote:/tmp
rsync -av /tmp/ /tmp/backup/
time ls
time sleep 2
watch -n 1 date
history
alias
unalias
which bash
whereis bash
man ls
man bash
whatis bash
apropos bash
help cd
ls
ls -l
ls -la
ls -lh
ls -ltr
ls --color
tree
tree -L 2
tree -a
pwd
du
du -h
du -sh *
df
df -h
df -T
df --total
find / -name "*.conf" 2>/dev/null
find /etc -type f -name "*.conf"
find . -type f -size +10M
find /var -type d
find /home -type l
touch testfile
touch {a..z}.txt
mkdir testdir
mkdir -p dir1/dir2/dir3
rmdir testdir
rmdir dir1/dir2/dir3
cp /etc/hosts ./hosts_backup
cp -r /etc/ ./etc_backup
mv testfile renamedfile
ln -s /etc/hostname my_hostname
ln file1 file2
rm -i temp.txt
rm -r temp_dir/
cat /etc/passwd
cat /etc/hostname
cat /etc/os-release
cat ~/.bashrc
cat /proc/cpuinfo
cat /proc/meminfo
head /etc/passwd
head -n 20 /var/log/syslog
tail /etc/passwd
tail -f /var/log/messages
wc -l /etc/passwd
wc -w /etc/passwd
wc -c /etc/passwd
stat /etc/passwd
stat /var/log/syslog
echo "Hello, world!"
echo "PATH=$PATH:/my/new/path" >> ~/.bashrc
echo "This is a test" > file.txt
echo "Appending text" >> file.txt
cp file.txt file_copy.txt
cp -r /etc ./etc_copy
mv file_copy.txt renamed_file.txt
chmod 755 testfile
chmod -R 644 ./dir1/
chown root:root file.txt
chown -R user:group ./dir1/
lsattr
chattr +i file.txt
df -hT
mount
mount | grep "/dev/sd"
umount /mnt/usb
mount /dev/sdb1 /mnt/usb
blkid
lsblk
lsblk -f
lsblk -o NAME,SIZE,FSTYPE,MOUNTPOINT
fdisk -l
parted -l
free
free -m
free -h
uptime
uptime -p
uptime -s
who
whoami
w
users
id
groups
last
lastlog
ps
ps aux
ps -ef
top
htop
kill -l
jobs
bg
fg
pgrep bash
pkill -l
ifconfig
ip addr
ip link
ip route
ip -s link
ping 8.8.8.8
ping -c 4 google.com
traceroute google.com
nslookup google.com
dig google.com
netstat -tuln
netstat -anp
ss
ss -tuln
curl http://example.com
curl -I http://example.com
wget http://example.com
wget -O - http://example.com
host google.com
arp -a
nmcli
nmcli device
nmcli connection
journalctl
journalctl -b
journalctl --since "1 hour ago"
tail -n 20 /var/log/dmesg
less /var/log/auth.log
dmesg
dmesg | tail
man ls
man bash
man ps
help cd
whatis ls
apropos bash
alias
unalias
history
time ls
watch -n 1 date
which bash
whereis bash
factor 42
echo "scale=10; 22/7" | bc
rev <<< "linux"
yes "I love Linux!"
cowsay "Hello, world!"
fortune
fortune | cowsay
sl
cmatrix
toilet "Linux!"
lolcat /etc/hostname
ssh localhost
scp file.txt user@remote:/tmp
rsync -av /tmp/ /tmp/backup/
env
printenv
cat ~/.ssh/id_rsa.pub
lsmod
modinfo loop
lsusb
lspci
cat /etc/group
cat /etc/shadow 2>/dev/null
getent passwd
getent group
crontab -l
crontab -e
uptime
date
cal
df -h
whoami
hostname
hostnamectl
uname
uname -a
uname -r
uname -s
lscpu
lscpu | grep "Model name"
lscpu | grep "MHz"
cat /etc/os-release
cat /proc/version
cat /proc/cpuinfo
cat /proc/meminfo
free -h
uptime
id
groups
who
w
last
lsblk
df -h
fdisk -l
mount
umount /mnt/usb
blkid
journalctl -b
dmesg
ps aux
top
htop
killall -9 firefox
pgrep ssh
netstat -tuln
ss -tuln
ping -c 4 8.8.8.8
ip addr
ip route
ip link
curl -I https://google.com
wget -O /dev/null https://example.com
traceroute google.com
nslookup google.com
dig google.com
nmcli device
nmcli connection show
ls -lh /var/log
cat /var/log/syslog
less /var/log/messages
tail -n 50 /var/log/auth.log
watch -n 1 "uptime"
df -h /
du -sh /home/*
lsusb
lspci -nn
cat /etc/fstab
mount | column -t
find / -type f -name "*.log" 2>/dev/null
find / -perm 777
find /etc -type f -name "*.conf"
find /home -type d -name "test*"
chmod 755 /path/to/file
chown user:user /path/to/file
ln -s /path/to/file /path/to/symlink
alias ll='ls -lh'
alias grep='grep --color=auto'
unalias ll
history | tail -n 20
du -sh /tmp/*
lsattr /path/to/file
chattr +i /path/to/important_file
file /bin/bash
file /etc/passwd
stat /var/log/syslog
wc -l /etc/hosts
sort /etc/passwd
uniq /etc/passwd
head -n 10 /etc/passwd
tail -n 10 /etc/passwd
grep root /etc/passwd
grep -i user /etc/group
cut -d: -f1 /etc/passwd
awk -F: '{print $1}' /etc/passwd
sed 's/root/ROOT/g' /etc/passwd
yes "Testing output"
cal 2024
seq 1 10
factor 100
bc <<< "scale=2; 22/7"
printf "Hello, %s!\n" "World"
basename /home/user/file.txt
dirname /home/user/file.txt
realpath /etc/passwd
lsblk -o NAME,FSTYPE,SIZE,MOUNTPOINT
blkid /dev/sda1
cat /proc/swaps
swapon --show
mount | column -t
df -Th
du -sh /var/*
lsof
lsof -i :22
lsof +D /var/log
netstat -rn
ss -plnt
arp -n
ip neigh
traceroute -m 5 google.com
ping -c 5 example.com
dig example.com +short
nslookup example.com
nmcli device status
nmcli connection show
lsmod
modprobe -r loop
modinfo ext4
uptime
who -u
w
id -u
id -g
groups $(whoami)
top -u root
htop
free -m
free -g
watch -n 1 free -h
time ls
time sleep 2
watch -n 1 "date +%T"
cat /proc/cpuinfo | grep "model name"
cat /proc/cpuinfo | grep "cpu cores"
dmidecode -t memory
dmesg | tail -n 20
journalctl -p err
journalctl --since "5 minutes ago"
ls -lh /tmp
ls -R /home/user
find . -name "*.sh"
find /tmp -type f -atime -1
find /var/log -type f -size +10M
grep -i "error" /var/log/syslog
awk '{print $1}' /etc/hosts
cut -d' ' -f1 /etc/hosts
sort /etc/hosts | uniq
head -5 /var/log/syslog
tail -f /var/log/syslog
ls -alhR /home/user
stat /etc/hosts
ln -s /var/log /home/user/log_link
alias ll='ls -l'
unalias ll
touch /tmp/testfile
mkdir -p /tmp/testdir/subdir
cp /etc/hosts /tmp/test_hosts
mv /tmp/testfile /tmp/renamed_testfile
echo "Hello, Linux" > /tmp/test.txt
cat /tmp/test.txt
chmod 644 /tmp/test.txt
chown user:user /tmp/test.txt
rm -i /tmp/test.txt
ls -lh /tmp/testfile
ln /tmp/testfile /tmp/testfile_hardlink
readlink /tmp/testfile_hardlink
whoami
hostname
uptime
date
cal 2024
uname -a
uname -r
dmesg
lscpu
lsblk
free -h
df -h
du -sh /var/*
ps aux | grep ssh
pkill -f "python script"
pgrep ssh
kill -9 12345
ip a
ip link show
ip route show
ping -c 4 8.8.8.8
traceroute 8.8.8.8
curl -I https://www.google.com
wget --spider https://www.example.com
dig google.com ANY
nslookup example.com
arp -a
nmcli dev show
nmcli con show
lsusb
lspci
modinfo vfat
lsmod | grep loop
top
htop
uptime
w
users
groups
id
cat /etc/passwd | wc -l
cat /etc/group | wc -l
awk -F':' '{print $1}' /etc/passwd
awk -F':' '{print $3}' /etc/passwd
cat /proc/cpuinfo | grep "processor"
cat /proc/meminfo | grep "MemTotal"
dmesg | grep error
journalctl -p 3 -xb
history | tail -n 10
alias ll='ls -alh'
unalias ll
watch -n 1 "ls -lh /var/log"
tree /etc/
tree -L 2 /home/
head -n 20 /var/log/messages
tail -n 50 /var/log/syslog
du -h --max-depth=1 /home/
df -hT
blkid
fdisk -l
mount | column -t
lsblk -f
lsattr
chattr +i /important/file
chmod 644 /path/to/file
chmod +x script.sh
chown user:user /path/to/file
ln -s /path/to/target symlink
touch /tmp/newfile
mkdir -p /tmp/newdir/subdir
stat /tmp/newfile
find /home/user -type f -name "*.log"
find /var -type d -name "*cache*"
echo "PATH=$PATH:/new/path" >> ~/.bashrc
cat /proc/uptime
cat /proc/version
lsusb -v
lspci -vv
nmcli device wifi list
ping -c 5 example.org
traceroute example.com
curl -v https://example.com
wget -O - https://example.org
ip a show
ip r show
ss -tuln
netstat -tuln
lsmod | grep ext
modprobe -r loop
top -b -n 1
htop
watch -n 1 free -h
uptime
cal
date +"%Y-%m-%d %H:%M:%S"
time sleep 1
factor 360
bc <<< "scale=2; 10/3"
yes "Running tests"
toilet "Hello"
sl
cowsay "Linux is great"
fortune | cowsay
cmatrix
rev <<< "linux"
printf "Linux is %d years old!\n" 30
basename /usr/local/bin/script.sh
dirname /usr/local/bin/script.sh
realpath /usr/local/bin
find . -type f -perm 777
find /etc -iname "*.conf"
alias ll='ls -lh'
unalias ll
history | grep sudo
cat /proc/version
cat /proc/filesystems
grep -i "usb" /var/log/dmesg
uptime -p
who -H
last -n 5
id -un
id -gn
ps -C sshd
ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | head
top -n 1 -b | head -15
htop -s MEM
free -t -h
df -x tmpfs
du -ah /var | sort -rh | head -n 20
lsblk -o NAME,UUID,SIZE,FSTYPE,MOUNTPOINT
ls -l /dev/disk/by-uuid/
mount | grep tmpfs
lsattr /etc/passwd
stat /etc/group
find /var/log -name "*.gz" -type f
find /etc -type f -exec ls -lh {} \;
find / -iname "*config*" 2>/dev/null
find /var/log -mtime -1
find . -type f -empty
locate hosts
updatedb
grep -rnw '/etc/' -e "root"
grep --color=always root /etc/passwd
awk '{ print $NF }' /etc/passwd
sed -n 1,5p /etc/passwd
cut -c 1-10 /etc/passwd
sort -u /etc/hosts
uniq -c /etc/hosts
rev /etc/passwd | head -n 5
echo $((5 + 10))
echo "scale=3; 10/3" | bc
printf "%-10s %s\n" "USER" "$USER"
basename /home/user/test.txt
dirname /home/user/test.txt
realpath /bin/ls
tree -C /home | head -10
lsusb | grep "Wi-Fi"
lspci | grep "Ethernet"
modinfo ext4
lsmod | wc -l
nmcli general
nmcli device show eth0
ping -w 5 1.1.1.1
ip a | grep inet
ip -s link show eth0
ip r | grep default
curl -s https://api.github.com | jq .
wget -q --spider https://example.com && echo "Online"
nslookup www.google.com
dig www.google.com A
arp -vn
watch -n 5 "date +%T"
cal -y 2024
date +"%Y-%m-%d %H:%M:%S"
time dd if=/dev/zero of=/dev/null count=1000000
factor 144
yes "Repeating this line..."
toilet -f future "LINUX"
sl -e
fortune | cowsay -n
cowsay -f tux "Use Linux!"
cmatrix -L
rev <<< "morecommands"
echo "New PATH is: $PATH"
export PATH=$PATH:/new/path
alias lt='ls -ltr'
unalias lt
history | tail -10
lsof -i :80
lsof -nP | grep LISTEN
netstat -i
ss -s
ss -t -a
cat /proc/net/dev
cat /proc/net/route
cat /proc/net/tcp
iptables -L
iptables -S
findmnt
lsblk -m
df -i
watch -n 1 free -m
dmidecode -t system
dmesg --level=err
journalctl -u ssh.service --since "10 minutes ago"
uptime -s
w -h
users | wc -w
id -a
ls -1 /proc/[0-9]*
ls -ld /var/log
find /usr/share -type l
touch /tmp/{file1,file2}
mkdir -p /tmp/{dir1,dir2}
stat /tmp/file1
chown root:root /tmp/file1
chmod 644 /tmp/file1
ln -s /etc/hostname /tmp/hostname_link
du -h /tmp/ | sort -rh | head -5
df -h --output=source,target
grep -E '^/dev' /proc/mounts
cut -f1,2 /etc/passwd
awk -F: '{ print $1, $3 }' /etc/passwd
sed -e 's/bash/sh/' /etc/passwd
sort -k3n /etc/passwd
uniq -d /etc/hosts
printf "Logged in as: %s\n" "$USER"
cat /proc/cmdline
cat /proc/uptime
cat /etc/services | head -20
cat /etc/protocols | grep tcp
ls /sys/class/net
ls /proc/1/fd
ls -lR /tmp
ls -d /etc/*
ls -lh /home/user
ls -lt /var/log
find /home -iname "*.sh"
find / -type d -name "test*" 2>/dev/null
find / -perm 644 2>/dev/null
find /var -type f -mtime +10
find /var -type f -size +1M
locate --limit 10 passwd
locate .bashrc
grep -v '^#' /etc/ssh/sshd_config
grep -c '^processor' /proc/cpuinfo
grep -i 'usb' /var/log/dmesg
awk '{if ($3 > 1000) print $1, $3}' /etc/passwd
awk -F: '{print $1, $7}' /etc/passwd
awk '{print $1}' /etc/hosts
sed 's/127.0.0.1/localhost/' /etc/hosts
sed -i 's/foo/bar/' file.txt
cut -d' ' -f1,2 /proc/cpuinfo
sort -u /var/log/messages
uniq -u /var/log/messages
head -20 /etc/group
tail -30 /etc/group
stat -c %a /etc/passwd
stat -c %n /etc/group
wc -c /var/log/syslog
wc -w /etc/ssh/sshd_config
printf "%10s %d\n" "Number:" 42
factor 42
basename /usr/bin/ls
dirname /usr/bin/ls
realpath /usr/bin/python3
file /etc/passwd
file /bin/bash
ls -l /etc/alternatives
lsusb -t
lspci -v
lsmod | grep vfat
modinfo loop
modprobe loop
dmesg | grep "error"
dmesg | tail -n 50
journalctl -k --since "30 min ago"
journalctl -u ssh.service --since "yesterday"
journalctl --disk-usage
uptime -p
w -s
users
whoami
who -b
id -G
id -g
id -u
ps -u $USER
ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | head -n 10
ps aux | grep nginx
pgrep -a bash
pkill -TERM nginx
top -o %MEM
htop -s CPU
free -k
free -m
free -g
lsblk -a
lsblk -d
lsblk -o NAME,FSTYPE,MOUNTPOINT
blkid
fdisk -l /dev/sda
parted -l
df -T
df -i
du -h --max-depth=1
du -ah /var/log
mount | grep "/dev/sd"
findmnt
cat /proc/mounts
lsattr -a
lsattr /etc/passwd
chattr +i /etc/passwd
tree /etc
tree -L 3 /var
chmod +x script.sh
chmod -R 750 /home/user
chown -R user:user /home/user
touch /tmp/test.txt
mkdir -p /tmp/test/{dir1,dir2}
stat /tmp/test.txt
ln -s /usr/bin/python3 /tmp/python_symlink
rm -i /tmp/test.txt
cp /etc/hosts /tmp/hosts_backup
mv /tmp/hosts_backup /tmp/renamed_hosts_backup
echo "Welcome to Linux!" > /tmp/welcome.txt
cat /tmp/welcome.txt
lsusb | grep "Wi-Fi"
nmcli device
nmcli device show wlan0
nmcli con show
ping -c 3 example.com
traceroute example.com
dig +short google.com
dig ANY example.com
nslookup example.com
curl -I https://example.com
curl -s https://api.github.com
wget -q --spider http://example.com && echo "Online"
ip addr show eth0
ip link show
ip neigh
arp -a
netstat -s
ss -lnt
ss -u
iptables -L
iptables -nvL
watch -n 5 "df -h"
watch -n 1 "free -h"
cal
cal 2025
date "+%Y-%m-%d %H:%M:%S"
date -u
time sleep 1
toilet "Hello, World!"
fortune | cowsay
cowsay -f tux "Hello from Linux!"
sl -l
rev <<< "Linux"
yes "Repeating text"
cmatrix -L
lsof -i :80
lsof -nP
lsof +D /var/log
killall -9 python
alias l='ls -lh'
unalias l
history | tail -20
ls -lR /
ls -S
ls -lhS
ls -lh --time-style=long-iso
ls -d */
ls --color=always
ls -lt | head -n 10
tree -d
tree -fi /var | head -n 20
pwd -P
df -BM
df -h --output=source,size,used,avail,pcent,target
du --exclude='*.log' -h /var
du --max-depth=2 /home | sort -hr | head -n 10
find /tmp -ctime -1
find /etc -name "*.conf" -exec cat {} \; | head -n 50
find /home/user -type f -exec du -h {} + | sort -hr | head -n 20
grep -r "error" /var/log
grep -L "bash" /etc/passwd
grep -E "^(user|admin)" /etc/passwd
grep -oE "[0-9]+" /etc/passwd | uniq
awk '{if (NR%2==0) print $0}' /etc/passwd
awk '/^root/ {print $1}' /etc/group
awk '{printf "Line %d: %s\n", NR, $0}' /etc/passwd
awk -F: '{print $NF}' /etc/passwd | sort | uniq -c
sed 's/^/#/g' /etc/hosts
sed -i.bak 's/bash/sh/' /etc/passwd
sed '5d' /etc/group
sed -n '2,4p' /etc/passwd
cut -d: -f1,3 /etc/passwd
cut -d' ' -f2- /etc/hosts
sort -k2 /etc/group
sort -r /etc/hosts
uniq -i /etc/group
uniq -d /var/log/syslog
head -n 15 /var/log/dmesg
tail -f /var/log/kern.log
wc -l /etc/passwd /etc/group /etc/hosts
wc -c /proc/cmdline
stat --format="%n %s %y" /var/log/syslog
stat --format="%A %n" /etc/fstab
touch -t 202401010000 /tmp/newfile
mkdir -v -p /tmp/a/b/c/d
cp -v /etc/hostname /tmp/hostname_copy
mv -v /tmp/hostname_copy /tmp/hostname_backup
ln -v -s /etc/hosts /tmp/hosts_symlink
ln /etc/group /tmp/group_hardlink
rm -v /tmp/group_hardlink
file /usr/bin/vim
file /bin/ls
readlink -f /etc/hostname
lsattr /etc/passwd
lsattr -d /tmp
chattr +i /tmp/protected_file
chmod -R 700 /home/user/private
chown -R user:group /home/user
blkid -o list
lsblk -o NAME,FSTYPE,LABEL,SIZE,MOUNTPOINT
lsblk -a | grep "sda"
mount | grep "^tmpfs"
findmnt -T /tmp
parted -l
fdisk -l /dev/sda
df -h --sync
free -b
free --si
uptime -s
uptime -p
uname --kernel-release
uname -m
cat /proc/partitions
cat /proc/version_signature
cat /proc/uptime | awk '{print $1" seconds"}'
cat /sys/class/dmi/id/product_name
cat /proc/net/dev | tail -n +3
ip link show dev eth0
ip -br addr show
ip -s link show eth0
ip a | grep inet
ip r | grep default
ping -i 0.5 -c 4 1.1.1.1
traceroute -n google.com
tracepath 8.8.8.8
nslookup example.com
dig +noall +answer example.com
dig @8.8.8.8 -x 1.1.1.1
curl -o /dev/null -s -w "%{http_code}" http://example.com
wget --no-check-certificate -q https://self-signed.badssl.com
nmcli -f NAME,UUID con show
nmcli radio wifi
nmcli device status
ethtool eth0
ss -tan
ss -u -a
netstat -i
netstat -r
arp -a | sort
journalctl -p 3
journalctl -f
journalctl --disk-usage
dmesg --ctime
dmesg | grep usb
dmesg | grep "eth"
lsmod | grep usb
modinfo overlay
lsof | grep "/var"
lsof -p 1
watch -n 2 ls /tmp
watch -n 5 "uptime"
yes "Test message..."
yes | head -n 20
factor 123456
echo {1..10}
echo {a..z}
echo "scale=5; sqrt(2)" | bc
echo "obase=16; 255" | bc
echo $RANDOM
rev <<< "reverse"
printf "%-10s %-10s\n" "User" "$USER"
seq 1 5 | paste -s -d,
date +%s
cal 2025
cal -3
ncal -w
cowsay "Hello, Linux!"
fortune | cowsay
toilet -f future "LINUX"
cmatrix -n
sl -F
ssh-keygen -l -f ~/.ssh/id_rsa.pub
scp /etc/hosts user@remote:/tmp/
rsync -avz /home/user/ remote:/backup/
find /var/log -exec grep -Hn "error" {} \;
find /etc -maxdepth 2 -type f -exec ls -lh {} +
find / -perm /111 -type f 2>/dev/null
alias ll='ls -lh --color=auto'
unalias ll
history | grep sudo
ls -lh --time-style=full-iso
ls -R /usr/share/doc | grep -i readme
tree -a --charset=ascii
tree -L 1 --filelimit 10
pwd -L
df --human-readable --sync
df -h --output=source,used,size,pcent
du -h /tmp/* | sort -rh | head -10
du -a /etc | grep -i conf
find /usr -type d -iname "bin" 2>/dev/null
find /home -type f -exec basename {} \; | sort | uniq
locate -i bash_history
grep -v '^#' /etc/fstab | grep -v '^$'
grep -o '\<root\>' /etc/passwd
grep -c 'bin/bash' /etc/passwd
grep --line-number "error" /var/log/messages
awk '/MemTotal/ {print $2 " KB"}' /proc/meminfo
awk 'NR % 2 == 0' /etc/passwd
awk 'END {print "Total lines: ", NR}' /etc/group
awk -F':' '{print $1 " has user ID " $3}' /etc/passwd
sed 's/[aeiou]/_/g' /etc/passwd | head -n 10
sed -n '/^root/p' /etc/passwd
sed '/nologin$/d' /etc/passwd
cut -c 1-5 /etc/passwd
cut -d' ' -f2- /etc/issue
sort -n /proc/cpuinfo | uniq -c
uniq -ic /var/log/dmesg | sort -n
head -n 20 /etc/services
tail -n 30 /etc/services
stat -c '%n: %s bytes' /etc/issue
stat --format='%A %n' /bin/bash
mkdir /tmp/testdir && rmdir /tmp/testdir
touch /tmp/test{1..5}.txt
ln -s /var/log /tmp/log_symlink
ln /etc/hostname /tmp/hostname_hardlink
rm /tmp/hostname_hardlink
file /var/log/syslog
file --mime-type /usr/bin/vim
readlink -e /etc/alternatives/java
chmod g+w /var/log
chmod o-rwx /home/user/private
chown -v user:user /tmp/testfile
lsblk --noheadings --output NAME,SIZE,FSTYPE
blkid -c /dev/null
mount --bind /tmp /mnt
umount /mnt
findmnt --types tmpfs
findmnt --list
free --mega
uptime -h
uptime -V
uname --nodename
uname --processor
cat /proc/swaps
cat /proc/stat | head -n 5
cat /proc/sys/fs/file-max
ip addr show lo
ip -br -4 addr
ip -s addr | grep "RX bytes"
ip route show table main
ping -c 5 -i 0.2 8.8.8.8
traceroute -m 5 1.1.1.1
tracepath google.com
nslookup -type=mx gmail.com
dig +short -x 8.8.8.8
dig +trace google.com
curl -I -X GET https://www.kernel.org
curl -o /dev/null -s -w "Time: %{time_total}\n" https://example.com
wget --spider --timeout=5 https://example.org
nmcli general hostname
nmcli device show wlan0
nmcli connection modify "Wired connection 1" ipv4.dns "8.8.8.8"
ethtool eth0 | grep "Speed"
ss -ntlp
ss -x
netstat -nap | grep LISTEN
netstat -rn
journalctl --list-boots
journalctl -k | head -n 50
journalctl -p info --since "2024-01-01"
dmesg --facility=daemon
dmesg --level=alert,crit,emerg
lsmod | wc -l
lsmod | grep overlay
modinfo -F description ext4
lsof +L1
lsof -u $(whoami)
watch -d -n 1 "ls -lh /tmp"
watch -n 10 "df -h | grep '/dev/sda'"
yes "Repetitive line" | head -n 15
echo {00..09}
echo {a..f} | tr ' ' '\n'
seq 0.1 0.1 1.0
seq 10 -2 0
date "+Today is %A, %d %B %Y"
date "+%T %Z"
cal -A 1 -B 1
cal --monday
toilet -f mono12 "Linux Rocks"
fortune | cowsay -d
cowsay -f tux "Open Source Rules"
cmatrix -ab
rev <<< "example"
printf "%-20s %-10s\n" "Item" "Price"
printf "%-10s: %04d\n" "Count" 25
echo "obase=16; ibase=10; 100" | bc
factor 789012
hostnamectl
hostnamectl status
lscpu | grep -E 'Architecture|Model'
lsusb -d 8087:
lspci -k | grep -A 2 "VGA"
cat /proc/loadavg
cat /proc/uptime | awk '{printf "Uptime: %.2f hours\n", $1/3600}'
cat /proc/net/snmp | grep Tcp
arp -d 192.168.0.1
iptables -L -nv
iptables -S
find /etc -type l
find /var -type f -empty
find /tmp -name "*.tmp" -delete
find /home -iname "*.pdf"
alias home='cd ~'
unalias home
history | grep "scp"
rsync -av /home/user/ /backup/home/
scp /tmp/file.txt user@remote:/tmp/
ssh-keygen -f /tmp/test_key
ls -ltr --group-directories-first
ls -lh --block-size=MB
ls --sort=size -lh
ls -X | grep ".txt"
tree -L 4 --dirsfirst /var
tree -I "*.log" /var/log
pwd -P
df --total --human-readable
df -h --exclude-type=tmpfs
du -ch /home/user | grep total
du -sh /var/lib/docker
find /var -name "*.log" -type f -exec rm -i {} \;
find /etc -type f -exec grep -H "root" {} +
find /home/user -type f -mtime -7
locate -i vimrc | head -n 5
grep -c "sshd" /var/log/auth.log
grep -i "kernel" /var/log/syslog | tail -n 20
grep -oE "\b\d{4}\b" /var/log/messages
awk '/eth0/ {print $1, $5}' /proc/net/dev
awk -F':' '{print $1 " => " $3}' /etc/passwd
awk 'BEGIN {OFS="\t"}; {print $1, $NF}' /etc/group
sed -n '5,10p' /etc/passwd
sed 's/^/#/' /etc/fstab
sed -i 's/127.0.0.1/localhost/' /etc/hosts
cut -d: -f1,7 /etc/passwd
cut -c1-15 /var/log/messages | sort | uniq -c
sort -r /etc/group | head -10
uniq -i /etc/hosts | wc -l
head -15 /var/log/dmesg | grep "usb"
tail -n 100 /var/log/kern.log | grep "error"
stat -c '%a %n' /etc/hosts
stat -L -c '%s %y' /var/log/syslog
mkdir -p /tmp/{a,b,c}
rmdir /tmp/c
touch /tmp/example.txt
ln -s /usr/bin/vim /tmp/vim_link
ln /etc/fstab /tmp/fstab_hardlink
chmod -R 755 /home/user/public
chown root:root /etc/hosts
lsblk --json
lsblk -o KNAME,SIZE,TYPE,FSTYPE
blkid /dev/sda1
mount --types tmpfs
umount /dev/sda1
findmnt -T /
findmnt -o TARGET,FSTYPE,SOURCE,OPTIONS
free -h --si
uptime -s
uname --kernel-version
cat /proc/filesystems
cat /proc/net/udp
cat /proc/sys/kernel/hostname
cat /sys/block/sda/queue/scheduler
ip link set dev eth0 up
ip addr add 192.168.1.100/24 dev eth0
ip route add default via 192.168.1.1
ping -q -c 4 -w 5 google.com
traceroute -n 8.8.8.8
tracepath example.com
nslookup google.com
nslookup -type=AAAA example.com
dig +short ANY google.com
dig @8.8.8.8 -x 172.217.10.110
curl -X GET https://example.com
curl -o output.html https://example.com
curl --trace-ascii debug.txt https://example.com
wget --mirror --convert-links https://example.org
wget --timestamping https://example.org/index.html
nmcli dev wifi list
nmcli con up "My WiFi"
nmcli dev disconnect wlan0
ss -ltp
ss -aupn | grep ":80"
netstat -ntu
netstat -tulnp | grep LISTEN
arp -v
journalctl --unit ssh.service -n 20
journalctl -k --since "2 hours ago"
dmesg -T | grep eth0
dmesg --level=crit | tail -10
lsmod | grep "bridge"
modinfo -F filename overlay
lsof -i :22
lsof /var/log/syslog
watch -n 5 "du -sh /var/log"
watch -d "ls -lh /tmp"
yes "Linux is awesome!" | head -5
echo {10..20} | tr ' ' '\n'
seq -w 10 2 30
date "+%A, %B %d, %Y"
cal -3
ncal -h -M
hostnamectl status
hostnamectl set-hostname new-hostname
lscpu | grep -E 'Thread|Core'
lsusb -s 001:003
lspci -vv | grep "Kernel driver"
lsblk --nodeps -o NAME,SIZE
cat /proc/cpuinfo | grep 'cache size'
cat /proc/loadavg
cat /proc/swaps
cat /proc/uptime | awk '{printf "Uptime: %.2f hours\n", $1/3600}'
cat /proc/net/tcp | wc -l
iptables -L INPUT
iptables -L OUTPUT
iptables -S
find /var -type f -size +1M
find /etc -iname "*.cfg" -exec ls -l {} +
find /home/user -perm -u+x -type f
alias ll='ls -la'
alias search="grep -rnw"
unalias search
history | tail -30
rsync -av --progress /home/user/ /backup/home/
scp user@remote:/path/to/file /local/path/
ssh-copy-id user@remote
acpid -f
acpid -d
addgroup developers
adduser alice
adjtimex --print
ar t library.a
ar rcs newlib.a file.o
arp -n
arping -c 3 192.168.0.1
ascii -x 41
awk '{print $1}' file.txt
echo "hello" | base32
echo "hello" | base64
basename /usr/local/bin/script.sh
blkid /dev/sda1
blockdev --getsize64 /dev/sda
cal 12 2023
cat /etc/passwd
chmod 755 file.sh
chown user:group file.txt
cmp file1.txt file2.txt
cp source.txt destination.txt
crontab -l
date "+%Y-%m-%d %H:%M:%S"
dd if=/dev/zero of=file.img bs=1M count=100
df -h
dmesg | grep error
du -sh /home
echo "Hello, world!"
env | grep PATH
find /var/log -name "*.log"
free -h
grep "error" /var/log/syslog
gzip file.txt
head -n 5 file.txt
hostnamectl set-hostname newhostname
kill -9 1234
ls -lh
mkdir -p /tmp/a/b/c
mount /dev/sda1 /mnt
mv file.txt newfile.txt
ps aux | grep apache
rm -rf /tmp/testdir
sed 's/foo/bar/g' file.txt
sort file.txt
tar -cvf archive.tar file1 file2
top -o %MEM
uname -a
uptime
wc -l file.txt
wget https://example.com/file.txt
unxz file.xz
unzip file.zip
uptime
users
usleep 1000000
uudecode file.uu
uuencode file.txt file.txt.uu
vconfig add eth0 10
vi file.txt
vlock                  
volname /dev/sr0               
w                              
wall "System maintenance at 5 PM"  
watch -n 5 "df -h"           
watchdog                           
wc -l file.txt                    
wget https://example.com           
which ls                            
who                                 
whoami                              
whois example.com                   
xargs -I {} echo "Hello, {}!"       
xxd file.bin                        
xz file.txt                   
xzcat file.xz                   
yes "Repeating line" | head -n 5 
zcat file.gz 
zcip     
hello