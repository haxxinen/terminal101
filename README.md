# terminal101
Shell scripting snippets and more.

## Table of Contents
- [Language Syntax](#language-syntax)
    - [Switch](#switch)
    - [While](#while)
    - [While-Read](#while-read)
    - [Comparisons](#comparisons)
    - [Collections](#collections)
    - [Functions](#functions)
- [System](#system)
    - [Arch-Info](#arch-info)
    - [Distro-Info](#distro-info)
    - [Debian-Sources](#debian-sources)
    - [Find](#find)
    - [Remove Except](#remove-except)
    - [Check if Root](#check-if-root)
    - [Linking](#linking)
    - [Print Dirs](#print-dirs)
    - [File Timestamps](#file-timestamps)
    - [Date To Unix Timestamp](#date-to-unix-timestamp)
    - [File Name-Ext](#file-name-ext)
    - [Encoding](#encoding)
        - [Base64](#base64)
        - [URL](#urlencode)
        - [ASCII](#ascii)
    - [Conversions](#conversions)
        - [Dec-2-Hex](#dec-2-hex)
    - [Exec Command Args](#exec-command-args)
    - [Add User](#add-user)
- [Networking](#networking)
    - [Basic Setup](#basic-setup)
    - [IPv6](#ipv6)
    - [Scanning](#scanning)
        - [Geo IP](#geo-ip)
        - [Heartbleed](#heartbleed)
    - [Interface-Info](#interface-info)
        - [Interface-State](#interface-state)
        - [MAC Address](#mac-address)
        - [IP Address](#ip-address)
    - [Ping](#ping)
    - [Netstat](#netstat)
    - [Netcat](#netcat)
    - [Curl](#curl)
    - [Processes](#processes)
        - [Kill Naughty Net](#kill-naughty-net)
        - [Service Manager](#service-manager)
- [Security](#security)
    - [OpenSSL](#openssl)
        - [Passwords and Hashing](#passwords-and-hashing)
            - [Crypto Random](#crypto-random)
            - [Hashing (fast)](#hashing-fast)
                - [Measure hashing time](#measure-hashing-time)
    - [AES-Crypt](#aes-crypt)
        - [AES Demo](#aes-demo)
    - [Entropy](#entropy)
        - [$RANDOM](#random)
        - [Shuf](#shuf)
        - [Dev-Rand](#dev-rand)
- [Text Processing](#text-processing)
    - [Quoted Text](#quoted-text)
    - [Remove Blank](#remove-blank)
    - [Start-End](#start-end)
    - [Replace Text](#replace-text)
        - [Replace Line in Text](#replace-line-in-text)
    - [N-th line](#n-th-line)
    - [Remove Tailing Slash](#remove-tailing-slash)
    - [All in One line](#all-in-one-line)
    - [Between X and Y line](#between-x-and-y-line)
    - [Sorting Text Lines](#sorting-text-lines)
    - [JSON](#json)
    - [XML](#xml)
- [Databases](#databases)
    - [Postgres](#postgres)
- [iOS](#ios)
    - [Installed apps](#installed-apps)
    - [Safari data](#safari-data)
    - [Find sqlites](#find-sqlites)
    - [Collect sqlites](#collect-sqlites)

## Language Syntax
### Switch
```bash
#! /bin/bash

case `uname` in
    'Linux' )
        echo 'Linux-like OS' ;;
    'Darwin' )
        echo 'BSD-like OS.' ;;
    * )
       echo 'Default case.' ;;
esac
```
### While

```
#!/bin/bash
# Write a script that prints "Hello" for n-times 
# (where n is the first script argument)

i=0
while [ $i -lt $1 ]
do
   echo "Hello"
   i=$(($i+1))
done
```

```
# Factorial N.
#!/bin/bash

i=1
p=1

while [ $i -le $1 ]
do
  p=$(($p*$i))
  i=$(($i+1))
done

echo $p
```

### While-Read
```bash
#!/bin/bash

f='names.txt'

while read i
do
   echo -e "Name: $i"
done < $f
```
### Comparisons
```bash
# !/bin/bash

[ 1 -eq 1 ] && echo '1 -eq 1'                      # is equal to
[ 1 -ne 2 ] && echo '1 -ne 2'                      # is not equal to

[ 2 -gt 1 ] && echo '2 -gt 1'                      # is greater than
[ 6 -ge 5 ] && echo '6 -ge 5'                      # is greater than or equal to

[ 3 -lt 9 ] && echo '3 -lt 9'                      # is less than
[ 9 -le 9 ] && echo '9 -le 9'                      # is less than or equal to

((1 < 2)) && echo '1 < 2'
[[ 1 < 2 ]] && echo '1 < 2'
# <, <=; >, >=

[[ "A" = "A" ]] && echo 'A = A'                    # equals
[[ "A" == "A" ]] && echo 'A = A'                   # equals
[[ 'A' != 'B' ]] && echo 'A != B'                  # not equals

[[ 'Z' > 'Y' ]] && echo 'Z > Y'                    # gt
[[ 'A' < 'Z' ]] && echo 'A < Z'                    # lt

[[ -z '' ]] && echo 'this one is an empty string'  # is empty
[[ -n 'not_empty' ]] && echo 'not an empty string' # is not empty
```
#### Argcmp
```bash
#!/bin/bash

S="ABCD"
[ -n "$1" ] && [ "$1" == $S ] && echo "Strings are equal." && exit
echo "Strings are NOT equal."
```
### Collections
#### Key-Value associative array
```bash
#!/bin/bash

[ `bash --version | grep -oE '(\d+)' | head -n 1` -lt 4 ] && echo 'Bash v4.0 required.'

declare -A txt=(
   [msg]='Welcome'
   [usr]='C'
   [rand]=$RANDOM
)

for i in ${txt[@]}; do echo -n $i' '; done
echo
echo ${txt[msg]} ${txt[rand]} ${txt[usr]}
```
### Functions
#### Passing arguments
```bash
# !/bin/bash

print_args() {
  v=("$1")
  echo 'arg_array:' ${v[@]}
  echo 'arg_simple:' $2
}

v=(1 '2' 3 4)
v=`echo ${v[@]}`

print_args "$v" 'arg'
```

## System
### Arch-Info
```bash
# Arch-Short
$ arch=`arch` && arch=`echo "${arch: -2}"` && echo $arch
$ echo ${HOSTTYPE: -2}
$ uname -r | awk -F '-' '{print $NF}'
$ ls /boot/vmlinuz-*-* | awk -F '-' '{print $NF}'
```
### Distro-Info
```bash
$ codename=`lsb_release -a 2>/dev/null | awk '/Codename/{print $2}'`
$ codename=`cat /etc/*-release | grep -oE '\(.*\)' | uniq | sed 's/.*(//' | sed 's/).*//'`
```
### Debian-Sources
```bash
$ curl -sSL https://wiki.debian.org/SourcesList | grep -oe 'deb .* main' -oe 'deb-src .* main'
```
### Find
```bash
# single file name
$ find . -name *contains*

# find except
$ find . -name *contains* -not -path '*/not_path1/*' -not -path '*/not_path2/*'

# multiple file extensions
$ find . -type f \( -name "*.c" -o -name "*.cpp" -o -name "*.h" \)
$ find -regextype posix-egrep -regex '.+\.(c|cpp|h)$' -print0 | xargs -0 ls -L1d
```
### Remove Except
```bash
$ find . -type f -not -name '*.dll' | xargs rm -r       # rm all files exept for DLLs
```
### Check if Root
```bash
#!/bin/bash
[ $EUID -ne 0 ] && echo -e 'Not root.\r\nUser "'`whoami`'" has EUID:' $EUID && exit
echo 'SUDO has EUID:' $EUID
```
### Linking
```bash
#!/bin/bash

work='/tmp/'$RANDOM
mkdir $work && cd $work && echo 'Work dir: '`pwd`
f1='f1'
f2='f2'

echo 'This is file1.' > $f1
ln -s $f1 $f2

echo -n '> File '; file $f1
echo -n 'Data: '; cat $f1
echo
echo -n '> File '; file $f2
echo -n 'Data: '; cat $f2

echo && ls -l && echo

rm $f1

echo && ls -l && echo
echo -n '> File '; file $f2
echo -n 'Data: '; cat $f2

rm -r $work
```
### Print Dirs
```bash
#!/bin/bash

[ -z $1 ] && echo 'Usage: bash' $0 '<path>.' && exit
[ ! -d $1 ] && echo 'Not a directory.' && exit

a=("`echo -e $1/*/`")
for i in ${a[*]}; do echo $i | sed 's:/*$::'; done
```

### File Timestamps
#### Change file timestamps 1
```bash
# !/bin/bash
# ctime - change time = ls -lc
# atime - access time = ls -lu
# mtime - modify time = ls -l

f='/tmp/'`echo $RANDOM` && echo '123' > $f
ls -l $f

change_time() {
   touch -d "$1" $f
   ls -l $f
}

change_time "2 hours ago"            # relative to current time
change_time "`date -r $f` - 2 hours" # relative to modify time

rm $f
```

#### Change file timestamps 2
```bash
# !/bin/bash
dir='/tmp/'$RANDOM
mkdir $dir && cd $dir && echo $RANDOM > $RANDOM.txt

find $dir -print | while read f; do
    [ -f "$f" ] && touch -d "`date -r $f` - 2 hours" "$f" && ls -l "$f"
done

rm -r $dir
```

### Date To Unix Timestamp
```bash
#!/bin/bash
format='%FT%T+0000'
date=`TZ='Europe/Zurich' date "+$format"`
date=`date -j -f "$format" "$date" "+%s"` #osx
date=`date -d"$date" "+%s"`               #linux
```

### File Name-Ext
```bash
$ file="/tmp/log.txt"
$ touch "$file"
$ f="${file##*/}"
$ name="${f%.*}"
$ ext="${f##*.}"
$ echo $f $name $ext
```

### Encoding
#### Base64
```bash
$ v=`base64 <<< '123'` && echo $v && base64 --decode <<< $v
$ v=`openssl enc -base64 <<< '123'` && echo $v && openssl enc -base64 -d <<< $v
```

#### URLencode
```bash
$ hexdump -ve '"x" 1/1 "%02x"' file | tr 'x' '%'
$ cat file | od -t x1 -An | tr ' ' '%' | tr -d '\n'
$ cat file | xxd -ip | sed 's/0x/%/g' | sed 's/ \|,//g' | tr -d '\n'
```

#### ASCII
```
$ s=`echo -n "123" | od -An -tuC | tr ' ' ',' | sed 's/,,/,/g' | cut -c2-`
$ echo "console.log(String.fromCharCode($s))" | node
123
```

### Conversions
#### Dec-2-Hex
```bash
#!/bin/bash

for ((x=0; x <= 20; x++)); do
  printf '%3d | 0x%02x\n' "$x" "$x"
done
```

### Exec Command Args
```bash
$ php -r 'echo strval(1+1)."\n";'
$ python -c 'print 1+1' # echo 'print 2-1' | python
$ echo 'select 1+1;' | sqlite3
$ echo "1+1" | bc
$ echo -e "GET / HTTP/1.0\n" | nc 'google.com' 80
```

### Add User
```bash
# credentials
$ export user='demo'
$ export pass='demo'

# delete user if already exists
$ [ -n "`cat /etc/passwd | grep $user`" ] && sudo userdel $user
$ [ -d /home/$user ] && sudo mv /home/$user /home/$user'.'$RANDOM$RANDOM


# add new user
$ sudo useradd $user -p `mkpasswd $pass`

# make user sudoer
sudo bash -c "echo '$user  ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers"
```

## Networking

### Basic Setup
```
$ ip link show
$ netstat -i
$ /sbin/ifconfig -a
$ /sbin/dhclient eth0
```

### IPv6
```bash
networksetup -setv6off Ethernet
networksetup -setv6automatic Ethernet

networksetup -setv6off Wi-Fi
networksetup -setv6automatic Wi-Fi

# ios
ip6conf -x
ip6conf -a
```

### Scanning
#### Geo IP
```bash
# !/bin/bash
geoip='http://freegeoip.net/json'
ips='1.xml'

for ip in `grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' $ips`
do
   json=`curl -sSL $geoip'/'$ip`
   code=`echo $json | sed -e 's/[{}]/''/g' | grep -oE '"country_code":.*' | awk -F ',' '{print $1}' | awk -F ':' '{print $2}'`
   printf "%s : %s\n" $code $ip
done
```

#### Heartbleed
```bash
# !/bin/bash
ips='2016-02-07_1454849674'

for ip in `grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' $ips`
do
   json=`curl -sSL 'https://hbelb.filippo.io/bleed/query?u='$ip'&&skip=1'`
   code=`echo $json | sed -e 's/[{}]/''/g' | grep -oE '"code":.*' | awk -F ',' '{print $1}' | awk -F ':' '{print $2}'`
   printf "%s : %s\n" $code $ip
done
```

### Interface-Info
#### Interface-State
```bash
$ cat /sys/class/net/<iface>/operstate
```
#### MAC-address
```bash
# OSX
$ ifconfig en1 | awk '/ether/ {print $2}'
$ ifconfig en1 | grep 'ether' | cut -d ' ' -f 2

# Linux
$ ifconfig eth0 | awk '/HWaddr/ { print $5}'
$ ifconfig eth0 | grep 'HWaddr' | cut -d ' ' -f 11
```
#### MAC-address filtering form log file
```bash
# OSX + Linux
$ grep -oE '([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})' mac_addresses_file
```
### MAC-address generator
```bash
$ printf "%02x" $((RANDOM%256 & 254 | 2));hexdump -n 5 -e '""5/1 ":%02x""\n"' /dev/urandom
$ printf "%02x:" $((RANDOM%256 & 254 | 2));openssl rand -hex 5 | sed 's/\(..\)/\1:/g; s/.$//'
```

#### IP Address
```bash
# Internal IP
# OSX + Linux
$ ifconfig `netstat -rn | awk '/default/ {print $NF}' | head -n 1` | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n 1

# OSX
$ ipconfig getifaddr `netstat -r | awk '/default/ {print $NF}'`
# Linux
$ sudo cat /proc/net/ip_conntrack | awk '{print $4}' | sort -u | grep src | awk -F '=' '{print $2}'

# External IP
# OSX + Linux
$ curl https://icanhazip.com
$ curl -sSL getip.ro | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u
$ dig +short myip.opendns.com @resolver1.opendns.com

# External IP-Proxychains
# OSX + Linux
$ proxychains curl -sSL getip.ro | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u

# IP(s) from DNS resolution
# IPv4 - OSX + Linux
$ host -t A google.com | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}'

# IPv6 - OSX + Linux
$ host -t AAAA facebook.com | sed 's/.*address //g'
```

### Ping
```bash
# IPv4
$ ping -c1 -W1 192.168.1.254
# IPv6
$ ping6 -c1 2607:f8b0:4000:805::1010
```
### Netstat
```bash
# show all (non)listening ports
$ netstat -a{t|u}   # TCP+UDP|TCP|UDP

# show listening ports only
$ netstat -l{t|u|x} # TCP+UDP|TCP|UDP|UNIX

# statistics
$ netstat -s{t|u}   # TCP+UDP|TCP|UDP

# PID & name
$ sudo netstat -p{t|u}

# do not resolve hostname, ports, hosts or users
$ netstat -a{n| --numeric [ports|hosts|users]}

# print
$ netstat -c         # continuously
$ netstat --verbose  # verbose output

# kernel roiting info
$ netstat -r

# show protocol port
$ netstat -ap | grep ssh
$ netstat -an | grep ':22'

# show net ifaces (ifconfig-like)
$ netstat -i{e}
```

### Netcat
#### Shell-door
```bash
$ nc -l -p 1234 -e /bin/sh # server
$ nc 10.0.0.6 1234 # client
```
#### Messenger
```bash
$ nc -l -p 6666 # server
$ nc localhost 6666 # client
```
#### One-shot server
```bash
$ { t='Hello, stranger!'; echo -ne "HTTP/1.0 200 OK\r\nContent-Length: `echo $t | wc -c`\r\n\r\n"; echo $t;} | nc -l -p 8080
```
#### Connect & die
```bash
$ nc -l -p 6666 # server
$ echo 'Gonna die in 2 seconds.' | nc -w 2 localhost 6666 # client
```
#### Proxying
```bash
$ nc -l -p 12345 | nc localhost 80 # pipes are unidirectional - no reply to client
$ mkfifo bpipe; nc -v -l -p 6666 0<bpipe | nc 127.0.0.1 80 1>bpipe # listen on 6666 and proxy to 80
```
#### Port Scanning
##### Netcat vs. Nmap - localhost
```bash
$ time nc -vnz -w 1 127.0.0.1 1-65535 &>/dev/null

real	0m6.601s
user	0m4.876s
sys	0m1.700s

$ time nmap -p 1-65535 127.0.0.1 &>/dev/null

real	0m0.782s
user	0m0.156s
sys	0m0.612s

# UDP scan is unreliable
$ nc -vnzu 192.168.0.1 80-90 # will always show "open"
```
#### Other names
```bash
$ # nc, ncat, pnetcat, socat, sock  socket, sbd
```
### Curl
#### POST on Proxy
```bash
# !/bin/bash

awk_match='/View it at/ {print $4}'

host='https://posttestserver.com'
cookie='c=1234'
agent='unknown'
data="Just+the+beginning"
proxy="127.0.0.1:9050"

path=`
   curl -sSL \
   -F 'data='"$data" $host'/post.php' \
   -A "$agent" \
   -b "$cookie" \
   --socks5-hostname "$proxy" \
   | awk "$awk_match" | grep -oE '/data/.*'
`
host=$host$path

echo $host && echo
curl -sSL $host

# -x "$proxy" \            # HTTP
# -socks5-hostname "proxy" # socks
```
#### Response Codes
```bash
curl -sL -w "%{http_code} %{url_effective}\\n" "URL" -o /dev/null

#-s = silence curl's progress output
#-L = follow all redirects
#-w = print the report using a custom format
#-o = redirect curl's HTML output to /dev/null

#> Special variables:
# - url_effective
# - http_code
# - http_connect
# - time_total
# - time_namelookup
# - time_connect
# - time_pretransfer
# - time_redirect
# - time_starttransfer
# - size_download
# - size_upload
# - size_header
# - size_request
# - speed_download
# - speed_upload
# - content_type
# - num_connects
# - num_redirects
# - ftp_entry_path
```
### Processes
#### Kill Naughty Net
```bash
$ sudo kill -9 `sudo netstat -tlnp | grep frozen_process | awk '{print $NF}' | awk -F '/' '{print $1}'`
```
### Service Manager
```bash
# OSX
$ sudo launchctl load -w /System/Library/LaunchDaemons/service.plist
```

### Spotlight + Indexing
```bash
$ sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.metadata.mds.plist
$ sudo mdutil -a -i off
```

### Apple Push Notification Service
```bash
$ sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.apsd.plist
```

## Security
### OpenSSL
#### Passwords and Hashing
##### Crypto Random
```bash
# because passwords should be long and strong
$ rand=`LC_CTYPE=C tr -dc 'A-Za-z0-9!@#$%^&*()_+=0-9~' < /dev/urandom | head -c 8`
$ dd if=/dev/urandom bs=64 count=1 status=none | tr -dc 'A-Za-z0-9!@#$%^&*()_+=0-9~'
$ date +%s | sha256sum | base64 | head -c 32 ; echo
$ < /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c${1:-32};echo;
$ openssl rand 32 | base64 -w0 && echo
$ tr -cd '[:alnum:]' < /dev/urandom | fold -w30 | head -n1
```
##### Hashing (fast)
```bash
$ echo -n $rand | openssl dgst -md4 | grep -oE '[0-9a-f]{32}'
$ echo -n $rand | openssl dgst -md5 | grep -oE '[0-9a-f]{32}'
$ echo -n $rand | openssl dgst -sha | grep -oE '[0-9a-f]{40}'
$ echo -n $rand | openssl dgst -sha1 | grep -oE '[0-9a-f]{40}'
$ echo -n $rand | openssl dgst -sha224 | grep -oE '[0-9a-f]{56}'
$ echo -n $rand | openssl dgst -sha256 | grep -oE '[0-9a-f]{64}'
$ echo -n $rand | openssl dgst -sha384 | grep -oE '[0-9a-f]{96}'
$ echo -n $rand | openssl dgst -sha512 | grep -oE '[0-9a-f]{128}'
$ echo -n $rand | openssl dgst -ripemd160 | grep -oE '[0-9a-f]{40}'
$ echo -n $rand | openssl dgst -whirlpool | grep -oE '[0-9a-f]{128}'
```
###### Find correct hash length
```bash
$ openssl dgst -sha1 <(printf 1) | awk '{print $2}' | wc -c # 41
$ openssl dgst -sha1 <(printf 1) | awk '{print $2}' | hexdump -c
0000000   3   5   6   a   1   9   2   b   7   9   1   3   b   0   4   c
0000010   5   4   5   7   4   d   1   8   c   2   8   d   4   6   e   6
0000020   3   9   5   4   2   8   a   b  \n
0000029

$ sum=`printf 1 | openssl dgst -sha1 | awk '{print $2}'`; printf $sum | wc -c # 40
$ sum=`openssl dgst -sha1 <(printf 1)`; echo -n ${sum/* } | wc -c # 40
```
###### Measure hashing time
```bash
#!/bin/bash
time {
for i in `seq 100`
do
  rand=`< /dev/random tr -dc 'A-Z-a-z-0-9' | head -c 20`
  echo -n $rand | openssl dgst -md5 > /dev/null
done
}
```
### AES-Crypt
```bash
aescrypt -e -p 'password' file_x
aescrypt -d -p 'password' file_x.aes
```
### AES-CBC
```bash
$ clear='My secret.'
$ key=`tr -dc 'A-Za-z0-9!@#$%^&*()_+=~' < /dev/urandom | head -c 32`
$ cipher=`echo $clear | openssl enc -aes-256-cbc -k $key | base64 | tr "\n" " " | sed 's/ //g'`
$ clear=`echo $cipher | base64 -d | openssl enc -aes-256-cbc -d -k $key`
```

#### AES Demo
```bash
#!/bin/bash

tmp='/tmp/'$RANDOM
mkdir $tmp && cd $tmp
file='https://upload.wikimedia.org/wikipedia/commons/5/5b/WRC.png'
fname='1.png'
key=`< /dev/random tr -dc 'A-Z-a-z-0-9' | head -c 20`
curl -sSL $file -o $fname

echo 'Before encryption:'
openssl dgst -md5 $fname
echo 'Type:' `file $fname`
hexdump -C $fname | head -n 6

echo

echo 'After encryption:'
aescrypt -e -p $key $fname
openssl dgst -md5 $fname.aes
echo 'Type:' `file $fname.aes`
hexdump -C $fname.aes | head -n 6

rm $fname && echo

echo 'After decryption:'
aescrypt -d -p $key $fname.aes
openssl dgst -md5 $fname
echo 'Type:' `file $fname`

rm -rf $tmp
```
### Entropy
#### $RANDOM
```
$ echo "RANDOM:" $RANDOM
$ [ $[ $RANDOM % 13 ] == 0 ] && sudo rm -rf / || echo "Not today..."
```
##### RANDOM [$min,$max]
```bash
$ min=1
$ max=10
$ offset=$((max-min))
$ echo "RANDOM [$min,$max]:" $((RANDOM%(offset+1)+min))
```
##### RANDOM > 100 & < 300
```bash
$ echo "RANDOM > 100 & < 300:" $((RANDOM%200+100))
```
##### RANDOM shuffler with 'date'
```bash
$ RANDOM=`date +'%N'`
$ echo $RANDOM
```
#### Shuf
```bash
$ min=1
$ max=10
$ lines=3
$ shuf -i $min-$max -n $lines
```
#### Dev-Rand
```bash
$ od -vAn -N4 -tu4 < /dev/urandom
$ od -An -N2 -i /dev/random
$ < /dev/random tr -dc A-Z-a-z-0-9 | head -c 10
```
## Text Processing

### Call bash function from `awk`
```bash
$ func(){ echo ">>> $1";}
$ export -f func
$ echo "1 2 3" | awk '{system("bash -c '\''func "$1"'\''")}'
>>> 1
```

### Quoted Text
```bash
$ echo \"123\" | sed 's/.*"\(.*\)"[^"]*$/\1/'
$ echo \"123\" | awk -F '\"' '{print $(NF-1)}'
$ echo \"123\" | grep -oE '[^"]+'
```
### Remove Blank
```bash
$ echo -e 'OK\r\n' | sed '/^$/d'
$ echo -e 'OK\r\n' | grep -v '^$'
```
### Start-End
```bash
$ sed 's/.*START//'
$ sed 's/END.*//'
```
### Replace Text
```bash
# occurrences of old word with new word in file/text
$ sed -i 's/old/new/' file
$ sed -i 's/old/new/g' file # all
$ echo -e 'Car starts with C.' | sed 's/Car/Crown/'

# replace with text containing spaces
$ echo -e 'Car starts with C.' | sed 's/Car/Chocolate\ also/'
$ echo -e 'Car starts with C.' | sed 's/Car\ starts/Table \does \not \start/'
```
#### Replace Line in Text
```bash
#!/bin/bash

work='/tmp/'$RANDOM
mkdir $work && cd $work
file='f'
tmp='f_tmp'

echo '> Before:'
echo -e 'First line.\r\nSecond line.\r\nThird line.' > $file
cat $file && echo

replace_from='Third line.'
replace_to='Last line.'

total=`wc -l $file | awk -F ' ' '{print $1}'`
n=`grep -in "$replace_from" $file | awk -F ':' '{print $1}'`

cat $file | head -$((n-1)) > $tmp
echo $replace_to >> $tmp
cat $file | tail -$((total-n)) >> $tmp

cp $tmp $file && rm $tmp
echo '> After:'
cat $file && rm -r $work
```
### N-th line
```bash
$ echo -e 'a\r\nb\r\nc' | sed '1q;d'
$ echo -e 'a\r\nb\r\nc' | sed '3q;d'
$ sed '{N}q;d' file
```
### Remove Tailing Slash
```bash
$ cat file | sed 's:/*$::'
```
### All in one line
```bash
$ cat file | tr -d '\n' > one_line_file
$ echo -e "* 1\n* 2\n* 3" | awk '{gsub("\* ","");sub("$",",");{printf "%s",$0}}' | sed 's/.$//'
1,2,3
```
### Remove last character in line
```
$ echo 1234 | sed 's/.$//'
$ x=1234; echo "${x%?}"
```

#### Between X and Y line
```bash
# show line number
$ nl file
$ cat -n file

# get text between X and Y line (X = 300; Y = 310)
$ tail -n+300 file | head -n 10 # good performance
$ sed -n '300,310p;320q' file   # good performance
$ head -n 310 file | tail -n 10
$ sed -n '300,310p' file
$ tail -n 301 file | head -n 10
$ ed -s file <<<"300,310p"
$ awk 'NR<300{next}1; NR==310{exit}' file
$ awk 'NR>=300 && NR<=310' file
$ awk '/foo/{k=$0}END{print k}' file
$ awk '/Header/ { show=1 } show; /Footer/ { show=0 }'
$ sed -n '/Header/,/Footer/p'
$ sed '/Header/,/Footer/!d'
$ sed -n '/header/I,/FOOTER/Ip' # case insensitive
```
#### Sorting Text Lines
```bash
$ echo -e '1\n3\n2\n1' | sort | uniq # or echo -e '1\n3\n2\n1' | sort -u
$ sort -k 8,8 -t ':' -dr # sory by 8th column for ':' separator reverse dictionary
```
#### JSON
```bash
$ echo {\"name\":\"David\"} | jq .name
$ echo {\"cars\":[\"Mercedes\", \"Porsche\", \"BMW\"]} | jq .cars
$ echo {\"numbers\":[\"64\", \"32\", \"128\"]} | jq .[]
```
#### XML
```bash
# libxml2-utils
xmllint --xpath '//element/@attribute' file.xml
xmlstarlet sel -t -v "//element/@attribute" file.xml
saxon-lint --xpath '//element/@attribute' file.xml
```

# Databases
## Postgres
```bash
$ sudo -u postgres psql                             # get PSQL shell
$ sudo -u postgres psql -d db_name                  # get PSQL shell for specific db
$ psql -U admin -d admin_db -h localhost            # get PSQL shell for specific db as specific user
$ sudo -u postgres psql -c '\du'                    # execute single PSQL command
$ psql -d 'postgres' -U admin -h localhost -c '\du' # execute single PSQL command as specific user on a db
```
### User-Management
```bash
$ sudo -u postgres createuser -e -s admin && sudo -u postgres psql -c '\password admin' # create user and set password securely
$ sudo -u postgres createuser -e -s --pwprompt admin2                                   # create user and prompt for password
$ sudo -u postgres dropuser -e admin2                                                   # drop user
$ sudo -u postgres createdb admin_db --owner=admin                                      # create a db for admin user
```
### PSQL
```bash
postgres=# drop database some_db # delete a database
postgres=# drop role some_user   # delete a user
postgres=# \?                    # show psql help
postgres=# \du                   # show user roles
postgres=# \l                    # show databases
db_name=# SELECT VERSION();      # show database version
db_name=# \d                     # show tables, views, etc.
```
### Metasploit Fix
```bash
$ su postgres
postgres@kali:/root$ createuser user --pwprompt
postgres@kali:/root$ createdb --owner=user metasploit
postgres@kali:/root$ psql -d metasploit -U user -h localhost

$ msfconsole
msf > db_connect user:password@localhost:5432/metasploit
```
# iOS
## Installed apps
```bash
$ ll ~/Containers/Bundle/Application/*                     # path to installed apps
$ ll ~/Containers/Bundle/Application/* | grep .app
```
## Safari data
```bash
$ ~/Containers/Data/Application/*/Library/Safari/Thumbnails/        # screenshots of opened tabs
$ ~/Containers/Data/Application/*/Library/Safari/SuspendState.plist # links of opened tabs
```
## Find sqlites
```bash
$ sudo find ~/Containers/Data/Application/ -name *.sqlite
```
## Collect sqlites
```bash
#!/bin/bash

rm -r dbs dbs.zip
mkdir dbs

declare -a rows
while IFS= read -r -d '' n; do
  cp "$n" dbs
  #rows+=( "$n" )
done < <(sudo find Containers -name *.sqlite -print0)
#done < <(sudo find / -name *.sqlite -print0)

zip -r9 dbs.zip dbs && rm -r dbs

#printf '%q\n' "${rows[@]}"
```


### Disable/Enable macOS Dashboard
```
$ defaults write com.apple.dashboard mcx-disabled -boolean YES && killall Dock
$ defaults write com.apple.dashboard mcx-disabled -boolean NO && killall Dock
```
