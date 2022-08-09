# Knockles - eBPF Port Knocking Tool 🚪🐝

Knockles 🦔, is a port knocking tool based on [eBPF](https://ebpf.io/what-is-ebpf) 🐝.
It allows you to remotely open a TCP connection while being completely invisible to port scanners.

- A single SYN request is sent on an opened || closed port 📨 📫
- It carries an OTP for authentication so you can be the only one to open a port 🔐 
- Once authentified, a random (HMAC based) port is opened for a TCP connection 🎲
- Then, the port is closed as soon as a connection has been established 🚪

## Server configuration

> Modify the following macros/variables

**./knockles/src/knockles.bpf.c**
- *l.6*:`PORT`: Port monitored for knocks [default: 80]

**./knockles/src/knockles.c**
- *l.16*:`HMAC_DURATION`: Time between two different OTP (in seconds) [default: 30]
- *l.17*:`LISTENING_DURATION`: Timeout of the opened port if no connection occurs (in seconds) [default: 30]
- *l.18*:`SECRET`: HMAC secret key **⚠️ Don't forget to modify this variable ⚠️** [default: MY_SECRET_KEY]

## Server compilation

### Requirements

#### Debian

```bash
sudo apt install git make pkg-config libelf-dev clang-11 libc6-dev-i386 bpftool libssl-dev -y
pip install scapy
```

#### Ubuntu

```bash
sudo apt install git make pkg-config libelf-dev clang-11 libc6-dev-i386 linux-tools-common linux-tools-$(uname -r) libssl-dev -y
pip install scapy
```

### Build

```bash
cd ./knockles/src
make
```

## Usage

### Server side

```text
Usage: ./knockles [OPTION]...
eBPF port knocking tool - Server.
      --help             display this help and exit
      --daemon           run program as daemon
```

### Client side

```text
usage: knuckknock.py [-h] -s KEY  -t TIME -d IP -p PORT

eBPF port knocking tool - Client.

optional arguments:
  -h, --help            show this help message and exit
  -s KEY , --secret KEY 
                        HMAC secret key
  -t TIME, --time TIME  generated HMAC duration
  -d IP, --dst IP       destination IP address
  -p PORT, --port PORT  monitored port
```
