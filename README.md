# Euclid 
**⚠ Still very early in development**

A x86_64 Linux application sandboxing tool demonstrating container isolation techniques via namespaces, cgroups, and seccomp. 

## Features
Creates an isolated execution environment via:
- **Namespace isolation**: Separate UTS (hostname), PID, mount, network, and IPC namespaces
- **Resource limits**: CPU, memory, swap, and pid restrictions through cgroups v2
- **Syscall filtering**: Whitelist-based syscall filtering through seccomp-bpf
- **Filesystem isolation**: Separate read-only root filesystem through the `pivot_root` syscall and tmpfs/overlayfs
- **Capability dropping**: Removes all Linux capabilities from the sandboxed process

## Prerequisites

### System Requirements
- Linux 4.5+ (for cgroups v2 support)
- x86_64 architecture
- Root or sudo access (for namespace and cgroup operations)

### Build Dependencies
* GCC
* GNU make

## Preparing a Root Filesystem
Euclid requires a minimal Linux root filesystem to use as the container's root. Alpine has been used during development

### Setting Up Alpine
```bash
# Create a directory for the rootfs
mkdir -p ~/alpine

# Download Alpine rootfs (grab the current link from the website)
cd ~/alpine
wget https://dl-cdn.alpinelinux.org/alpine/v3.23/releases/x86_64/alpine-minirootfs-3.23.3-x86_64.tar.gz

# Extract the rootfs
tar -xvf alpine-minirootfs-3.23.3-x86_64.tar.gz

# Remove the archive from the rootfs
rm -rf alpine-minirootfs-3.23.3-x86_64.tar.gz
```

## Configuration
Configuration of Euclid is compiled-in to reduce the attack surface that comes with having external configuration files. The constants to configure Euclid are located near the beginning of `src/context.c`.

## Installation
Compile the project
```bash
make
```
Install the compiled binary
```bash
sudo make install
```

### Make Targets 
- `make` - Compile the binary
- `make install` – Install binary
- `make clean` – Remove build objects
- `make fclean` - Remove build objects and binary

## Usage
Run the sandbox
```bash
sudo euclid
```
This launches the sandbox with the command specified in the configuration (`/bin/sh` by default). 

## Planned Enhancements
- User namespaces (`CLONE_NEWUSER`)

## License
GNU General Public License V2

Copyright (c) 2026 Jacob Niemeir
