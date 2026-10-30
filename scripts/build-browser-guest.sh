#!/bin/bash
# An isolated 32-bit browser guest, never the CodiServer ISO rootfs.
set -euo pipefail
cd "$(dirname "$0")/../.."
root="$PWD/downloads/desktop-v86-source/debian-root"
if [[ -e "$root" ]]; then echo "Guest root already exists; inspect before rebuilding: $root" >&2; exit 1; fi
sudo -n unshare --mount --propagation private mmdebstrap --keyring="$PWD/downloads/desktop-v86-source/debian-bookworm-archive.gpg" --architectures=i386 --variant=minbase \
 --include=linux-image-686,initramfs-tools,busybox,bash,python3,gcc,libc6-dev,make,nano,sqlite3,ca-certificates \
 --aptopt='APT::Install-Recommends "false"' \
 bookworm "$root" 'deb http://deb.debian.org/debian bookworm main' 'deb http://security.debian.org/debian-security bookworm-security main'
