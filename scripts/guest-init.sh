#!/bin/sh
export PATH=/bin:/sbin:/usr/bin HOME=/home/guest TERM=vt100
mount -t devtmpfs devtmpfs /dev
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mkdir -p /dev/pts
mount -t devpts devpts /dev/pts -o mode=620,ptmxmode=666
[ -e /dev/ptmx ] || ln -s pts/ptmx /dev/ptmx
while read -r module; do insmod "/modules/$module" || echo "Module failed: $module"; done < /modules/load-order
if mount -t 9p -o trans=virtio,version=9p2000.L,cache=none host9p /home/guest; then
    chown 1000:1000 /home/guest
    chmod 777 /home/guest
    echo 'Shared home mounted at /home/guest'
else
    echo 'ERROR: shared home could not be mounted'
    chown 1000:1000 /home/guest
fi
chmod 666 /dev/console /dev/ttyS0 /dev/null
ifconfig lo 127.0.0.1 up
printf '0 2147483647\n' > /proc/sys/net/ipv4/ping_group_range
case " $(cat /proc/cmdline) " in
  *' guest_net=1 '*)
    if ifconfig eth0 10.86.0.2 netmask 255.255.255.0 up && route add default gw 10.86.0.1; then
      printf 'nameserver 10.86.0.3\n' > /etc/resolv.conf
      echo 'Guest Internet relay configured through the WebOS server.'
    else
      echo 'Guest network interface failed to configure.'
    fi
    ;;
esac
cd /home/guest
printf '\nCodiServer browser guest: ready\n'
printf 'Guest home is shared with Files and Text Editor. Session files are temporary.\n'
printf 'Try: ls, cat Documents/README.txt, vi notes.txt, ping 127.0.0.1\n\n'
while true; do /sbin/drop-to-guest; echo 'Shell exited. Starting a fresh shell.'; done
