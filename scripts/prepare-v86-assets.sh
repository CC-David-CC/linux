#!/bin/bash
# Prepare the ignored browser runtime from the already retained local cache.
set -euo pipefail
project="$(cd "$(dirname "$0")/.." && pwd)"
cache="$project/../../downloads/desktop-v86-source"
v86src="$cache/v86-cc37f35c43bf14865d74ad76879ecf9410f69eb1"
out="$project/.build/v86"
mkdir -p "$out"
verify() {
    local expected="$1" file="$2" actual
    actual="$(sha256sum "$file" | cut -d' ' -f1)"
    [[ "$actual" == "$expected" ]] || { echo "Hash mismatch: $file ($actual)" >&2; exit 1; }
}
verify 1b41074f7a5604f528dac6842baf7afccd79d7370b97ea3241944c275b67bec1 "$cache/npm/package/build/libv86.js"
verify 2f0c4150f266415b754a84a32e6f8e4c975a1d3abb94c78b047fa30027db1ef1 "$cache/npm/package/build/v86.wasm"
verify 73e3f359102e3a9982c35fce98eb7cd08f18303ac7f1ba6ebfbe6cdc1c244d98 "$v86src/bios/seabios.bin"
verify a4bc0d80cc3ca028c73dafa8fee396b8d054ce87ebd8abfbd31b06b437607880 "$v86src/bios/vgabios.bin"
verify 3d0c734693b5614c665529413aeb339ededd54112c38c463602db932ec43ceae "$cache/debian-root/boot/vmlinuz-6.1.0-54-686"
verify 1f6f750c0d13b69c76b5388c55c14ba9178384da134cb82fd4c3ddd1394413f7 "$cache/debian-root/bin/busybox"
verify ef7792b351dba25b48ad223224966db839b132efd7755d26f422ba2eb0f1a6a1 "$cache/debian-root/usr/lib/i386-linux-gnu/libc.so.6"
verify 8b8fc0e5299310235f0238db8d1bfeeafed24bb68201879e6dbc2fe0576eb593 "$cache/debian-root/usr/lib/i386-linux-gnu/ld-linux.so.2"
verify e8c62c6add098fca77a4229efeb393f7cb421128e2c3d2edd4084931bae83c67 "$cache/debian-root/usr/lib/i386-linux-gnu/libresolv.so.2"
cp "$cache/npm/package/build/libv86.js" "$cache/npm/package/build/v86.wasm" \
   "$v86src/bios/seabios.bin" "$v86src/bios/vgabios.bin" \
   "$cache/debian-root/boot/vmlinuz-6.1.0-54-686" "$out/"
mv "$out/vmlinuz-6.1.0-54-686" "$out/vmlinuz"
cp "$v86src/LICENSE" "$out/LICENSE-v86"
cp "$v86src/bios/COPYING.LESSER" "$out/LICENSE-bios"
cp "$cache/debian-root/usr/share/doc/busybox/copyright" "$out/LICENSE-busybox"
cp "$cache/debian-root/usr/share/doc/linux-image-6.1.0-54-686/copyright" "$out/LICENSE-linux"
python3 "$project/scripts/build-browser-initramfs.py"
(
    cd "$out"
    sha256sum libv86.js v86.wasm seabios.bin vgabios.bin vmlinuz initramfs.cpio.gz > MANIFEST.sha256
    sha256sum -c MANIFEST.sha256
)
echo "Prepared v86 0.5.472 guest assets in $out (ignored by Git)."
