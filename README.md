# Linux guest source — optional WebOS component

This repository owns the existing Worker guest client/runtime, versioned guest runtime inputs, guest init/CDMUX sources, image builders and retained protocol fixture. The18 original files and their actual earlier paths retain exact blobs/modes and filtered history. This source component is meaningful guest/worker/image implementation, not an enabled desktop view.

v86 engine/source/firmware live in the separate engines/v86 repository. The old Desktop's global boot/session orchestration remains preserved in its historical source reference; deliberate optional-view integration and lifecycle separation are pending. Terminal remains its independent apps/terminal source. Linux home is temporary guest memory, separate from server-backed account files. Linux/v86 is never a dependency of the minimum system.

The versioned image was inspected as static build data:974 archive entries, no populated guest/root homes or session/key payload found by the scoped inventory. It is a base image, not a copied live guest volume. Original guest build scripts are preserved references: they require a prepared isolated i386 toolchain and some use sudo/chroot. Do not run them against a live machine or the old workspace; build-interface/toolchain porting remains explicit work. The retained old browser test references its former shared driver and needs a new test harness. No production networking or service activation occurred.

## Guest networking source

The separately extracted guest backend is now organized under `server/guest_service/`, with quota and policy fixtures under `tests/legacy-guest-service/`. The former browser client is preserved under `legacy/` pending a public-interface port. Python authorization uses Accounts' public JOSE interface. Read `server/README.md` before testing: native operator input manifests and privileged kernel tests remain unqualified and must not be mistaken for a ready deployment. This update does not enable Linux or networking in the desktop.

## Prepare the optional browser guest

Use the verified v86 package and firmware and prepare an isolated Debian
bookworm i386 build root. [Guest runtime inputs](scripts/guest-runtime-inputs.json)
lists public download locations and SHA-256 values for the runtime packages,
GCC, binutils, v86, firmware and optional i686 uv release. The listed runtime
packages match the 612 Debian runtime files in the archived image.

The input directory contains a usr-merged Debian installation under
`debian-root/`, the extracted npm tarball under `npm/package/`, and a checkout
of the listed firmware source under `v86-<commit>/`. The Debian root needs its
package database and a module dependency index for the pinned kernel.

With the input layout expected by the preparation script, run:

```sh
bash scripts/prepare-v86-assets.sh /path/to/prepared/inputs /path/to/i686/uv
```

The optional second argument includes Python and uv. The command verifies its
input checksums and prepares a new ignored `.build/v86/` directory with the
checksum manifest and an `image.json` entry for the rebuilt guest. The browser
worker fixture uses that entry. The script also creates the ignored
\`assets/terminal/v86\` link to the output so the worker can load its library.

Build on a Linux host that can run i386 applications and supports rootless
Bubblewrap namespaces. The builder runs the isolated Debian BusyBox and C
compiler through Bubblewrap. It uses host `as`, `ld`, `dpkg-query` and Python,
and reads package metadata and module dependencies from the Debian build root.
