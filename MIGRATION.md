# Optional Linux guest backend extraction

Original source: `4f72ea86928666189b32f6f05c2c697a37341d06`. The existing Linux worker/image sources and history remain intact. Sixteen additional source/test paths have one owner here:

- Thirteen Python modules: `active-system/guest_service/*.py` → `server/guest_service/`.
- Former browser network adapter: `active-system/guest_service/client.mjs` → `legacy/network-client.mjs`, pending a public host/session interface port.
- Quota and signin-policy fixtures: `active-system/scripts/guest-{usage,signin-policy}-check.py` → `tests/legacy-guest-service/`.

Both `desktop-preview/active-system/` and `active-system/` histories were retained. Filtered mechanical baseline: `da4d36df7a8b22a8338417120b2f4521b5941f0e`; merge: `b0778841f1bcd3ecafb547cba5cad3013e4c777f`. All16 blobs, paths and modes were verified before functional changes. Private phase27 preserves per-path history, commit/ref maps, original-scope status, command logs and isolated baseline/installed-wheel evidence.

The functional port is a separate commit: three JOSE imports use Accounts' documented public primitives; backend packaging is explicit; fixture paths and console runners use the new layout. All retained test classes/assertions remain unchanged. Native deployment manifests/operators, kernel/systemd/QEMU tests, issuer grant endpoint and desktop integration remain OPEN. No optional source is enabled by adding it to this repository.
