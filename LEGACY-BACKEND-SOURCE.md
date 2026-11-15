# Retained legacy backend source

Owner: linux. Optional guest grants/cookie custody and legacy constrained relay.

Legacy source only, not a current supported import path or command. Original cross-package namespaces, private imports, target paths, key/account custody, host/network/process actions and fixtures must be ported deliberately before use. Do not add sys.path shims, privileged globals, fake storage or automatic service/firewall actions to make it run. No old module/driver is imported or executed by this extraction; no active backend or minimum dependency changes.

## Source and history

Desktop snapshot `4f72ea86928666189b32f6f05c2c697a37341d06`; exact source baseline `48583d9f3d786ea065f6e564d121f9b65c33d8d5`; separate mechanical merge `d84ecf569933614843060801b6daeaf17b7d1b46`. Private phase41 retains original/earlier paths, copy-boundary notes and commit/ref maps. No active package/module/test body changed.

| Original path | Retained path |
|---|---|
| `active-system/guest-relay/requirements.txt` | `legacy/backend/guest-relay/requirements.txt` |
| `active-system/guest-relay/server.py` | `legacy/backend/guest-relay/server.py` |
| `active-system/origin_service/guest_authority.py` | `legacy/backend/origin_service/guest_authority.py` |
| `active-system/origin_service/guest_cookie.py` | `legacy/backend/origin_service/guest_cookie.py` |

These sources remain outside supported package/build/test entrypoints. Existing source baseline failures remain separate; syntax/history checks do not establish old protocol or current application compatibility. Preserve native signed-worker/authorization checks during a real public-interface port. External publication is not authorized by this source retention.
