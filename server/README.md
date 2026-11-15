# Optional Linux guest network backend

`guest_service/` owns the original guest-wire authorization, packet policy, account quotas, worker/coordinator/frontend and native operator source. Browser relay networking belongs to the Browser repository. Terminal is a separate app; v86 is a separate engine. This backend is not a minimum-system dependency and is not enabled. Installing its Python package starts no listener and performs no operator action.

The mechanical extraction preserves14 guest-service files and two fixtures from source commit `4f72ea86928666189b32f6f05c2c697a37341d06`, including their earlier `desktop-preview/active-system/` histories. Exact blobs and modes were checked before the functional port. The legacy client is at `legacy/network-client.mjs`; its old identity/session imports need a deliberate public-interface port before use.

A separate functional commit imports Accounts' public JOSE primitives, packages the backend and updates fixture paths/console runners. Test classes and assertions remain unchanged. The old fixture mains wrote hash reports into the old checkout; these are replaced with ordinary unittest console runners.

The native `installation.py`/`operator.py` input manifests retain the former deployment layout as historical implementation evidence. They have NOT been qualified for this new package; do not run them. No kernel rules, systemd units, UIDs, QEMU processes or services are installed by this source pass. A future operator port needs explicit packaging, custody, rollback and real kernel/worker tests; import success does not prove that boundary.

The full signin-policy fixture includes a `sudo unshare ... nft` test. It is retained unmodified and not executed during source organization. Pure quota tests run with disposable SQLite files in a private test home whose ancestors satisfy the unchanged custody checks. Native kernel/systemd/worker/Gecko/v86 acceptance and desktop human/agent operations remain OPEN.

## Qualification

All28 unchanged SQLite quota tests passed before extraction and again using the installed wheel. Six signed guest-wire tests passed using Accounts' public JOSE API and generated fixture issuer/client keys. Twelve installed modules imported with app source, old workspace and recovery source hidden. The fixture issuer does not qualify a live issuer endpoint.

After installing the reviewed component and Accounts packages in an isolated environment, `python tests/legacy-guest-service/guest-usage-check.py` runs the quota fixture with temporary data. `python -m unittest discover -s tests -p 'test_*.py'` runs the signed protocol checks. Do not run the full legacy signin-policy fixture without reviewing its sudo/private-kernel requirements.
