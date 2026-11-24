## What changed

<!-- Description and reason. Link the issue. -->

## Protocol impact

<!-- Wire types, handshake, federation, storage schema. Is it backward compatible with a relay that has not been updated yet? -->

## Security impact

<!-- Untrusted input, limits, entitlement, identity checks. What is the hostile path and how is it covered? -->

## Verification

- [ ] `dart analyze` is clean
- [ ] `flutter test --no-pub` is green
- [ ] `dart compile exe bin/dtm_host.dart` builds
- [ ] tested against a live relay with `host_probe.py`

## Checklist

- [ ] One logical change
- [ ] Limits enforced before allocation
- [ ] `host.db` untouched on upgrade
- [ ] No envelope contents, keys or seeds in logs
