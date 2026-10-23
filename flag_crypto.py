"""
Shared XOR-obfuscation helpers used to hide flag *base secrets* inside the
source so a naive `grep -R "NGDSA{"` sweep doesn't turn up literal flag
text. This is NOT real security — it only stops casual reading, not
someone who finds `unshroud()` here and decodes a blob by hand. That's the
intended solve path for SOURCE_PERISTERI (Phase 2, flag hidden in source).

Per README: IDOR_BREACH and WS_SIDECHANNEL are intentionally left
UN-obfuscated in main.py, because their intended solve path is interacting
with the running app, not reading source.

Per-team flag UNIQUENESS (so Team A can't hand Team B a working flag) is a
separate mechanism — see derive_flag() in main.py, which combines a base
secret from this module with FLAG_SECRET_SALT (env var, same for every
container this event) and TEAM_ID (env var, unique per container) via
HMAC-SHA256. This module only hides the base secret each flag is derived
from; it has nothing to do with per-team uniqueness.
"""


def _keystream(key: str, length: int) -> bytes:
    key_bytes = key.encode("utf-8")
    return bytes(key_bytes[i % len(key_bytes)] for i in range(length))


def shroud(plaintext: str, key: str) -> str:
    """Dev-time helper to (re)generate the hex blobs pasted into main.py.
    Not called at runtime by the app itself. Example:

        python3 -c "from flag_crypto import shroud; print(shroud('my-new-base-secret', 'SOME_FLAG_key'))"
    """
    data = plaintext.encode("utf-8")
    ks = _keystream(key, len(data))
    return bytes(b ^ k for b, k in zip(data, ks)).hex()


def unshroud(hexblob: str, key: str) -> str:
    """Decode a shrouded base secret at import time."""
    data = bytes.fromhex(hexblob)
    ks = _keystream(key, len(data))
    return bytes(b ^ k for b, k in zip(data, ks)).decode("utf-8")
