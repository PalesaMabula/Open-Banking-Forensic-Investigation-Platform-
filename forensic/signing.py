"""Ed25519 digital signatures for forensic evidence.

Each forensic event's hash is signed with the gateway's private key. This
protects against a tamperer who recomputes the SHA-256 hash chain: a forged
event would also need a valid signature, which requires the private key.

Verification uses the matching public key, which can be published so that an
independent party can confirm the evidence without trusting the platform.

PROTOTYPE LIMITATION: the private key is stored in a local PEM file
(data/signing_key.pem, excluded from version control). In a production
forensic deployment the signing key would be held in a hardware security
module (HSM) kept separate from the evidence store, so that no one with
database access can also produce signatures.
"""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature

import config

_KEY_PATH = config.DATA_DIR / "signing_key.pem"
_private_key = None


def _load_or_create_key() -> Ed25519PrivateKey:
    """Loads the signing key from disk, generating and persisting one on first use."""
    global _private_key
    if _private_key is not None:
        return _private_key

    config.DATA_DIR.mkdir(parents=True, exist_ok=True)

    if _KEY_PATH.exists():
        with open(_KEY_PATH, "rb") as fh:
            _private_key = serialization.load_pem_private_key(fh.read(), password=None)
    else:
        _private_key = Ed25519PrivateKey.generate()
        pem = _private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(_KEY_PATH, "wb") as fh:
            fh.write(pem)

    return _private_key


def sign(message: str) -> str:
    """Returns the hex-encoded Ed25519 signature of the given message string."""
    key = _load_or_create_key()
    return key.sign(message.encode("utf-8")).hex()


def verify(message: str, signature_hex: str | None) -> bool:
    """Returns True if signature_hex is a valid signature of message, else False."""
    if not signature_hex:
        return False
    try:
        public_key = _load_or_create_key().public_key()
        public_key.verify(bytes.fromhex(signature_hex), message.encode("utf-8"))
        return True
    except (InvalidSignature, ValueError):
        return False


def get_public_key_hex() -> str:
    """Returns the raw public key as hex, for independent verification."""
    public_key = _load_or_create_key().public_key()
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return raw.hex()