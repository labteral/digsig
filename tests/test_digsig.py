#!/usr/bin/env python3
"""digsig test suite.

Coverage:
- Sign/verify and tampered-message rejection in every mode (ECDSA
  secp256k1 SHA3-256, ECDSA secp256k1 keccak-256 ethereum, RSA PSS-MGF1
  SHA256, RSA PSS-MGF1 SHA3-256).
- Key loading: RAW_VALUE (int, canonical 32-byte values and hex strings),
  ETHEREUM_JSON keystores (dict and JSON string), private/public PEM,
  P12/PFX with password, without certificate and unencrypted.
- Known hashing vectors (sha256, sha3_256, keccak_256, ripemd160).
- Public API surface: top-level exports and PublicKey/PrivateKey
  .get_instance() loading by filepath (.json, .p12, .pem).
- Contract and negative cases: hex-string signatures, str messages,
  invalid modes, unsupported raw values.

Requirements: the package itself plus its declared dependencies
(cryptography, eth-account) + pycryptodome (used by digsig.hashing for
keccak) + pytest. Works across the whole supported cryptography range.
"""
import base64
import datetime
import hashlib
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa as rsa_module
from cryptography.x509.oid import NameOID
from eth_account import Account
from eth_keys.constants import SECPK1_N

from digsig import __version__
from digsig.ecdsa import EcdsaFormats, EcdsaModes, EcdsaPrivateKey, EcdsaPublicKey
from digsig.errors import InvalidSignatureError
from digsig.hashing import HashFunctions, hash_message
from digsig.rsa import RsaFormats, RsaModes, RsaPrivateKey, RsaPublicKey

MSG = b"digsig test message"
TAMPERED = b"digsig TAMPERED message"


def test_version():
    assert __version__ == "2.2610.0"


# ------------------------------------------------------------------ hashing
def test_hash_sha256_vector():
    # SHA-256 of the empty string (known vector)
    assert hash_message(b"", "sha256").hex() == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_hash_sha3_256_vector():
    # SHA3-256 of the empty string (known vector)
    assert hash_message(b"", "sha3_256").hex() == (
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    )


def test_hash_keccak_256_vector():
    # Keccak-256 of the empty string (known Ethereum vector)
    assert hash_message(b"", "keccak_256").hex() == (
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    )


def test_hash_unknown_algorithm():
    with pytest.raises(NotImplementedError):
        hash_message(b"x", "no_such_algorithm")


def test_hash_accepts_str_message():
    # str messages are accepted and encoded as utf-8
    assert hash_message("digsig test string", HashFunctions.SHA256) == hash_message(
        b"digsig test string", HashFunctions.SHA256
    )


def test_hash_ripemd160_vector():
    # RIPEMD-160 of the empty string (known vector). On OpenSSL 3 without
    # the legacy provider the algorithm is unavailable and digsig raises
    # NotImplementedError; where it is available the vector must match.
    if "ripemd160" in hashlib.algorithms_available:
        assert hash_message(b"", HashFunctions.RIPEMD160).hex() == (
            "9c1185a5c5e9fc54612808977ee8f548b2258d31"
        )
    else:
        with pytest.raises(NotImplementedError):
            hash_message(b"", HashFunctions.RIPEMD160)


# ------------------------------------------------------------------ ECDSA
@pytest.mark.parametrize("mode", sorted(EcdsaModes.options()))
def test_ecdsa_sign_verify_tamper(mode):
    key = EcdsaPrivateKey(mode=mode)
    signature = key.sign(MSG)
    key.public_key.verify(MSG, signature)
    with pytest.raises(InvalidSignatureError):
        key.public_key.verify(TAMPERED, signature)


def test_ecdsa_load_raw_value():
    key = EcdsaPrivateKey(mode=EcdsaModes.SECP256K1_KECCAK_256_ETHEREUM)
    reloaded = EcdsaPrivateKey(
        mode=EcdsaModes.SECP256K1_KECCAK_256_ETHEREUM,
        key=key.private_value,
        key_format=EcdsaFormats.RAW_VALUE,
    )
    assert reloaded.public_key.ethereum_address == key.public_key.ethereum_address
    signature = reloaded.sign(MSG)
    key.public_key.verify(MSG, signature)


def test_ecdsa_load_ethereum_json_keystore():
    account = Account.create()
    keystore = Account.encrypt(account.key, "digsig-test-password")
    key = EcdsaPrivateKey(
        mode=EcdsaModes.SECP256K1_KECCAK_256_ETHEREUM,
        key=keystore,
        password="digsig-test-password",
        key_format=EcdsaFormats.ETHEREUM_JSON,
    )
    assert key.public_key.ethereum_address.lower() == account.address.lower()
    signature = key.sign(MSG)
    key.public_key.verify(MSG, signature)


def test_ecdsa_public_key_from_value():
    key = EcdsaPrivateKey(mode=EcdsaModes.SECP256K1_SHA3_256)
    signature = key.sign(MSG)
    public = EcdsaPublicKey(
        mode=EcdsaModes.SECP256K1_SHA3_256,
        key=key.public_key.public_bytes,
        key_format=EcdsaFormats.RAW_VALUE,
    )
    public.verify(MSG, signature)
    with pytest.raises(InvalidSignatureError):
        public.verify(TAMPERED, signature)


def test_ecdsa_public_key_from_value_ethereum():
    key = EcdsaPrivateKey(mode=EcdsaModes.SECP256K1_KECCAK_256_ETHEREUM)
    signature = key.sign(MSG)
    public = EcdsaPublicKey(
        mode=EcdsaModes.SECP256K1_KECCAK_256_ETHEREUM,
        key=key.public_key.public_bytes,
        key_format=EcdsaFormats.RAW_VALUE,
    )
    assert public.ethereum_address == key.public_key.ethereum_address
    public.verify(MSG, signature)
    with pytest.raises(InvalidSignatureError):
        public.verify(TAMPERED, signature)


# ------------------------------------------------------------------ RSA
def _make_p12(
    password: bytes,
    include_cert: bool = True,
    encryption=None,
) -> bytes:
    private_key = rsa_module.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    cert = None
    if include_cert:
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "digsig-tests")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1))
            .sign(private_key, hashes.SHA256())
        )
    if encryption is None:
        encryption = serialization.BestAvailableEncryption(password)
    return serialization.pkcs12.serialize_key_and_certificates(
        b"digsig-tests",
        private_key,
        cert,
        None,
        encryption,
    )


@pytest.mark.parametrize("mode", sorted(RsaModes.options()))
def test_rsa_sign_verify_tamper(mode):
    key = RsaPrivateKey(mode=mode)
    signature = key.sign(MSG)
    key.public_key.verify(MSG, signature)
    with pytest.raises(InvalidSignatureError):
        key.public_key.verify(TAMPERED, signature)


@pytest.mark.parametrize("mode", sorted(RsaModes.options()))
def test_rsa_pem_roundtrip(mode):
    key = RsaPrivateKey(mode=mode)
    signature = key.sign(MSG)

    private_reloaded = RsaPrivateKey(
        mode=mode, key=key.private_pem, key_format=RsaFormats.PEM
    )
    private_reloaded.public_key.verify(MSG, signature)

    public_reloaded = RsaPublicKey(
        mode=mode, key=key.public_key.public_pem, key_format=RsaFormats.PEM
    )
    public_reloaded.verify(MSG, signature)
    with pytest.raises(InvalidSignatureError):
        public_reloaded.verify(TAMPERED, signature)


@pytest.mark.parametrize("mode", sorted(RsaModes.options()))
def test_rsa_load_p12_with_password(mode):
    p12 = _make_p12(b"digsig-p12-password")
    key = RsaPrivateKey(
        mode=mode,
        key=p12,
        password="digsig-p12-password",
        key_format=RsaFormats.P12,
    )
    signature = key.sign(MSG)
    key.public_key.verify(MSG, signature)


def test_rsa_p12_wrong_password():
    p12 = _make_p12(b"digsig-p12-password")
    with pytest.raises(Exception):
        RsaPrivateKey(
            mode=RsaModes.PSS_MGF1_SHA256,
            key=p12,
            password="wrong-password",
            key_format=RsaFormats.P12,
        )


def test_ecdsa_keystore_wrong_password():
    account = Account.create()
    keystore = Account.encrypt(account.key, "digsig-test-password")
    with pytest.raises(Exception):
        EcdsaPrivateKey(
            mode=EcdsaModes.SECP256K1_KECCAK_256_ETHEREUM,
            key=keystore,
            password="wrong-password",
            key_format=EcdsaFormats.ETHEREUM_JSON,
        )


# ------------------------------------------- hex-string signatures
@pytest.mark.parametrize("mode", sorted(EcdsaModes.options()))
def test_ecdsa_verify_accepts_hex_string_signature(mode):
    key = EcdsaPrivateKey(mode=mode)
    signature_hex = key.sign(MSG).hex()
    key.public_key.verify(MSG, signature_hex)
    with pytest.raises(InvalidSignatureError):
        key.public_key.verify(TAMPERED, signature_hex)


@pytest.mark.parametrize("mode", sorted(RsaModes.options()))
def test_rsa_verify_accepts_hex_string_signature(mode):
    key = RsaPrivateKey(mode=mode)
    signature_hex = key.sign(MSG)
    if isinstance(signature_hex, bytes):
        signature_hex = signature_hex.hex()
    key.public_key.verify(MSG, signature_hex)
    with pytest.raises(InvalidSignatureError):
        key.public_key.verify(TAMPERED, signature_hex)


# ------------------------------------------------- key properties
@pytest.mark.parametrize("mode", sorted(EcdsaModes.options()))
def test_ecdsa_public_base64_matches_public_bytes(mode):
    import base64 as b64
    key = EcdsaPrivateKey(mode=mode)
    assert key.public_key.public_base64 == b64.b64encode(
        key.public_key.public_bytes
    ).decode("ascii")


def test_ethereum_address_format():
    import re
    key = EcdsaPrivateKey(mode=EcdsaModes.SECP256K1_KECCAK_256_ETHEREUM)
    address = key.public_key.ethereum_address
    assert re.fullmatch(r"0x[0-9a-f]{40}", address)


# ------------------------------------------------- public API surface
def test_top_level_exports():
    # The public surface must stay importable from the package top level.
    import digsig

    for name in (
        "EcdsaPrivateKey",
        "EcdsaPublicKey",
        "EcdsaModes",
        "EcdsaFormats",
        "RsaPrivateKey",
        "RsaPublicKey",
        "RsaModes",
        "RsaFormats",
        "PublicKey",
        "PrivateKey",
    ):
        assert hasattr(digsig, name), name


def test_invalid_mode_raises_value_error():
    with pytest.raises(ValueError):
        EcdsaPrivateKey(mode="NO_SUCH_MODE")
    with pytest.raises(ValueError):
        RsaPrivateKey(mode="NO_SUCH_MODE")


def test_ecdsa_raw_value_small_int_is_padded():
    # Integer values are normalized to 32 bytes internally, so values
    # < 2**248 (leading zero bytes) are loadable and equivalent to their
    # padded byte form.
    key = EcdsaPrivateKey(
        mode=EcdsaModes.SECP256K1_KECCAK_256_ETHEREUM,
        key=1,
        key_format=EcdsaFormats.RAW_VALUE,
    )
    reloaded = EcdsaPrivateKey(
        mode=EcdsaModes.SECP256K1_KECCAK_256_ETHEREUM,
        key=b"\x00" * 31 + b"\x01",
        key_format=EcdsaFormats.RAW_VALUE,
    )
    assert (
        key.public_key.ethereum_address
        == reloaded.public_key.ethereum_address
    )
    signature = key.sign(MSG)
    reloaded.public_key.verify(MSG, signature)


# ---------------------------------------- additional key loading paths
@pytest.mark.parametrize("mode", sorted(EcdsaModes.options()))
@pytest.mark.parametrize("value", [
    -1, 0, b"", b"\x00" * 32, SECPK1_N, SECPK1_N + 1,
    2 ** 256, SECPK1_N.to_bytes(32, "big"), b"\xff" * 33,
])
def test_ecdsa_rejects_private_scalars_outside_curve_order(mode, value):
    with pytest.raises(ValueError, match="Private scalar"):
        EcdsaPrivateKey(mode=mode, key=value)


@pytest.mark.parametrize("mode", sorted(EcdsaModes.options()))
@pytest.mark.parametrize("value", [1, 122, SECPK1_N - 1])
def test_ecdsa_private_scalar_boundaries_roundtrip(mode, value):
    key = EcdsaPrivateKey(mode=mode, key=value)
    reloaded = EcdsaPrivateKey(mode=mode, key=value.to_bytes(32, "big"))
    reloaded.public_key.verify(MSG, key.sign(MSG))


def test_ecdsa_public_key_from_hex_string():
    # RAW_VALUE public keys may be provided as hex strings.
    key = EcdsaPrivateKey(mode=EcdsaModes.SECP256K1_KECCAK_256_ETHEREUM)
    public = EcdsaPublicKey(
        mode=EcdsaModes.SECP256K1_KECCAK_256_ETHEREUM,
        key=key.public_key.public_bytes.hex(),
        key_format=EcdsaFormats.RAW_VALUE,
    )
    assert public.ethereum_address == key.public_key.ethereum_address
    signature = key.sign(MSG)
    public.verify(MSG, signature)
    with pytest.raises(InvalidSignatureError):
        public.verify(TAMPERED, signature)


def test_ecdsa_load_raw_bytes_without_key_format():
    # 32-byte raw values load with the default key_format (RAW_VALUE).
    original = EcdsaPrivateKey(mode=EcdsaModes.SECP256K1_KECCAK_256_ETHEREUM)
    raw32 = original.private_value.to_bytes(32, "big")
    reloaded = EcdsaPrivateKey(
        mode=EcdsaModes.SECP256K1_KECCAK_256_ETHEREUM,
        key=raw32,
    )
    assert (
        reloaded.public_key.ethereum_address
        == original.public_key.ethereum_address
    )
    signature = reloaded.sign(MSG)
    original.public_key.verify(MSG, signature)


def test_get_ethereum_account_roundtrip():
    # get_ethereum_account() exports an ETHEREUM_JSON keystore that must
    # reload to the same key. Supported on both eth-account lines (0.5.x
    # and >= 0.6): the key is exported as canonical 32-byte bytes.
    key = EcdsaPrivateKey(mode=EcdsaModes.SECP256K1_KECCAK_256_ETHEREUM)
    keystore = key.get_ethereum_account("digsig-test-password")
    reloaded = EcdsaPrivateKey(
        mode=EcdsaModes.SECP256K1_KECCAK_256_ETHEREUM,
        key=keystore,
        password="digsig-test-password",
        key_format=EcdsaFormats.ETHEREUM_JSON,
    )
    assert (
        reloaded.public_key.ethereum_address
        == key.public_key.ethereum_address
    )
    # The default password ('') is valid too; when reloading, '' must be
    # passed explicitly (None reaches Account.decrypt and raises TypeError).
    keystore_nopw = key.get_ethereum_account()
    reloaded_nopw = EcdsaPrivateKey(
        mode=EcdsaModes.SECP256K1_KECCAK_256_ETHEREUM,
        key=keystore_nopw,
        password="",
        key_format=EcdsaFormats.ETHEREUM_JSON,
    )
    assert (
        reloaded_nopw.public_key.ethereum_address
        == key.public_key.ethereum_address
    )


def test_rsa_load_unencrypted_p12_default_format():
    # An unencrypted P12 loads with no password and the default key_format
    # (P12).
    p12 = _make_p12(b"", include_cert=True, encryption=serialization.NoEncryption())
    key = RsaPrivateKey(mode=RsaModes.PSS_MGF1_SHA256, key=p12)
    signature = key.sign(MSG)
    key.public_key.verify(MSG, signature)


def test_rsa_public_pem_from_str_default_format():
    # A PEM public key provided as str (e.g. base64-decoded) loads with the
    # default key_format (PEM).
    key = RsaPrivateKey(mode=RsaModes.PSS_MGF1_SHA256)
    pem_str = key.public_key.public_pem
    encoded = base64.b64encode(pem_str.encode("ascii")).decode("ascii")
    public = RsaPublicKey(
        mode=RsaModes.PSS_MGF1_SHA256,
        key=base64.b64decode(encoded).decode("ascii"),
    )
    signature = key.sign(MSG)
    public.verify(MSG, signature)
    with pytest.raises(InvalidSignatureError):
        public.verify(TAMPERED, signature)


def test_sign_and_verify_accept_str_message():
    # sign() and verify() accept str messages (encoded as utf-8).
    ecdsa_key = EcdsaPrivateKey(mode=EcdsaModes.SECP256K1_KECCAK_256_ETHEREUM)
    signature = ecdsa_key.sign("message as str")
    ecdsa_key.public_key.verify("message as str", signature)
    with pytest.raises(InvalidSignatureError):
        ecdsa_key.public_key.verify("tampered message", signature)

    rsa_key = RsaPrivateKey(mode=RsaModes.PSS_MGF1_SHA256)
    rsa_signature = rsa_key.sign("message as str")
    rsa_key.public_key.verify("message as str", rsa_signature)
    with pytest.raises(InvalidSignatureError):
        rsa_key.public_key.verify("tampered message", rsa_signature)


def test_ecdsa_load_ethereum_json_keystore_as_json_string():
    # ETHEREUM_JSON keystores may be provided serialized as a JSON string.
    account = Account.create()
    keystore = Account.encrypt(account.key, "digsig-keystore-password")
    key = EcdsaPrivateKey(
        mode=EcdsaModes.SECP256K1_KECCAK_256_ETHEREUM,
        key=json.dumps(keystore),
        password="digsig-keystore-password",
        key_format=EcdsaFormats.ETHEREUM_JSON,
    )
    assert key.public_key.ethereum_address.lower() == account.address.lower()


@pytest.mark.parametrize("invalid_v", range(29, 35))
def test_ecdsa_ethereum_rejects_invalid_recovery_id(invalid_v):
    key = EcdsaPrivateKey(mode=EcdsaModes.SECP256K1_KECCAK_256_ETHEREUM)
    signature = bytearray(key.sign(MSG))
    signature[-1] = invalid_v
    with pytest.raises(InvalidSignatureError):
        key.public_key.verify(MSG, bytes(signature))


def test_ecdsa_str_message_65_byte_signature():
    # Ethereum-mode signatures of str messages are 65 bytes (r || s || v).
    key = EcdsaPrivateKey(mode=EcdsaModes.SECP256K1_KECCAK_256_ETHEREUM)
    signature = key.sign('{"a":1,"b":"c"}')
    assert len(signature) == 65
    assert len(signature.hex()) == 130
    key.public_key.verify('{"a":1,"b":"c"}', signature)


def test_ecdsa_ethereum_known_wire_vector():
    # Deterministic contract vector: ECDSA-keccak signing is deterministic
    # (RFC 6979), so this signature must stay stable across digsig,
    # cryptography and eth-account versions. This full-length test key also
    # works with the historical implementation that did not pad integers.
    key = EcdsaPrivateKey(
        mode=EcdsaModes.SECP256K1_KECCAK_256_ETHEREUM,
        key=b"\x01" * 32,
        key_format=EcdsaFormats.RAW_VALUE,
    )
    assert key.public_key.ethereum_address == (
        "0x1a642f0e3c3af545e7acbd38b07251b3990914f1"
    )
    assert key.sign("hello").hex() == (
        "f186a035b50de31ac4d913b550ae6fe2fe9e7225c635f108c71e9135de228a2a"
        "567dd55d0a4d2115d30c9226903b0feef967ae4d2daf2c07c7fb70676600c15d1b"
    )


def test_rsa_load_p12_without_certificate():
    # P12 archives containing only the private key (no certificate).
    p12 = _make_p12(b"digsig-p12-no-cert", include_cert=False)
    key = RsaPrivateKey(
        mode=RsaModes.PSS_MGF1_SHA256,
        key=p12,
        password="digsig-p12-no-cert",
        key_format=RsaFormats.P12,
    )
    signature = key.sign(MSG)
    key.public_key.verify(MSG, signature)


# ------------------------------ filepath loading (PublicKey/PrivateKey)
def test_private_key_get_instance_json_and_p12(tmp_path):
    from digsig import PrivateKey

    account = Account.create()
    keystore = Account.encrypt(account.key, "digsig-auto-password")
    json_path = tmp_path / "keystore.json"
    json_path.write_text(json.dumps(keystore), encoding="utf-8")
    ecdsa_key = PrivateKey.get_instance(
        filepath=str(json_path), password="digsig-auto-password"
    )
    assert (
        ecdsa_key.public_key.ethereum_address.lower()
        == account.address.lower()
    )

    p12_path = tmp_path / "signer.p12"
    p12_path.write_bytes(_make_p12(b"digsig-auto-password"))
    rsa_key = PrivateKey.get_instance(
        filepath=str(p12_path), password="digsig-auto-password"
    )
    signature = rsa_key.sign(MSG)
    rsa_key.public_key.verify(MSG, signature)


def test_public_key_get_instance_pem(tmp_path):
    from digsig import PublicKey

    key = RsaPrivateKey(mode=RsaModes.PSS_MGF1_SHA256)
    pem_path = tmp_path / "signer.pem"
    pem_path.write_text(key.public_key.public_pem, encoding="ascii")
    public = PublicKey.get_instance(filepath=str(pem_path))
    signature = key.sign(MSG)
    public.verify(MSG, signature)
    with pytest.raises(InvalidSignatureError):
        public.verify(TAMPERED, signature)
