#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .hashing import hash_message, HashFunctions
from .digsig import PublicKeyInterface, PrivateKeyInterface
from .errors import InvalidSignatureError
from .utils import (
    Options,
    big_endian_to_int,
)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import exceptions as cryptography_exceptions
from eth_account import Account as EthereumAccount
from eth_account.messages import defunct_hash_message, encode_defunct
from eth_keys import keys as EthereumKeys, exceptions as eth_keys_exceptions
from eth_keys.constants import SECPK1_N
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography import x509
import base64


def _to_standard_signature_bytes(signature_bytes):
    if len(signature_bytes) != 65:
        return signature_bytes
    v = signature_bytes[-1]
    if v in (27, 28):
        return signature_bytes[:64] + bytes([v - 27])
    if v >= 35:
        return signature_bytes[:64] + bytes([(v - 35) % 2])
    return signature_bytes


class EcdsaFormats(Options):
    RAW_VALUE = 'RAW_VALUE'
    ETHEREUM_JSON = 'ETHEREUM_JSON'
    PEM = 'PEM'
    DER = 'DER'
    CER = 'CER'


class EcdsaModes(Options):
    SECP256K1_SHA3_256 = 'SECP256K1_SHA3_256'
    SECP256K1_KECCAK_256_ETHEREUM = 'SECP256K1_KECCAK_256_ETHEREUM'


class EcdsaPublicKey(PublicKeyInterface):
    def __init__(
        self,
        filepath: str = None,
        mode: str = None,
        key_format: str = None,
        key=None,
    ):
        self._public_bytes = None
        self._public_key_object = None

        if mode not in EcdsaModes.options():
            raise ValueError

        if key_format is None:
            key_format = EcdsaFormats.RAW_VALUE
        if key_format not in EcdsaFormats.options():
            raise ValueError

        self._mode = mode
        self._key_format = key_format
        self._eliptic_curve = getattr(ec, self._mode.split('_')[0])()

        if key is not None:
            self._load_public_value(key)
        elif filepath is not None:
            with open(filepath, 'rb') as input_file:
                self._load_public_value(input_file.read())
        else:
            raise ValueError

    @property
    def public_bytes(self):
        return self._public_bytes

    @property
    def public_base64(self):
        return base64.b64encode(self.public_bytes).decode('ascii')

    @property
    def public_value(self):
        return self._public_value

    @property
    def public_pem(self):
        return self._public_key_object.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode('ascii')

    @property
    def ethereum_address(self):
        return f'0x{hash_message(self.public_bytes, HashFunctions.KECCAK_256)[-20:].hex()}'

    def verify(self, message, signature) -> bool:
        if isinstance(message, str):
            message = bytes(message, 'utf-8')

        if isinstance(signature, str):
            signature = bytes.fromhex(signature)

        if self._mode == EcdsaModes.SECP256K1_KECCAK_256_ETHEREUM:
            message_hash = defunct_hash_message(message)
            try:
                signature_bytes_standard = _to_standard_signature_bytes(
                    signature)
                signature_obj = EthereumKeys.Signature(
                    signature_bytes=signature_bytes_standard)
                obtained_public_value = signature_obj.recover_public_key_from_msg_hash(
                    message_hash).to_bytes()
                if obtained_public_value != self._public_bytes:
                    raise eth_keys_exceptions.BadSignature
            except (ValueError, eth_keys_exceptions.BadSignature):
                raise InvalidSignatureError

        else:
            hash_function = '_'.join(self._mode.split('_')[1:]).lower()
            message_hash = hash_message(message, hash_function)
            try:
                self._public_key_object.verify(
                    signature, message_hash,
                    ec.ECDSA(getattr(hashes, hash_function.upper())()))
            except cryptography_exceptions.InvalidSignature:
                raise InvalidSignatureError

    def _load_public_value(self, key):
        if self._key_format == EcdsaFormats.RAW_VALUE:
            if isinstance(key, dict):
                if set(key) != {'x', 'y'} or any(type(key[k]) is not int or not 0 <= key[k] < 2**256 for k in key):
                    raise ValueError('Expected public x/y coordinates')
                key = key['x'].to_bytes(32, 'big') + key['y'].to_bytes(32, 'big')
            if isinstance(key, str):
                key = bytes.fromhex(key.strip().removeprefix('0x'))
            elif isinstance(key, bytes) and len(key) not in (33, 64, 65):
                try:
                    key = bytes.fromhex(key.decode('ascii').strip().removeprefix('0x'))
                except (ValueError, UnicodeError):
                    raise ValueError('Expected a raw or hexadecimal secp256k1 public key') from None
            self._public_bytes = key
        elif self._key_format in (EcdsaFormats.PEM, EcdsaFormats.DER, EcdsaFormats.CER):
            if isinstance(key, str):
                key = key.encode('ascii')
            if self._key_format == EcdsaFormats.CER:
                loader = x509.load_pem_x509_certificate if key.lstrip().startswith(b'-----BEGIN') else x509.load_der_x509_certificate
                public = loader(key).public_key()
            else:
                loader = serialization.load_pem_public_key if self._key_format == EcdsaFormats.PEM else serialization.load_der_public_key
                public = loader(key)
            if not isinstance(public, ec.EllipticCurvePublicKey) or not isinstance(public.curve, ec.SECP256K1):
                raise ValueError('Expected a secp256k1 public key')
            self._public_bytes = public.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)[1:]
        else:
            raise ValueError
        self._load_public_key()

    def _load_public_key(self):
        if not isinstance(self._public_bytes, bytes) or len(self._public_bytes) not in (33, 64, 65):
            raise ValueError('Expected a 64-byte public key or SEC1 point')
        encoded = b'\x04' + self._public_bytes if len(self._public_bytes) == 64 else self._public_bytes
        self._public_key_object = ec.EllipticCurvePublicKey.from_encoded_point(self._eliptic_curve, encoded)
        self._public_bytes = self._public_key_object.public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)[1:]

        self._public_value = {
            'x': big_endian_to_int(self._public_bytes[:32]),
            'y': big_endian_to_int(self._public_bytes[32:]),
        }


class EcdsaPrivateKey(PrivateKeyInterface):
    def __init__(
        self,
        filepath: str = None,
        password: str = None,
        mode: str = None,
        key_format: str = None,
        key=None,
    ):
        self._private_value = None
        self._private_key_object = None
        self._public_key_object = None

        if mode not in EcdsaModes.options():
            raise ValueError
        self._mode = mode
        self._eliptic_curve = getattr(ec, self._mode.split('_')[0])()

        if key is None and filepath is None:
            self._generate_private_value()
            return

        if key_format is None:
            key_format = EcdsaFormats.RAW_VALUE
        if key_format not in EcdsaFormats.options():
            raise ValueError
        self._key_format = key_format

        if key is not None:
            self._load_private_value(key, password)

        elif filepath is not None:
            self._load_private_key_from_file(filepath, password)

    @property
    def public_key(self):
        return self._public_key_object

    @property
    def private_value(self):
        return self._private_value

    @property
    def private_bytes(self):
        return self.private_value.to_bytes(32, 'big')

    @property
    def private_value_base64(self):
        return base64.b64encode(self.private_bytes).decode('ascii')

    @property
    def private_value_hex(self):
        return self.private_bytes.hex()

    def get_ethereum_account(self, password: str = None):
        password = password if password is not None else ''
        # eth-account >= 0.6 no longer accepts int keys; the canonical
        # 32-byte form is accepted by both supported lines.
        return EthereumAccount.encrypt(
            self._private_value.to_bytes(32, 'big'), password)

    def sign(self, message) -> bytes:
        if isinstance(message, str):
            message = bytes(message, 'utf-8')

        if not isinstance(message, bytes):
            raise ValueError

        if self._mode == EcdsaModes.SECP256K1_KECCAK_256_ETHEREUM:
            # Public-API signing path, identical output on eth-account
            # 0.5.x and >= 0.6 (deterministic RFC 6979 signatures).
            signed = EthereumAccount.sign_message(
                encode_defunct(primitive=message),
                private_key=self._private_key_object.to_bytes(),
            )
            signature = bytes(signed.signature)

        else:
            hash_function = '_'.join(self._mode.split('_')[1:]).lower()
            message_hash = hash_message(message, hash_function)
            signature = self._private_key_object.sign(
                message_hash,
                ec.ECDSA(getattr(hashes, hash_function.upper())()),
            )
        return signature

    def _generate_private_value(self):
        self._private_value = ec.generate_private_key(
            self._eliptic_curve).private_numbers().private_value
        self._load_private_key()

    def _load_private_value(self, key, password: str = None):
        if self._key_format == EcdsaFormats.ETHEREUM_JSON:
            if not isinstance(key, dict):
                key = json.loads(key)
            private_value = bytes(EthereumAccount.decrypt(key, password))
            self._private_value = big_endian_to_int(private_value)
        elif self._key_format == EcdsaFormats.RAW_VALUE:
            if isinstance(key, bytes):
                key = big_endian_to_int(key)
            if not isinstance(key, int):
                raise ValueError(f'{type(key)} is not int')
            self._private_value = key
        elif self._key_format in (EcdsaFormats.PEM, EcdsaFormats.DER):
            if isinstance(key, str):
                key = key.encode('ascii')
            if isinstance(password, str):
                password = password.encode('utf-8')
            loader = serialization.load_pem_private_key if self._key_format == EcdsaFormats.PEM else serialization.load_der_private_key
            private = loader(key, password=password)
            if not isinstance(private, ec.EllipticCurvePrivateKey) or not isinstance(private.curve, ec.SECP256K1):
                raise ValueError('Expected a secp256k1 private key')
            self._private_value = private.private_numbers().private_value
        else:
            raise ValueError
        self._load_private_key()

    def _load_private_key(self):
        if type(self._private_value) is not int or not 1 <= self._private_value < SECPK1_N:
            raise ValueError('Private scalar must be in the secp256k1 range [1, n).')
        if self._mode == EcdsaModes.SECP256K1_KECCAK_256_ETHEREUM:
            # Canonical 32-byte form: eth_keys rejects shorter values, and
            # generated/loaded values may legitimately have leading zeros.
            self._private_key_object = EthereumKeys.PrivateKey(
                self._private_value.to_bytes(32, 'big'))
            public_bytes = self._private_key_object.public_key.to_bytes()
            self._public_key_object = EcdsaPublicKey(
                key=public_bytes,
                mode=self._mode,
                key_format=EcdsaFormats.RAW_VALUE,
            )
        else:
            self._private_key_object = ec.derive_private_key(
                self._private_value, self._eliptic_curve)
            public_numbers = self._private_key_object.public_key(
            ).public_numbers()
            # Pad coordinates to 32 bytes: a leading zero byte is a valid
            # coordinate and from_encoded_point requires exactly 65 bytes.
            public_bytes = public_numbers.x.to_bytes(32, 'big') \
                + public_numbers.y.to_bytes(32, 'big')
            self._public_key_object = EcdsaPublicKey(
                key=public_bytes,
                mode=self._mode,
                key_format=EcdsaFormats.RAW_VALUE,
            )

    def _load_private_key_from_file(self, filepath: str, password: str):
        with open(filepath, 'rb') as input_file:
            data = input_file.read()
        self._load_private_value(data, password)
