#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .hashing import hash_message, HashFunctions
from .digsig import PublicKeyInterface, PrivateKeyInterface
from .errors import InvalidSignatureError
from .utils import (
    Options,
    big_endian_to_int,
    int_to_big_endian,
    get_extension,
)
from enum import Enum
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import exceptions as cryptography_exceptions
from eth_account import Account as EthereumAccount
from eth_account.messages import defunct_hash_message
from eth_account._utils.signing import sign_message_hash, to_standard_signature_bytes
from eth_keys import keys as EthereumKeys, exceptions as eth_keys_exceptions
import json
import os
from cryptography.hazmat.primitives import hashes


class EcdsaFormats(Options):
    RAW_VALUE = 'RAW_VALUE'
    ETHEREUM_JSON = 'ETHEREUM_JSON'


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

        if key_format not in EcdsaFormats.options():
            raise ValueError

        self._mode = mode
        self._key_format = key_format
        self._eliptic_curve = getattr(ec, self._mode.split('_')[0])()

        if key is not None:
            self._load_public_value(key)
        elif filepath is not None:
            raise NotImplementedError
        else:
            raise ValueError

    @property
    def public_bytes(self):
        return self._public_bytes

    @property
    def public_value(self):
        return self._public_value

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
                signature_bytes_standard = to_standard_signature_bytes(signature)
                signature_obj = EthereumKeys.Signature(signature_bytes=signature_bytes_standard)
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
                self._public_key_object.verify(signature, message,
                                               ec.ECDSA(getattr(hashes, hash_function.upper())()))
            except cryptography_exceptions.InvalidSignature:
                raise InvalidSignatureError

    def _load_public_value(self, key):
        if self._key_format == EcdsaFormats.RAW_VALUE:
            if isinstance(key, str):
                key = bytes.fromhex(key)
            self._public_bytes = key
        else:
            raise ValueError
        self._load_public_key()

    def _load_public_key(self):
        if self._mode != EcdsaModes.SECP256K1_KECCAK_256_ETHEREUM:
            self._public_key_object = ec.EllipticCurvePublicKey.from_encoded_point(
                self._eliptic_curve, self._public_bytes)

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

    def sign(self, message) -> bytes:
        if isinstance(message, str):
            message = bytes(message, 'utf-8')

        if not isinstance(message, bytes):
            raise ValueError

        if self._mode == EcdsaModes.SECP256K1_KECCAK_256_ETHEREUM:
            message_hash = defunct_hash_message(message)
            (_, _, _, signature) = sign_message_hash(self._private_key_object, message_hash)

        else:
            hash_function = '_'.join(self._mode.split('_')[1:]).lower()
            message_hash = hash_message(message, hash_function)
            signature = self._private_key_object.sign(
                message_hash,
                ec.ECDSA(getattr(hashes, hash_function.upper())()),
            )
        return signature

    def _generate_private_value(self):
        if self._mode == EcdsaModes.SECP256K1_KECCAK_256_ETHEREUM:
            private_value = hash_message(os.urandom(32), HashFunctions.KECCAK_256)
            self._private_value = big_endian_to_int(private_value)
        else:
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
            if isinstance(key, str):
                key = bytes.fromhex(key)
            if isinstance(key, bytes):
                key = big_endian_to_int(key)
            self._private_value = key
        else:
            raise ValueError
        self._load_private_key()

    def _load_private_key(self):
        if self._mode == EcdsaModes.SECP256K1_KECCAK_256_ETHEREUM:
            self._private_key_object = EthereumKeys.PrivateKey(
                int_to_big_endian(self._private_value))
            public_bytes = self._private_key_object.public_key.to_bytes()
            self._public_key_object = EcdsaPublicKey(
                key=public_bytes,
                mode=self._mode,
                key_format=EcdsaFormats.RAW_VALUE,
            )
            return

        self._private_key_object = ec.derive_private_key(self._private_value, self._eliptic_curve)
        public_numbers = self._private_key_object.public_key().public_numbers()
        public_bytes = int_to_big_endian(public_numbers.x) + int_to_big_endian(public_numbers.y)
        self._public_key_object = EcdsaPublicKey(
            key=public_bytes,
            mode=self._mode,
            key_format=EcdsaFormats.RAW_VALUE,
        )

    def _load_private_key_from_file(self, filepath: str, password: str):
        with open(filepath, 'rb') as input_file:
            data = input_file.read()
        self._load_private_value(data, password)
