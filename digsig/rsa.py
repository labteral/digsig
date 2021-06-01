#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .hashing import hash_message
from .digsig import PublicKeyInterface, PrivateKeyInterface
from .errors import InvalidSignatureError
from .utils import Options
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    pkcs12,
    load_pem_private_key,
    load_der_private_key,
    load_pem_public_key,
    load_der_public_key,
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography import exceptions as cryptography_exceptions


class RsaFormats(Options):
    P12 = 'P12'
    PFX = 'PFX'
    PEM = 'PEM'
    DER = 'DER'


class RsaModes(Options):
    PSS_MGF1_SHA3_256 = 'PSS_MGF1_SHA3_256'
    PSS_MGF1_SHA256 = 'PSS_MGF1_SHA256'


class RsaPublicKey(PublicKeyInterface):
    def __init__(
        self,
        filepath: str = None,
        mode: str = None,
        key_format: str = None,
        key=None,
    ):
        self._public_key_object = None

        if mode not in RsaModes.options():
            raise ValueError
        self._mode = mode

        if key_format is None:
            key_format = RsaFormats.PEM
        if key_format not in RsaFormats.options():
            raise ValueError
        self._key_format = key_format

        if key is not None:
            if isinstance(key, str):
                key = bytes(key, 'ascii')
            self._load_public_key(key)
        elif filepath is not None:
            self._load_public_key_from_file(filepath)
        else:
            raise ValueError

    @property
    def public_pem(self):
        return self._public_key_object.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo,
        ).decode('ascii')

    def verify(self, message, signature):
        if isinstance(message, str):
            message = bytes(message, 'utf-8')

        if isinstance(signature, str):
            signature = bytes.fromhex(signature)

        hash_function = '_'.join(self._mode.split('_')[2:]).lower()
        message_hash = hash_message(message, hash_function)

        cryptography_hash_algorithm = getattr(hashes, hash_function.upper())()
        padding_object = padding.PSS(
            mgf=padding.MGF1(cryptography_hash_algorithm),
            salt_length=padding.PSS.MAX_LENGTH,
        )
        try:
            self._public_key_object.verify(
                signature,
                message_hash,
                padding_object,
                cryptography_hash_algorithm,
            )
        except cryptography_exceptions.InvalidSignature:
            raise InvalidSignatureError

    def _load_public_key(self, key: bytes):
        if self._key_format == RsaFormats.PEM:
            self._public_key_object = load_pem_public_key(key)

        elif self._key_format == RsaFormats.DER:
            self._public_key_object = load_der_public_key(key)

        else:
            raise ValueError

    def _load_public_key_from_file(self, filepath: str):
        with open(filepath, 'rb') as input_file:
            data = input_file.read()
        self._load_public_key(data)


class RsaPrivateKey(PrivateKeyInterface):
    def __init__(
        self,
        filepath: str = None,
        password: str = None,
        mode: str = None,
        key_format: str = None,
        key: str = None,
        key_size: int = None,
    ):
        self._private_key_object = None
        self._public_key_object = None

        if mode not in RsaModes.options():
            raise ValueError
        self._mode = mode

        if key is None and filepath is None:
            if key_size is None:
                key_size = 4096
            self._generate_private_key(key_size)
            return

        if key_format is None:
            key_format = RsaFormats.P12
        if key_format not in RsaFormats.options():
            raise ValueError
        self._key_format = key_format

        if key is not None:
            if isinstance(key, str):
                key = bytes(key, 'ascii')
            self._load_private_key(key, password)

        if filepath is not None:
            self._load_private_key_from_file(filepath, password)

    @property
    def public_key(self):
        return self._public_key_object

    @property
    def private_pem(self):
        return self._private_key_object.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption(),
        ).decode('ascii')

    def sign(self, message) -> str:
        if isinstance(message, str):
            message = bytes(message, 'utf-8')

        hash_function = '_'.join(self._mode.split('_')[2:]).lower()
        message_hash = hash_message(message, hash_function)

        cryptography_hash_algorithm = getattr(hashes, hash_function.upper())()
        padding_object = padding.PSS(
            mgf=padding.MGF1(cryptography_hash_algorithm),
            salt_length=padding.PSS.MAX_LENGTH,
        )
        signature = self._private_key_object.sign(
            message_hash,
            padding_object,
            cryptography_hash_algorithm,
        )
        return signature

    def _set_public_key_object(self):
        public_key_bytes = self._private_key_object.public_key().public_bytes(
            Encoding.PEM,
            PublicFormat.SubjectPublicKeyInfo,
        )
        self._public_key_object = RsaPublicKey(
            mode=self._mode,
            key_format=RsaFormats.PEM,
            key=public_key_bytes,
        )

    def _generate_private_key(self, key_size: int):
        self._private_key_object = rsa.generate_private_key(
            public_exponent=65537, key_size=key_size)
        self._set_public_key_object()

    def _load_private_key(self, key, password: str = None):
        if isinstance(password, str):
            password = bytes(password, 'utf-8')

        if self._key_format in [RsaFormats.P12, RsaFormats.PFX]:
            # private_key, certificate, additional_certificates
            self._private_key_object, _, _ = pkcs12.load_key_and_certificates(
                key, password)

        elif self._key_format == RsaFormats.PEM:
            self._private_key_object = load_pem_private_key(key, password)

        elif self._key_format == RsaFormats.DER:
            self._private_key_object = load_der_private_key(key, password)

        else:
            raise ValueError

        self._set_public_key_object()

    def _load_private_key_from_file(self, filepath: str, password: str):
        with open(filepath, 'rb') as input_file:
            data = input_file.read()
        self._load_private_key(data, password)
