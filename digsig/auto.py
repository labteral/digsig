#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .ecdsa import (
    EcdsaPrivateKey,
    EcdsaPublicKey,
    EcdsaModes,
    EcdsaFormats,
)
from .rsa import (
    RsaPrivateKey,
    RsaPublicKey,
    RsaModes,
    RsaFormats,
)
from .utils import get_extension
from .errors import NotSupportedError
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa


class PublicKey:
    @staticmethod
    def get_instance(
        filepath: str = None,
        mode: str = None,
        key_format: str = None,
        key=None,
    ):

        if key is None:
            if filepath is None:
                raise ValueError('A public key or filepath is required')
            with open(filepath, 'rb') as input_file:
                key = input_file.read()
        if key_format is None:
            data = key.encode('ascii') if isinstance(key, str) else key
            if isinstance(data, bytes) and data.lstrip().startswith(b'-----BEGIN CERTIFICATE'):
                key_format = RsaFormats.CER
            elif isinstance(data, bytes) and data.lstrip().startswith(b'-----BEGIN'):
                key_format = RsaFormats.PEM
            elif filepath is not None and get_extension(str(filepath)).lower() in ('cer', 'crt'):
                key_format = RsaFormats.CER
            elif isinstance(key, dict):
                key_format = EcdsaFormats.RAW_VALUE
            elif isinstance(data, bytes) and (len(data) in (33, 64, 65) or all(c in b'0123456789abcdefABCDEFx \r\n\t' for c in data)):
                key_format = EcdsaFormats.RAW_VALUE
            else:
                key_format = RsaFormats.DER
        if mode is None:
            if key_format == EcdsaFormats.RAW_VALUE:
                mode = EcdsaModes.SECP256K1_KECCAK_256_ETHEREUM
            else:
                data = key.encode('ascii') if isinstance(key, str) else key
                if key_format == RsaFormats.CER:
                    loader = x509.load_pem_x509_certificate if data.lstrip().startswith(b'-----BEGIN') else x509.load_der_x509_certificate
                    public = loader(data).public_key()
                else:
                    loader = serialization.load_pem_public_key if key_format == RsaFormats.PEM else serialization.load_der_public_key
                    public = loader(data)
                if isinstance(public, rsa.RSAPublicKey):
                    mode = RsaModes.PSS_MGF1_SHA256
                elif isinstance(public, ec.EllipticCurvePublicKey) and isinstance(public.curve, ec.SECP256K1):
                    mode = EcdsaModes.SECP256K1_KECCAK_256_ETHEREUM
                else:
                    raise ValueError('Unsupported public key algorithm')
        if mode in RsaModes.options():
            public_key_class = RsaPublicKey
        elif mode in EcdsaModes.options():
            public_key_class = EcdsaPublicKey
        else:
            raise ValueError('Unsupported signature mode')
        return public_key_class(key=key, mode=mode, key_format=key_format)

# Backwards compatible
PublicKeyAuto = PublicKey


class PrivateKey:
    @staticmethod
    def get_instance(
        filepath: str = None,
        password: str = None,
        mode: str = None,
        key_format: str = None,
        key=None,
    ):
        if filepath is not None:
            extension = get_extension(filepath).lower()
            if extension == 'json':
                mode = mode if mode else EcdsaModes.SECP256K1_KECCAK_256_ETHEREUM
                key_format = key_format if key_format else EcdsaFormats.ETHEREUM_JSON
                private_key_class = EcdsaPrivateKey

            elif extension == 'p12' or extension == 'pfx':
                mode = mode if mode else RsaModes.PSS_MGF1_SHA256
                key_format = key_format if key_format else RsaFormats.P12
                private_key_class = RsaPrivateKey

            else:
                raise NotSupportedError

            return private_key_class(
                filepath=filepath,
                password=password,
                mode=mode,
                key_format=key_format,
            )

        if key is not None:
            if mode is None or EcdsaModes is None:
                raise ValueError

            if mode in EcdsaModes.options():
                private_key_class = EcdsaPrivateKey
                if key_format not in EcdsaFormats.options():
                    raise ValueError
            elif mode in RsaModes.options():
                private_key_class = RsaPrivateKey
                if key_format not in RsaFormats.options():
                    raise ValueError
            else:
                raise ValueError

            return private_key_class(
                key=key,
                password=password,
                mode=mode,
                key_format=key_format,
            )

        raise ValueError

# Backwards compatible
PrivateKeyAuto = PrivateKey
