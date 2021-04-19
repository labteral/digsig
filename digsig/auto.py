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


class PublicKeyAuto:
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
            if extension == 'pem' or extension == 'cer':
                mode = mode if mode else RsaModes.PSS_MGF1_SHA256
                key_format = key_format if key_format else extension.upper()
                public_key_class = RsaPublicKey

            else:
                raise NotSupportedError

            return public_key_class(
                filepath=filepath,
                mode=mode,
                key_format=key_format,
                key=key,
            )

        if key is not None:
            raise NotImplementedError

        raise ValueError


class PrivateKeyAuto:
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
                if key_format not in EcdsaFormats.options():
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