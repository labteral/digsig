#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from web3 import Web3
from eth_account.messages import defunct_hash_message
from .crypto import sha256_str_to_bin


class PrivateKeyExtensions:
    P12 = 'p12'
    PFX = 'pfx'
    JSON = 'json'


class PrivateKey:
    def __init__(self,
                 filepath: str = None,
                 password: str = None,
                 content: str = None,
                 extension: str = None):
        if password is None:
            password = ''
        if extension is None:
            extension = filepath.split('.')[-1].lower()
        load_method = f'_load_{extension}'
        if not load_method in dir(self):
            raise ValueError(f'{extension} extension not supported')
        getattr(self, load_method)(filepath, password, content)

    def _load_p12(self, filepath: str, password: str, content: str):
        self.family = 'rsa'
        if content is not None:
            raise NotImplementedError
        else:
            with open(filepath, 'rb') as input_file:
                self._private_key, _, _ = pkcs12.load_key_and_certificates(
                    input_file.read(), bytes(password, 'utf-8'))

    def _load_pfx(self, filepath: str, password: str, content: str):
        self._load_p12(filepath, password, content)

    def _load_json(self, filepath: str, password: str, content: str):
        if content is not None:
            private_key_dict = json.loads(content)
        else:
            private_key_dict = json.load(open(filepath, 'r'))

        # Ethereum
        if 'address' in private_key_dict:
            self._load_json_ethereum(private_key_dict, password)
            return

        raise ValueError(f'JSON format not supported')

    def _load_json_ethereum(self, private_key_dict: dict, password: str):
        self.family = 'ethereum'
        web3 = Web3()
        private_key = web3.eth.account.decrypt(private_key_dict, password)
        self._private_key = web3.eth.account.privateKeyToAccount(private_key)

    def sign(self, text: str) -> str:
        sign_method = f'_sign_{self.family}'
        return getattr(self, sign_method)(text)

    def sign_file(self, filepath: str) -> str:
        raise NotImplementedError

    def _sign_rsa(self, text: str):
        text_hash = sha256_str_to_bin(text)

        padding_object = padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        )

        signature = self._private_key.sign(
            text_hash,
            padding_object,
            hashes.SHA256(),
        ).hex()

        self._private_key.public_key().verify(
            bytes.fromhex(signature),
            text_hash,
            padding_object,
            hashes.SHA256(),
        )

        return signature

    def _sign_ethereum(self, text: str):
        text_hash = defunct_hash_message(text=text)
        signature = self._private_key.signHash(text_hash)['signature'].hex()[2:]
        return signature