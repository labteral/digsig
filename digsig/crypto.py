import hashlib
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

from web3 import Web3
from eth_account.messages import defunct_hash_message


def sha256_str_to_bin(text: str) -> str:
    return sha256_bin_to_bin(bytes(text, 'utf-8'))


def sha256_bin_to_bin(bin: bytes) -> str:
    return hashlib.sha256(bin).digest()


class PrivateKey:
    def __init__(self, filepath: str, password: str = None):
        if password is None:
            password = ''
        extension = filepath.split('.')[-1].lower()
        load_method = f'_load_{extension}'

        if not load_method in dir(self):
            raise ValueError(f'{extension} extension not supported')

        getattr(self, load_method)(filepath, password)

    def _load_p12(self, filepath: str, password: str):
        self.family = 'rsa'
        with open(filepath, 'rb') as input_file:
            self.private_key, _, _ = pkcs12.load_key_and_certificates(input_file.read(),
                                                                      bytes(password, 'utf-8'))

    def _load_pfx(self, filepath: str, password: str):
        self._load_p12(filepath, password)

    def _load_json(self, filepath: str, password: str):
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
        self.private_key = web3.eth.account.privateKeyToAccount(private_key)

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

        signature = self.private_key.sign(
            text_hash,
            padding_object,
            hashes.SHA256(),
        ).hex()

        self.private_key.public_key().verify(
            bytes.fromhex(signature),
            text_hash,
            padding_object,
            hashes.SHA256(),
        )

        return signature

    def _sign_ethereum(self, text: str):
        text_hash = defunct_hash_message(text=text)
        signature = self.private_key.signHash(text_hash)['signature'].hex()[2:]
        return signature