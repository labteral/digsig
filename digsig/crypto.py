import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


def sha256_str_to_bin(text: str) -> str:
    return sha256_bin_to_bin(bytes(text, 'utf-8'))


def sha256_bin_to_bin(bin: bytes) -> str:
    return hashlib.sha256(bin).digest()


class PrivateKey:
    def __init__(self, filepath: str, password: str = None):
        if password is None:
            password = ''
        self.extension = filepath.split('.')[-1].lower()
        load_method = f'_load_{self.extension}'

        if not load_method in dir(self):
            raise NotImplementedError(f'extension {self.extension} not supported')

        getattr(self, load_method)(filepath, password)

    def _load_p12(self, filepath: str, password: str):
        with open(filepath, 'rb') as input_file:
            try:
                self.private_key, _, _ = pkcs12.load_key_and_certificates(
                    input_file.read(), bytes(password, 'utf-8'))
            except ValueError:
                self.private_key = None

    def sign(self, text: str) -> str:
        sign_method = f'_sign_{self.extension}'
        return getattr(self, sign_method)(text)

    def sign_file(self, filepath: str) -> str:
        raise NotImplementedError

    def _sign_p12(self, text):
        return self._sign_rsa(text)

    def _sign_rsa(self, text: str):
        padding_object = padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        )

        signature = self.private_key.sign(
            sha256_str_to_bin(text),
            padding_object,
            hashes.SHA256(),
        ).hex()

        self.private_key.public_key().verify(
            bytes.fromhex(signature),
            sha256_str_to_bin(text),
            padding_object,
            hashes.SHA256(),
        )

        return signature
