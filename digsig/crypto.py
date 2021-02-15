import hashlib


def sha256_str_to_bin(text: str) -> str:
    return sha256_bin_to_bin(bytes(text, 'utf-8'))


def sha256_bin_to_bin(bin: bytes) -> str:
    return hashlib.sha256(bin).digest()
