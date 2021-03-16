import hashlib
from Crypto.Hash import keccak


class HashFunctions:
    BLAKE2b = 'blake2b'
    BLAKE2s = 'blake2s'
    SHA1 = 'sha1'
    SHA224 = 'sha224'
    SHA256 = 'sha256'
    SHA384 = 'sha384'
    SHA512 = 'sha512'
    SHA3_224 = 'sha3_224'
    SHA3_256 = 'sha3_256'
    SHA3_384 = 'sha3_384'
    SHA3_512 = 'sha3_512'
    MD5 = 'md5'
    MD4 = 'md4'
    MDC2 = 'mdc2'
    MD5_SHA1 = 'md5-sha1'
    SM3 = 'sm3'
    SHA512_224 = 'SHA512_224'
    SHA512_256 = 'SHA512_256'
    WHIRLPOOL = 'whirlpool'
    RIPEMD160 = 'ripemd160'
    KECCAK_224 = 'keccak_224'
    KECCAK_256 = 'keccak_256'
    KECCAK_384 = 'keccak_384'
    KECCAK_512 = 'keccak_512'


HASHLIB_HASH_FUNCTIONS = {
    'blake2b',
    'blake2s',
    'sha1',
    'sha224',
    'sha256',
    'sha384',
    'sha512',
    'sha3_224',
    'sha3_256',
    'sha3_384',
    'sha3_512',
    'md5',
}

KECCAK_HASH_FUNCTIONS = {
    'keccak_224',
    'keccak_256',
    'keccak_384',
    'keccak_512',
}

HASHLIB_EXTRA_HASH_FUNCTIONS = hashlib.algorithms_available.difference(HASHLIB_HASH_FUNCTIONS)


def hash_message(message, algorithm: str) -> bytes:
    if isinstance(message, str):
        message = bytes(message, 'utf-8')

    if algorithm in HASHLIB_HASH_FUNCTIONS:
        return getattr(hashlib, algorithm)(message).digest()

    if algorithm in HASHLIB_EXTRA_HASH_FUNCTIONS:
        hasher = hashlib.new(algorithm)
        hasher.update(message)
        return hasher.digest()

    if algorithm in KECCAK_HASH_FUNCTIONS:
        return keccak.new(data=message, digest_bits=int(algorithm[-3:])).digest()

    raise NotImplementedError
