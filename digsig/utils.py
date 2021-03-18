#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .hashing import hash_message, HashFunctions


class Options:
    @classmethod
    def options(cls):
        return set([
            getattr(cls, model_type)
            for model_type in filter(lambda x: x[:2] != '__', cls.__dict__.keys())
        ])


def get_extension(filepath: str) -> str:
    return filepath.split('.')[-1]


def big_endian_to_int(value: bytes) -> int:
    return int.from_bytes(value, "big")


def int_to_big_endian(value: int) -> bytes:
    return value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
