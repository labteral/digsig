#!/usr/bin/env python
# -*- coding: utf-8 -*-


class PublicKeyInterface:
    def __init__(
        self,
        filepath: str = None,
        mode: str = None,
        key_format: str = None,
        key=None,
    ):
        raise NotImplementedError

    def verify(self, message, signature) -> bool:
        raise NotImplementedError


class PrivateKeyInterface:
    def __init__(
        self,
        filepath: str = None,
        password: str = None,
        mode: str = None,
        key_format: str = None,
        key=None,
    ):
        raise NotImplementedError

    @property
    def public_key(self):
        raise NotImplementedError

    def sign(self, message) -> bytes:
        raise NotImplementedError