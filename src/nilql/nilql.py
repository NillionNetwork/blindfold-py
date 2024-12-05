"""
Python library for working with encrypted data within nilDB queries and
replies.
"""
from __future__ import annotations
from typing import Union
import doctest
import secrets
import hashlib

# Maximum sizes of plaintext values that can be encrypted.
_PLAINTEXT_UNSIGNED_INTEGER_MAX = 4294967296
_PLAINTEXT_STRING_BUFFER_LEN_MAX = 4096

def secret_key(cluster: dict = None, operations: dict = None) -> dict:
    """
    Return a secret key built according to what is specified in the supplied
    cluster configuration and operation list.
    """
    # Create instance with default cluster configuration and operations
    # specification, updating the configuration and specification with the
    # supplied arguments.
    operations = {} or operations
    instance = {
        'value': None,
        'cluster': cluster,
        'operations': operations
    }

    if len([op for (op, status) in instance['operations'].items() if status]) > 1:
        raise ValueError(
            'cannot create secret key that supports multiple operations'
        )

    if len([op for (op, status) in instance['operations'].items() if status]) < 1:
        raise ValueError(
            'cannot create secret key that supports no operations'
        )

    if instance['operations']['match']:
        salt = secrets.token_bytes(64)
        instance['value'] = {'salt': salt}

    return instance

def encrypt(key: dict, plaintext: Union[int, str]) -> bytes:
    """
    Return the ciphertext obtained by using the supplied key to encrypt the
    supplied plaintext.
    """
    instance = None

    # Encrypting (i.e., hashing) a value for matching.
    if 'salt' in key['value'] and key['operations']['match']:
        buffer = None

        # Encrypting (i.e., hashing) an integer for matching.
        if isinstance(plaintext, int):
            if plaintext < 0 or plaintext >= _PLAINTEXT_UNSIGNED_INTEGER_MAX:
                raise ValueError('plaintext must be 32-bit nonnegative integer value')
            buffer = plaintext.to_bytes(8, 'little')

        # Encrypting (i.e., hashing) a string for matching.
        if isinstance(plaintext, str):
            buffer = plaintext.encode()
            if len(buffer) > _PLAINTEXT_STRING_BUFFER_LEN_MAX:
                raise ValueError(
                    'plaintext string must be possible to encode in 4096 bytes or fewer'
                )

        instance = hashlib.sha512(key['value']['salt'] + buffer).digest()

        if len(key['cluster']['nodes']) > 1:
            instance = [instance for _ in key['cluster']['nodes']]

    return instance

if __name__ == '__main__':
    doctest.testmod() # pragma: no cover
