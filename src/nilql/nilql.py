"""
Python library for working with encrypted data within nilDB queries and
replies.
"""
from __future__ import annotations
from typing import Union, Sequence
import doctest
import secrets
import hashlib
import bcl

_PLAINTEXT_SIGNED_INTEGER_MIN = -2147483648
"""Minimum plaintext 32-bit signed integer value that can be encrypted."""

_PLAINTEXT_SIGNED_INTEGER_MAX = 2147483647
"""Maximum plaintext 32-bit signed integer value that can be encrypted."""

_SECRET_SHARED_SIGNED_INTEGER_MODULUS = 4294967296
"""Modulus to use for additive secret sharing of 32-bit signed integers."""

_PLAINTEXT_STRING_BUFFER_LEN_MAX = 4096
"""Maximum length of plaintext string values that can be encrypted."""

def _encode(value: Union[int, str]) -> bytes:
    """
    Encode a numeric value or string as a byte array. The encoding includes
    information about the type of the value (to enable decoding without any
    additional context).

    >>> _encode(123).hex()
    '007b00008000000000'
    >>> _encode('abc').hex()
    '01616263'

    If a value cannot be encoded, an exception is raised.

    >>> _encode([1, 2, 3])
    Traceback (most recent call last):
      ...
    ValueError: cannot encode value
    """
    if isinstance(value, int):
        return (
            bytes([0]) +
            (value - _PLAINTEXT_SIGNED_INTEGER_MIN).to_bytes(8, 'little')
        )

    if isinstance(value, str):
        return bytes([1]) + value.encode('UTF-8')

    raise ValueError('cannot encode value')

def _decode(value: bytes) -> Union[int, str]:
    """
    Decode a bytes-like object back into a numeric value or string.

    >>> _decode(_encode(123))
    123
    >>> _decode(_encode('abc'))
    'abc'

    If a value cannot be decoded, an exception is raised.

    >>> _decode([1, 2, 3])
    Traceback (most recent call last):
      ...
    TypeError: can only decode bytes-like object
    >>> _decode(bytes([2]))
    Traceback (most recent call last):
      ...
    ValueError: cannot decode value
    """
    if not isinstance(value, bytes):
        raise TypeError('can only decode bytes-like object')

    if value[0] == 0: # Indicates encoded value is a 32-bit signed integer.
        integer = int.from_bytes(value[1:], 'little')
        return integer + _PLAINTEXT_SIGNED_INTEGER_MIN

    if value[0] == 1: # Indicates encoded value is a UTF-8 string.
        return value[1:].decode('UTF-8')

    raise ValueError('cannot decode value')

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

    if len([op for (op, status) in instance['operations'].items() if status]) != 1:
        raise ValueError('secret key must support exactly one operation')

    if instance['operations'].get('match'):
        salt = secrets.token_bytes(64)
        instance['value'] = {'salt': salt}

    if instance['operations'].get('store'):
        if len(instance['cluster']['nodes']) == 1:
            instance['value'] = bcl.symmetric.secret()

    return instance

def encrypt(key: dict, plaintext: Union[int, str]) -> bytes:
    """
    Return the ciphertext obtained by using the supplied key to encrypt the
    supplied plaintext.

    >>> key = secret_key({'nodes': [{}]}, {'store': True})
    >>> isinstance(encrypt(key, 123), bytes)
    True
    """
    instance = None

    # Encrypt a value for storage and retrieval.
    if key['operations'].get('store'):
        bytes_ = _encode(plaintext)

        if len(key['cluster']['nodes']) == 1:
            # For single-node clusters, the data is encrypted using a symmetric key.
            instance = bcl.symmetric.encrypt(key['value'], bcl.plain(_encode(plaintext)))
        elif len(key['cluster']['nodes']) > 1:
            # For multi-node clusters, the ciphertext is secret-shared across the nodes
            # using XOR.
            shares = []
            aggregate = bytes(len(bytes_))
            for _ in range(len(key['cluster']['nodes']) - 1):
                mask = secrets.token_bytes(len(bytes_))
                aggregate = bytes(a ^ b for (a, b) in zip(aggregate, mask))
                shares.append(mask)
            shares.append(bytes(a ^ b for (a, b) in zip(aggregate, bytes_)))
            instance = shares

    # Encrypt (i.e., hash) a value for matching.
    if key['operations'].get('match') and 'salt' in key['value']:
        buffer = None

        # Encrypt (i.e., hash) an integer for matching.
        if isinstance(plaintext, int):
            if plaintext < 0 or plaintext >= _PLAINTEXT_SIGNED_INTEGER_MAX:
                raise ValueError('plaintext must be 32-bit nonnegative integer value')
            buffer = plaintext.to_bytes(8, 'little')

        # Encrypt (i.e., hash) a string for matching.
        if isinstance(plaintext, str):
            buffer = plaintext.encode()
            if len(buffer) > _PLAINTEXT_STRING_BUFFER_LEN_MAX:
                raise ValueError(
                    'plaintext string must be possible to encode in 4096 bytes or fewer'
                )

        instance = hashlib.sha512(key['value']['salt'] + buffer).digest()

        if len(key['cluster']['nodes']) > 1:
            instance = [instance for _ in key['cluster']['nodes']]

    # Encrypt a numerical value for summation.
    if key['operations'].get('sum'):
        if len(key['cluster']['nodes']) > 1:
            # Use additive secret sharing for multi-node clusters.
            shares = []
            total = 0
            for _ in range(len(key['cluster']['nodes']) - 1):
                share_ = secrets.randbelow(_SECRET_SHARED_SIGNED_INTEGER_MODULUS)
                shares.append(share_)
                total = (total + share_) % _SECRET_SHARED_SIGNED_INTEGER_MODULUS

            shares.append((plaintext - total) % _SECRET_SHARED_SIGNED_INTEGER_MODULUS)
            instance = shares

    return instance

def decrypt(key: dict, ciphertext: Union[bytes, Sequence[bytes]]) -> bytes:
    """
    Return the ciphertext obtained by using the supplied key to encrypt the
    supplied plaintext.

    >>> key = secret_key({'nodes': [{}, {}]}, {'store': True})
    >>> decrypt(key, encrypt(key, 123))
    123
    >>> key = secret_key({'nodes': [{}, {}]}, {'store': True})
    >>> decrypt(key, encrypt(key, -10))
    -10
    >>> key = secret_key({'nodes': [{}]}, {'store': True})
    >>> decrypt(key, encrypt(key, 'abc'))
    'abc'
    >>> key = secret_key({'nodes': [{}]}, {'store': True})
    >>> decrypt(key, encrypt(key, 123))
    123
    >>> key = secret_key({'nodes': [{}, {}]}, {'sum': True})
    >>> decrypt(key, encrypt(key, 123))
    123
    >>> key = secret_key({'nodes': [{}, {}]}, {'sum': True})
    >>> decrypt(key, encrypt(key, -10))
    -10

    If a value cannot be decrypted, an exception is raised.

    >>> key = secret_key({'nodes': [{}, {}]}, {'abc': True})
    >>> decrypt(key, encrypt(key, [1, 2, 3]))
    Traceback (most recent call last):
      ...
    ValueError: cannot decrypt supplied ciphertext using the supplied key
    """
    # Decrypt a value that was encrypted for storage and retrieval.
    if key['operations'].get('store'):
        if len(key['cluster']['nodes']) == 1:
            # Single-node clusters use symmetric encryption.
            return _decode(bcl.symmetric.decrypt(key['value'], ciphertext))

        # Multi-node clusters use XOR-based secret sharing.
        shares = ciphertext
        bytes_ = bytes(len(shares[0]))
        for share_ in shares:
            bytes_ = bytes(a ^ b for (a, b) in zip(bytes_, share_))

        return _decode(bytes_)

    if key['operations'].get('sum'):
        if len(key['cluster']['nodes']) > 1:
            total = 0
            for share_ in ciphertext:
                total = (total + share_) % _SECRET_SHARED_SIGNED_INTEGER_MODULUS

            if total > _PLAINTEXT_SIGNED_INTEGER_MAX:
                total -= _SECRET_SHARED_SIGNED_INTEGER_MODULUS

            return total

    raise ValueError('cannot decrypt supplied ciphertext using the supplied key')

def share(document: Union[int, str, dict]) -> Sequence[dict]:
    """
    Convert a document that may contain ciphertexts intended for decentralized
    clusters into secret shares of that document. Shallow copies are created
    whenever possible.

    >>> d = {
    ...     'id': 0,
    ...     'age': {'$share': [1, 2, 3]},
    ...     'dat': {'loc': {'$share': [4, 5, 6]}}
    ... }
    >>> for d in share(d): print(d)
    {'id': 0, 'age': {'%share': 1}, 'dat': {'loc': {'%share': 4}}}
    {'id': 0, 'age': {'%share': 2}, 'dat': {'loc': {'%share': 5}}}
    {'id': 0, 'age': {'%share': 3}, 'dat': {'loc': {'%share': 6}}}

    A document with no ciphertexts intended for decentralized clusters is
    unmodofied; a list containing this document is returned.

    >>> share({'id': 0, 'age': 23})
    [{'id': 0, 'age': 23}]

    Any attempt to convert a document that has an incorrect structure raises
    an exception.

    >>> share([])
    Traceback (most recent call last):
      ...
    TypeError: document must be an integer, string, or dictionary
    >>> share({'id': 0, 'age': {'$share': [1, 2, 3], 'extra': [1, 2, 3]}})
    Traceback (most recent call last):
      ...
    ValueError: share object has incorrect structure
    >>> share({
    ...     'id': 0,
    ...     'age': {'$share': [1, 2, 3]},
    ...     'dat': {'loc': {'$share': [4, 5]}}
    ... })
    Traceback (most recent call last):
      ...
    ValueError: inconsistent share quantities in document
    """
    # Return a single share for integer and string values.
    if isinstance(document, (int, str)):
        return [document]

    if not isinstance(document, dict):
        raise TypeError('document must be an integer, string, or dictionary')

    # Handle the relevant base case: a document containing shares that were
    # obtained using the ``encrypt`` function.
    keys = set(document.keys())
    if '$share' in keys:
        shares = document['$share']
        if not isinstance(shares, list) or len(keys) != 1:
            raise ValueError('share object has incorrect structure')
        return [{'%share': s} for s in shares]

    # Determine the number of shares in each subdocument.
    k_to_vs = {}
    for k, v in document.items():
        k_to_vs[k] = share(v)
    quantity = max(len(vs) for vs in k_to_vs.values())

    # Build each of the shares.
    shares = [{} for _ in range(quantity)]
    for k, vs in k_to_vs.items():
        if len(vs) == 1:
            for i in range(quantity):
                shares[i][k] = vs[0]
        elif len(vs) == quantity:
            for i in range(quantity):
                shares[i][k] = vs[i]
        else:
            raise ValueError('inconsistent share quantities in document')

    return shares

if __name__ == '__main__':
    doctest.testmod() # pragma: no cover
