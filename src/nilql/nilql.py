"""
Python library for working with encrypted data within nilDB queries and
replies.
"""
from __future__ import annotations
from typing import Union, Sequence
import doctest
import base64
import secrets
import hashlib
import bcl
import pailliers

_PLAINTEXT_SIGNED_INTEGER_MIN = -2147483648
"""Minimum plaintext 32-bit signed integer value that can be encrypted."""

_PLAINTEXT_SIGNED_INTEGER_MAX = 2147483647
"""Maximum plaintext 32-bit signed integer value that can be encrypted."""

_SECRET_SHARED_SIGNED_INTEGER_MODULUS = 4294967296
"""Modulus to use for additive secret sharing of 32-bit signed integers."""

_PLAINTEXT_STRING_BUFFER_LEN_MAX = 4096
"""Maximum length of plaintext string values that can be encrypted."""

def _pack(b: bytes) -> str:
    """
    Encode a bytes-like object as a Base64 string (for compatibility with JSON).
    """
    return base64.b64encode(b).decode('ascii')

def _unpack(s: str) -> bytes:
    """
    Decode a bytes-like object from its Base64 string encoding.
    """
    return base64.b64decode(s)

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

class SecretKey(dict):
    """
    Data structure for secret key instances.
    """
    @staticmethod
    def generate(cluster: dict = None, operations: dict = None) -> SecretKey:
        """
        Return a secret key built according to what is specified in the supplied
        cluster configuration and operation list.

        >>> sk = SecretKey.generate({'nodes': [{}]}, {'sum': True})
        >>> isinstance(sk, SecretKey)
        True
        """
        # Create instance with default cluster configuration and operations
        # specification, updating the configuration and specification with the
        # supplied arguments.
        instance = SecretKey({
            'material': {},
            'cluster': cluster,
            'operations': {} or operations
        })

        if (
            not isinstance(cluster, dict) or
            'nodes' not in cluster or
            not isinstance(cluster['nodes'], Sequence)
        ):
            raise ValueError('valid cluster configuration is required')

        if len(cluster['nodes']) < 1:
            raise ValueError('cluster configuration must contain at least one node')

        if (
            (not isinstance(operations, dict)) or
            (not set(operations.keys()).issubset({'store', 'match', 'sum'}))
        ):
            raise ValueError('valid operations specification is required')

        if len([op for (op, status) in instance['operations'].items() if status]) != 1:
            raise ValueError('secret key must support exactly one operation')

        if instance['operations'].get('store'):
            if len(instance['cluster']['nodes']) == 1:
                instance['material'] = bcl.symmetric.secret()

        if instance['operations'].get('match'):
            # Salt for deterministic hashing.
            instance['material'] = secrets.token_bytes(64)

        if instance['operations'].get('sum'):
            if len(instance['cluster']['nodes']) == 1:
                instance['material'] = pailliers.secret(2048)

        return instance

    def dump(self: SecretKey) -> dict:
        """
        Return a JSON-compatible :obj:`dict` representation of this key
        instance.
        
        >>> import json
        >>> sk = SecretKey.generate({'nodes': [{}]}, {'store': True})
        >>> isinstance(json.dumps(sk.dump()), str)
        True
        """
        dictionary = {
            'material': {},
            'cluster': self['cluster'],
            'operations': self['operations'],
        }

        if isinstance(self['material'], (bytes, bytearray)):
            dictionary['material'] = _pack(self['material'])
        elif self['material'] == {}:
            pass # There is no key material for clusters with multiple nodes.
        else:
            # Secret key for Paillier encryption.
            dictionary['material'] = {
                'l': str(self['material'][0]),
                'm': str(self['material'][1]),
                'n': str(self['material'][2]),
                'g': str(self['material'][3])
            }

        return dictionary

    @staticmethod
    def load(dictionary: SecretKey) -> dict:
        """
        Create an instance from its JSON-compatible dictionary
        representation.

        >>> sk = SecretKey.generate({'nodes': [{}]}, {'store': True})
        >>> sk == SecretKey.load(sk.dump())
        True
        """
        secret_key = SecretKey({
            'material': {},
            'cluster': dictionary['cluster'],
            'operations': dictionary['operations'],
        })

        if isinstance(dictionary['material'], str):
            secret_key['material'] = _unpack(dictionary['material'])
            # If this is a secret symmetric key, ensure it has the
            # expected type.
            if 'store' in secret_key['operations']:
                secret_key['material'] = bytes.__new__(
                    bcl.secret,
                    secret_key['material']
                )

        elif len(dictionary['material'].keys()) == 0:
            pass # There is no key material for clusters with multiple nodes.

        else:
            # Secret key for Paillier encryption.
            secret_key['material'] = tuple.__new__(
                pailliers.secret,
                (
                    int(dictionary['material']['l']),
                    int(dictionary['material']['m']),
                    int(dictionary['material']['n']),
                    int(dictionary['material']['g'])
                )
            )

        return secret_key

class PublicKey(dict):
    """
    Data structure for public key instances.
    """
    @staticmethod
    def generate(secret_key: SecretKey) -> PublicKey:
        """
        Return a public key built according to what is specified in the supplied
        secret key.

        >>> sk = SecretKey.generate({'nodes': [{}]}, {'sum': True})
        >>> isinstance(PublicKey.generate(sk), PublicKey)
        True
        """
        # Create instance with default cluster configuration and operations
        # specification, updating the configuration and specification with the
        # supplied arguments.
        instance = PublicKey({
            'cluster': secret_key['cluster'],
            'operations': secret_key['operations']
        })

        if isinstance(secret_key['material'], pailliers.secret):
            instance['material'] = pailliers.public(secret_key['material'])
        else:
            raise ValueError('cannot create public key for supplied secret key')

        return instance

    def dump(self: PublicKey) -> dict:
        """
        Return a JSON-compatible :obj:`dict` representation of this key
        instance.

        >>> import json
        >>> sk = SecretKey.generate({'nodes': [{}]}, {'sum': True})
        >>> pk = PublicKey.generate(sk)
        >>> isinstance(json.dumps(pk.dump()), str)
        True
        """
        dictionary = {
            'material': {},
            'cluster': self['cluster'],
            'operations': self['operations'],
        }

        # Public key for Paillier encryption.
        dictionary['material'] = {
            'n': str(self['material'][0]),
            'g': str(self['material'][1])
        }

        return dictionary

    @staticmethod
    def load(dictionary: PublicKey) -> dict:
        """
        Create an instance from its JSON-compatible dictionary
        representation.

        >>> sk = SecretKey.generate({'nodes': [{}]}, {'sum': True})
        >>> pk = PublicKey.generate(sk)
        >>> pk == PublicKey.load(pk.dump())
        True
        """
        public_key = PublicKey({
            'cluster': dictionary['cluster'],
            'operations': dictionary['operations'],
        })

        # Public key for Paillier encryption.
        public_key['material'] = tuple.__new__(
            pailliers.public,
            (
                int(dictionary['material']['n']),
                int(dictionary['material']['g'])
            )
        )

        return public_key

def encrypt(
        key: Union[SecretKey, PublicKey],
        plaintext: Union[int, str]
    ) -> Union[str, Sequence[str], Sequence[int]]:
    """
    Return the ciphertext obtained by using the supplied key to encrypt the
    supplied plaintext.

    >>> key = SecretKey.generate({'nodes': [{}]}, {'store': True})
    >>> isinstance(encrypt(key, 123), str)
    True
    """
    buffer = None

    # Encode an integer for storage or matching.
    if isinstance(plaintext, int):
        if (
            plaintext < _PLAINTEXT_SIGNED_INTEGER_MIN or
            plaintext >= _PLAINTEXT_SIGNED_INTEGER_MAX
        ):
            raise ValueError('numeric plaintext must be a valid 32-bit signed integer')
        buffer = _encode(plaintext)
    elif 'sum' in key['operations']: # Non-integer cannot be encrypted for summation.
        raise ValueError('numeric plaintext must be a valid 32-bit signed integer')

    # Encode a string for storage or matching.
    if isinstance(plaintext, str):
        buffer = _encode(plaintext)
        if len(buffer) > _PLAINTEXT_STRING_BUFFER_LEN_MAX + 1:
            raise ValueError(
                'string plaintext must be possible to encode in 4096 bytes or fewer'
            )

    instance = None

    # Encrypt a value for storage and retrieval.
    if key['operations'].get('store'):
        if len(key['cluster']['nodes']) == 1:
            # For single-node clusters, the data is encrypted using a symmetric key.
            instance = _pack(
                bcl.symmetric.encrypt(key['material'], bcl.plain(buffer))
            )
        elif len(key['cluster']['nodes']) > 1:
            # For multi-node clusters, the ciphertext is secret-shared across the nodes
            # using XOR.
            shares = []
            aggregate = bytes(len(buffer))
            for _ in range(len(key['cluster']['nodes']) - 1):
                mask = secrets.token_bytes(len(buffer))
                aggregate = bytes(a ^ b for (a, b) in zip(aggregate, mask))
                shares.append(mask)
            shares.append(bytes(a ^ b for (a, b) in zip(aggregate, buffer)))
            instance = list(map(_pack, shares))

    # Encrypt (i.e., hash) a value for matching.
    if key['operations'].get('match'):
        instance = _pack(hashlib.sha512(key['material'] + buffer).digest())

        # If there are multiple nodes, prepare the same ciphertext for each.
        if len(key['cluster']['nodes']) > 1:
            instance = [instance for _ in key['cluster']['nodes']]

    # Encrypt a numerical value for summation.
    if key['operations'].get('sum'):
        if len(key['cluster']['nodes']) == 1:
            instance = hex(pailliers.encrypt(key['material'], plaintext))[2:] # No '0x'.
        elif len(key['cluster']['nodes']) > 1:
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

def decrypt(
        key: SecretKey,
        ciphertext: Union[str, Sequence[str], Sequence[int]]
    ) -> Union[bytes, int]:
    """
    Return the ciphertext obtained by using the supplied key to encrypt the
    supplied plaintext.

    >>> key = SecretKey.generate({'nodes': [{}, {}]}, {'store': True})
    >>> decrypt(key, encrypt(key, 123))
    123
    >>> key = SecretKey.generate({'nodes': [{}, {}]}, {'store': True})
    >>> decrypt(key, encrypt(key, -10))
    -10
    >>> key = SecretKey.generate({'nodes': [{}]}, {'store': True})
    >>> decrypt(key, encrypt(key, 'abc'))
    'abc'
    >>> key = SecretKey.generate({'nodes': [{}]}, {'store': True})
    >>> decrypt(key, encrypt(key, 123))
    123
    >>> key = SecretKey.generate({'nodes': [{}, {}]}, {'sum': True})
    >>> decrypt(key, encrypt(key, 123))
    123
    >>> key = SecretKey.generate({'nodes': [{}, {}]}, {'sum': True})
    >>> decrypt(key, encrypt(key, -10))
    -10

    An exception is raised if a ciphertext cannot be decrypted using the
    supplied key (*e.g.*, because one or both are malformed or they are
    incompatible).

    >>> key = SecretKey.generate({'nodes': [{}, {}]}, {'store': True})
    >>> decrypt(key, 'abc')
    Traceback (most recent call last):
      ...
    TypeError: secret key requires a valid ciphertext from a multi-node cluster
    >>> decrypt(
    ...     SecretKey({'cluster': {'nodes': [{}]}, 'operations': {}}),
    ...     'abc'
    ... )
    Traceback (most recent call last):
      ...
    ValueError: cannot decrypt supplied ciphertext using the supplied key
    """
    error = ValueError(
        'cannot decrypt supplied ciphertext using the supplied key'
    )

    # Confirm that the secret key and ciphertext have compatible clusters.
    if len(key['cluster']['nodes']) == 1:
        if not isinstance(ciphertext, str):
            raise TypeError(
              'secret key requires a valid ciphertext from a single-node cluster'
            )
    else:
        if (
            isinstance(ciphertext, str) or
            (not isinstance(ciphertext, Sequence)) or
            (not (
                all(isinstance(c, int) for c in ciphertext) or
                all(isinstance(c, str) for c in ciphertext)
            ))
        ):
            raise TypeError(
              'secret key requires a valid ciphertext from a multi-node cluster'
            )

        if (
            isinstance(ciphertext, Sequence) and
            len(key['cluster']['nodes']) != len(ciphertext)
        ):
            raise ValueError(
              'secret key and ciphertext must have the same associated cluster size'
            )

    # Decrypt a value that was encrypted for storage and retrieval.
    if key['operations'].get('store'):
        if len(key['cluster']['nodes']) == 1:
            # Single-node clusters use symmetric encryption.
            try:
                return _decode(
                    bcl.symmetric.decrypt(
                        key['material'],
                        bcl.cipher(_unpack(ciphertext))
                        )
                )
            except Exception as exc:
                raise error from exc

        # Multi-node clusters use XOR-based secret sharing.
        shares = [_unpack(share) for share in ciphertext]
        bytes_ = bytes(len(shares[0]))
        for share_ in shares:
            bytes_ = bytes(a ^ b for (a, b) in zip(bytes_, share_))

        return _decode(bytes_)

    # Decrypt a value that was encrypted fo summation.
    if key['operations'].get('sum'):
        if len(key['cluster']['nodes']) == 1:
            return pailliers.decrypt(
                key['material'],
                pailliers.cipher(int(ciphertext, 16))
            )

        if len(key['cluster']['nodes']) > 1:
            total = 0
            for share_ in ciphertext:
                total = (total + share_) % _SECRET_SHARED_SIGNED_INTEGER_MODULUS

            if total > _PLAINTEXT_SIGNED_INTEGER_MAX:
                total -= _SECRET_SHARED_SIGNED_INTEGER_MODULUS

            return total

    raise error

def allot(
        document: Union[int, bool, str, list, dict]
    ) -> Sequence[Union[int, bool, str, list, dict]]:
    """
    Convert a document that may contain ciphertexts intended for multi-node
    clusters into secret shares of that document. Shallow copies are created
    whenever possible.

    >>> d = {
    ...     'id': 0,
    ...     'age': {'$allot': [1, 2, 3]},
    ...     'dat': {'loc': {'$allot': [4, 5, 6]}}
    ... }
    >>> for d in allot(d): print(d)
    {'id': 0, 'age': {'$share': 1}, 'dat': {'loc': {'$share': 4}}}
    {'id': 0, 'age': {'$share': 2}, 'dat': {'loc': {'$share': 5}}}
    {'id': 0, 'age': {'$share': 3}, 'dat': {'loc': {'$share': 6}}}

    A document with no ciphertexts intended for decentralized clusters is
    unmodofied; a list containing this document is returned.

    >>> allot({'id': 0, 'age': 23})
    [{'id': 0, 'age': 23}]

    Any attempt to convert a document that has an incorrect structure raises
    an exception.

    >>> allot(1.23)
    Traceback (most recent call last):
      ...
    TypeError: integer, boolean, string, list, or dictionary expected
    >>> allot({'id': 0, 'age': {'$allot': [1, 2, 3], 'extra': [1, 2, 3]}})
    Traceback (most recent call last):
      ...
    ValueError: allotment must only have one key
    >>> allot({
    ...     'id': 0,
    ...     'age': {'$allot': [1, 2, 3]},
    ...     'dat': {'loc': {'$allot': [4, 5]}}
    ... })
    Traceback (most recent call last):
      ...
    ValueError: number of shares in subdocument is not consistent
    """
    # Return a single share for integer and string values.
    if isinstance(document, (int, bool, str)):
        return [document]

    if isinstance(document, list):
        results = list(map(allot, document))

        # Determine the number of shares that must be created.
        multiplicity = 1
        for result in results:
            if len(result) != 1:
                if multiplicity == 1:
                    multiplicity = len(result)
                elif multiplicity != len(result):
                    raise ValueError("number of shares is not consistent")

        # Create and return the appropriate number of shares.
        shares = []
        for i in range(multiplicity):
            share = []
            for result in results:
                share.append(result[0 if len(result) == 1 else i])
            shares.append(share)

        return shares

    if isinstance(document, dict):
        # Document is an array of shares obtained from the ``encrypt`` function
        # that must be allotted to nodes.
        if '$allot' in document:
            if len(document.keys()) != 1:
                raise ValueError('allotment must only have one key')

            items = document['$allot']
            if isinstance(items, list):

                # Simple allotment.
                if all(isinstance(item, (int, str)) for item in items):
                    return [{'$share': item} for item in document['$allot']]

                # More complex allotment with list of share lists.
                return [
                    {'$share': [share['$share'] for share in shares]}
                    for shares in allot([{'$allot': item} for item in items])
                ]

        # Document is a general-purpose key-value mapping.
        results = {}
        multiplicity = 1
        for key in document:
            result = allot(document[key])
            results[key] = result
            if len(result) != 1:
                if multiplicity == 1:
                    multiplicity = len(result)
                elif multiplicity != len(result):
                    raise ValueError(
                        'number of shares in subdocument is not consistent'
                    )

        # Create the appropriate number of document shares.
        shares = []
        for i in range(multiplicity):
            share = {}
            for key in results:
                results_for_key = results[key]
                share[key] = results_for_key[0 if len(results_for_key) == 1 else i]
            shares.append(share)

        return shares

    raise TypeError(
        'integer, boolean, string, list, or dictionary expected'
    )

def unify(
        secret_key: SecretKey,
        documents: Sequence[Union[int, bool, str, list, dict]]
    ) -> Union[int, bool, str, list, dict]:
    """
    Convert an object that may contain ciphertexts intended for multi-node
    clusters into secret shares of that object. Shallow copies are created
    whenever possible.

    >>> data = {
    ...     'a': [True, 'v', 12],
    ...     'b': [False, 'w', 34],
    ...     'c': [True, 'x', 56],
    ...     'd': [False, 'y', 78],
    ...     'e': [True, 'z', 90],
    ... }
    >>> sk = SecretKey.generate({'nodes': [{}, {}, {}]}, {'store': True})
    >>> encrypted = {
    ...     'a': [True, 'v', {'$allot': encrypt(sk, 12)}],
    ...     'b': [False, 'w', {'$allot': encrypt(sk, 34)}],
    ...     'c': [True, 'x', {'$allot': encrypt(sk, 56)}],
    ...     'd': [False, 'y', {'$allot': encrypt(sk, 78)}],
    ...     'e': [True, 'z', {'$allot': encrypt(sk, 90)}],
    ... }
    >>> shares = allot(encrypted)
    >>> decrypted = unify(sk, shares)
    >>> data == decrypted
    True

    It is possible to wrap nested lists of shares to reduce the overhead
    associated with the ``{'$allot': ...}`` and ``{'$share': ...}`` wrappers.

    >>> data = {
    ...     'a': [1, [2, 3]],
    ...     'b': [4, 5, 6],
    ... }
    >>> sk = SecretKey.generate({'nodes': [{}, {}, {}]}, {'store': True})
    >>> encrypted = {
    ...     'a': {'$allot': [encrypt(sk, 1), [encrypt(sk, 2), encrypt(sk, 3)]]},
    ...     'b': {'$allot': [encrypt(sk, 4), encrypt(sk, 5), encrypt(sk, 6)]}
    ... }
    >>> shares = allot(encrypted)
    >>> decrypted = unify(sk, shares)
    >>> data == decrypted
    True
    """
    if len(documents) == 1:
        return documents[0]

    if all(isinstance(document, list) for document in documents):
        length = len(documents[0])
        if all(len(document) == length for document in documents[1:]):
            return [
                unify(secret_key, [share[i] for share in documents])
                for i in range(length)
            ]

    if all(isinstance(document, dict) for document in documents):
        # Documents are shares.
        if all('$share' in document for document in documents):

            # Simple share.
            if all(
                isinstance(document['$share'], (int, str))
                for document in documents
            ):
                return decrypt(
                    secret_key,
                    [document['$share'] for document in documents]
                )

            # Share consisting of list of shares.
            return [
                unify(
                    secret_key,
                    [{'$share': share} for share in shares]
                )
                for shares in zip(*[document['$share'] for document in documents])
            ]

        # Documents are general-purpose key-value mappings.
        keys = documents[0].keys()
        if all(document.keys() == keys for document in documents[1:]):
            results = {}
            for key in keys:
                results[key] = unify(
                    secret_key,
                    [document[key] for document in documents]
                )
            return results

    # Base case: all documents must be equivalent.
    all_values_equal = True
    for i in range(1, len(documents)):
        all_values_equal &= documents[0] == documents[i]

    if all_values_equal:
        return documents[0]

    raise TypeError('array of compatible document shares expected')

if __name__ == '__main__':
    doctest.testmod() # pragma: no cover
