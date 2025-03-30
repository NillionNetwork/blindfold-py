"""
Python library for working with encrypted data within nilDB queries and
replies.
"""
from __future__ import annotations
from typing import Union, Optional, Sequence
import doctest
import base64
import secrets
import hashlib
import hmac
from lagrange import lagrange
import bcl
import pailliers

_PLAINTEXT_SIGNED_INTEGER_MIN = -2147483648
"""Minimum plaintext 32-bit signed integer value that can be encrypted."""

_PLAINTEXT_SIGNED_INTEGER_MAX = 2147483647
"""Maximum plaintext 32-bit signed integer value that can be encrypted."""

_SECRET_SHARED_SIGNED_INTEGER_MODULUS = (2 ** 32) + 15
"""Modulus to use for additive secret sharing of 32-bit signed integers."""

_PLAINTEXT_STRING_BUFFER_LEN_MAX = 4096
"""Maximum length of plaintext string values that can be encrypted."""

_HASH = hashlib.sha512
"""Hash function used for HKDF and matching."""

_SHAMIRS_MINIMUM_SHARES_FOR_RECONSTRUCTION = 2
"""Minimum number of shares required to reconstruct a Shamir secret."""

def _hkdf_extract(salt: bytes, input_key: bytes) -> bytes:
    """
    Extracts a pseudorandom key (PRK) using HMAC with the given salt and input key material.
    If the salt is empty, a zero-filled byte string of the same length as the hash function's
    digest size is used.
    """
    if len(salt) == 0:
        salt = bytes([0] * _HASH().digest_size)
    return hmac.new(salt, input_key, _HASH).digest()

def _hkdf_expand(pseudo_random_key: bytes, info: bytes, length: int) -> bytes:
    """
    Expands the pseudo_random_key into an output key material (OKM) of the desired length using
    HMAC-based expansion.
    """
    t = b''
    okm = b''
    i = 0
    while len(okm) < length:
        i += 1
        t = hmac.new(pseudo_random_key, t + info + bytes([i]), _HASH).digest()
        okm += t
    return okm[:length]

def _hkdf(length: int, input_key: bytes, salt: bytes = b'', info: bytes = b'') -> bytes:
    """
    Extract a pseudorandom key of `length` from `input_key` and optionally `salt` and `info`.
    """
    prk = _hkdf_extract(salt, input_key)
    return _hkdf_expand(prk, info, length)

def _random_bytes(length: int, seed: Optional[bytes] = None, salt: Optional[bytes] = None) -> bytes:
    """
    Return a random :obj:`bytes` value of the specified length (using
    the seed if one is supplied).
    """
    if seed is not None:
        return _hkdf(length, seed, b'' if salt is None else salt)

    return secrets.token_bytes(length)

def _random_int(
        minimum: int,
        maximum: int,
        seed: Optional[bytes] = None
    ) -> int:
    """
    Return a random integer value within the specified range (using
    the seed if one is supplied) by leveraging rejection sampling.
    """
    if minimum < 0 or minimum > 1:
        raise ValueError('minimum must be 0 or 1')

    if maximum <= minimum or maximum >= _SECRET_SHARED_SIGNED_INTEGER_MODULUS:
        raise ValueError(
          'maximum must be greater than the minimum and less than the modulus'
        )

    # Deterministically generate an integer in the specified range
    # using the supplied seed. This specific technique is implemented
    # explicitly for compatibility with corresponding libraries for
    # other languages and platforms.
    if seed is not None:
        range_ = maximum - minimum
        integer = None
        index = 0
        while integer is None or integer > range_:
            bytes_ = bytearray(_random_bytes(8, seed, index.to_bytes(64, 'little')))
            index += 1
            bytes_[4] &= 1
            bytes_[5] &= 0
            bytes_[6] &= 0
            bytes_[7] &= 0
            small = int.from_bytes(bytes_[:4], 'little')
            large = int.from_bytes(bytes_[4:], 'little')
            integer = small + large * (2 ** 32)

        return minimum + integer

    return minimum + secrets.randbelow(maximum + 1 - minimum)

def _shamirs_eval(poly, x, prime):
    """
    Evaluates polynomial (coefficient tuple) at x.
    """
    accum = 0
    for coeff in reversed(poly):
        accum *= x
        accum += coeff
        accum %= prime
    return accum

def _shamirs_shares(
        secret,
        total_shares,
        minimum_shares=_SHAMIRS_MINIMUM_SHARES_FOR_RECONSTRUCTION,
        prime=_SECRET_SHARED_SIGNED_INTEGER_MODULUS
):
    """
    Generates a random Shamir pool for a given secret and returns share points.
    """
    if minimum_shares > total_shares:
        raise ValueError("Pool secret would be irrecoverable.")

    poly = [secret] + [secrets.randbelow(prime - 1) for _ in range(minimum_shares - 1)]
    points = [[i, _shamirs_eval(poly, i, prime)] for i in range(1, total_shares + 1)]
    return points

def _shamirs_recover(shares, prime=_SECRET_SHARED_SIGNED_INTEGER_MODULUS):
    """
    Recover the secret from share points.
    """
    if len(shares) < _SHAMIRS_MINIMUM_SHARES_FOR_RECONSTRUCTION:
        raise ValueError(
            f'need at least {_SHAMIRS_MINIMUM_SHARES_FOR_RECONSTRUCTION} shares'
        )

    return lagrange(shares, prime)

def _shamirs_add(shares1, shares2, prime=_SECRET_SHARED_SIGNED_INTEGER_MODULUS):
    """
    Adds two sets of shares pointwise, assuming they use the same x-values.
    """
    if len(shares1) != len(shares2):
        raise ValueError('shares sets must have the same length')

    return [
        [x1, (y1 + y2) % prime]
        for (x1, y1), (x2, y2) in zip(shares1, shares2)
        if x1 == x2
    ]

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

def _encode(value: Union[int, str, bytes]) -> bytes:
    """
    Encode an integer, string, or binary plaintext as a binary value.
    The encoding includes information about the type of the value in
    the first byte (to enable decoding without any additional context).

    >>> _encode(123).hex()
    '007b00008000000000'
    >>> _encode('abc').hex()
    '01616263'
    >>> _encode(bytes([1, 2, 3])).hex()
    '02010203'

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

    if isinstance(value, bytes):
        return bytes([2]) + value

    raise ValueError('cannot encode value')

def _decode(value: bytes) -> Union[int, str, bytes]:
    """
    Decode a binary value back into an integer, string, or binary plaintext.

    >>> _decode(_encode(123))
    123
    >>> _decode(_encode('abc'))
    'abc'
    >>> _decode(_encode(bytes([1, 2, 3])))
    b'\\x01\\x02\\x03'

    If a value cannot be decoded, an exception is raised.

    >>> _decode([1, 2, 3])
    Traceback (most recent call last):
      ...
    TypeError: can only decode from a bytes value
    >>> _decode(bytes([3]))
    Traceback (most recent call last):
      ...
    ValueError: cannot decode value
    """
    if not isinstance(value, bytes):
        raise TypeError('can only decode from a bytes value')

    if value[0] == 0: # Indicates encoded value is a 32-bit signed integer.
        integer = int.from_bytes(value[1:], 'little')
        return integer + _PLAINTEXT_SIGNED_INTEGER_MIN

    if value[0] == 1: # Indicates encoded value is a UTF-8 string.
        return value[1:].decode('UTF-8')

    if value[0] == 2: # Indicates encoded value is binary data.
        return value[1:]

    raise ValueError('cannot decode value')

class SecretKey(dict):
    """
    Data structure for representing all categories of secret key instances.
    """
    @staticmethod
    def generate(
        cluster: dict = None,
        operations: dict = None,
        seed: Union[bytes, bytearray, str] = None
    ) -> SecretKey:
        """
        Return a secret key built according to what is specified in the supplied
        cluster configuration and operation specification.

        >>> sk = SecretKey.generate({'nodes': [{}]}, {'sum': True})
        >>> isinstance(sk, SecretKey)
        True
        """
        # Normalize type of seed argument.
        if isinstance(seed, str):
            seed = seed.encode()

        # Create instance with default cluster configuration and operations
        # specification, updating the configuration and specification with the
        # supplied arguments.
        secret_key = SecretKey({
            'material': {},
            'cluster': cluster,
            'operations': operations
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
            (not set(operations.keys()).issubset({'store', 'match', 'sum', 'redundancy'}))
        ):
            raise ValueError('valid operations specification is required')

        if len([op for (op, status) in secret_key['operations'].items() if status]) != 1:
            raise ValueError('secret key must support exactly one operation')

        if secret_key['operations'].get('store'):
            # Symmetric key for encrypting the plaintext or the shares of a plaintext.
            secret_key['material'] = (
                bcl.symmetric.secret()
                if seed is None else
                bytes.__new__(bcl.secret, _random_bytes(32, seed))
            )

        if secret_key['operations'].get('match'):
            # Salt for deterministic hashing of the plaintext.
            secret_key['material'] = _random_bytes(64, seed)

        if secret_key['operations'].get('sum'):
            if len(secret_key['cluster']['nodes']) == 1:
                # Paillier secret key for encrypting a plaintext integer value.
                if seed is not None:
                    raise RuntimeError(
                        'seed-based derivation of summation-compatible keys ' +
                        'is not supported for single-node clusters'
                    )
                secret_key['material'] = pailliers.secret(256)
            else:
                # Distinct multiplicative mask for each additive share.
                secret_key['material'] = [
                    _random_int(
                        1,
                        _SECRET_SHARED_SIGNED_INTEGER_MODULUS - 1,
                        (
                            _random_bytes(64, seed, i.to_bytes(64, 'little'))
                            if seed is not None else
                            None
                        )
                    )
                    for i in range(len(secret_key['cluster']['nodes']))
                ]

        if secret_key['operations'].get('redundancy'):
            if len(secret_key['cluster']['nodes']) == 1:
                raise RuntimeError(
                    'Redundancy is not supported for single-node clusters'
                )
            # Distinct multiplicative mask for each additive share.
            secret_key['material'] = [
                _random_int(
                    1,
                    _SECRET_SHARED_SIGNED_INTEGER_MODULUS - 1,
                    (
                        _random_bytes(64, seed, i.to_bytes(64, 'little'))
                        if seed is not None else
                        None
                    )
                )
                for i in range(len(secret_key['cluster']['nodes']))
            ]

        return secret_key

    def dump(self: SecretKey) -> dict:
        """
        Return a JSON-compatible dictionary representation of this key
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

        if isinstance(self['material'], list):
            # Additive secret sharing node-specific masks.
            if all(isinstance(k, int) for k in self['material']):
                dictionary['material'] = self['material']
        elif isinstance(self['material'], (bytes, bytearray)):
            dictionary['material'] = _pack(self['material'])
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
    def load(dictionary: dict) -> SecretKey:
        """
        Return an instance built from a JSON-compatible dictionary
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

        if isinstance(dictionary['material'], list):
            # Additive secret sharing node-specific masks.
            if all(isinstance(k, int) for k in dictionary['material']):
                secret_key['material'] = dictionary['material']
        elif isinstance(dictionary['material'], str):
            secret_key['material'] = _unpack(dictionary['material'])
            # If this is a secret symmetric key, ensure it has the
            # expected type.
            if 'store' in secret_key['operations']:
                secret_key['material'] = bytes.__new__(
                    bcl.secret,
                    secret_key['material']
                )
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

class ClusterKey(SecretKey):
    """
    Data structure for representing all categories of cluster key instances.
    """
    @staticmethod
    def generate( # pylint: disable=arguments-differ # Seeds not supported.
        cluster: dict = None,
        operations: dict = None
    ) -> ClusterKey:
        """
        Return a cluster key built according to what is specified in the supplied
        cluster configuration and operation specification.

        >>> ck = ClusterKey.generate({'nodes': [{}, {}, {}]}, {'sum': True})
        >>> isinstance(ck, ClusterKey)
        True

        Cluster keys can only be created for clusters that have two or more nodes.

        >>> ClusterKey.generate({'nodes': [{}]}, {'store': True})
        Traceback (most recent call last):
          ...
        ValueError: cluster configuration must have at least two nodes
        """
        # Create instance with default cluster configuration and operations
        # specification, updating the configuration and specification with the
        # supplied arguments.
        cluster_key = ClusterKey(SecretKey.generate(cluster, operations))

        if len(cluster_key['cluster']['nodes']) == 1:
            raise ValueError('cluster configuration must have at least two nodes')

        # Cluster keys contain no cryptographic material.
        if 'material' in cluster_key:
            del cluster_key['material']
# =======
#         # Ensure that the secret key material is the identity value
#         # for the supported operation.
#         if len(cluster_key['cluster']['nodes']) > 1:
#             if cluster_key['operations'].get('store'):
#                 cluster_key['material'] = bytes(_PLAINTEXT_STRING_BUFFER_LEN_MAX)
#             if cluster_key['operations'].get('sum') or cluster_key['operations'].get('redundancy'):
#                 cluster_key['material'] = 1
# >>>>>>> d7c678d (feat: Add Shamir secret sharing)

        return cluster_key

    def dump(self: ClusterKey) -> dict:
        """
        Return a JSON-compatible dictionary representation of this key
        instance.
        
        >>> import json
        >>> ck = ClusterKey.generate({'nodes': [{}, {}, {}]}, {'store': True})
        >>> isinstance(json.dumps(ck.dump()), str)
        True
        """
        return {
            'cluster': self['cluster'],
            'operations': self['operations'],
        }

    @staticmethod
    def load(dictionary: dict) -> ClusterKey:
        """
        Return an instance built from a JSON-compatible dictionary
        representation.

        >>> ck = ClusterKey.generate({'nodes': [{}, {}, {}]}, {'store': True})
        >>> ck == ClusterKey.load(ck.dump())
        True
        """
        return ClusterKey({
            'cluster': dictionary['cluster'],
            'operations': dictionary['operations'],
        })

class PublicKey(dict):
    """
    Data structure for representing all categories of public key instances.
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
        public_key = PublicKey({
            'cluster': secret_key['cluster'],
            'operations': secret_key['operations']
        })

        if isinstance(secret_key['material'], pailliers.secret):
            public_key['material'] = pailliers.public(secret_key['material'])
        else:
            raise ValueError('cannot create public key for supplied secret key')

        return public_key

    def dump(self: PublicKey) -> dict:
        """
        Return a JSON-compatible dictionary representation of this key
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
        Return an instance built from a JSON-compatible dictionary
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
        plaintext: Union[int, str, bytes]
    ) -> Union[str, Sequence[str], Sequence[int], Sequence[Sequence[int]]]:
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
    elif ('sum' in key['operations'] or 'redundancy' in key['operations']):
        # Non-integer cannot be encrypted for summation.
        raise ValueError('numeric plaintext must be a valid 32-bit signed integer')

    # Encode string or binary data for storage or matching.
    if isinstance(plaintext, (str, bytes)):
        buffer = _encode(plaintext)
        if len(buffer) > _PLAINTEXT_STRING_BUFFER_LEN_MAX + 1:
            raise ValueError(
                'string or binary plaintext must be possible to encode in ' +
                str(_PLAINTEXT_STRING_BUFFER_LEN_MAX) +
                ' bytes or fewer'
            )

    # Encrypt a plaintext for storage and retrieval.
    if key['operations'].get('store'):
        # For single-node clusters, the data is encrypted using a symmetric key.
        if len(key['cluster']['nodes']) == 1:
            return _pack(
                bcl.symmetric.encrypt(key['material'], bcl.plain(buffer))
            )

        # For multiple-node clusters, the ciphertext is secret-shared using XOR
        # (with each share symmetrically encrypted in the case of a secret key).
        optional_enc = (
            (lambda s: bcl.symmetric.encrypt(key['material'], bcl.plain(s)))
            if 'material' in key else
            (lambda s: s)
        )
        shares = []
        aggregate = bytes(len(buffer))
        for _ in range(len(key['cluster']['nodes']) - 1):
            mask = _random_bytes(len(buffer))
            aggregate = bytes(a ^ b for (a, b) in zip(aggregate, mask))
            shares.append(optional_enc(mask))
        shares.append(optional_enc(
            bytes(a ^ b for (a, b) in zip(aggregate, buffer))
        ))
        return list(map(_pack, shares))

    # Encrypt (i.e., hash) a plaintext for matching.
    if key['operations'].get('match'):
        # The deterministic salted hash of the encoded plaintext is the ciphertext.
        ciphertext = _pack(_HASH(key['material'] + buffer).digest())

        # For multiple-node clusters, replicate the ciphertext for each node.
        if len(key['cluster']['nodes']) > 1:
            ciphertext = [ciphertext for _ in key['cluster']['nodes']]

        return ciphertext

    # Encrypt an integer plaintext in a summation-compatible way.
    if key['operations'].get('sum'):
        # Only 32-bit signed integer plaintexts are supported.
        if not isinstance(plaintext, int):
            raise TypeError(
                'plaintext to encrypt for sum operation must be integer'
            )

        # For single-node clusters, the Paillier cryptosystem is used.
        if len(key['cluster']['nodes']) == 1:
            return hex(pailliers.encrypt(key['material'], plaintext))[2:] # No '0x'.

        # For multiple-node clusters, additive secret sharing is used.
        masks = [
            key['material'][i] if 'material' in key else 1
            for i in range(len(key['cluster']['nodes']))
        ]
        shares = []
        total = 0
        quantity = len(key['cluster']['nodes'])
        for i in range(quantity - 1):
            share_ =  _random_int(0, _SECRET_SHARED_SIGNED_INTEGER_MODULUS - 1)
            shares.append(
                (masks[i] * share_)
                %
                _SECRET_SHARED_SIGNED_INTEGER_MODULUS
            )
            total = (total + share_) % _SECRET_SHARED_SIGNED_INTEGER_MODULUS

        shares.append(
            (
                masks[quantity - 1] *
                ((plaintext - total) % _SECRET_SHARED_SIGNED_INTEGER_MODULUS)
            ) % _SECRET_SHARED_SIGNED_INTEGER_MODULUS
        )
        return shares

    if key['operations'].get('redundancy'):
        if len(key['cluster']['nodes']) == 1:
            raise RuntimeError('redundancy is not supported for single-node clusters')

        # Use Shamir's secret sharing for multiple-node clusters.
        masks = [
            key['material'][i] if 'material' in key else 1
            for i in range(len(key['cluster']['nodes']))
        ]
        num_nodes = len(key['cluster']['nodes'])
        shares = _shamirs_shares(plaintext, num_nodes)
        for (i, share) in enumerate(shares):
            share[1] = (masks[i] * share[1]) % _SECRET_SHARED_SIGNED_INTEGER_MODULUS

        return shares
    # The below should not occur unless the key's cluster or operations
    # information is malformed/missing or the plaintext is unsupported.
    raise ValueError(
        'cannot encrypt the supplied plaintext using the supplied key'
    )

def decrypt(
        key: SecretKey,
        ciphertext: Union[str, Sequence[str], Sequence[int], Sequence[Sequence[int]]]
    ) -> Union[int, str, bytes]:
    """
    Return the plaintext obtained by using the supplied key to decrypt the
    supplied ciphertext.

    >>> key = SecretKey.generate({'nodes': [{}, {}]}, {'store': True})
    >>> decrypt(key, encrypt(key, 123))
    123
    >>> key = SecretKey.generate({'nodes': [{}, {}]}, {'store': True})
    >>> decrypt(key, encrypt(key, -10))
    -10
    >>> key = SecretKey.generate({'nodes': [{}, {}]}, {'store': True})
    >>> decrypt(key, encrypt(key, bytes([1, 2, 3])))
    b'\\x01\\x02\\x03'
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
    >>> key = SecretKey.generate({'nodes': [{}, {}]}, {'redundancy': True})
    >>> decrypt(key, encrypt(key, 123))
    123
    >>> key = SecretKey.generate({'nodes': [{}, {}]}, {'redundancy': True})
    >>> decrypt(key, encrypt(key, -10))
    -10

    An exception is raised if a ciphertext cannot be decrypted using the
    supplied key (*e.g.*, because one or both are malformed or they are
    incompatible).

    >>> key = SecretKey.generate({'nodes': [{}, {}]}, {'store': True})
    >>> decrypt(key, 'abc')
    Traceback (most recent call last):
      ...
    ValueError: secret key and ciphertext must have the same associated cluster size
    >>> decrypt(
    ...     SecretKey({'cluster': {'nodes': [{}]}, 'operations': {}}),
    ...     'abc'
    ... )
    Traceback (most recent call last):
      ...
    ValueError: cannot decrypt the supplied ciphertext using the supplied key
    """
    error = ValueError(
        'cannot decrypt the supplied ciphertext using the supplied key'
    )

    # Confirm that the secret key and ciphertext have compatible cluster
    # specifications.
    if len(key['cluster']['nodes']) == 1:
        if not isinstance(ciphertext, str):
            raise ValueError(
              'secret key requires a valid ciphertext from a single-node cluster'
            )
    else:
        if (
            (not isinstance(ciphertext, Sequence)) or
            (not (
                all(
                    (
                        isinstance(c, Sequence) and
                        len(c) == 2 and
                        all(isinstance(x, int) for x in c)
                    )
                    for c in ciphertext
                ) or
                all(isinstance(c, int) for c in ciphertext) or
                all(isinstance(c, str) for c in ciphertext)
            ))
        ):
            raise ValueError(
              'secret key requires a valid ciphertext from a multiple-node cluster'
            )

        if (
            isinstance(ciphertext, Sequence) and
            len(key['cluster']['nodes']) != len(ciphertext)
        ) and not key['operations'].get('redundancy'):
            raise ValueError(
              'secret key and ciphertext must have the same associated cluster size'
            )

    # Decrypt a value that was encrypted for storage and retrieval.
    if key['operations'].get('store'):
        # For single-node clusters, the plaintext is encrypted using a symmetric key.
        if len(key['cluster']['nodes']) == 1:
            try:
                return _decode(
                    bcl.symmetric.decrypt(
                        key['material'],
                        bcl.cipher(_unpack(ciphertext))
                    )
                )
            except Exception as exc:
                raise error from exc

        # For multiple-node clusters, the ciphertext is secret-shared using XOR
        # (with each share symmetrically encrypted in the case of a secret key).
        shares = [_unpack(share) for share in ciphertext]
        if 'material' in key:
            try:
                shares = [
                    bcl.symmetric.decrypt(key['material'], bcl.cipher(share))
                    for share in shares
                ]
            except Exception as exc:
                raise error from exc

        bytes_ = bytes(len(shares[0]))
        for share_ in shares:
            bytes_ = bytes(a ^ b for (a, b) in zip(bytes_, share_))

        return _decode(bytes_)

    # Decrypt a value that was encrypted in a summation-compatible way.
    if key['operations'].get('sum'):
        # For single-node clusters, the Paillier cryptosystem is used.
        if len(key['cluster']['nodes']) == 1:
            return pailliers.decrypt(
                key['material'],
                pailliers.cipher(int(ciphertext, 16))
            )

        # For multiple-node clusters, additive secret sharing is used.
        inverse_masks = [
            pow(
                key['material'][i] if 'material' in key else 1,
                _SECRET_SHARED_SIGNED_INTEGER_MODULUS - 2,
                _SECRET_SHARED_SIGNED_INTEGER_MODULUS
            )
            for i in range(len(key['cluster']['nodes']))
        ]
        shares = ciphertext
        plaintext = 0
        for (i, share_) in enumerate(shares):
            plaintext = (
                plaintext +
                ((inverse_masks[i] * share_) % _SECRET_SHARED_SIGNED_INTEGER_MODULUS)
            ) % _SECRET_SHARED_SIGNED_INTEGER_MODULUS

        # Field elements in the "upper half" of the field represent negative
        # integers.
        if plaintext > _PLAINTEXT_SIGNED_INTEGER_MAX:
            plaintext -= _SECRET_SHARED_SIGNED_INTEGER_MODULUS

        return plaintext

    # Decrypt a value that was encrypted in a summation-compatible way.
    if key['operations'].get('redundancy'):
        if len(key['cluster']['nodes']) == 1:
            raise RuntimeError('redundancy is not supported for single-node clusters')

        # For multiple-node clusters, additive secret sharing is used.
        inverse_masks = [
            pow(
                key['material'][i] if 'material' in key else 1,
                _SECRET_SHARED_SIGNED_INTEGER_MODULUS - 2,
                _SECRET_SHARED_SIGNED_INTEGER_MODULUS
            )
            for i in range(len(key['cluster']['nodes']))
        ]
        shares = ciphertext
        for (i, share) in enumerate(shares):
            share[1] = (
                inverse_masks[share[0] - 1] * shares[i][1]
            ) % _SECRET_SHARED_SIGNED_INTEGER_MODULUS
        plaintext = _shamirs_recover(shares)

        # Field elements in the "upper half" of the field represent negative
        # integers.
        if plaintext > _PLAINTEXT_SIGNED_INTEGER_MAX:
            plaintext -= _SECRET_SHARED_SIGNED_INTEGER_MODULUS

        return plaintext

    raise error

def allot(
        document: Union[int, bool, str, list, dict]
    ) -> Sequence[Union[int, bool, str, list, dict]]:
    """
    Convert a document that may contain ciphertexts intended for multiple-node
    clusters into secret shares of that document. Shallow copies are created
    whenever possible.

    >>> d = {
    ...     'id': 0,
    ...     'age': {'%allot': [1, 2, 3]},
    ...     'dat': {'loc': {'%allot': [4, 5, 6]}}
    ... }
    >>> for d in allot(d): print(d)
    {'id': 0, 'age': {'%share': 1}, 'dat': {'loc': {'%share': 4}}}
    {'id': 0, 'age': {'%share': 2}, 'dat': {'loc': {'%share': 5}}}
    {'id': 0, 'age': {'%share': 3}, 'dat': {'loc': {'%share': 6}}}

    A document with no ciphertexts intended for decentralized clusters is
    unmodofied; a list containing this document is returned.

    >>> allot({'id': 0, 'age': 23})
    [{'id': 0, 'age': 23}]

    Any attempt to convert a document that has an incorrect structure raises
    an exception.

    >>> allot({1, 2, 3})
    Traceback (most recent call last):
      ...
    TypeError: boolean, integer, float, string, list, dictionary, or None expected
    >>> allot({'id': 0, 'age': {'%allot': [1, 2, 3], 'extra': [1, 2, 3]}})
    Traceback (most recent call last):
      ...
    ValueError: allotment must only have one key
    >>> allot({
    ...     'id': 0,
    ...     'age': {'%allot': [1, 2, 3]},
    ...     'dat': {'loc': {'%allot': [4, 5]}}
    ... })
    Traceback (most recent call last):
      ...
    ValueError: number of shares in subdocument is not consistent
    """
    # Values and ``None`` are base cases; return a single share.
    if isinstance(document, (bool, int, float, str)) or document is None:
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
                    raise ValueError('number of shares is not consistent')

        # Create and return the appropriate number of shares.
        shares = []
        for i in range(multiplicity):
            share = []
            for result in results:
                share.append(result[0 if len(result) == 1 else i])
            shares.append(share)

        return shares

    if isinstance(document, dict):
        # Document contains shares obtained from the ``encrypt`` function
        # that must be allotted to nodes.
        if '%allot' in document:
            if len(document.keys()) != 1:
                raise ValueError('allotment must only have one key')

            items = document['%allot']
            if isinstance(items, list):

                # Simple allotment.
                if (
                    all(isinstance(item, int) for item in items) or
                    all(isinstance(item, str) for item in items)
                ):
                    return [{'%share': item} for item in document['%allot']]

                # More complex allotment with nested lists of shares.
                return [
                    {'%share': [share['%share'] for share in shares]}
                    for shares in allot([{'%allot': item} for item in items])
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
        'boolean, integer, float, string, list, dictionary, or None expected'
    )

def unify(
        secret_key: SecretKey,
        documents: Sequence[Union[int, bool, str, list, dict]],
        ignore: Sequence[str] = None
    ) -> Union[int, bool, str, list, dict]:
    """
    Convert an object that may contain ciphertexts intended for multiple-node
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
    ...     'a': [True, 'v', {'%allot': encrypt(sk, 12)}],
    ...     'b': [False, 'w', {'%allot': encrypt(sk, 34)}],
    ...     'c': [True, 'x', {'%allot': encrypt(sk, 56)}],
    ...     'd': [False, 'y', {'%allot': encrypt(sk, 78)}],
    ...     'e': [True, 'z', {'%allot': encrypt(sk, 90)}],
    ... }
    >>> shares = allot(encrypted)
    >>> decrypted = unify(sk, shares)
    >>> data == decrypted
    True

    It is possible to wrap nested lists of shares to reduce the overhead
    associated with the ``{'%allot': ...}`` and ``{'%share': ...}`` wrappers.

    >>> data = {
    ...     'a': [1, [2, 3]],
    ...     'b': [4, 5, 6],
    ...     'c': None,
    ...     'd': 1.23
    ... }
    >>> sk = SecretKey.generate({'nodes': [{}, {}, {}]}, {'store': True})
    >>> encrypted = {
    ...     'a': {'%allot': [encrypt(sk, 1), [encrypt(sk, 2), encrypt(sk, 3)]]},
    ...     'b': {'%allot': [encrypt(sk, 4), encrypt(sk, 5), encrypt(sk, 6)]},
    ...     'c': None,
    ...     'd': 1.23
    ... }
    >>> shares = allot(encrypted)
    >>> decrypted = unify(sk, shares)
    >>> data == decrypted
    True

    The ``ignore`` parameter specifies which keys should be ignored during
    unification. By default, ``'_created'`` and ``'_updated'`` are ignored.

    >>> shares[0]['_created'] = '123'
    >>> shares[1]['_created'] = '456'
    >>> shares[2]['_created'] = '789'
    >>> shares[0]['_updated'] = 'ABC'
    >>> shares[1]['_updated'] = 'DEF'
    >>> shares[2]['_updated'] = 'GHI'
    >>> decrypted = unify(sk, shares)
    >>> data == decrypted
    True
    """
    if ignore is None:
        ignore = ['_created', '_updated']

    if len(documents) == 1:
        return documents[0]

    if all(isinstance(document, list) for document in documents):
        length = len(documents[0])
        if all(len(document) == length for document in documents[1:]):
            return [
                unify(secret_key, [share[i] for share in documents], ignore)
                for i in range(length)
            ]

    if all(isinstance(document, dict) for document in documents):
        # Documents are shares.
        if all('%share' in document for document in documents):

            # Simple document shares.
            if (
                all(isinstance(d['%share'], int) for d in documents) or
                all(isinstance(d['%share'], str) for d in documents)
            ):
                return decrypt(
                    secret_key,
                    [document['%share'] for document in documents]
                )

            # Document shares consisting of nested lists of shares.
            return [
                unify(
                    secret_key,
                    [{'%share': share} for share in shares],
                    ignore
                )
                for shares in zip(*[document['%share'] for document in documents])
            ]

        # Documents are general-purpose key-value mappings.
        keys = documents[0].keys()
        if all(document.keys() == keys for document in documents[1:]):
            # For ignored keys, unification is not performed and
            # they are omitted from the results.
            keys = [key for key in keys if key not in ignore]
            results = {}
            for key in keys:
                results[key] = unify(
                    secret_key,
                    [document[key] for document in documents],
                    ignore
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
