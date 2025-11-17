"""
Python library for working with encrypted data within nilDB queries and
replies.
"""
from __future__ import annotations
from typing import Union, Optional, Sequence, Callable
import doctest
import base64
import secrets
import hashlib
from parts import parts
from hkdfs import hkdfs
import bcl
import shamirs
import pailliers

_PAILLIER_KEY_LENGTH: int = 2048
"""Length in bits of Paillier keys."""

_SECRET_SHARED_SIGNED_INTEGER_MODULUS: int = (2 ** 32) + 15
"""Modulus to use for secret shares of 32-bit signed integers."""

_PLAINTEXT_SIGNED_INTEGER_MIN: int = -(2 ** 31)
"""Minimum plaintext 32-bit signed integer value that can be encrypted."""

_PLAINTEXT_SIGNED_INTEGER_MAX: int = (2 ** 31) - 1
"""Maximum plaintext 32-bit signed integer value that can be encrypted."""

_PLAINTEXT_STRING_BUFFER_LEN_MAX: int = 4096
"""Maximum length of plaintext string value that can be encrypted."""

_HASH: Callable[[Union[bytes, bytearray]], hashlib._hashlib.HASH] = hashlib.sha512
"""
Hash function used for HKDF and deterministic encryption compatible with matching.
"""

def _xor(a: Union[bytes, bytearray], b: Union[bytes, bytearray]) -> bytes:
    """
    Return the bitwise XOR of two arrays of bytes.

    :param a: First argument.
    :param b: Second argument.
    """
    return bytes(a_i ^ b_i for (a_i, b_i) in zip(a, b))

def _random_bytes(
        length: int,
        seed: Optional[Union[bytes, bytearray]] = None,
        salt: Optional[Union[bytes, bytearray]] = None
    ) -> bytes:
    """
    Return a random :obj:`bytes` value of the specified length (using
    the seed if one is supplied).

    :param length: Target length of random :obj:`bytes` value.
    :param seed: Seed from which to deterministically derive the result.
    :param salt: Salt to use during deterministic derivation.
    """
    if seed is not None:
        return hkdfs(length, seed, salt or bytes(0), hash=_HASH)

    return secrets.token_bytes(length)

def _random_int(
        minimum: int,
        maximum: int,
        seed: Optional[Union[bytes, bytearray]] = None
    ) -> int:
    """
    Return a random integer value within the specified range (using
    the seed if one is supplied) by leveraging rejection sampling.
    
    :param minimum: Minimum permitted integer value (inclusive).
    :param maximum: Maximum permitted integer value (inclusive).
    :param seed: Seed from which to deterministically derive the result.

    This function relies on rejection sampling both in its implementation and
    indirectly via :obj:`random.randbelow`.

    >>> _random_int(-1, 1)
    Traceback (most recent call last):
      ...
    ValueError: minimum must be 0 or 1
    >>> _random_int(1, -1)
    Traceback (most recent call last):
      ...
    ValueError: maximum must be greater than the minimum and less than the modulus
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

def _pack(b: Union[bytes, bytearray]) -> str:
    """
    Encode a bytes-like object as a Base64 string (for compatibility with JSON).

    :param b: Data to encode.
    """
    return base64.b64encode(b).decode('ascii')

def _unpack(s: str) -> bytes:
    """
    Decode a bytes-like object from its Base64 string encoding.

    :param s: String to decode.
    """
    return base64.b64decode(s)

def _encode(value: Union[int, str, bytes, bytearray]) -> bytes:
    """
    Encode an integer, string, or binary plaintext as a binary value
    (keeping track of type information in the first byte).

    :param value: Value to encode as binary data.

    The encoding includes information about the type of the value in
    the first byte (to enable decoding without any additional context).

    >>> _encode(123).hex()
    '007b00008000000000'
    >>> _encode('abc').hex()
    '01616263'
    >>> _encode(bytes([1, 2, 3])).hex()
    '02010203'
    >>> _encode(bytearray([1, 2, 3])).hex()
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

    if isinstance(value, (bytes, bytearray)):
        return bytes([2]) + value

    raise ValueError('cannot encode value')

def _decode(value: Union[bytes, bytearray]) -> Union[int, str, bytes]:
    """
    Decode a binary value back into an integer, string, or binary plaintext.

    :param value: Binary data to decode into a value.

    This function complements :obj:`_encode`.

    >>> _decode(_encode(123))
    123
    >>> _decode(_encode('abc'))
    'abc'
    >>> _decode(_encode(bytes([1, 2, 3])))
    b'\\x01\\x02\\x03'
    >>> _decode(_encode(bytearray([1, 2, 3])))
    b'\\x01\\x02\\x03'

    If a value cannot be decoded, an exception is raised.

    >>> _decode([1, 2, 3])
    Traceback (most recent call last):
      ...
    TypeError: value must be a bytes-like object
    >>> _decode(bytes([3]))
    Traceback (most recent call last):
      ...
    ValueError: cannot decode value
    """
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError('value must be a bytes-like object')

    if value[0] == 0: # Indicates encoded value is a 32-bit signed integer.
        integer = int.from_bytes(value[1:], 'little')
        return integer + _PLAINTEXT_SIGNED_INTEGER_MIN

    if value[0] == 1: # Indicates encoded value is a UTF-8 string.
        return value[1:].decode('UTF-8')

    if value[0] == 2: # Indicates encoded value is binary data.
        return value[1:]

    raise ValueError('cannot decode value')

def _validate_cluster_configuration(cluster: dict):
    """
    Ensure the provided cluster configuration is valid.

    :param cluster: Cluster configuration.

    A configuration must satisfy independent requirements that govern its type
    and what keys/values it must have.

    >>> _validate_cluster_configuration([{}, {}, {}])
    Traceback (most recent call last):
      ...
    TypeError: cluster configuration must be a dictionary
    >>> _validate_cluster_configuration({})
    Traceback (most recent call last):
      ...
    ValueError: cluster configuration must specify nodes
    >>> _validate_cluster_configuration({'nodes': 123})
    Traceback (most recent call last):
      ...
    TypeError: cluster configuration node specification must be a sequence
    >>> _validate_cluster_configuration({'nodes': []})
    Traceback (most recent call last):
      ...
    ValueError: cluster configuration must contain at least one node

    This function does not check the supplied arguments against requirements
    for particular key types. Those checks are performed within the methods
    of specific key classes.
    """
    # Check the cluster configuration.
    if not isinstance(cluster, dict):
        raise TypeError('cluster configuration must be a dictionary')

    if 'nodes' not in cluster:
        raise ValueError('cluster configuration must specify nodes')

    if not isinstance(cluster['nodes'], Sequence):
        raise TypeError(
            'cluster configuration node specification must be a sequence'
        )

    if len(cluster['nodes']) < 1:
        raise ValueError('cluster configuration must contain at least one node')

def _validate_operations_specification(operations: dict):
    """
    Ensure the provided operations specification is valid.

    :param specification: Operations specification.

    A specification must satisfy independent requirements that govern its type
    and what keys/values it must have.

    >>> _validate_operations_specification([])
    Traceback (most recent call last):
      ...
    TypeError: operations specification must be a dictionary
    >>> _validate_operations_specification({'foo': True})
    Traceback (most recent call last):
      ...
    ValueError: permitted operations are limited to store, match, and sum
    >>> _validate_operations_specification({'store': 123})
    Traceback (most recent call last):
      ...
    TypeError: operations specification values must be boolean
    >>> _validate_operations_specification({'store': True, 'sum': True})
    Traceback (most recent call last):
      ...
    ValueError: operations specification must designate exactly one operation

    This function does not check the supplied arguments against requirements
    for particular key types. Those checks are performed within the methods
    of specific key classes.
    """
    # Check the operations specification.
    if not isinstance(operations, dict):
        raise TypeError('operations specification must be a dictionary')

    if not set(operations.keys()).issubset({'store', 'match', 'sum'}):
        raise ValueError(
            'permitted operations are limited to store, match, and sum'
        )

    if not all(isinstance(value, bool) for value in operations.values()):
        raise TypeError('operations specification values must be boolean')

    if len([op for (op, status) in operations.items() if status]) != 1:
        raise ValueError(
            'operations specification must designate exactly one operation'
        )

def _validate_key_attributes(
        cluster: dict,
        operations: dict,
        threshold: Optional[int] = None
    ):
    """
    Ensure the provided cluster configuration, operations specification, and
    threshold are valid and compatible with one another.

    :param cluster: Cluster configuration.
    :param operations: Specification of supported operations on ciphertexts.
    :param threshold: Lower bound on number of parties required to decrypt a
        ciphertext.

    The threshold parameter is checked for its independent validity.

    >>> _validate_key_attributes({'nodes': [{}, {}, {}]}, {'sum': True}, 'abc')
    Traceback (most recent call last):
      ...
    TypeError: threshold must be an integer

    Furthermore, the supplied arguments must also be compatible and consistent
    with one another.

    >>> _validate_key_attributes({'nodes': [{}, {}, {}]}, {'sum': True}, 4)
    Traceback (most recent call last):
      ...
    ValueError: threshold must be a positive integer not larger than the cluster size
    >>> _validate_key_attributes({'nodes': [{}]}, {'sum': True}, 2)
    Traceback (most recent call last):
      ...
    ValueError: thresholds are only supported for multiple-node clusters
    >>> _validate_key_attributes({'nodes': [{}, {}, {}]}, {'sum': True}, 4)
    Traceback (most recent call last):
      ...
    ValueError: threshold must be a positive integer not larger than the cluster size
    >>> _validate_key_attributes({'nodes': [{}, {}, {}]}, {'match': True}, 2)
    Traceback (most recent call last):
      ...
    ValueError: thresholds are only supported for the store and sum operations

    This function does not check the supplied arguments against requirements
    for particular key types. Those checks are performed within the methods
    of specific key classes.
    """
    # Check the threshold value (if one is supplied).
    if threshold is not None:
        if not isinstance(threshold, int):
            raise TypeError('threshold must be an integer')

        if len(cluster['nodes']) == 1:
            raise ValueError(
                'thresholds are only supported for multiple-node clusters'
            )

        if threshold < 1 or threshold > len(cluster['nodes']):
            raise ValueError(
                'threshold must be a positive integer not larger than the cluster size'
            )


        if (not operations.get('store')) and (not operations.get('sum')):
            raise ValueError(
                'thresholds are only supported for the store and sum operations'
            )

class SecretKey(dict):
    """
    Data structure for representing all categories of secret key instances.
    """

    _paillier_key_length: int = _PAILLIER_KEY_LENGTH
    """
    Static parameter for Paillier cryptosystem (introduced in order to allow
    modification in tests).
    """

    def __init__(
        self: SecretKey,
        cluster: dict,
        operations: dict,
        threshold: Optional[int] = None
    ):
        """
        Create an instance of a secret key after checking that all arguments are valid.
        """
        _validate_cluster_configuration(cluster)
        _validate_operations_specification(operations)
        _validate_key_attributes(cluster, operations, threshold)

        self['cluster'] = cluster
        self['operations'] = operations

        if threshold is not None:
            self['threshold'] = threshold

    @staticmethod
    def generate(
        cluster: dict,
        operations: dict,
        threshold: Optional[int] = None,
        seed: Optional[Union[bytes, bytearray, str]] = None
    ) -> SecretKey:
        """
        Return a secret key built according to what is specified in the supplied
        cluster configuration, operations specification, and other parameters.

        :param cluster: Cluster configuration for this key.
        :param operations: Specification of supported operations on ciphertexts.
        :param threshold: Minimum number of parties required to decrypt a
            ciphertext.
        :param seed: Seed from which to deterministically derive cryptographic
            material.

        The supplied arguments determine which encryption protocol is used when
        encrypting ciphertexts with this key.

        >>> sk = SecretKey.generate({'nodes': [{}]}, {'sum': True})
        >>> isinstance(sk, SecretKey)
        True

        Supplying an invalid combination of configurations and/or parameters
        raises a corresponding exception.

        >>> SecretKey.generate({'nodes': [{}]}, {'sum': True}, seed={})
        Traceback (most recent call last):
          ...
        TypeError: seed must be a bytes-like object or a string
        >>> SecretKey.generate({'nodes': [{}]}, {'sum': True}, threshold='abc')
        Traceback (most recent call last):
          ...
        TypeError: threshold must be an integer
        >>> SecretKey.generate({'nodes': [{}, {}]}, {'match': True}, threshold=1)
        Traceback (most recent call last):
          ...
        ValueError: thresholds are only supported for the store and sum operations
        >>> SecretKey.generate({'nodes': [{}]}, {'sum': True}, threshold=1)
        Traceback (most recent call last):
          ...
        ValueError: thresholds are only supported for multiple-node clusters
        >>> SecretKey.generate({'nodes': [{}, {}]}, {'sum': True}, threshold=-1)
        Traceback (most recent call last):
          ...
        ValueError: threshold must be a positive integer not larger than the cluster size
        >>> SecretKey.generate({'nodes': [{}, {}]}, {'sum': True}, threshold=3)
        Traceback (most recent call last):
          ...
        ValueError: threshold must be a positive integer not larger than the cluster size
        >>> SecretKey.generate({'nodes': [{}]}, {'sum': True}, seed=bytes([123]))
        Traceback (most recent call last):
          ...
        ValueError: seed-based ... summation-compatible ... not supported for single-node ...
        """
        secret_key = SecretKey(cluster, operations, threshold)

        if seed is not None and not isinstance(seed, (bytes, bytearray, str)):
            raise TypeError('seed must be a bytes-like object or a string')

        # Normalize type of seed argument.
        if isinstance(seed, str):
            seed = seed.encode()

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
                    raise ValueError(
                        'seed-based derivation of summation-compatible secret keys ' +
                        'is not supported for single-node clusters'
                    )
                secret_key['material'] = pailliers.secret(SecretKey._paillier_key_length)
            else:
                # Distinct multiplicative mask for each share.
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

    def _modulus(self: SecretKey, silent: bool = False) -> int:
        """
        Return the modulus governing the domain of plaintexts of the Paillier,
        additive, or Shamir's scheme corresponding to this key instance.

        :param silent: Return ``None`` if there is no associated modulus.

        The optional argument ``silent`` can be used to ensure this method
        returns ``None`` if the scheme associated with a key instance has no
        modulus.

        >>> sk = SecretKey.generate({'nodes': [{}, {}, {}]}, {'store': True}, 2)
        >>> isinstance(sk._modulus(), int)
        True
        >>> sk = SecretKey.generate({'nodes': [{}]}, {'sum': True})
        >>> isinstance(sk._modulus(), int)
        True
        >>> sk = SecretKey.generate({'nodes': [{}, {}]}, {'sum': True})
        >>> isinstance(sk._modulus(), int)
        True
        >>> sk = SecretKey.generate({'nodes': [{}, {}, {}]}, {'sum': True}, 2)
        >>> isinstance(sk._modulus(), int)
        True
        >>> SecretKey.generate(
        ...     {'nodes': [{}]},
        ...     {'store': True}
        ... )._modulus(True) is None
        True

        If the ``silent`` argument is not ``True`` and no modulus is associated
        with this instance, an exception is raised.

        >>> SecretKey.generate({'nodes': [{}]}, {'store': True})._modulus()
        Traceback (most recent call last):
          ...
        ValueError: scheme associated with key has no modulus
        >>> SecretKey.generate({'nodes': [{}, {}]}, {'store': True})._modulus()
        Traceback (most recent call last):
          ...
        ValueError: scheme associated with key has no modulus
        >>> SecretKey.generate({'nodes': [{}]}, {'match': True})._modulus()
        Traceback (most recent call last):
          ...
        ValueError: scheme associated with key has no modulus
        """
        if isinstance(self.get('threshold'), int):
            return _SECRET_SHARED_SIGNED_INTEGER_MODULUS

        if self.get('operations').get('sum'):
            return (
                self.get('material')[2]
                if len(self['cluster']['nodes']) == 1 else
                _SECRET_SHARED_SIGNED_INTEGER_MODULUS
            )

        if silent:
            return None

        raise ValueError('scheme associated with key has no modulus')

    def dump(self: SecretKey) -> dict:
        """
        Return a JSON-compatible dictionary representation of this key
        instance. This method complements the :obj:`load` method.
        """
        dictionary = {
            'material': {},
            'cluster': self['cluster'],
            'operations': self['operations'],
        }
        if 'threshold' in self:
            dictionary['threshold'] = self['threshold']

        if isinstance(self['material'], list):
            # Node-specific masks for secret shares (for sum operations).
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

        :param dictionary: Dictionary representation of a secret key.

        This method complements the :obj:`dump` method and also makes it
        possible to work with JSON representations of keys.

        >>> sk = SecretKey.generate({'nodes': [{}]}, {'store': True})
        >>> import json
        >>> sk_json = json.dumps(sk.dump())
        >>> sk == SecretKey.load(json.loads(sk_json))
        True

        Any attempt to supply an invalid input raises an exception.

        >>> SecretKey.load('abc')
        Traceback (most recent call last):
          ...
        TypeError: dictionary expected
        """
        if not isinstance(dictionary, dict):
            raise TypeError('dictionary expected')

        cluster = dictionary.get('cluster')
        operations = dictionary.get('operations')
        threshold = dictionary.get('threshold')
        secret_key = SecretKey(cluster, operations, threshold)

        # Validate and normalize/wrap the key material.
        material = dictionary.get('material')

        if operations.get('store'):
            # A symmetric key (to encrypt individual values or secret shares)
            # is expected.
            if not isinstance(material, str):
                raise TypeError(
                    'operations specification requires key material to be a string'
                )

            buffer = _unpack(material)
            if len(buffer) != 32:
                raise ValueError('key material must have a length of 32 bytes')

            # Wrap the key material in the expected symmetric key class.
            secret_key['material'] = bytes.__new__(bcl.secret, buffer)

        elif operations.get('match'):
            # A salt for hashing is expected.
            if not isinstance(material, str):
                raise TypeError(
                    'operations specification requires key material to be a string'
                )

            buffer = _unpack(material)
            if len(buffer) != 64:
                raise ValueError('key material must have a length of 64 bytes')

            secret_key['material'] = buffer

        elif operations.get('sum') and len(cluster['nodes']) == 1:
            # Paillier secret key (to support summation-compatible encryption for
            # single-node clusters) is expected.
            if not isinstance(material, dict):
                raise TypeError(
                    'operations specification requires key material to be a dictionary'
                )

            if not all(parameter in material for parameter in 'lmng'):
                raise ValueError(
                    'key material must contain all required parameters'
                )

            if not all(
                isinstance(material[parameter], str)
                for parameter in ['l', 'm', 'n', 'g']
            ):
                raise TypeError('key material parameter values must be strings')

            try:
                parameters = tuple(int(material[parameter]) for parameter in 'lmng')
            except Exception as exc:
                raise ValueError(
                    'key material parameter strings must be convertible to integer values'
                ) from exc

            # Checking that the material contents (provided as integers represent
            # values that are within the correct range is the responsibility of the
            # constructor from the imported library.
            secret_key['material'] = tuple.__new__(pailliers.secret, parameters)

        elif operations.get('sum') and len(cluster['nodes']) > 1:

            # Node-specific masks for secret shares (to support summation-compatible
            # encryption for multiple-node clusters) are expected.

            if not isinstance(material, list):
                raise TypeError(
                    'operations specification requires key material to be a list'
                )

            if len(material) != len(cluster['nodes']):
                raise ValueError(
                    'cluster configuration requires key material to have length ' +
                    str(len(cluster['nodes']))
                )

            # Ensure the masks are integers and that the integers are in the right
            # range to represent multiplicative masks.
            if not all(isinstance(k, int) for k in material):
                raise TypeError('key material must contain integers')

            if not all(
                1 <= k < _SECRET_SHARED_SIGNED_INTEGER_MODULUS
                for k in material
            ):
                raise ValueError(
                    'key material must contain integers within the correct range'
                )

            secret_key['material'] = material

        return secret_key

class ClusterKey(SecretKey):
    """
    Data structure for representing all categories of cluster key instances.
    """
    @staticmethod
    def generate( # pylint: disable=arguments-differ # Seeds not supported.
        cluster: dict,
        operations: dict,
        threshold: Optional[int] = None
    ) -> ClusterKey:
        """
        Return a cluster key built according to what is specified in the supplied
        cluster configuration and operations specification.

        :param cluster: Cluster configuration for this key.
        :param operations: Specification of supported operations on ciphertexts.
        :param threshold: Minimum number of parties required to decrypt a
            ciphertext.

        The supplied arguments determine which encryption protocol is used when
        encrypting ciphertexts with this key.

        >>> ck = ClusterKey.generate({'nodes': [{}, {}, {}]}, {'sum': True})
        >>> isinstance(ck, ClusterKey)
        True

        Cluster keys can only be created for clusters that have two or more
        nodes and can only enable encryption for storage and summation
        compatibility.

        >>> ClusterKey.generate({'nodes': [{}]}, {'store': True})
        Traceback (most recent call last):
          ...
        ValueError: cluster configuration must contain at least two nodes
        >>> ClusterKey.generate({'nodes': [{}, {}, {}]}, {'match': True})
        Traceback (most recent call last):
          ...
        ValueError: cluster keys cannot support matching-compatible encryption
        """
        _validate_cluster_configuration(cluster)

        if len(cluster['nodes']) == 1:
            raise ValueError('cluster configuration must contain at least two nodes')

        _validate_operations_specification(operations)

        if operations.get('match'):
            raise ValueError(
                'cluster keys cannot support matching-compatible encryption'
            )

        _validate_key_attributes(cluster, operations, threshold)
        
        cluster_key = SecretKey(cluster, operations, threshold)
        cluster_key.__class__ = ClusterKey

        return cluster_key

    def dump(self: ClusterKey) -> dict:
        """
        Return a JSON-compatible dictionary representation of this key
        instance. This method complements the :obj:`load` method.
        """
        dictionary = {
            'cluster': self['cluster'],
            'operations': self['operations']
        }
        if 'threshold' in self:
            dictionary['threshold'] = self['threshold']

        return dictionary

    @staticmethod
    def load(dictionary: dict) -> ClusterKey:
        """
        Return an instance built from a JSON-compatible dictionary
        representation.

        :param dictionary: Dictionary representation of a cluster key.

        This method complements the :obj:`dump` method and also makes it
        possible to work with JSON representations of keys.

        >>> cluster = {'nodes': [{}, {}, {}]}
        >>> ck = ClusterKey.generate(cluster, {'sum': True}, threshold=2)
        >>> import json
        >>> ck_json = json.dumps(ck.dump())
        >>> ck == ClusterKey.load(json.loads(ck_json))
        True

        Any attempt to supply an invalid input raises an exception.

        >>> ClusterKey.load('abc')
        Traceback (most recent call last):
          ...
        TypeError: dictionary expected
        >>> ClusterKey.load({
        ...    'cluster': {'nodes': [{}, {}]},
        ...    'operations': {'store': True},
        ...    'material': 'abc'
        ... })
        Traceback (most recent call last):
          ...
        ValueError: cluster keys cannot contain key material
        """
        if not isinstance(dictionary, dict):
            raise TypeError('dictionary expected')

        cluster = dictionary.get('cluster')
        _validate_cluster_configuration(cluster)

        if len(cluster['nodes']) == 1:
            raise ValueError('cluster configuration must contain at least two nodes')

        operations = dictionary.get('operations')
        _validate_operations_specification(operations)

        if operations.get('match'):
            raise ValueError(
                'cluster keys cannot support matching-compatible encryption'
            )

        threshold = dictionary.get('threshold')
        _validate_key_attributes(cluster, operations, threshold)

        if 'material' in dictionary:
            raise ValueError('cluster keys cannot contain key material')

        return ClusterKey(cluster, operations, threshold)

class PublicKey(dict):
    """
    Data structure for representing all categories of public key instances.
    """
    @staticmethod
    def generate(secret_key: SecretKey) -> PublicKey:
        """
        Return a public key built according to what is specified in the supplied
        secret key.

        :param secret_key: Secret key from which to derive this public key.

        A public key can only be derived from a compatible secret key.

        >>> sk = SecretKey.generate({'nodes': [{}]}, {'sum': True})
        >>> isinstance(PublicKey.generate(sk), PublicKey)
        True
        >>> ck = SecretKey.generate({'nodes': [{}, {}]}, {'sum': True})
        >>> PublicKey.generate(ck)
        Traceback (most recent call last):
          ...
        TypeError: secret key material must be of the correct type
        >>> ck = ClusterKey.generate({'nodes': [{}, {}]}, {'sum': True})
        >>> PublicKey.generate(ck)
        Traceback (most recent call last):
          ...
        TypeError: secret key expected
        """
        # No internal validation of the supplied secret key is performed 
        # beyond what is necessary for the generation of this public key. 
        # It is also assumed that the encapsulated key from the Paillier 
        # cryptosystem library has valid internal structure.

        if isinstance(secret_key, ClusterKey) or not isinstance(secret_key, SecretKey):
            raise TypeError('secret key expected')

        if not isinstance(secret_key.get('material'), pailliers.secret):
            raise TypeError('secret key material must be of the correct type')

        return PublicKey({
            'cluster': secret_key['cluster'],
            'operations': secret_key['operations'],
            'material': pailliers.public(secret_key['material'])
        })

    def dump(self: PublicKey) -> dict:
        """
        Return a JSON-compatible dictionary representation of this key
        instance. This method complements the :obj:`load` method.
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
    def load(dictionary: dict) -> PublicKey:
        """
        Return an instance built from a JSON-compatible dictionary
        representation.

        :param dictionary: Dictionary representation of a public key.

        This method complements the :obj:`dump` method and also makes it
        possible to work with JSON representations of keys.

        >>> sk = SecretKey.generate({'nodes': [{}]}, {'sum': True})
        >>> pk = PublicKey.generate(sk)
        >>> import json
        >>> pk_json = json.dumps(pk.dump())
        >>> pk == PublicKey.load(pk.dump())
        True

        Any attempt to supply an invalid input raises an exception.

        >>> PublicKey.load('abc')
        Traceback (most recent call last):
          ...
        TypeError: dictionary expected
        >>> PublicKey.load({
        ...    'cluster': {'nodes': [{}]},
        ...    'operations': {'sum': True},
        ...    'threshold': 3
        ... })
        Traceback (most recent call last):
          ...
        ValueError: public keys cannot specify a threshold
        """
        if not isinstance(dictionary, dict):
            raise TypeError('dictionary expected')

        cluster = dictionary.get('cluster')
        _validate_cluster_configuration(cluster)

        if len(cluster['nodes']) != 1:
            raise ValueError(
                'public keys are only supported for single-node clusters'
            )

        operations = dictionary.get('operations')
        _validate_operations_specification(operations)

        if 'sum' not in operations:
            raise ValueError('public keys can only support the sum operation')

        if 'threshold' in dictionary:
            raise ValueError('public keys cannot specify a threshold')

        _validate_key_attributes(cluster, operations)

        material = dictionary.get('material')

        if not isinstance(material, dict):
            raise TypeError('key material must be a dictionary')

        if not ('n' in material and 'g' in material):
            raise ValueError(
                'key material does not contain all required parameters'
            )

        if not (isinstance(material['n'], str) and isinstance(material['g'], str)):
            raise TypeError('key material dictionary values must be strings')

        public_key = PublicKey({'cluster': cluster, 'operations': operations})

        try:
            parameters = tuple(int(material[parameter]) for parameter in 'ng')
        except Exception as exc:
            raise ValueError(
                'key material parameter strings must be convertible to integer values'
            ) from exc

        # Checking that the material contents (provided as integers represent
        # values that are within the correct range is the responsibility of the
        # constructor from the imported library.
        public_key['material'] = tuple.__new__(pailliers.public, parameters)

        return public_key

def encrypt(
        key: Union[SecretKey, ClusterKey, PublicKey],
        plaintext: Union[int, str, bytes, bytearray]
    ) -> Union[str, Sequence[str], Sequence[int], Sequence[Sequence[int]]]:
    """
    Return the ciphertext obtained by using the supplied key to encrypt the
    supplied plaintext.

    :param key: Key to use for performing encryption.
    :param plaintext: Plaintext to encrypt.

    The supplied key determines which protocol is used to perform the encryption.

    >>> sk = SecretKey.generate({'nodes': [{}]}, {'store': True})
    >>> len(encrypt(sk, 'abc'))
    60
    >>> sk = SecretKey.generate({'nodes': [{}]}, {'match': True}, seed='xyz')
    >>> encrypt(sk, 'abc')[:70]
    'Y3V9Nm4o3F5cTEy+oy3utP19m8XA1eMQ2zFfQiEdGpkE92g4X7eXy4T1yH4u1aBtw0FUs0'
    >>> sk = SecretKey.generate({'nodes': [{}]}, {'sum': True})
    >>> pk = PublicKey.generate(sk)
    >>> isinstance(encrypt(pk, 123), str)
    True
    >>> sk = SecretKey.generate({'nodes': [{}, {}]}, {'store': True})
    >>> shares = encrypt(sk, 'abc')
    >>> len(shares) == 2 and all(isinstance(share, str) for share in shares)
    True
    >>> ck = ClusterKey.generate({'nodes': [{}, {}, {}]}, {'sum': True})
    >>> shares = encrypt(ck, 123)
    >>> len(shares) == 3 and all(isinstance(share, int) for share in shares)
    True

    When encrypting for a single-node cluster in a summation-compatible way, it
    is possible to supply the secret key. However, this introduces a performance
    overhead because a public key must be generated in this case.

    >>> sk = SecretKey.generate({'nodes': [{}]}, {'sum': True})
    >>> isinstance(encrypt(sk, 123), str)
    True

    Invocations that involve invalid argument values or types may raise an
    exception. The type of the ``key`` argument is checked. Incompatibilities
    between the key's attribute values and the supplied ``plaintext`` argument
    are detected. However, the values associated with those attributes (such as
    the cluster configuration, the cryptographic material associated with the
    supplied key, interdependencies between these, and so on) are not checked
    for validity.

    >>> encrypt('abc', 123)
    Traceback (most recent call last):
      ...
    TypeError: secret key, cluster key, or public key expected
    >>> key = SecretKey.generate({'nodes': [{}]}, {'sum': True})
    >>> encrypt(key, {})
    Traceback (most recent call last):
      ...
    TypeError: plaintext must be string, integer, or bytes-like object
    >>> encrypt(key, 'abc')
    Traceback (most recent call last):
      ...
    TypeError: summation-compatible encryption requires a numeric plaintext
    >>> encrypt(key, 2 ** 64)
    Traceback (most recent call last):
      ...
    ValueError: numeric plaintext must be a valid 32-bit signed integer
    >>> del key['operations']['sum']
    >>> encrypt(key, 123)
    Traceback (most recent call last):
      ...
    ValueError: cannot encrypt the supplied plaintext using the supplied key
    """
    if not isinstance(key, (SecretKey, ClusterKey, PublicKey)):
        raise TypeError('secret key, cluster key, or public key expected')

    # Local variable for the encoded binary representation of the plaintext.
    # This variable may or may not be used depending on the supplied key and
    # plaintext type.
    buffer = None

    # Check and encode (for storage or matching) integer plaintext.
    if isinstance(plaintext, int):
        # Only 32-bit signed integer plaintexts are supported.
        if (
            plaintext < _PLAINTEXT_SIGNED_INTEGER_MIN or
            plaintext > _PLAINTEXT_SIGNED_INTEGER_MAX
        ):
            raise ValueError('numeric plaintext must be a valid 32-bit signed integer')

        # Encode an integer for storage or matching.
        buffer = _encode(plaintext)

    # Encode a string or binary plaintext for storage or matching.
    elif isinstance(plaintext, (str, bytes, bytearray)):
        buffer = _encode(plaintext)
        if len(buffer) > _PLAINTEXT_STRING_BUFFER_LEN_MAX + 1:
            raise ValueError(
                'string or binary plaintext must be at most ' +
                str(_PLAINTEXT_STRING_BUFFER_LEN_MAX) +
                ' bytes or fewer in length'
            )

    # Invalid plaintext.
    else:
        raise TypeError('plaintext must be string, integer, or bytes-like object')

    # Encrypt a plaintext for storage and retrieval.
    if key['operations'].get('store'):
        # The data or secret shares of the data might or might not be encrypted
        # by a symmetric key (depending on the supplied key's parameters).
        optional_enc = (
            (lambda s: bcl.symmetric.encrypt(key['material'], bcl.plain(s)))
            if 'material' in key else
            (lambda s: s)
        )

        # For single-node clusters, only a secret key can be used to encrypt for
        # storage. The data is encrypted using a symmetric key found in the supplied
        # secret key.
        if len(key['cluster']['nodes']) == 1:
            return _pack(optional_enc(buffer))

        # For multiple-node clusters and no threshold, a secret-shared plaintext
        # is obtained using XOR (with each share symmetrically encrypted in the
        # case of a secret key).
        if 'threshold' not in key:
            shares = []
            aggregate = bytes(len(buffer))
            for _ in range(len(key['cluster']['nodes']) - 1):
                mask = _random_bytes(len(buffer))
                aggregate = _xor(aggregate, mask)
                shares.append(optional_enc(mask))
            shares.append(optional_enc(_xor(aggregate, buffer)))
            return list(map(_pack, shares))

        # For multiple-node clusters and a threshold, the plaintext is secret-shared
        # using Shamir's secret sharing (with each share symmetrically encrypted in
        # the case of a secret key).
        padding = 4 - (len(buffer) % 4) # Padding to make length a multiple of four.
        buffer = bytes([255] * padding) + buffer # Pad until length is a multiple of four.
        subarrays = list(parts(buffer, length=4)) # Split into subarrays of length four.

        # Build up shares of the plaintext where each share is actually a list of
        # shares (one such share per subarray of the plaintext).
        shares_of_array = [[] for _ in range(len(key['cluster']['nodes']))]
        for subarray in subarrays:
            subarray_as_int = int.from_bytes(subarray, byteorder='little', signed=False)
            subarray_as_shares = [
                (share.index, share.value)
                for share in shamirs.shares(
                    plaintext=(subarray_as_int % _SECRET_SHARED_SIGNED_INTEGER_MODULUS),
                    quantity=len(key['cluster']['nodes']),
                    modulus=_SECRET_SHARED_SIGNED_INTEGER_MODULUS,
                    threshold=key['threshold'],
                    compact=True # Do not store modulus in share objects.
                )
            ]
            for (i, subarray_share) in enumerate(subarray_as_shares):
                shares_of_array[i].append(subarray_share)

        # Convert each share from a list (of subarray shares) representation into a
        # single integer representation.
        shares = []
        for (i, share_of_array) in enumerate(shares_of_array):
            # Each Shamir's share has an index and a value component. The index
            # will not change within each share (assuming the share indices are
            # always the same and in the same order). Therefore, the index is
            # only stored once to reduce its overhead.
            index = share_of_array[0][0].to_bytes(4, byteorder='little', signed=False)
            share_of_array_as_bytes = bytes(0) + index
            for subarray_share in share_of_array:
                value = subarray_share[1].to_bytes(5, byteorder='little', signed=False)
                share_of_array_as_bytes = share_of_array_as_bytes + value
            shares.append(_pack(optional_enc(share_of_array_as_bytes)))

        return shares

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
        # Non-integer plaintexts cannot be encrypted for summation.
        if not isinstance(plaintext, int):
            raise TypeError('summation-compatible encryption requires a numeric plaintext')

        # For single-node clusters, the Paillier cryptosystem is used. Only a
        # Paillier secret or public key can be used to encrypt for summation.
        if len(key['cluster']['nodes']) == 1:
            return hex(pailliers.encrypt(
              # Support encryption with either a public or secret key.
              (key if isinstance(key, PublicKey) else PublicKey.generate(key))['material'],
              plaintext
            ))[2:] # Drop '0x' prefix.

        # For multiple-node clusters and no threshold, additive secret sharing is used.
        if 'threshold' not in key:
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

        # For multiple-node clusters and a threshold, Shamir's secret sharing is used.
        masks = [
            key['material'][i] if 'material' in key else 1
            for i in range(len(key['cluster']['nodes']))
        ]
        shares = [
            (
                share.index,
                (masks[i] * share.value) % _SECRET_SHARED_SIGNED_INTEGER_MODULUS
            )
            for (i, share) in enumerate(shamirs.shares(
                plaintext=(plaintext % _SECRET_SHARED_SIGNED_INTEGER_MODULUS),
                quantity=len(key['cluster']['nodes']),
                modulus=_SECRET_SHARED_SIGNED_INTEGER_MODULUS,
                threshold=key['threshold'],
                compact=True # Do not store modulus in share objects.
            ))
        ]

        return shares

    # The below should not occur unless the key's cluster or operations
    # information is malformed/missing or the plaintext is unsupported.
    raise ValueError('cannot encrypt the supplied plaintext using the supplied key')

def decrypt(
        key: Union[SecretKey, ClusterKey],
        ciphertext: Union[str, Sequence[str], Sequence[int], Sequence[Sequence[int]]]
    ) -> Union[int, str, bytes]:
    """
    Return the plaintext obtained by using the supplied key to decrypt the
    supplied ciphertext.

    :param key: Key to use for performing decryption.
    :param ciphertext: Ciphertext to decrypt.

    The supplied key determines which protocol is used to perform the decryption.

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
    >>> key = SecretKey.generate({'nodes': [{}, {}]}, {'sum': True}, threshold=2)
    >>> decrypt(key, encrypt(key, 123))
    123
    >>> key = SecretKey.generate({'nodes': [{}, {}, {}, {}]}, {'sum': True}, threshold=3)
    >>> decrypt(key, encrypt(key, 123)[:-1])
    123
    >>> key = SecretKey.generate({'nodes': [{}, {}, {}, {}]}, {'sum': True}, threshold=2)
    >>> decrypt(key, encrypt(key, 123)[2:])
    123
    >>> key = SecretKey.generate({'nodes': [{}, {}]}, {'sum': True}, threshold=1)
    >>> decrypt(key, encrypt(key, 123)[1:])
    123
    >>> key = SecretKey.generate({'nodes': [{}, {}]}, {'sum': True}, threshold=2)
    >>> decrypt(key, encrypt(key, -10))
    -10

    A decryption threshold of ``1`` **is permitted** in order to accommodate
    seamlessly scenarios in which it may be useful to replicate plaintext or
    encrypted data across nodes (such as for redundancy).
    
    >>> key = SecretKey.generate({'nodes': [{}, {}, {}]}, {'store': True}, threshold=1)
    >>> decrypt(key, encrypt(key, 123)[:1])
    123
    >>> decrypt(key, encrypt(key, 123)[1:2])
    123
    >>> decrypt(key, encrypt(key, 123)[2:])
    123

    However, the use of a threshold of ``1``  incurs the same representation
    size overheads (compared to simply keeping copies of the same data on
    different nodes) as the use of larger threshold values. For example, note
    below that ``80`` > ``68`` and that ``28`` > ``8``.

    >>> key = SecretKey.generate({'nodes': [{}]}, {'store': True})
    >>> len(encrypt(key, 123))
    68
    >>> key = SecretKey.generate({'nodes': [{}, {}, {}]}, {'store': True}, threshold=1)
    >>> len(encrypt(key, 123)[0])
    80
    >>> key = SecretKey.generate({'nodes': [{}, {}, {}]}, {'store': True}, threshold=3)
    >>> len(encrypt(key, 123)[0])
    80
    >>> import base64
    >>> len(base64.b64encode(int(123).to_bytes(4, 'little')))
    8
    >>> key = ClusterKey.generate({'nodes': [{}, {}, {}]}, {'store': True}, threshold=1)
    >>> len(encrypt(key, 123)[0])
    28
    >>> key = ClusterKey.generate({'nodes': [{}, {}, {}]}, {'store': True}, threshold=3)
    >>> len(encrypt(key, 123)[0])
    28

    An exception is raised if a ciphertext cannot be decrypted using the
    supplied key (*e.g.*, because one or both are malformed or they are
    incompatible). The type of the``key`` argument is checked. Incompatibilities
    between the key's attribute values and the supplied ``ciphertext`` argument
    are detected. However, the values associated with those attributes (such as
    the cluster configuration, the cryptographic material associated with the
    supplied key, interdependencies between these, and so on) are not checked
    for validity.

    >>> decrypt('abc', 123)
    Traceback (most recent call last):
      ...
    TypeError: secret key or cluster key expected
    >>> key = SecretKey.generate({'nodes': [{}, {}]}, {'store': True})
    >>> decrypt(key, 'abc')
    Traceback (most recent call last):
      ...
    ValueError: key requires a valid ciphertext from a multiple-node cluster
    >>> key = SecretKey.generate({'nodes': [{}]}, {'store': True})
    >>> ciphertext = encrypt(key, 'abc')
    >>> key['operations'] = {}
    >>> decrypt(key, ciphertext)
    Traceback (most recent call last):
      ...
    ValueError: cannot decrypt the supplied ciphertext using the supplied key
    >>> key = SecretKey.generate({'nodes': [{}, {}]}, {'store': True})
    >>> key_alt = SecretKey.generate({'nodes': [{}, {}]}, {'store': True})
    >>> decrypt(key_alt, encrypt(key, 123))
    Traceback (most recent call last):
      ...
    ValueError: cannot decrypt the supplied ciphertext using the supplied key
    """
    if not isinstance(key, (SecretKey, ClusterKey)):
        raise TypeError('secret key or cluster key expected')

    error = ValueError(
        'cannot decrypt the supplied ciphertext using the supplied key'
    )

    # Identify common (i.e., not operation-specific) incompatibilities between
    # the supplied key and ciphertext.
    if len(key['cluster']['nodes']) == 1:
        if not isinstance(ciphertext, str):
            raise ValueError(
              'key requires a valid ciphertext from a single-node cluster'
            )
    else: # Key has a multiple-node cluster configuration.
        # Reject ciphertexts that are not compatible with multiple-node clusters.
        if isinstance(ciphertext, str) or not isinstance(ciphertext, Sequence):
            raise ValueError(
              'key requires a valid ciphertext from a multiple-node cluster'
            )

        # Reject share sequences that do not contain enough shares.
        if (
            isinstance(ciphertext, Sequence) and
            len(ciphertext) < (
                key['threshold']
                if 'threshold' in key else
                len(key['cluster']['nodes'])
            )
        ):
            raise ValueError(
              'ciphertext must have enough shares for cluster size or threshold'
            )

    # Decrypt a value that was encrypted for storage and retrieval.
    if key['operations'].get('store'):
        # The plaintext or secret shares of the plaintext might or might not
        # have been encrypted by a symmetric key (depending on the supplied key).
        optional_dec = (
            (lambda c: bcl.symmetric.decrypt(key['material'], bcl.cipher(c)))
            if 'material' in key else
            (lambda c: c)
        )

        # For single-node clusters, the plaintext is encrypted using a symmetric key.
        if len(key['cluster']['nodes']) == 1:
            # Ciphertext type already confirmed in common checks above.
            try:
                return _decode(optional_dec(_unpack(ciphertext)))
            except Exception as exc:
                raise error from exc

        # For multiple-node clusters, the ciphertext must be a sequence of shares
        # (each element being Base64-encoded binary value). The quantity of shares
        # is already confirmed during the common checks above.
        if not all(isinstance(c, str) for c in ciphertext):
            raise TypeError('secret shares must all be Base64-encoded binary values')

        # Each share consists of Base64-encoded (possibly encrypted) binary data.
        shares = [_unpack(share) for share in ciphertext]
        try:
            shares = [optional_dec(share) for share in shares]
        except Exception as exc:
            raise error from exc

        # For multiple-node clusters and no threshold, the plaintext is secret-shared
        # using XOR.
        if 'threshold' not in key:
            # Accept only sequences of XOR secret shares that all have the same length.
            if len({len(share) for share in shares}) != 1:
                raise ValueError('secret shares must have matching lengths')

            # Build up encoded plaintext as ``buffer``; its decoding is then returned.
            buffer = bytes(len(shares[0]))
            for share_ in shares:
                buffer = _xor(buffer, share_)

            return _decode(buffer)

        # For multiple-node clusters and a threshold, Shamir's secret sharing is used
        # to create a secret-shared plaintext.

        # Accept only sequences of shares having sufficient and matching lengths.
        lengths = list({len(share) for share in shares})
        if not (len(lengths) == 1 and lengths[0] >= 9):
            raise ValueError('secret shares must have sufficient and matching lengths')

        # Build up encoded plaintext as ``buffer``; its decoding is then returned.
        shares_of_plaintext = [list(parts(share[4:], length=5)) for share in shares]
        indices = [ # Ordered list of indices for the shares of the plaintext.
            int.from_bytes(share[:4], byteorder='little', signed=False)
            for share in shares
        ]
        number_of_plaintext_subarrays = len(shares_of_plaintext[0])
        buffer = bytes(0) # Accumulator for assembling plaintext (an array of bytes).
        for i in range(number_of_plaintext_subarrays): # Subarrays making up plaintext.
            subarray_shares = [
                [
                    indices[j],
                    int.from_bytes(subarray_share[i], byteorder='little', signed=False)
                ]
                for (j, subarray_share) in enumerate(shares_of_plaintext)
            ]
            subarray_as_int = shamirs.reveal(
                shares=[shamirs.share(*share) for share in subarray_shares],
                modulus=_SECRET_SHARED_SIGNED_INTEGER_MODULUS,
                threshold=key['threshold']
            )
            subarray_as_bytes = subarray_as_int.to_bytes(
                4,
                byteorder='little',
                signed=False
            )
            buffer += subarray_as_bytes

        # Drop padding bytes (added during encryption so that byte count is a
        # multiple of four).
        while buffer[0] == 255:
            buffer = buffer[1:]

        return _decode(buffer)

    # Decrypt a value that was encrypted in a summation-compatible way.
    if key['operations'].get('sum'):
        # For single-node clusters, the Paillier cryptosystem is used.
        if len(key['cluster']['nodes']) == 1:
            # Ciphertext type already confirmed in common checks.
            plaintext = pailliers.decrypt(
                key['material'],
                pailliers.cipher(int(ciphertext, 16))
            )

        # For multiple-node clusters and no threshold, additive secret sharing is used.
        elif 'threshold' not in key:
            # Accept only sequences of additive secret shares. Ciphertext type
            # and quantity of shares are already confirmed by common checks.
            if not all(isinstance(c, int) for c in ciphertext):
                raise TypeError('secret shares must all be integers')

            if not all(
                0 <= c < _SECRET_SHARED_SIGNED_INTEGER_MODULUS
                for c in ciphertext
            ):
                raise ValueError(
                    'secret shares must all be nonnegative integers less than the modulus'
                )

            # Store the decryption result in ``plaintext``.
            inverse_masks = [
                pow(
                    key['material'][i] if 'material' in key else 1,
                    _SECRET_SHARED_SIGNED_INTEGER_MODULUS - 2,
                    _SECRET_SHARED_SIGNED_INTEGER_MODULUS
                )
                for i in range(len(key['cluster']['nodes']))
            ]
            plaintext = 0
            for (i, share_) in enumerate(ciphertext):
                plaintext = (
                    plaintext +
                    ((inverse_masks[i] * share_) % _SECRET_SHARED_SIGNED_INTEGER_MODULUS)
                ) % _SECRET_SHARED_SIGNED_INTEGER_MODULUS

        # For multiple-node clusters and a threshold, Shamir's secret sharing is used.
        else:
            # Accept only sequences of Shamir's secret shares (in integer form).
            # Ciphertext type and quantity of shares are already confirmed by
            # common checks.
            if not all(isinstance(share, Sequence) for share in ciphertext):
                raise TypeError('secret shares must all be sequences')

            if not all(len(share) == 2 for share in ciphertext):
                raise ValueError('secret shares must all have two components')

            if not all(all(isinstance(x, int) for x in share) for share in ciphertext):
                raise TypeError('secret share index and value components must be integers')

            if not (
                all(
                    1 <= share[0] < _SECRET_SHARED_SIGNED_INTEGER_MODULUS
                    for share in ciphertext
                ) and
                len({share[0] for share in ciphertext}) == len(ciphertext)
            ):
                raise ValueError(
                    'secret share index components must be distinct positive ' +
                    'integers less than the modulus'
                )

            if not all(
                0 <= share[1] < _SECRET_SHARED_SIGNED_INTEGER_MODULUS
                for share in ciphertext
            ):
                raise ValueError(
                    'secret share value components must be nonnegative integers ' +
                    'less than the modulus'
                )

            # Store the decryption result in ``plaintext``.
            inverse_masks = [
                pow(
                    key['material'][i] if 'material' in key else 1,
                    _SECRET_SHARED_SIGNED_INTEGER_MODULUS - 2,
                    _SECRET_SHARED_SIGNED_INTEGER_MODULUS
                )
                for i in range(len(key['cluster']['nodes']))
            ]
            shares = [
                (
                    share[0],
                    (
                        inverse_masks[share[0] - 1] * share[1]
                    ) % _SECRET_SHARED_SIGNED_INTEGER_MODULUS
                )
                for (i, share) in enumerate(ciphertext)
            ]
            plaintext = shamirs.reveal(
                shares=[shamirs.share(*share) for share in shares],
                modulus=_SECRET_SHARED_SIGNED_INTEGER_MODULUS,
                threshold=key['threshold']
            )

        # Field elements in the "upper half" of the fields used for the Paillier,
        # additive and Shamir's schemes represent negative integers.
        if plaintext > _PLAINTEXT_SIGNED_INTEGER_MAX:
            plaintext -= key._modulus() # pylint: disable=protected-access

        return plaintext

    # The below should not occur unless the key's cluster or operations
    # information is malformed/missing or the ciphertext is unsupported.
    raise error

def allot(
        document: Union[bool, int, float, str, list, dict, None]
    ) -> Sequence[Union[bool, int, float, str, list, dict, None]]:
    """
    Convert a document that may contain ciphertexts intended for multiple-node
    clusters into secret shares of that document.

    :param document: Document to convert into secret shares.

    The output consists of a sequence of documents; the number of documents in
    the sequence is determined by the number of secret shares that appear in
    ciphertext values found in the document. Shallow copies are created whenever
    possible.

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

    When performing allotment, ``None`` is a valid document share leaf value.

    >>> d = {
    ...     'age': {'%allot': [1, 2]},
    ...     'name': None
    ... }
    >>> for d in allot(d): print(d)
    {'age': {'%share': 1}, 'name': None}
    {'age': {'%share': 2}, 'name': None}
    >>> allot(None)
    [None]

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
    >>> allot([
    ...     0,
    ...     {'%allot': [1, 2, 3]},
    ...     {'loc': {'%allot': [4, 5]}}
    ... ])
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
                    raise ValueError(
                        'number of shares in subdocument is not consistent'
                    )

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
        key: Union[SecretKey, ClusterKey],
        documents: Sequence[Union[bool, int, float, str, list, dict]],
        ignore: Optional[Sequence[str]] = None
    ) -> Union[bool, int, float, str, list, dict, None]:
    """
    Combine a sequence of compatible secret shares of a document into one
    document.

    :param key: Key with which to reconstruct leaf values from secret shares.
    :param documents: Sequence of document secret shares to combine.
    :param ignore: Sequence of dictionary keys to ignore. 

    Corresponding plaintexts acting as leaf values are deduplicated and 
    corresponding secret shares acting as leaf values are used to reconstruct
    plaintexts that appear in the resulting document.

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

    When performing unification, ``None`` is a valid document share leaf value.

    >>> unify(sk, [None, None]) == None
    True

    The ``ignore`` parameter specifies which dictionary keys should be ignored
    during unification. By default, ``'_created'`` and ``'_updated'`` are
    ignored.

    >>> shares[0]['_created'] = '123'
    >>> shares[1]['_created'] = '456'
    >>> shares[2]['_created'] = '789'
    >>> shares[0]['_updated'] = 'ABC'
    >>> shares[1]['_updated'] = 'DEF'
    >>> shares[2]['_updated'] = 'GHI'
    >>> decrypted = unify(sk, shares)
    >>> data == decrypted
    True

    Unification returns the sole document when a one-document list is supplied.

    >>> 123 == unify(sk, [123])
    True

    Any attempt to supply incompatible document shares raises an exception.

    >>> unify('abc', [])
    Traceback (most recent call last):
      ...
    TypeError: secret key or cluster key expected
    >>> unify(sk, 123)
    Traceback (most recent call last):
      ...
    TypeError: sequence of documents expected
    >>> unify(sk, [123, 'abc'])
    Traceback (most recent call last):
      ...
    TypeError: sequence of compatible document shares expected
    >>> unify(sk, [123, 123], 456)
    Traceback (most recent call last):
      ...
    TypeError: ignored keys must be supplied as a sequence of strings
    """
    if not isinstance(key, (SecretKey, ClusterKey)):
        raise TypeError('secret key or cluster key expected')

    if not isinstance(documents, Sequence):
        raise TypeError('sequence of documents expected')

    if ignore is None:
        ignore = ['_created', '_updated']
    else:
        if (
            not isinstance(ignore, Sequence) or
            not all(isinstance(k, str) for k in ignore)
        ):
            raise TypeError(
                'ignored keys must be supplied as a sequence of strings'
            )

    if len(documents) == 1:
        return documents[0]

    if all(isinstance(document, list) for document in documents):
        length = len(documents[0])
        if all(len(document) == length for document in documents[1:]):
            return [
                unify(key, [share[i] for share in documents], ignore)
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
                    key,
                    [document['%share'] for document in documents]
                )

            # Document shares consisting of nested lists of shares.
            return [
                unify(
                    key,
                    [{'%share': share} for share in shares],
                    ignore
                )
                for shares in zip(*[document['%share'] for document in documents])
            ]

        # Documents are general-purpose key-value mappings.
        ks = documents[0].keys()
        if all(document.keys() == ks for document in documents[1:]):
            # For ignored attributes, unification is not performed and
            # they are omitted from the results.
            ks = [k for k in ks if k not in ignore]
            results = {}
            for k in ks:
                results[k] = unify(
                    key,
                    [document[k] for document in documents],
                    ignore
                )

            return results

    # Base case: all documents must be equivalent.
    all_values_equal = True
    for i in range(1, len(documents)):
        all_values_equal &= documents[0] == documents[i]

    if all_values_equal:
        return documents[0]

    raise TypeError('sequence of compatible document shares expected')

if __name__ == '__main__':
    doctest.testmod() # pragma: no cover
