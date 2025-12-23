"""
Test suite containing functional unit tests of exported functions. Click on a
**[source]** link beside any test method to view the examples found in that
particular test.
"""
from typing import Union
from collections.abc import Sequence
from unittest import TestCase
from importlib import import_module
import functools
import math
import json
import base64
import hashlib
import pytest

import shamirs
import pailliers
import blindfold

_SECRET_SHARED_SIGNED_INTEGER_MODULUS: int = (2 ** 32) + 15
"""Modulus to use for secret shares of 32-bit signed integers."""

_PLAINTEXT_SIGNED_INTEGER_MIN: int = -(2 ** 31)
"""Minimum plaintext 32-bit signed integer value that can be encrypted."""

_PLAINTEXT_SIGNED_INTEGER_MAX: int = (2 ** 31) - 1
"""Maximum plaintext 32-bit signed integer value that can be encrypted."""

_PLAINTEXT_STRING_BUFFER_LEN_MAX: int = 4096
"""Maximum length of plaintext string value that can be encrypted."""

seed_values: Union[str, bytes] = [
    "012345678901234567890123456789012345678901234567890123456789",
    "012345678901234567890123456789012345678901234567890123456789".encode()
]
"""
Seeds used for tests confirming that key generation from seeds is consistent.
"""

plaintext_integer_values: Sequence[int] = [
    _PLAINTEXT_SIGNED_INTEGER_MIN, -123, 0, 123, _PLAINTEXT_SIGNED_INTEGER_MAX
]
"""
Sequence of plaintext integer values used across multiple tests.
"""

plaintext_string_values: Sequence[str] = [
    'x' * length
    for length in [
        0, 1, 3, 5, 10, 50, 256, 385, 500, 1000, 2000,
        _PLAINTEXT_STRING_BUFFER_LEN_MAX
    ]
]
"""
Sequence of plaintext string values used across multiple tests.
"""

plaintext_bytes_values: Sequence[bytes] = [
    bytes(0), bytearray([123]), bytes([123] * _PLAINTEXT_STRING_BUFFER_LEN_MAX)
]
"""
Sequence of plaintext binary values used across multiple tests.
"""

scenarios: tuple[int, Union[None, int], Sequence[set[int]]] = [
    (1, None, [{0}]),
    (2, None, [{0, 1}]),
    (3, None, [{0, 1, 2}]),

    # Scenarios with thresholds but no missing shares.
    (2, 1, [{0, 1}]),
    (2, 2, [{0, 1}]),
    (3, 1, [{0, 1, 2}]),
    (3, 2, [{0, 1, 2}]),
    (3, 3, [{0, 1, 2}]),

    # Scenarios with thresholds and missing shares.
    (2, 1, [{0}, {1}]),
    (3, 1, [{0}, {1}, {2}, {1, 2}, {0, 1}, {0, 2}]),
    (3, 2, [{0, 1}, {0, 2}, {1, 2}]),
    (4, 2, [{0, 1}, {1, 2}, {2, 3}, {0, 2}, {1, 3}, {0, 3}, {0, 1, 2}]),
    (4, 3, [{0, 1, 2}, {1, 2, 3}, {0, 1, 3}, {0, 2, 3}]),
    (5, 2, [{0, 4}, {1, 3}, {0, 2}, {2, 3}]),
    (5, 3, [{0, 1, 4}, {1, 3, 4}, {0, 2, 4}, {1, 2, 3}, {1, 2, 3, 4}]),
    (5, 4, [{0, 1, 4, 2}, {0, 1, 3, 4}])
]
"""
Common collection of scenarios for the store and sum operations.
"""

# Modify the Paillier secret key length to reduce running time of tests.
blindfold.SecretKey._paillier_prime_bit_length = 256 # pylint: disable=protected-access

def to_hash_base64(output: Union[bytes, list[int]]) -> str:
    """
    Helper function for converting a large output from a test into a
    short hash.
    """
    if isinstance(output, list) and all(isinstance(o, int) for o in output):
        output = functools.reduce(
            (lambda a, b: a + b),
            [o.to_bytes(8, 'little') for o in output]
        )

    return base64.b64encode(hashlib.sha256(output).digest()).decode('ascii')

def cluster(size: int) -> blindfold.Cluster:
    """
    Return a cluster configuration of the specified size.
    """
    return {'nodes': [{} for _ in range(size)]}

def thresholds(n: int) -> Sequence[int]:
    """
    Return an array of valid threshold values for a given cluster size.
    """
    return [] if n == 1 else [None] + list(range(1, n + 1))

class TestAPI(TestCase):
    """
    Test that the exported classes and functions match the expected API.
    """
    def test_exports(self):
        """
        Check that the module exports the expected classes and functions.
        """
        module = import_module('blindfold.blindfold')
        self.assertTrue({
            'Cluster', 'Operations',
            'SecretKey', 'ClusterKey', 'PublicKey',
            'encrypt', 'decrypt', 'allot', 'unify'
        }.issubset(module.__dict__.keys()))

def common_key_methods_dump_load(
        test_case: TestCase,
        Key: type, # pylint: disable=invalid-name
        key: Union[blindfold.SecretKey, blindfold.PublicKey, blindfold.ClusterKey]
    ):
    """
    Common pattern for testing dump/load methods of cryptographic key classes.
    """
    key_from_dict = Key.load(key.dump())
    test_case.assertTrue(isinstance(key_from_dict, Key))
    test_case.assertEqual(key_from_dict, key)

    key_from_json = Key.load(json.loads(json.dumps(key.dump())))
    test_case.assertTrue(isinstance(key_from_json, Key))
    test_case.assertEqual(key_from_json, key)


class TestKeys(TestCase):
    """
    Tests of methods of cryptographic key classes.
    """
    def test_key_operations_for_store(self):
        """
        Test key generate, dump, JSONify, and load for the store operation.
        """
        for Key in [blindfold.SecretKey, blindfold.ClusterKey]:
            for n in [1, 2, 3]:
                if not (Key == blindfold.ClusterKey and n == 1):
                    for t in thresholds(n):
                        key = Key.generate(cluster(n), {'store': True}, t)
                        common_key_methods_dump_load(self, Key, key)

    def test_key_operations_for_match(self):
        """
        Test key generate, dump, JSONify, and load methods for the match operation.
        """
        for n in [1, 2, 3]:
            sk = blindfold.SecretKey.generate(cluster(n), {'match': True})
            common_key_methods_dump_load(self, blindfold.SecretKey, sk)

    def test_key_operations_for_sum_with_single_node(self):
        """
        Test key generate, dump, JSONify, and load methods for the sum operation
        with a single node.
        """
        sk = blindfold.SecretKey.generate(cluster(1), {'sum': True})
        common_key_methods_dump_load(self, blindfold.SecretKey, sk)
        pk = blindfold.PublicKey.generate(sk)
        common_key_methods_dump_load(self, blindfold.PublicKey, pk)

    def test_key_operations_for_sum_with_multiple_nodes(self):
        """
        Test key generate, dump, JSONify, and load methods for the sum operation
        with multiple (without/with threshold) nodes.
        """
        for Key in [blindfold.SecretKey, blindfold.ClusterKey]:
            for n in [1, 2, 3]:
                if not (Key == blindfold.ClusterKey and n == 1):
                    for t in thresholds(n):
                        key = Key.generate(cluster(n), {'sum': True}, t)
                        common_key_methods_dump_load(self, Key, key)

    def test_secret_key_from_seed_for_store(self):
        """
        Test key generation from seed for the store operation both with a single
        node and multiple (without/with threshold) nodes.
        """
        for seed in seed_values:
            for n in [1, 2, 3]:
                for t in thresholds(n):
                    sk_from_seed = blindfold.SecretKey.generate(
                        cluster(n),
                        {'store': True},
                        t,
                        seed
                    )
                    self.assertEqual(
                        to_hash_base64(sk_from_seed['material']),
                        '2bW6BLeeCTqsCqrijSkBBPGjDb/gzjtGnFZt0nsZP8w='
                    )

                    sk = blindfold.SecretKey.generate(cluster(n), {'store': True}, t)
                    self.assertNotEqual(
                        to_hash_base64(sk['material']),
                        '2bW6BLeeCTqsCqrijSkBBPGjDb/gzjtGnFZt0nsZP8w='
                    )

    def test_secret_key_from_seed_for_match(self):
        """
        Test key generation from seed for the match operation with a single node.
        """
        for seed in seed_values:
            for n in [1, 2, 3]:
                sk_from_seed = blindfold.SecretKey.generate(
                    cluster(n),
                    {'match': True},
                    seed=seed
                )
                self.assertEqual(
                    to_hash_base64(sk_from_seed['material']),
                    'qbcFGTOGTPo+vs3EChnVUWk5lnn6L6Cr/DIq8li4H+4='
                )

                sk = blindfold.SecretKey.generate(cluster(n), {'match': True})
                self.assertNotEqual(
                    to_hash_base64(sk['material']),
                    'qbcFGTOGTPo+vs3EChnVUWk5lnn6L6Cr/DIq8li4H+4='
                )

    def test_secret_key_from_seed_for_sum_with_multiple_nodes(self):
        """
        Test key generation from seed for the sum operation with multiple
        (without/with a threshold) nodes.
        """
        for seed in seed_values:
            for (n, hash_from_material) in [
              (2, 'GmmTqmaeT0Uhe1h94yJHEQXG45beO6t+z/m9EBZCNAY='),
              (3, 'L8RiHNq2EUgt/fDOoUw9QK2NISeUkAkhxHHIPoHPZ84='),
              (4, 'xUiGGrAEfTZpNl2aIe2V+Vk+HCSTElREbeXNV/hePJg='),
              (5, '4k7lscMoSb8WOcIcChURfE6GfIe5gN+Hc3MiQeD4tKI='),
            ]:
                for t in thresholds(n):
                    sk_from_seed = blindfold.SecretKey.generate(
                        cluster(n),
                        {'sum': True},
                        t,
                        seed=seed
                    )
                    self.assertEqual(
                        to_hash_base64(sk_from_seed['material']),
                        hash_from_material
                    )

                    sk = blindfold.SecretKey.generate(cluster(n), {'sum': True}, t)
                    self.assertNotEqual(
                        to_hash_base64(sk['material']),
                        hash_from_material
                    )

class TestKeysError(TestCase):
    """
    Tests of errors raised by methods of cryptographic key classes.
    """
    def test_key_generation_errors(self):
        """
        Test errors that can occur during key generation.
        """
        # Cluster configuration errors.
        for Key in [blindfold.SecretKey, blindfold.ClusterKey]:
            for ops in [{'store': True}, {'match': True}, {'sum': True}]:
                with pytest.raises(
                    TypeError,
                    match='cluster configuration must be a dictionary'
                ):
                    Key.generate(123, ops)

                with pytest.raises(
                    ValueError,
                    match='cluster configuration must specify nodes'
                ):
                    Key.generate({}, ops)

                with pytest.raises(
                    TypeError,
                    match='cluster configuration node specification must be a sequence'
                ):
                    Key.generate({'nodes': 123}, ops)

                with pytest.raises(
                    ValueError,
                    match='cluster configuration must contain at least one node'
                ):
                    Key.generate(cluster(0), ops)

                if Key == blindfold.ClusterKey and not ops.get('match'):
                    with pytest.raises(
                        ValueError,
                        match='cluster configuration must contain at least two nodes'
                    ):
                        Key.generate(cluster(1), ops)

        # Operations specification errors.
        for Key in [blindfold.SecretKey, blindfold.ClusterKey]:
            for n in [1, 2, 3, 4]:
                if not (Key == blindfold.ClusterKey and n == 1):
                    with pytest.raises(
                        TypeError,
                        match='operations specification must be a dictionary'
                    ):
                        Key.generate(cluster(n), 123)

                    with pytest.raises(
                        ValueError,
                        match='permitted operations are limited to store, match, and sum'
                    ):
                        Key.generate(cluster(n), {'foo': True})

                    with pytest.raises(
                        TypeError,
                        match='operations specification values must be boolean'
                    ):
                        Key.generate(cluster(n), {'store': 123})

                    with pytest.raises(
                        ValueError,
                        match='operations specification must designate exactly one operation'
                    ):
                        Key.generate(cluster(n), {})

                    if Key == blindfold.ClusterKey and n >= 2:
                        with pytest.raises(
                            ValueError,
                            match='cluster keys cannot support matching-compatible encryption'
                        ):
                            Key.generate(cluster(n), {'match': True})

        # Threshold errors.
        for Key in [blindfold.SecretKey, blindfold.ClusterKey]:
            for n in [1, 2, 3, 4]:
                for ops in [{'store': True}, {'sum': True}]:
                    if not (Key == blindfold.ClusterKey and n == 1):
                        with pytest.raises(
                            TypeError,
                            match='threshold must be an integer'
                        ):
                            Key.generate(cluster(n), ops, threshold='abc')

                    if Key == blindfold.SecretKey and n == 1:
                        with pytest.raises(
                            ValueError,
                            match='thresholds are only supported for multiple-node clusters'
                        ):
                            Key.generate(cluster(n), ops, threshold=1)

                    if n >= 2:
                        for t in [2 - n, n + 1]:
                            with pytest.raises(
                                ValueError,
                                match=(
                                    'threshold must be a positive integer ' +
                                    'not larger than the cluster size'
                                )
                            ):
                                Key.generate(cluster(n), ops, threshold=t)

                    if Key == blindfold.SecretKey and n >= 2:
                        with pytest.raises(
                            ValueError,
                            match=(
                                'thresholds are only supported for the store ' +
                                'and sum operations'
                            )
                        ):
                            Key.generate(cluster(n), {'match': True}, threshold=n)

        # Seed errors.
        for n in [1, 2, 3, 4]:
            for ops in [{'store': True}, {'match': True}, {'sum': True}]:
                with pytest.raises(
                    TypeError,
                    match='seed must be a bytes-like object or a string'
                ):
                    blindfold.SecretKey.generate(cluster(n), ops, seed=123)

                if n == 1 and ops.get('sum'):
                    with pytest.raises(
                        ValueError,
                        match=(
                            'seed-based derivation of summation-compatible secret keys ' +
                            'is not supported for single-node clusters'
                        )
                    ):
                        blindfold.SecretKey.generate(cluster(n), ops, seed="ABC")

        # Public key errors.
        for Key in [blindfold.SecretKey, blindfold.ClusterKey]:
            for n in [1, 2, 3, 4]:
                for ops in [{'store': True}, {'match': True}, {'sum': True}]:
                    if not (Key == blindfold.ClusterKey and (n == 1 or ops.get('match'))):
                        if Key == blindfold.ClusterKey:
                            with pytest.raises(
                                TypeError,
                                match='secret key expected'
                            ):
                                key = Key.generate(cluster(n), ops)
                                blindfold.PublicKey.generate(key)

                        # Valid but incompatible secret keys.
                        if Key == blindfold.SecretKey and not (n == 1 and ops.get('sum')):
                            with pytest.raises(
                                TypeError,
                                match='secret key material must be of the correct type'
                            ):
                                key = Key.generate(cluster(n), ops)
                                blindfold.PublicKey.generate(key)

                        # Potentially compatible but malformed secret key.
                        if Key == blindfold.SecretKey and n == 1 and ops.get('sum'):
                            with pytest.raises(
                                TypeError,
                                match='secret key material must be of the correct type'
                            ):
                                key = Key.generate(cluster(n), ops)
                                key['material'] = 123
                                blindfold.PublicKey.generate(key)

    def test_key_dumping_and_loading_errors(self):
        """
        Test errors that can occur during key dumping and loading (excluding
        the errors that can occur due to checks performed within key generation
        methods).
        """
        # pylint: disable=too-many-statements

        # Errors that can occur due to checks performed within key generation
        # are not considered within these tests. The only exception is that a
        # single test is included to ensure that the corresponding constructors
        # or validation methods are invoked. These are identified via comments.

        # Secret keys: invalid cluster configuration and operations specification.
        for n in [1, 2, 3, 4]:
            for ops in [{'store': True}, {'match': True}, {'sum': True}]:
                # Check that cluster configuration validation is invoked.
                with pytest.raises(
                    TypeError,
                    match='cluster configuration must be a dictionary'
                ):
                    sk_dict = blindfold.SecretKey.generate(cluster(n), ops).dump()
                    del sk_dict['cluster']
                    blindfold.SecretKey.load(sk_dict)

                # Check that operation specification validation is invoked.
                with pytest.raises(
                    TypeError,
                    match='operations specification must be a dictionary'
                ):
                    sk_dict = blindfold.SecretKey.generate(cluster(n), ops).dump()
                    del sk_dict['operations']
                    blindfold.SecretKey.load(sk_dict)

                # Check that key attribute compatibility validation is invoked.
                with pytest.raises(
                    TypeError,
                    match='threshold must be an integer'
                ):
                    sk_dict = blindfold.SecretKey.generate(cluster(n), ops).dump()
                    sk_dict['threshold'] = "abc"
                    blindfold.SecretKey.load(sk_dict)

                # Check all material attribute type errors for the possible operations.
                with pytest.raises(
                    TypeError,
                    match=(
                        'operations specification requires key material to be a ' +
                        (('dictionary' if n == 1 else 'list')  if 'sum' in ops else 'string')
                    )
                ):
                    sk_dict = blindfold.SecretKey.generate(cluster(n), ops).dump()
                    del sk_dict['material']
                    blindfold.SecretKey.load(sk_dict)

        # Secret keys: invalid material for matching and storage.
        for n in [1, 2, 3, 4]:
            with pytest.raises(
                ValueError,
                match='key material must have a length of 32 bytes'
            ):
                sk_store_dict = blindfold.SecretKey.generate(cluster(n), {'store': True}).dump()
                sk_match_dict = blindfold.SecretKey.generate(cluster(n), {'match': True}).dump()
                sk_store_dict['material'] = sk_match_dict['material']
                blindfold.SecretKey.load(sk_store_dict)

            with pytest.raises(
                ValueError,
                match='key material must have a length of 64 bytes'
            ):
                sk_store_dict = blindfold.SecretKey.generate(cluster(n), {'store': True}).dump()
                sk_match_dict = blindfold.SecretKey.generate(cluster(n), {'match': True}).dump()
                sk_match_dict['material'] = sk_store_dict['material']
                blindfold.SecretKey.load(sk_match_dict)

        # Secret keys: invalid material for summation on single-node clusters.
        for parameter in ['l', 'm', 'n', 'g']:
            with pytest.raises(
                ValueError,
                match='key material must contain all required parameters'
            ):
                sk_dict = blindfold.SecretKey.generate(cluster(1), {'sum': True}).dump()
                del sk_dict['material'][parameter]
                blindfold.SecretKey.load(sk_dict)

            with pytest.raises(
                TypeError,
                match='key material parameter values must be strings'
            ):
                sk_dict = blindfold.SecretKey.generate(cluster(1), {'sum': True}).dump()
                sk_dict['material'][parameter] = 123
                blindfold.SecretKey.load(sk_dict)

            with pytest.raises(
                ValueError,
                match='key material parameter strings must be convertible to integer values'
            ):
                sk_dict = blindfold.SecretKey.generate(cluster(1), {'sum': True}).dump()
                sk_dict['material'][parameter] = 'abc'
                blindfold.SecretKey.load(sk_dict)

        # Secret keys: invalid material for summation on multiple-node clusters.
        for n in [2, 3, 4]:
            with pytest.raises(
                TypeError,
                match='perations specification requires key material to be a list'
            ):
                sk_dict = blindfold.SecretKey.generate(cluster(n), {'sum': True}).dump()
                sk_dict['material'] = 123
                blindfold.SecretKey.load(sk_dict)

            with pytest.raises(
                ValueError,
                match='cluster configuration requires key material to have length ' + str(n)
            ):
                sk_dict = blindfold.SecretKey.generate(cluster(n), {'sum': True}).dump()
                sk_dict['material'].pop()
                blindfold.SecretKey.load(sk_dict)

            with pytest.raises(
                TypeError,
                match='key material must contain integers'
            ):
                sk_dict = blindfold.SecretKey.generate(cluster(n), {'sum': True}).dump()
                sk_dict['material'][0] = 'abc'
                blindfold.SecretKey.load(sk_dict)

            with pytest.raises(
                ValueError,
                match='key material must contain integers within the correct range'
            ):
                sk_dict = blindfold.SecretKey.generate(cluster(n), {'sum': True}).dump()
                sk_dict['material'][0] = 0 # Masks for secret shares must be nonzero.
                blindfold.SecretKey.load(sk_dict)

        # Cluster keys.
        for n in [1, 2, 3, 4]:
            for ops in [{'store': True}, {'match': True}, {'sum': True}]:
                if n != 1 and not ops.get('match'):
                    # Check that cluster configuration validation is invoked.
                    with pytest.raises(
                        TypeError,
                        match='cluster configuration must be a dictionary'
                    ):
                        ck_dict = blindfold.ClusterKey.generate(cluster(n), ops).dump()
                        del ck_dict['cluster']
                        blindfold.ClusterKey.load(ck_dict)

                if n == 1 and not ops.get('match'):
                    with pytest.raises(
                        ValueError,
                        match='cluster configuration must contain at least two nodes'
                    ):
                        ck_dict = blindfold.ClusterKey.generate(cluster(2), ops).dump()
                        ck_dict['cluster'] = cluster(n)
                        blindfold.ClusterKey.load(ck_dict)

                if n != 1 and not ops.get('match'):
                    # Check that operations specification validation is invoked.
                    with pytest.raises(
                        TypeError,
                        match='operations specification must be a dictionary'
                    ):
                        ck_dict = blindfold.ClusterKey.generate(cluster(n), ops).dump()
                        del ck_dict['operations']
                        blindfold.ClusterKey.load(ck_dict)

                if n != 1 and ops.get('match'):
                    with pytest.raises(
                        ValueError,
                        match='cluster keys cannot support matching-compatible encryption'
                    ):
                        ck_dict = blindfold.ClusterKey.generate(cluster(n), {'store': True}).dump()
                        ck_dict['operations'] = ops
                        blindfold.ClusterKey.load(ck_dict)

                if n != 1 and not ops.get('match'):
                    # Check that key attribute compatibility validation is invoked.
                    with pytest.raises(
                        TypeError,
                        match='threshold must be an integer'
                    ):
                        ck_dict = blindfold.ClusterKey.generate(cluster(n), ops).dump()
                        ck_dict['threshold'] = "abc"
                        blindfold.ClusterKey.load(ck_dict)

                    with pytest.raises(
                        ValueError,
                        match='cluster keys cannot contain key material'
                    ):
                        ck_dict = blindfold.ClusterKey.generate(cluster(n), ops).dump()
                        ck_dict['material'] = {}
                        blindfold.ClusterKey.load(ck_dict)

        # Public keys.
        sk = blindfold.SecretKey.generate(cluster(1), {'sum': True})

        # Check that cluster configuration validation is invoked.
        with pytest.raises(
            TypeError,
            match='cluster configuration must be a dictionary'
        ):
            pk_dict = blindfold.PublicKey.generate(sk).dump()
            del pk_dict['cluster']
            blindfold.PublicKey.load(pk_dict)

        # Check that operations specification validation is invoked.
        with pytest.raises(
            TypeError,
            match='operations specification must be a dictionary'
        ):
            pk_dict = blindfold.PublicKey.generate(sk).dump()
            del pk_dict['operations']
            blindfold.PublicKey.load(pk_dict)

        with pytest.raises(
            ValueError,
            match='public keys are only supported for single-node clusters'
        ):
            pk_dict = blindfold.PublicKey.generate(sk).dump()
            pk_dict['cluster'] = {'nodes': [{}, {}]}
            blindfold.PublicKey.load(pk_dict)

        for ops in [{'store': True}, {'match': True}]:
            with pytest.raises(
                ValueError,
                match='public keys can only support the sum operation'
            ):
                pk_dict = blindfold.PublicKey.generate(sk).dump()
                pk_dict['operations'] = ops
                blindfold.PublicKey.load(pk_dict)

        with pytest.raises(
            ValueError,
            match='public keys cannot specify a threshold'
        ):
            pk_dict = blindfold.PublicKey.generate(sk).dump()
            pk_dict['threshold'] = 1
            blindfold.PublicKey.load(pk_dict)

        with pytest.raises(
            TypeError,
            match='key material must be a dictionary'
        ):
            pk_dict = blindfold.PublicKey.generate(sk).dump()
            pk_dict['material'] = 123
            blindfold.PublicKey.load(pk_dict)

        for parameter in ['n', 'g']:
            with pytest.raises(
                ValueError,
                match='key material does not contain all required parameters'
            ):
                pk_dict = blindfold.PublicKey.generate(sk).dump()
                del pk_dict['material'][parameter]
                blindfold.PublicKey.load(pk_dict)

            with pytest.raises(
                TypeError,
                match='key material parameter values must be strings'
            ):
                pk_dict = blindfold.PublicKey.generate(sk).dump()
                pk_dict['material'][parameter] = 123
                blindfold.PublicKey.load(pk_dict)

            with pytest.raises(
                ValueError,
                match='key material parameter strings must be convertible to integer values'
            ):
                pk_dict = blindfold.PublicKey.generate(sk).dump()
                pk_dict['material'][parameter] = 'abc'
                blindfold.PublicKey.load(pk_dict)

class TestFunctions(TestCase):
    """
    Tests of the functional and algebraic properties of encryption/decryption functions.
    """
    def test_encrypt_decrypt_for_store(self):
        """
        Test encryption and decryption for the store operation with single/multiple
        nodes and without/with threshold (including subcluster combinations).
        """
        for (n, t, combinations) in scenarios:
            for Key in [blindfold.SecretKey, blindfold.ClusterKey]:
                if not (n == 1 and Key == blindfold.ClusterKey):
                    key = Key.generate(cluster(n), {'store': True}, t)
                    for plaintext in (
                        plaintext_integer_values +
                        plaintext_string_values +
                        plaintext_bytes_values
                    ):
                        ciphertext = blindfold.encrypt(key, plaintext)
                        for combination in combinations:
                            decrypted = blindfold.decrypt(
                                key,
                                (
                                    ciphertext
                                    if t is None else
                                    [ciphertext[i] for i in combination]
                                )
                            )
                            self.assertEqual(decrypted, plaintext)

    def test_encrypt_for_match(self):
        """
        Test encryption for the match operation.
        """
        for n in [1, 2, 3]:
            sk_a = blindfold.SecretKey.generate(cluster(n), {'match': True})
            sk_b = blindfold.SecretKey.generate(cluster(n), {'match': True})

            for (plaintext_one, plaintext_two, comparison) in [
                (123, 123, True),
                (123, 0, False),
                ('ABC', 'ABC', True),
                ('ABC', 'abc', False),
                (bytes([1, 2, 3]), bytes([1, 2, 3]), True),
                (bytes([1, 2, 3]), bytes([4, 5, 6, 7, 8, 9]), False)
            ]:
                ciphertext_one_a = blindfold.encrypt(sk_a, plaintext_one)
                ciphertext_two_a = blindfold.encrypt(sk_a, plaintext_two)
                self.assertEqual(
                    ciphertext_one_a == ciphertext_two_a,
                    comparison
                )

                ciphertext_one_b = blindfold.encrypt(sk_b, plaintext_one)
                self.assertEqual(
                    ciphertext_one_a == ciphertext_one_b,
                    False
                )

    def test_encrypt_decrypt_for_sum_with_single_node(self):
        """
        Test encryption and decryption for the sum operation with a single node
        using a public key.
        """
        sk = blindfold.SecretKey.generate(cluster(1), {'sum': True})
        pk = blindfold.PublicKey.generate(sk)
        for plaintext in plaintext_integer_values:
            ciphertext = blindfold.encrypt(pk, plaintext)
            decrypted = blindfold.decrypt(sk, ciphertext)
            self.assertEqual(decrypted, plaintext)

    def test_encrypt_decrypt_for_sum_with_multiple_nodes(self):
        """
        Test encryption and decryption for the sum operation with single/multiple
        nodes and without/with threshold (including subcluster combinations).
        """
        for (n, t, combinations) in scenarios:
            for Key in [blindfold.SecretKey, blindfold.ClusterKey]:
                if not (n == 1 and Key == blindfold.ClusterKey):
                    key = Key.generate(cluster(n), {'sum': True}, t)
                    for plaintext in plaintext_integer_values:
                        ciphertext = blindfold.encrypt(key, plaintext)
                        for combination in combinations:
                            decrypted = blindfold.decrypt(
                                key,
                                (
                                    ciphertext
                                    if t is None else
                                    [ciphertext[i] for i in combination]
                                )
                            )
                            self.assertEqual(decrypted, plaintext)

class TestRepresentations(TestCase):
    """
    Tests the portability and compatibility of key and ciphertext representations.
    """
    def test_representations_for_store_with_single_node(self):
        """
        Confirm ability to handle representation of keys and ciphertexts for
        storage in a single-node cluster.
        """
        plaintext = 'abc'
        sk = blindfold.SecretKey.load({
            'cluster': cluster(1),
            'operations': {'store': True},
            'material': 'SnC3NBHUXwCbvpayZy9mNZqM3OZa7DlbF9ocHM4nT8Q='
        })
        for seed in seed_values:
            self.assertEqual(
                sk,
                blindfold.SecretKey.generate(cluster(1), {'store': True}, seed=seed)
            )
            ciphertext = 'eJHSIhn4VxpgLWuvk4/dWVm3bYhyTnmeqiGw33lkvEZJ1vvLn5RodwBdpqo='
            self.assertEqual(blindfold.decrypt(sk, ciphertext), plaintext)

    def test_representations_for_store_with_multiple_nodes(self):
        """
        Confirm ability to handle representation of keys and ciphertexts for
        storage in a multiple-node cluster.
        """
        plaintext = 'abc'

        ck = blindfold.ClusterKey.load({
            'cluster': cluster(3),
            'operations': {'store': True}
        })
        self.assertEqual(ck, blindfold.ClusterKey.generate(cluster(3), {'store': True}))
        ciphertext = ['Ifkz2Q==', '8nqHOQ==', '0uLWgw==']
        self.assertEqual(blindfold.decrypt(ck, ciphertext), plaintext)

        sk = blindfold.SecretKey.load({
            'cluster': cluster(3),
            'operations': {'store': True},
            'material': 'SnC3NBHUXwCbvpayZy9mNZqM3OZa7DlbF9ocHM4nT8Q='
        })
        for seed in seed_values:
            self.assertEqual(
                sk,
                blindfold.SecretKey.generate(cluster(3), {'store': True}, seed=seed)
            )
            ciphertext = [
                'ioDjqeotjngxp8XLRBYMToS2rpCFJdFGFhPP28tb0EZrFc087sVGCoDXHuU=',
                '3cZW1FAxcRauF/N1x/daEDX5rX7c08N8NgVYtzVhJphXNVuwrN6YA1nbiIM=',
                'BPzn43eqMovPECsMzlDRq/sG73lqeprbadWa+SzZ+WlZ5m3Vst24KBpNGgI='
            ]
            self.assertEqual(blindfold.decrypt(sk, ciphertext), plaintext)

    def test_representations_for_store_with_multiple_nodes_with_threshold(self):
        """
        Confirm ability to handle representation of keys and ciphertexts for
        storage (with threshold) in a multiple-node cluster.
        """
        plaintext = 'abc'

        ck = blindfold.ClusterKey.load({
            'cluster': cluster(3),
            'operations': {'store': True},
            'threshold': 2
        })
        self.assertEqual(
            ck,
            blindfold.ClusterKey.generate(cluster(3), {'store': True}, threshold=2)
        )
        ciphertext = ['AQAAAAICrcwAdifgFQA=', 'AgAAAAUEWpkA+u1dyAA=', 'AwAAAAgGB2YAb7TbegA=']
        self.assertEqual(blindfold.decrypt(ck, ciphertext), plaintext)

        sk = blindfold.SecretKey.load({
            'cluster': cluster(3),
            'operations': {'store': True},
            'threshold': 2,
            'material': 'SnC3NBHUXwCbvpayZy9mNZqM3OZa7DlbF9ocHM4nT8Q='
        })
        for seed in seed_values:
            self.assertEqual(
                sk,
                blindfold.SecretKey.generate(
                    cluster(3),
                    {'store': True},
                    threshold=2,
                    seed=seed
                )
            )
            ciphertext = [
                'gbwfluBqUakTrjEtOREArFjEctKIV1gI8Yv4bQv75MJnN2FN2+kJU+exIuv7yVec/Z/ILu7r',
                'R0RPv8fE4vPZKudck1qzrxvg0FOn/HAHSEIX0Io0BFJexMP5V7VvyHg0/94853bUzWTBocmL',
                'a2/usuHy69KFodRixaUdnsBxSDPRXikwqt/JqeXjolUSU1l7Hn1atWC0soC6zHdRM+NXreD9'
            ]
            self.assertEqual(blindfold.decrypt(sk, ciphertext), plaintext)

    def test_representations_for_sum_with_single_node(self):
        """
        Confirm ability to handle representation of keys and ciphertexts for
        summation (with threshold) in a single-node cluster.
        """
        plaintext = 123
        sk = blindfold.SecretKey.load({
            'cluster': cluster(1),
            'operations': {'sum': True},
            'material':{
                'l': (
                    '17180710124328693910455057887214184059303187053517283200908251615178685092277'
                    '68781003825543371514027055406794542204777828069029196158617836785676131719196'
                ),
                'm': (
                    '36750926513795853434585168117489663841456031899314231851820160524157189283164'
                    '50771207416561620439623920688439253141292243122044846050470239308322700782213'
                ),
                'n': (
                    '10308426074597216346273034732328510435581912232110369920544950969107211055366'
                    '81739294313759304465108824301069626243406484904984349541681357234446259866326'
                    '7'
                ),
                'g': (
                    '80305305698293730896962830440487758915654402490995374612274802412883992221923'
                    '17259092079214965301856055627777412259469950046153383889046622294722297977903'
                    '21844769070633792102283544209510902482137967535730134757715877943631913072743'
                    '01123732060710963981670091105550908978777514231236658174687534680701412538826'
                )
            }
        })
        ciphertext = (
            '55869d61244f52780793eeb7c79b1a681b1c54536041f6703073c93f1e45da8208'
            '2e23e5ada2f27819c88fe07a0e2321b9460582fcc6ab8ca62eb3a912ec6e997ab0'
            'eb930fdc8fe4035f924bf027d3900db0677e694dbdba50b24cd0fb60a37710a919'
            'a4faf5fe43c85d7a4758ae99f1a3162c64d080943605af34b2bfd10d88'
        )
        self.assertEqual(blindfold.decrypt(sk, ciphertext), plaintext)

    def test_representations_for_sum_with_multiple_nodes(self):
        """
        Confirm ability to handle representation of keys and ciphertexts for
        summation in a multiple-node cluster.
        """
        plaintext = 123

        ck = blindfold.ClusterKey.load({
            'cluster': cluster(3),
            'operations': {'sum': True}
        })
        self.assertEqual(ck, blindfold.ClusterKey.generate(cluster(3), {'sum': True}))
        ciphertext = [plaintext + 456, 789, _SECRET_SHARED_SIGNED_INTEGER_MODULUS - 456 - 789]
        self.assertEqual(blindfold.decrypt(ck, ciphertext), plaintext)

        sk = blindfold.SecretKey.load({
            'cluster': cluster(3),
            'operations': {'sum': True},
            'material': [2677312581, 321207441, 2186773557]
        })
        for seed in seed_values:
            self.assertEqual(
                sk,
                blindfold.SecretKey.generate(cluster(3), {'sum': True}, seed=seed)
            )
            ciphertext = [3874430451, 3116877887, 2318008363]
            self.assertEqual(blindfold.decrypt(sk, ciphertext), plaintext)

    def test_representations_for_sum_with_multiple_nodes_with_threshold(self):
        """
        Confirm ability to handle representation of keys and ciphertexts for
        summation (with threshold) in a multiple-node cluster.
        """
        plaintext = 123

        ck = blindfold.ClusterKey.load({
            'cluster': cluster(3),
            'operations': {'sum': True},
            'threshold': 2
        })
        self.assertEqual(
            ck,
            blindfold.ClusterKey.generate(cluster(3), {'sum': True}, threshold=2)
        )
        ciphertext = [[1, 1382717699], [2, 2765435275], [3, 4148152851]]
        self.assertEqual(blindfold.decrypt(ck, ciphertext), plaintext)

        sk = blindfold.SecretKey.load({
            'cluster': cluster(3),
            'operations': {'sum': True},
            'threshold': 2,
            'material': [2677312581, 321207441, 2186773557]
        })
        for seed in seed_values:
            self.assertEqual(
                sk,
                blindfold.SecretKey.generate(
                    cluster(3),
                    {'sum': True},
                    threshold=2,
                    seed=seed
                )
            )
            ciphertext = [(1, 177325002), (2, 986000561), (3, 2621193783)]
            self.assertEqual(blindfold.decrypt(sk, ciphertext), plaintext)

class TestCiphertextSizes(TestCase):
    """
    Tests that ciphertext sizes conform to known closed formulas.
    """
    def test_ciphertext_sizes_for_store(self):
        """
        Confirm that ciphertexts compatible with the storage operation have
        the expected sizes.
        """
        for Key in [blindfold.SecretKey, blindfold.ClusterKey]:
            for n in [1, 2, 3]:
                if not (Key == blindfold.ClusterKey and n == 1):
                    for t in thresholds(n):
                        key = Key.generate(cluster(n), {'store': True}, t)
                        for plaintext in plaintext_string_values:
                            ciphertext = blindfold.encrypt(key, plaintext)
                            overhead = 40 if Key == blindfold.SecretKey else 0
                            k = len(plaintext)
                            self.assertLessEqual(
                                len(ciphertext[0] if n >= 2 else ciphertext),
                                (
                                    math.ceil((1 + k + overhead) * (4 / 3)) + 2
                                    if t is None else
                                    math.ceil(
                                        math.ceil(
                                            (1 + k + 3) * (5 / 4) + 5 + overhead
                                        )
                                        *
                                        (4 / 3)
                                    ) + 2
                                )
                            )

    def test_ciphertext_sizes_for_match(self):
        """
        Confirm that ciphertexts compatible with the match operation have the
        expected sizes.
        """
        for n in [1, 2, 3]:
            sk = blindfold.SecretKey.generate(cluster(n), {'match': True})
            for plaintext in plaintext_string_values:
                ciphertext = blindfold.encrypt(sk, plaintext)
                self.assertEqual(len(ciphertext[0] if n >= 2 else ciphertext), 88)

    def test_ciphertext_sizes_for_sum(self):
        """
        Confirm that ciphertexts compatible with the sum operation have the
        expected sizes.
        """
        for plaintext in plaintext_integer_values:
            sk = blindfold.SecretKey.generate(cluster(1), {'sum': True})
            pk = blindfold.PublicKey.generate(sk)
            # The ciphertext's bit length is four times as large as the bit length
            # of the primes generated for the secret key. This bit length is then
            # divided by four to determine the length of its hex representation.
            self.assertEqual(
                len(blindfold.encrypt(pk, plaintext)),
                # pylint: disable=protected-access
                ((blindfold.SecretKey._paillier_prime_bit_length * 4) // 4)
            )

            for Key in [blindfold.SecretKey, blindfold.ClusterKey]:
                for n in [2, 3]:
                    for t in thresholds(n):
                        key = Key.generate(cluster(n), {'sum': True}, t)
                        share = blindfold.encrypt(key, plaintext)[0]
                        if t is None:
                            self.assertLess(share,_SECRET_SHARED_SIGNED_INTEGER_MODULUS)
                        else:
                            self.assertLess(share[0],_SECRET_SHARED_SIGNED_INTEGER_MODULUS)
                            self.assertLess(share[1],_SECRET_SHARED_SIGNED_INTEGER_MODULUS)

class TestFunctionsErrors(TestCase):
    """
    Tests verifying that encryption/decryption methods return expected errors.
    """
    def test_encrypt_errors(self):
        """
        Test errors that can occur during encryption.
        """
        with pytest.raises(
            TypeError,
            match='secret key, cluster key, or public key expected'
        ):
            blindfold.encrypt('abc', 123)

        for Key in [blindfold.SecretKey, blindfold.ClusterKey]:
            for n in [1, 2, 3]:
                for t in thresholds(n):
                    if not (Key == blindfold.ClusterKey and n == 1):
                        with pytest.raises(
                            TypeError,
                            match='plaintext must be string, integer, or bytes-like object'
                        ):
                            key = Key.generate(cluster(n), {'sum': True}, t)
                            blindfold.encrypt(key, {})

                        with pytest.raises(
                            ValueError,
                            match='cannot encrypt the supplied plaintext using the supplied key'
                        ):
                            key = Key.generate(cluster(n), {'sum': True}, t)
                            del key['operations']['sum']
                            blindfold.encrypt(key, 123)

        for Key in [blindfold.SecretKey, blindfold.ClusterKey]:
            for n in [1, 2, 3]:
                for t in thresholds(n):
                    for ops in [{'store': True}, {'match': True}]:
                        if not (
                            (Key == blindfold.ClusterKey and (n == 1 or ops.get('match')))
                            or
                            (t is not None and ops.get('match'))
                        ):
                            with pytest.raises(
                                ValueError,
                                match='numeric plaintext must be a valid 32-bit signed integer'
                            ):
                                key = Key.generate(cluster(n), ops, t)
                                plaintext = _PLAINTEXT_SIGNED_INTEGER_MAX + 1
                                blindfold.encrypt(key, plaintext)

                            with pytest.raises(
                                ValueError,
                                match=(
                                    'string or binary plaintext must be at most ' +
                                    str(_PLAINTEXT_STRING_BUFFER_LEN_MAX) +
                                    ' bytes or fewer in length'
                                )
                            ):
                                key = Key.generate(cluster(n), ops)
                                plaintext = 'x' * (_PLAINTEXT_STRING_BUFFER_LEN_MAX + 1)
                                blindfold.encrypt(key, plaintext)

        for Key in [blindfold.SecretKey, blindfold.ClusterKey]:
            for n in [1, 2, 3]:
                for t in thresholds(n):
                    if not (Key == blindfold.ClusterKey and n == 1):
                        key = Key.generate(cluster(n), {'sum': True}, t)
                        ek = blindfold.PublicKey.generate(key) if n == 1 else key

                        with pytest.raises(
                            TypeError,
                            match='summation-compatible encryption requires a numeric plaintext'
                        ):
                            blindfold.encrypt(ek, 'abc')

                        with pytest.raises(
                            ValueError,
                            match='numeric plaintext must be a valid 32-bit signed integer'
                        ):
                            blindfold.encrypt(ek, _PLAINTEXT_SIGNED_INTEGER_MAX + 1)

    def test_decrypt_errors_invalid_key(self):
        """
        Test errors that can occur during decryption with an invalid key.
        """
        with pytest.raises(
            TypeError,
            match='secret key or cluster key expected'
        ):
            sk = blindfold.SecretKey.generate(cluster(1), {'sum': True})
            pk = blindfold.PublicKey.generate(sk)
            blindfold.decrypt(pk, blindfold.encrypt(sk, 123))

        with pytest.raises(
            ValueError,
            match='cannot decrypt the supplied ciphertext using the supplied key'
        ):
            sk = blindfold.SecretKey.generate(cluster(2), {'store': True})
            ciphertext = blindfold.encrypt(sk, 'abc')
            sk['operations'] = {}
            blindfold.decrypt(sk, ciphertext)

        with pytest.raises(
            ValueError,
            match=(
                'threshold must be a positive integer less than the quantity of shares'
            )
        ):
            ck = blindfold.ClusterKey.generate(cluster(3), {'sum': True}, threshold=3)
            ck['threshold'] = 4 # Invalid key manipulation.
            blindfold.encrypt(ck, 123)

    def test_decrypt_errors_key_ciphertext_conflict(self):
        """
        Test errors that can occur during decryption when the key and
        ciphertext conflict.
        """
        for operations in [{'store': True}, {'sum': True}]:
            sk_one = blindfold.SecretKey.generate(cluster(1), operations)
            sk_two = blindfold.SecretKey.generate(cluster(2), operations)
            sk_three = blindfold.SecretKey.generate(cluster(3), operations)
            ciphertext_one = blindfold.encrypt(sk_one, 123)
            ciphertext_two = blindfold.encrypt(sk_two, 123)

            with pytest.raises(
                ValueError,
                match='key requires a valid ciphertext from a single-node cluster'
            ):
                blindfold.decrypt(sk_one, ciphertext_two)

            with pytest.raises(
                ValueError,
                match='key requires a valid ciphertext from a multiple-node cluster'
            ):
                blindfold.decrypt(sk_two, ciphertext_one)

            with pytest.raises(
                ValueError,
                match='ciphertext must have enough shares for cluster size or threshold'
            ):
                blindfold.decrypt(sk_three, ciphertext_two)

        for n in [1, 3]:
            with pytest.raises(
                ValueError,
                match='cannot decrypt the supplied ciphertext using the supplied key'
            ):
                sk = blindfold.SecretKey.generate(cluster(n), {'store': True})
                sk_alt = blindfold.SecretKey.generate(cluster(n), {'store': True})
                blindfold.decrypt(sk_alt, blindfold.encrypt(sk, 123))

    def test_decrypt_errors_invalid_ciphertext(self):
        """
        Test errors that can occur during decryption when the ciphertext is
        invalid.
        """
        with pytest.raises(
            TypeError,
            match='secret shares must all be Base64-encoded binary values'
        ):
            sk = blindfold.SecretKey.generate(cluster(2), {'store': True})
            ciphertext = blindfold.encrypt(sk, 'abc')
            ciphertext[0] = 123
            blindfold.decrypt(sk, ciphertext)

        with pytest.raises(
            ValueError,
            match='secret shares must have matching lengths'
        ):
            ck = blindfold.ClusterKey.generate(cluster(2), {'store': True})
            ciphertext_one = blindfold.encrypt(sk, '')
            ciphertext_two = blindfold.encrypt(sk, 'abc')
            blindfold.decrypt(ck, [ciphertext_one[0], ciphertext_two[1]])

        with pytest.raises(
            ValueError,
            match='secret shares must have sufficient and matching lengths'
        ):
            ck = blindfold.ClusterKey.generate(cluster(2), {'store': True}, threshold=1)
            ciphertext_one = blindfold.encrypt(ck, '')
            ciphertext_two = blindfold.encrypt(ck, 'abc')
            blindfold.decrypt(ck, [ciphertext_one[0], ciphertext_two[1]])

        with pytest.raises(
            TypeError,
            match='secret shares must all be integers'
        ):
            sk = blindfold.SecretKey.generate(cluster(2), {'sum': True})
            ciphertext = blindfold.encrypt(sk, 123)
            ciphertext[0] = 'abc'
            blindfold.decrypt(sk, ciphertext)

        with pytest.raises(
            ValueError,
            match='secret shares must all be nonnegative integers less than the modulus'
        ):
            sk = blindfold.SecretKey.generate(cluster(2), {'sum': True})
            ciphertext = blindfold.encrypt(sk, 123)
            ciphertext[0] = -1
            blindfold.decrypt(sk, ciphertext)

        with pytest.raises(
            TypeError,
            match='secret shares must all be sequences'
        ):
            ck = blindfold.ClusterKey.generate(cluster(3), {'sum': True}, threshold=2)
            ciphertext = blindfold.encrypt(ck, 123)
            ciphertext[0] = 123
            blindfold.decrypt(ck, ciphertext)

        with pytest.raises(
            ValueError,
            match='secret shares must all have two components'
        ):
            ck = blindfold.ClusterKey.generate(cluster(3), {'sum': True}, threshold=2)
            ciphertext = blindfold.encrypt(ck, 123)
            ciphertext[0] = ciphertext[0][:1]
            blindfold.decrypt(ck, ciphertext)

        with pytest.raises(
            TypeError,
            match='secret share index and value components must be integers'
        ):
            ck = blindfold.ClusterKey.generate(cluster(3), {'sum': True}, threshold=2)
            ciphertext = blindfold.encrypt(ck, 123)
            ciphertext[0] = (ciphertext[0][0], 'abc')
            blindfold.decrypt(ck, ciphertext)

        with pytest.raises(
            ValueError,
            match=(
                'secret share index components must be distinct positive integers ' +
                'less than the modulus'
            )
        ):
            ck = blindfold.ClusterKey.generate(cluster(3), {'sum': True}, threshold=2)
            ciphertext = blindfold.encrypt(ck, 123)
            ciphertext[0] = (ciphertext[1][0], ciphertext[1][1])
            blindfold.decrypt(ck, ciphertext)

        with pytest.raises(
            ValueError,
            match=(
                'secret share value components must be nonnegative integers ' +
                'less than the modulus'
            )
        ):
            ck = blindfold.ClusterKey.generate(cluster(3), {'sum': True}, threshold=2)
            ciphertext = blindfold.encrypt(ck, 123)
            ciphertext[0] = (ciphertext[0][0], -1)
            blindfold.decrypt(ck, ciphertext)

class TestSecureComputations(TestCase):
    """
    Tests consisting of end-to-end workflows involving secure computation.
    """
    # pylint: disable=protected-access # To access ``SecretKey._modulus`` method.
    def test_workflow_for_secure_sum_mul_with_single_node(self):
        """
        Test secure summation workflow with a cluster that has a single node.
        """
        sk = blindfold.SecretKey.generate(cluster(1), {'sum': True})
        pk = blindfold.PublicKey.generate(sk)

        # Ciphertexts are always represented as hexadecimal strings
        # for portability (due to the large integer sizes required
        # within the Paillier cryptosystem).
        a = pailliers.cipher(int(blindfold.encrypt(pk, 123), 16))
        b = pailliers.cipher(int(blindfold.encrypt(pk, 456), 16))
        c = pailliers.cipher(int(blindfold.encrypt(pk, 789), 16))
        r = hex(
                pailliers.add(
                    pk['material'],
                    pailliers.mul(pk['material'], a, 2),
                    pailliers.mul(pk['material'], b, -1),
                    c
                )
            )

        decrypted = blindfold.decrypt(sk, r)
        self.assertEqual(decrypted, (2 * 123) + (-1 * 456) + 789)

    def test_workflow_for_secure_sum_mul_with_multiple_nodes(self):
        """
        Test secure summation workflow with a cluster that has multiple nodes.
        """
        sk = blindfold.SecretKey.generate(cluster(3), {'sum': True})

        (a0, a1, a2) = blindfold.encrypt(sk, 123)
        (b0, b1, b2) = blindfold.encrypt(sk, 456)
        (c0, c1, c2) = blindfold.encrypt(sk, 789)
        (r0, r1, r2) = (
            ((2 * a0) + (-1 * b0) + c0) % _SECRET_SHARED_SIGNED_INTEGER_MODULUS,
            ((2 * a1) + (-1 * b1) + c1) % _SECRET_SHARED_SIGNED_INTEGER_MODULUS,
            ((2 * a2) + (-1 * b2) + c2) % _SECRET_SHARED_SIGNED_INTEGER_MODULUS
        )

        decrypted = blindfold.decrypt(sk, [r0, r1, r2])
        self.assertEqual(decrypted, (2 * 123) + (-1 * 456) + 789)

    def test_workflow_for_secure_sum_mul_with_multiple_nodes_with_threshold(self):
        """
        Test secure summation workflow with a cluster that has multiple nodes
        (with a threshold).
        """
        sk = blindfold.SecretKey.generate(cluster(3), {'sum': True}, threshold=2)

        xs = [shamirs.share(*s) for s in blindfold.encrypt(sk, 123)]
        ys = [shamirs.share(*s) for s in blindfold.encrypt(sk, 456)]
        zs = [shamirs.share(*s) for s in blindfold.encrypt(sk, 789)]
        rs = shamirs.add(
            shamirs.mul(xs, 2, modulus=_SECRET_SHARED_SIGNED_INTEGER_MODULUS),
            shamirs.mul(ys, -1, modulus=_SECRET_SHARED_SIGNED_INTEGER_MODULUS),
            zs,
            modulus=_SECRET_SHARED_SIGNED_INTEGER_MODULUS
        )

        decrypted = blindfold.decrypt(sk, rs)
        self.assertEqual(decrypted, (2 * 123) + (-1 * 456) + 789)

class TestDocumentFunctions(TestCase):
    """
    Test allotment/unification functions for working with secret-shared documents.
    """
    def test_allot(self):
        """
        Check that a document is converted correctly into secret shares.
        """
        with open('test/test_blindfold.json', 'r', encoding='utf8') as file:
            data = json.load(file)
            allotted = blindfold.allot(data['encrypted'])
            self.assertEqual(allotted, data['allotted'])

    def test_unify(self):
        """
        Check that document secret shares are unified correctly into a single
        document.
        """
        with open('test/test_blindfold.json', 'r', encoding='utf8') as file:
            data = json.load(file)
            unified = blindfold.unify(
                blindfold.ClusterKey.generate(cluster(3), {"store": True}),
                data['shares']["85ce66f5-9049-47cc-a81b-403cd6b49227"],
            )
            self.assertEqual(unified, data['plaintext'])
