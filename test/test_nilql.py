"""
Test suite containing functional unit tests of exported functions.
"""
from typing import Union
from unittest import TestCase
from importlib import import_module
import functools
import json
import base64
import hashlib
import pytest

import nilql

from src.nilql.nilql import add_shamir_shares

_SECRET_SHARED_SIGNED_INTEGER_MODULUS = (2 ** 32) + 15

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

SECRET_KEY_FOR_SUM_WITH_SINGLE_NODE = nilql.SecretKey.generate(
  {'nodes': [{}]},
  {'sum': True}
)
"""
Precomputed constant that can be reused to reduce running time of tests.
"""

SEED = "012345678901234567890123456789012345678901234567890123456789"
"""
Seed used for tests confirming that key generation from seeds is consistent.
"""

class TestAPI(TestCase):
    """
    Test that the exported classes and functions match the expected API.
    """
    def test_exports(self):
        """
        Check that the module exports the expected classes and functions.
        """
        module = import_module('nilql.nilql')
        self.assertTrue({
            'SecretKey', 'ClusterKey', 'PublicKey',
            'encrypt', 'decrypt', 'allot', 'unify'
        }.issubset(module.__dict__.keys()))

class TestKeys(TestCase):
    """
    Tests of methods of cryptographic key classes.
    """
    def test_key_operations_for_store(self):
        """
        Test key generate, dump, JSONify, and load for store operation.
        """
        for cluster in [{'nodes': [{}]}, {'nodes': [{}, {}, {}]}]:
            sk = nilql.SecretKey.generate(cluster, {'store': True})
            sk_loaded = nilql.SecretKey.load(sk.dump())
            self.assertTrue(isinstance(sk, nilql.SecretKey))
            self.assertEqual(sk_loaded, sk)

            sk_from_json = nilql.SecretKey.load(
                json.loads(json.dumps(sk.dump()))
            )
            self.assertEqual(sk_from_json, sk)

    def test_key_operations_for_match(self):
        """
        Test key generate, dump, JSONify, and load for store operation.
        """
        for cluster in [{'nodes': [{}]}, {'nodes': [{}, {}, {}]}]:
            sk = nilql.SecretKey.generate(cluster, {'match': True})
            sk_loaded = nilql.SecretKey.load(sk.dump())
            self.assertTrue(isinstance(sk, nilql.SecretKey))
            self.assertEqual(sk_loaded, sk)

            sk_from_json = nilql.SecretKey.load(
                json.loads(json.dumps(sk.dump()))
            )
            self.assertEqual(sk_from_json, sk)

    def test_key_operations_for_sum_with_single_node(self):
        """
        Test key generate, dump, JSONify, and load for store operation
        with a single node.
        """
        sk = nilql.SecretKey.generate({'nodes': [{}]}, {'sum': True})
        sk_loaded = nilql.SecretKey.load(sk.dump())
        self.assertTrue(isinstance(sk, nilql.SecretKey))
        self.assertEqual(sk_loaded, sk)

        sk_from_json = nilql.SecretKey.load(
            json.loads(json.dumps(sk.dump()))
        )
        self.assertEqual(sk_from_json, sk)

        pk = nilql.PublicKey.generate(sk)
        pk_loaded = nilql.PublicKey.load(pk.dump())
        self.assertTrue(isinstance(pk, nilql.PublicKey))
        self.assertEqual(pk_loaded, pk)

        pk_from_json = nilql.PublicKey.load(
            json.loads(json.dumps(pk.dump()))
        )
        self.assertEqual(pk_from_json, pk)

    def test_key_operations_for_sum_with_multiple_nodes(self):
        """
        Test key generate, dump, JSONify, and load for sum operation
        with multiple nodes.
        """
        sk = nilql.SecretKey.generate({'nodes': [{}, {}, {}]}, {'sum': True})
        sk_loaded = nilql.SecretKey.load(sk.dump())
        self.assertTrue(isinstance(sk, nilql.SecretKey))
        self.assertEqual(sk_loaded, sk)

        sk_from_json = nilql.SecretKey.load(
            json.loads(json.dumps(sk.dump()))
        )
        self.assertEqual(sk_from_json, sk)

    def test_key_operations_for_redundancy_with_multiple_nodes(self):
        """
        Test key generate, dump, JSONify, and load for redundancy operation
        with multiple nodes.
        """
        sk = nilql.SecretKey.generate({'nodes': [{}, {}, {}]}, {'redundancy': True})
        sk_loaded = nilql.SecretKey.load(sk.dump())
        self.assertTrue(isinstance(sk, nilql.SecretKey))
        self.assertEqual(sk_loaded, sk)

        sk_from_json = nilql.SecretKey.load(
            json.loads(json.dumps(sk.dump()))
        )
        self.assertEqual(sk_from_json, sk)

    def test_key_from_seed_for_store_with_single_node(self):
        """
        Test key generation from seed for store operation with a single node.
        """
        sk_from_seed = nilql.SecretKey.generate({'nodes': [{}]}, {'store': True}, SEED)
        self.assertEqual(
            to_hash_base64(sk_from_seed['material']),
            '2bW6BLeeCTqsCqrijSkBBPGjDb/gzjtGnFZt0nsZP8w='
        )
        sk = nilql.SecretKey.generate({'nodes': [{}]}, {'store': True})
        self.assertNotEqual(
            to_hash_base64(sk['material']),
            '2bW6BLeeCTqsCqrijSkBBPGjDb/gzjtGnFZt0nsZP8w='
        )

    def test_key_from_seed_for_store_with_multiple_nodes(self):
        """
        Test key generation from seed for store operation with multiple nodes.
        """
        sk_from_seed = nilql.SecretKey.generate({'nodes': [{}, {}, {}]}, {'store': True}, SEED)
        self.assertEqual(
            to_hash_base64(sk_from_seed['material']),
            '2bW6BLeeCTqsCqrijSkBBPGjDb/gzjtGnFZt0nsZP8w='
        )
        sk = nilql.SecretKey.generate({'nodes': [{}, {}, {}]}, {'store': True})
        self.assertNotEqual(
            to_hash_base64(sk['material']),
            '2bW6BLeeCTqsCqrijSkBBPGjDb/gzjtGnFZt0nsZP8w='
        )

    def test_key_from_seed_for_match_with_single_node(self):
        """
        Test key generation from seed for match operation with a single node.
        """
        sk_from_seed = nilql.SecretKey.generate({'nodes': [{}]}, {'match': True}, SEED)
        self.assertEqual(
            to_hash_base64(sk_from_seed['material']),
            'qbcFGTOGTPo+vs3EChnVUWk5lnn6L6Cr/DIq8li4H+4='
        )
        sk = nilql.SecretKey.generate({'nodes': [{}]}, {'match': True})
        self.assertNotEqual(
            to_hash_base64(sk['material']),
            'qbcFGTOGTPo+vs3EChnVUWk5lnn6L6Cr/DIq8li4H+4='
        )

    def test_key_from_seed_for_match_with_multiple_nodes(self):
        """
        Test key generation from seed for match operation with a single node.
        """
        sk_from_seed = nilql.SecretKey.generate({'nodes': [{}, {}, {}]}, {'match': True}, SEED)
        self.assertEqual(
            to_hash_base64(sk_from_seed['material']),
            'qbcFGTOGTPo+vs3EChnVUWk5lnn6L6Cr/DIq8li4H+4='
        )
        sk = nilql.SecretKey.generate({'nodes': [{}, {}, {}]}, {'match': True})
        self.assertNotEqual(
            to_hash_base64(sk['material']),
            'qbcFGTOGTPo+vs3EChnVUWk5lnn6L6Cr/DIq8li4H+4='
        )

    def test_key_from_seed_for_sum_with_multiple_nodes(self):
        """
        Test key generation from seed for sum operation with multiple nodes.
        """
        sk_from_seed = nilql.SecretKey.generate({'nodes': [{}, {}, {}]}, {'sum': True}, SEED)
        self.assertEqual(
            to_hash_base64(sk_from_seed['material']),
            'L8RiHNq2EUgt/fDOoUw9QK2NISeUkAkhxHHIPoHPZ84='
        )
        sk = nilql.SecretKey.generate({'nodes': [{}, {}, {}]}, {'sum': True})
        self.assertNotEqual(
            to_hash_base64(sk['material']),
            'L8RiHNq2EUgt/fDOoUw9QK2NISeUkAkhxHHIPoHPZ84='
        )

    def test_key_from_seed_for_redundancy_with_multiple_nodes(self):
        """
        Test key generation from seed for redundancy operation with multiple nodes.
        """
        sk_from_seed = nilql.SecretKey.generate({'nodes': [{}, {}, {}]}, {'redundancy': True}, SEED)
        self.assertEqual(
            to_hash_base64(sk_from_seed['material']),
            'L8RiHNq2EUgt/fDOoUw9QK2NISeUkAkhxHHIPoHPZ84='
        )
        sk = nilql.SecretKey.generate({'nodes': [{}, {}, {}]}, {'redundancy': True})
        self.assertNotEqual(
            to_hash_base64(sk['material']),
            'L8RiHNq2EUgt/fDOoUw9QK2NISeUkAkhxHHIPoHPZ84='
        )

class TestKeysError(TestCase):
    """
    Tests of errors thrown by methods of cryptographic key classes.
    """
    def test_secret_key_generation_errors(self):
        """
        Test errors in secret key generation.
        """
        with pytest.raises(
            ValueError,
            match='valid cluster configuration is required'
        ):
            nilql.SecretKey.generate(123, {'store': True})

        with pytest.raises(
            ValueError,
            match='cluster configuration must contain at least one node'
        ):
            nilql.SecretKey.generate({'nodes': []}, {'store': True})

        with pytest.raises(
            ValueError,
            match='valid operations specification is required'
        ):
            nilql.SecretKey.generate({'nodes': [{}]}, 123)

        with pytest.raises(
            ValueError,
            match='secret key must support exactly one operation'
        ):
            nilql.SecretKey.generate({'nodes': [{}]}, {})

    def test_public_key_generation_errors(self):
        """
        Test errors in public key generation.
        """
        with pytest.raises(
            ValueError,
            match='cannot create public key for supplied secret key'
        ):
            sk = nilql.SecretKey.generate({'nodes':[{}, {}]}, {'sum': True})
            nilql.PublicKey.generate(sk)

class TestFunctions(TestCase):
    """
    Tests of the functional and algebraic properties of encryption/decryption functions.
    """
    def test_encrypt_decrypt_for_store(self):
        """
        Test encryption and decryption for storing.
        """
        for cluster in [{'nodes': [{}]}, {'nodes': [{}, {}, {}]}]:
            sk = nilql.SecretKey.generate(cluster, {'store': True})

            plaintext = 123
            decrypted = nilql.decrypt(sk, nilql.encrypt(sk, plaintext))
            self.assertEqual(decrypted, plaintext)

            plaintext = 'abc'
            decrypted = nilql.decrypt(sk, nilql.encrypt(sk, plaintext))
            self.assertEqual(decrypted, plaintext)

    def test_encrypt_for_match(self):
        """
        Test encryption for matching.
        """
        for cluster in [{'nodes': [{}]}, {'nodes': [{}, {}, {}]}]:
            sk = nilql.SecretKey.generate(cluster, {'match': True})
            ciphertext_one = nilql.encrypt(sk, 123)
            ciphertext_two = nilql.encrypt(sk, 123)
            ciphertext_three = nilql.encrypt(sk, 'abc')
            ciphertext_four = nilql.encrypt(sk, 'abc')
            ciphertext_five = nilql.encrypt(sk, 'ABC')
            self.assertEqual(ciphertext_one, ciphertext_two)
            self.assertEqual(ciphertext_three, ciphertext_four)
            self.assertNotEqual(ciphertext_four, ciphertext_five)

    def test_encrypt_decrypt_of_int_for_sum_single(self):
        """
        Test encryption and decryption for sum operation with a single node.
        """
        sk = SECRET_KEY_FOR_SUM_WITH_SINGLE_NODE
        pk = nilql.PublicKey.generate(sk)
        plaintext = 123
        ciphertext = nilql.encrypt(pk, plaintext)
        decrypted = nilql.decrypt(sk, ciphertext)
        self.assertEqual(decrypted, plaintext)

    def test_encrypt_decrypt_of_int_for_sum_multiple(self):
        """
        Test encryption and decryption for sum operation with multiple nodes.
        """
        sk = nilql.SecretKey.generate({'nodes': [{}, {}, {}]}, {'sum': True})
        plaintext = 123
        ciphertext = nilql.encrypt(sk, plaintext)
        decrypted = nilql.decrypt(sk, ciphertext)
        self.assertEqual(decrypted, plaintext)

    def test_encrypt_decrypt_of_int_for_redundancy_multiple(self):
        """
        Test encryption and decryption for redundancy operation with multiple nodes.
        """
        sk = nilql.SecretKey.generate({'nodes': [{}, {}, {}]}, {'redundancy': True})
        plaintext = 123
        ciphertext = nilql.encrypt(sk, plaintext)
        decrypted = nilql.decrypt(sk, ciphertext)
        self.assertEqual(decrypted, plaintext)

    def test_encrypt_decrypt_of_int_for_redundancy_with_one_failure_multiple(self):
        """
        Test encryption and decryption for redundancy operation with multiple nodes.
        """
        sk = nilql.SecretKey.generate({'nodes': [{}, {}, {}]}, {'redundancy': True})
        plaintext = 123
        ciphertext = nilql.encrypt(sk, plaintext)
        decrypted = nilql.decrypt(sk, ciphertext[1:])
        self.assertEqual(decrypted, plaintext)

class TestCiphertextRepresentations(TestCase):
    """
    Tests of the portable representation of ciphertexts.
    """
    def test_ciphertext_representation_for_store_with_multiple_nodes(self):
        """
        Test that ciphertext representation when storing in a multiple-node cluster.
        """
        cluster = {'nodes': [{}, {}, {}]}
        operations = {'store': True}
        ck = nilql.ClusterKey.generate(cluster, operations)
        plaintext = 'abc'
        ciphertext = ['Ifkz2Q==', '8nqHOQ==', '0uLWgw==']
        decrypted = nilql.decrypt(ck, ciphertext)
        self.assertEqual(decrypted, plaintext)

    def test_ciphertext_representation_for_sum_with_multiple_nodes(self):
        """
        Test that ciphertext representation when storing in a multiple-node cluster.
        """
        cluster = {'nodes': [{}, {}, {}]}
        operations = {'sum': True}
        ck = nilql.ClusterKey.generate(cluster, operations)
        plaintext = 123
        ciphertext = [456, 246, 4294967296 + 15 - 123 - 456]
        decrypted = nilql.decrypt(ck, ciphertext)
        self.assertEqual(decrypted, plaintext)

    def test_ciphertext_representation_for_redundancy_with_multiple_nodes(self):
        """
        Test that ciphertext representation when storing in a multiple-node cluster.
        """
        cluster = {'nodes': [{}, {}, {}]}
        operations = {'redundancy': True}
        ck = nilql.ClusterKey.generate(cluster, operations)
        plaintext = 123
        ciphertext = [[1, 1382717699], [2, 2765435275], [3, 4148152851]]
        decrypted = nilql.decrypt(ck, ciphertext)
        self.assertEqual(decrypted, plaintext)

class TestFunctionsErrors(TestCase):
    """
    Tests verifying that encryption/decryption methods return expected errors.
    """
    def test_encrypt_of_int_for_store_error(self):
        """
        Test range error during encryption of integer for matching.
        """
        with pytest.raises(
            ValueError,
            match='numeric plaintext must be a valid 32-bit signed integer'
        ):
            cluster = {'nodes': [{}]}
            operations = {'store': True}
            sk = nilql.SecretKey.generate(cluster, operations)
            plaintext = 2 ** 32
            nilql.encrypt(sk, plaintext)

    def test_encrypt_of_str_for_store_error(self):
        """
        Test range error during encryption of string for matching.
        """
        with pytest.raises(
            ValueError,
            match='string or binary plaintext must be possible to encode in 4096 bytes or fewer'
        ):
            cluster = {'nodes': [{}]}
            operations = {'store': True}
            sk = nilql.SecretKey.generate(cluster, operations)
            plaintext = 'X' * 4097
            nilql.encrypt(sk, plaintext)

    def test_encrypt_of_int_for_match_error(self):
        """
        Test range error during encryption of integer for matching.
        """
        with pytest.raises(
            ValueError,
            match='numeric plaintext must be a valid 32-bit signed integer'
        ):
            cluster = {'nodes': [{}]}
            operations = {'match': True}
            sk = nilql.SecretKey.generate(cluster, operations)
            plaintext = 2 ** 32
            nilql.encrypt(sk, plaintext)

    def test_encrypt_of_str_for_match_error(self):
        """
        Test range error during encryption of string for matching.
        """
        with pytest.raises(
            ValueError,
            match='string or binary plaintext must be possible to encode in 4096 bytes or fewer'
        ):
            cluster = {'nodes': [{}]}
            operations = {'match': True}
            sk = nilql.SecretKey.generate(cluster, operations)
            plaintext = 'X' * 4097
            nilql.encrypt(sk, plaintext)

    def test_encrypt_of_int_for_sum_error(self):
        """
        Test range error during encryption of integer for matching.
        """
        for cluster in [{'nodes': [{}]}, {'nodes': [{}, {}, {}]}]:
            with pytest.raises(
                ValueError,
                match='numeric plaintext must be a valid 32-bit signed integer'
            ):
                sk = nilql.SecretKey.generate(cluster, {'sum': True})
                ek = nilql.PublicKey.generate(sk) if len(cluster['nodes']) == 1 else sk
                nilql.encrypt(ek, 'abc')

            with pytest.raises(
                ValueError,
                match='numeric plaintext must be a valid 32-bit signed integer'
            ):
                sk = nilql.SecretKey.generate(cluster, {'sum': True})
                ek = nilql.PublicKey.generate(sk) if len(cluster['nodes']) == 1 else sk
                nilql.encrypt(ek, 2 ** 32)

    def test_decrypt_for_store_cluster_size_mismatch_error(self):
        """
        Test errors in decryption for store operation due to cluster size mismatch.
        """
        sk_one = nilql.SecretKey.generate({'nodes': [{}]}, {'store': True})
        sk_two = nilql.SecretKey.generate({'nodes': [{}, {}]}, {'store': True})
        sk_three = nilql.SecretKey.generate({'nodes': [{}, {}, {}]}, {'store': True})
        ciphertext_one = nilql.encrypt(sk_one, 123)
        ciphertext_two = nilql.encrypt(sk_two, 123)

        with pytest.raises(
            ValueError,
            match='secret key requires a valid ciphertext from a single-node cluster'
        ):
            nilql.decrypt(sk_one, ciphertext_two)

        with pytest.raises(
            ValueError,
            match='secret key and ciphertext must have the same associated cluster size'
        ):
            nilql.decrypt(sk_two, ciphertext_one)

        with pytest.raises(
            ValueError,
            match='secret key and ciphertext must have the same associated cluster size'
        ):
            nilql.decrypt(sk_three, ciphertext_two)

    def test_decrypt_for_store_key_mismatch_error(self):
        """
        Test errors in decryption for store operation due to key mismatch.
        """
        with pytest.raises(
            ValueError,
            match='cannot decrypt the supplied ciphertext using the supplied key'
        ):
            sk = nilql.SecretKey.generate({'nodes': [{}]}, {'store': True})
            sk_alt = nilql.SecretKey.generate({'nodes': [{}]}, {'store': True})
            plaintext = 123
            ciphertext = nilql.encrypt(sk, plaintext)
            nilql.decrypt(sk_alt, ciphertext)

class TestSecureComputations(TestCase):
    """
    Tests consisting of end-to-end workflows involving secure computation.
    """
    def test_workflow_for_secure_sum_with_multiple_nodes(self):
        """
        Test secure summation workflow for a cluster that has multiple nodes.
        """
        sk = nilql.SecretKey.generate({'nodes': [{}, {}, {}]}, {'sum': True})
        (a0, b0, c0) = nilql.encrypt(sk, 123)
        (a1, b1, c1) = nilql.encrypt(sk, 456)
        (a2, b2, c2) = nilql.encrypt(sk, 789)
        (a3, b3, c3) = (
            (a0 + a1 + a2) % (2 ** 32 + 15),
            (b0 + b1 + b2) % (2 ** 32 + 15),
            (c0 + c1 + c2) % (2 ** 32 + 15)
        )
        decrypted = nilql.decrypt(sk, [a3, b3, c3])
        self.assertEqual(decrypted, 123 + 456 + 789)

    def test_workflow_for_secure_redundancy_sum_with_multiple_nodes(self):
        """
        Test secure summation workflow for a cluster that has multiple nodes.
        """
        sk = nilql.SecretKey.generate({'nodes': [{}, {}, {}]}, {'redundancy': True})
        (a0, b0, c0) = nilql.encrypt(sk, 123)
        (a1, b1, c1) = nilql.encrypt(sk, 456)
        (a2, b2, c2) = nilql.encrypt(sk, 789)
        (a3, b3, c3) = add_shamir_shares(
            add_shamir_shares([a0, b0, c0], [a1, b1, c1]),
            [a2, b2, c2]
        )
        decrypted = nilql.decrypt(sk, [a3, b3, c3])
        self.assertEqual(decrypted, 123 + 456 + 789)
