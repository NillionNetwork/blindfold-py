"""
Test suite containing functional unit tests of exported functions.
"""
from unittest import TestCase
from importlib import import_module
import json
import pytest

import nilql

secret_key_for_sum_with_one_node = nilql.SecretKey.generate(
  {'nodes': [{}]},
  {'sum': True}
)
"""
Precomputed constants that can be reused to reduce running time of tests.
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
            'SecretKey', 'PublicKey', 'encrypt', 'decrypt', 'allot', 'unify'
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
            self.assertTrue(sk == sk_loaded)

            sk_from_json = nilql.SecretKey.load(
                json.loads(json.dumps(sk.dump()))
            )
            self.assertTrue(sk == sk_from_json)

    def test_key_operations_for_match(self):
        """
        Test key generate, dump, JSONify, and load for store operation.
        """
        for cluster in [{'nodes': [{}]}, {'nodes': [{}, {}, {}]}]:
            sk = nilql.SecretKey.generate(cluster, {'match': True})
            sk_loaded = nilql.SecretKey.load(sk.dump())
            self.assertTrue(isinstance(sk, nilql.SecretKey))
            self.assertTrue(sk == sk_loaded)

            sk_from_json = nilql.SecretKey.load(
                json.loads(json.dumps(sk.dump()))
            )
            self.assertTrue(sk == sk_from_json)

    def test_key_operations_for_sum_with_single_node(self):
        """
        Test key generate, dump, JSONify, and load for store operation
        with a single node.
        """
        sk = nilql.SecretKey.generate({'nodes': [{}]}, {'sum': True})
        sk_loaded = nilql.SecretKey.load(sk.dump())
        self.assertTrue(isinstance(sk, nilql.SecretKey))
        self.assertTrue(sk == sk_loaded)

        sk_from_json = nilql.SecretKey.load(
            json.loads(json.dumps(sk.dump()))
        )
        self.assertTrue(sk == sk_from_json)

        pk = nilql.PublicKey.generate(sk)
        pk_loaded = nilql.PublicKey.load(pk.dump())
        self.assertTrue(isinstance(pk, nilql.PublicKey))
        self.assertTrue(pk == pk_loaded)

        pk_from_json = nilql.PublicKey.load(
            json.loads(json.dumps(pk.dump()))
        )
        self.assertTrue(pk == pk_from_json)

    def test_key_operations_for_sum_with_multiple_nodes(self):
        """
        Test key generate, dump, JSONify, and load for store operation
        with multiple nodes.
        """
        sk = nilql.SecretKey.generate({'nodes': [{}, {}, {}]}, {'sum': True})
        sk_loaded = nilql.SecretKey.load(sk.dump())
        self.assertTrue(isinstance(sk, nilql.SecretKey))
        self.assertTrue(sk == sk_loaded)

        sk_from_json = nilql.SecretKey.load(
            json.loads(json.dumps(sk.dump()))
        )
        self.assertTrue(sk == sk_from_json)

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
            self.assertTrue(plaintext == decrypted)

            plaintext = 'abc'
            decrypted = nilql.decrypt(sk, nilql.encrypt(sk, plaintext))
            self.assertTrue(plaintext == decrypted)

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
            self.assertTrue(ciphertext_one == ciphertext_two)
            self.assertTrue(ciphertext_three == ciphertext_four)
            self.assertTrue(ciphertext_four != ciphertext_five)

    def test_encrypt_decrypt_of_int_for_sum_single(self):
        """
        Test encryption and decryption for sum operation with a single node.
        """
        sk = secret_key_for_sum_with_one_node
        pk = nilql.PublicKey.generate(sk)
        plaintext = 123
        ciphertext = nilql.encrypt(pk, plaintext)
        decrypted = nilql.decrypt(sk, ciphertext)
        self.assertTrue(plaintext == decrypted)

    def test_encrypt_decrypt_of_int_for_sum_multiple(self):
        """
        Test encryption and decryption for sum operation with multiple nodes.
        """
        sk = nilql.SecretKey.generate({'nodes': [{}, {}, {}]}, {'sum': True})
        plaintext = 123
        ciphertext = nilql.encrypt(sk, plaintext)
        decrypted = nilql.decrypt(sk, ciphertext)
        self.assertTrue(plaintext == decrypted)

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
        sk = nilql.SecretKey.generate(cluster, operations)
        plaintext = 'abc'
        ciphertext = ['Ifkz2Q==', '8nqHOQ==', '0uLWgw==']
        decrypted = nilql.decrypt(sk, ciphertext)
        self.assertTrue(plaintext == decrypted)

    def test_ciphertext_representation_for_sum_with_multiple_nodes(self):
        """
        Test that ciphertext representation when storing in a multiple-node cluster.
        """
        cluster = {'nodes': [{}, {}, {}]}
        operations = {'sum': True}
        sk = nilql.SecretKey.generate(cluster, operations)
        plaintext = 123
        ciphertext = [456, 246, 4294967296 - 123 - 456]
        decrypted = nilql.decrypt(sk, ciphertext)
        self.assertTrue(plaintext == decrypted)

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
            plaintext = 2**32
            nilql.encrypt(sk, plaintext)

    def test_encrypt_of_str_for_store_error(self):
        """
        Test range error during encryption of string for matching.
        """
        with pytest.raises(
            ValueError,
            match='string plaintext must be possible to encode in 4096 bytes or fewer'
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
            plaintext = 2**32
            nilql.encrypt(sk, plaintext)

    def test_encrypt_of_str_for_match_error(self):
        """
        Test range error during encryption of string for matching.
        """
        with pytest.raises(
            ValueError,
            match='string plaintext must be possible to encode in 4096 bytes or fewer'
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
            TypeError,
            match='secret key requires a valid ciphertext from a single-node cluster'
        ):
            nilql.decrypt(sk_one, ciphertext_two)

        with pytest.raises(
            TypeError,
            match='secret key requires a valid ciphertext from a multi-node cluster'
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
            match='cannot decrypt supplied ciphertext using the supplied key'
        ):
            sk = nilql.SecretKey.generate({'nodes': [{}]}, {'store': True})
            sk_alt = nilql.SecretKey.generate({'nodes': [{}]}, {'store': True})
            plaintext = 123
            ciphertext = nilql.encrypt(sk, plaintext)
            nilql.decrypt(sk_alt, ciphertext)
