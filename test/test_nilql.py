"""
Test suite containing functional unit tests of exported functions.
"""
from unittest import TestCase
from importlib import import_module
import pytest

import nilql

class Test_nilql(TestCase):
    """
    Tests involving published examples demonstrating the use of the library.
    """
    def test_exports(self):
        """
        Check that the module exports the expected classes and functions.
        """
        module = import_module('nilql.nilql')
        self.assertTrue({
            'secret_key', 'public_key', 'encrypt', 'decrypt', 'share'
        }.issubset(module.__dict__.keys()))

    def test_secret_key_creation(self):
        """
        Test key generation.
        """
        cluster = {'nodes': [{}]}
        operations = {'match': True}
        sk = nilql.secret_key(cluster, operations)
        self.assertTrue('value' in sk)

    def test_secret_key_creation_errors(self):
        """
        Test key generation.
        """
        with pytest.raises(
            ValueError,
            match='secret key must support exactly one operation'
        ):
            cluster = {'nodes': [{}]}
            operations = {'match': True, 'sum': True}
            nilql.secret_key(cluster, operations)

        with pytest.raises(
            ValueError,
            match='secret key must support exactly one operation'
        ):
            cluster = {'nodes': [{}]}
            operations = {}
            nilql.secret_key(cluster, operations)

    def test_encrypt_of_int_for_match(self):
        """
        Test encryption of integer for matching.
        """
        cluster = {'nodes': [{}]}
        operations = {'match': True}
        sk = nilql.secret_key(cluster, operations)
        plaintext = 123
        ciphertext = nilql.encrypt(sk, plaintext)
        self.assertTrue(isinstance(ciphertext, str))

    def test_encrypt_of_str_for_match_single(self):
        """
        Test encryption of string for matching.
        """
        sk = nilql.secret_key({'nodes': [{}]}, {'match': True})
        plaintext = 'ABC'
        ciphertext = nilql.encrypt(sk, plaintext)
        self.assertTrue(isinstance(ciphertext, str))

    def test_encrypt_of_str_for_match_multiple(self):
        """
        Test encryption of string for matching.
        """
        sk = nilql.secret_key({'nodes': [{}, {}]}, {'match': True})
        plaintext = 'ABC'
        ciphertext = nilql.encrypt(sk, plaintext)
        self.assertTrue(
            len(ciphertext) == 2
            and
            all(isinstance(c, str) for c in ciphertext)
        )

    def test_encrypt_of_int_for_sum_single(self):
        """
        Test encryption of string for matching.
        """
        sk = nilql.secret_key({'nodes': [{}]}, {'sum': True})
        pk = nilql.public_key(sk)
        plaintext = 123
        ciphertext = nilql.encrypt(pk, plaintext)
        self.assertTrue(isinstance(ciphertext, int))

    def test_decrypt_of_int_for_sum_single(self):
        """
        Test encryption of string for matching.
        """
        sk = nilql.secret_key({'nodes': [{}]}, {'sum': True})
        pk = nilql.public_key(sk)
        plaintext = 123
        ciphertext = nilql.encrypt(pk, plaintext)
        plaintext_ = nilql.decrypt(sk, ciphertext)
        self.assertTrue(plaintext == plaintext_)

    def test_encrypt_of_int_for_match_error(self):
        """
        Test range error during encryption of integer for matching.
        """
        with pytest.raises(
            ValueError,
            match='plaintext must be 32-bit nonnegative integer value'
        ):
            cluster = {'nodes': [{}]}
            operations = {'match': True}
            sk = nilql.secret_key(cluster, operations)
            plaintext = 2**32
            nilql.encrypt(sk, plaintext)

    def test_encrypt_of_str_for_match_error(self):
        """
        Test range error during encryption of string for matching.
        """
        with pytest.raises(
            ValueError,
            match='plaintext string must be possible to encode in 4096 bytes or fewer'
        ):
            cluster = {'nodes': [{}]}
            operations = {'match': True}
            sk = nilql.secret_key(cluster, operations)
            plaintext = 'X' * 4097
            nilql.encrypt(sk, plaintext)
