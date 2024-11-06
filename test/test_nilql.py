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
            'secret_key', 'encrypt'
        }.issubset(module.__dict__.keys()))

    def test_secret_key_creation(self):
        """
        Test key generation.
        """
        cluster = {'decentralized': False}
        operations = {'match': True, 'sum': False}
        sk = nilql.secret_key(cluster, operations)
        self.assertTrue('value' in sk)

    def test_secret_key_creation_errors(self):
        """
        Test key generation.
        """
        with pytest.raises(
            ValueError,
            match='cannot create secret key that supports both match and sum operations'
        ):
            cluster = {'decentralized': False}
            operations = {'match': True, 'sum': True}
            nilql.secret_key(cluster, operations)

        with pytest.raises(
            ValueError,
            match='cannot create secret key that supports no operations'
        ):
            cluster = {'decentralized': False}
            operations = {'match': False, 'sum': False}
            nilql.secret_key(cluster, operations)

    def test_encrypt_of_int_for_match(self):
        """
        Test encryption of integer for matching.
        """
        cluster = {'decentralized': False}
        operations = {'match': True, 'sum': False}
        sk = nilql.secret_key(cluster, operations)
        plaintext = 123
        ciphertext = nilql.encrypt(sk, plaintext)
        self.assertTrue(isinstance(ciphertext, bytes) and len(ciphertext) == 64)

    def test_encrypt_of_str_for_match(self):
        """
        Test encryption of string for matching.
        """
        cluster = {'decentralized': False}
        operations = {'match': True, 'sum': False}
        sk = nilql.secret_key(cluster, operations)
        plaintext = 'ABC'
        ciphertext = nilql.encrypt(sk, plaintext)
        self.assertTrue(isinstance(ciphertext, bytes) and len(ciphertext) == 64)

    def test_encrypt_of_int_for_match_error(self):
        """
        Test range error during encryption of integer for matching.
        """
        with pytest.raises(
            ValueError,
            match='plaintext must be 32-bit nonnegative integer value'
        ):
            cluster = {'decentralized': False}
            operations = {'match': True, 'sum': False}
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
            cluster = {'decentralized': False}
            operations = {'match': True, 'sum': False}
            sk = nilql.secret_key(cluster, operations)
            plaintext = 'X' * 4097
            nilql.encrypt(sk, plaintext)
