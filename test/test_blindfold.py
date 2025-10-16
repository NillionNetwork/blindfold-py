"""
Test suite containing functional unit tests of exported functions.
"""
from typing import Union, Set, Sequence
from unittest import TestCase
from importlib import import_module
import functools
import json
import base64
import hashlib
import pytest

import shamirs
import pailliers
import blindfold

# Modify the Paillier secret key length to reduce running time of tests.
blindfold.SecretKey._paillier_key_length = 256 # pylint: disable=protected-access

_SEED = "012345678901234567890123456789012345678901234567890123456789"
"""
Seed used for tests confirming that key generation from seeds is consistent.
"""

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

def cluster(size: int) -> Sequence[Set]:
    """
    Return a cluster of the specified size.
    """
    return {'nodes': [{} for _ in range(size)]}

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
            'SecretKey', 'ClusterKey', 'PublicKey',
            'encrypt', 'decrypt', 'allot', 'unify'
        }.issubset(module.__dict__.keys()))

class TestKeys(TestCase):
    """
    Tests of methods of cryptographic key classes.
    """
    def test_key_operations_for_store(self):
        """
        Test key generate, dump, JSONify, and load for the store operation.
        """
        for (Key, cluster_, threshold) in [
            (blindfold.SecretKey, cluster(1), None),
            (blindfold.SecretKey, cluster(3), None),
            (blindfold.SecretKey, cluster(3), 1),
            (blindfold.SecretKey, cluster(3), 2),
            (blindfold.ClusterKey, cluster(3), None),
            (blindfold.ClusterKey, cluster(3), 1),
            (blindfold.ClusterKey, cluster(3), 2)
        ]:
            key = Key.generate(cluster_, {'store': True}, threshold)
            key_loaded = Key.load(key.dump())
            self.assertTrue(isinstance(key, Key))
            self.assertEqual(key_loaded, key)

            key_from_json = Key.load(json.loads(json.dumps(key.dump())))
            self.assertEqual(key_from_json, key)

    def test_key_operations_for_match(self):
        """
        Test key generate, dump, JSONify, and load methods for the match operation.
        """
        for (Key, cluster_) in [
            (blindfold.SecretKey, cluster(1)),
            (blindfold.SecretKey, cluster(3)),
            (blindfold.ClusterKey, cluster(3)),
        ]:
            key = Key.generate(cluster_, {'match': True})
            key_loaded = Key.load(key.dump())
            self.assertTrue(isinstance(key, Key))
            self.assertEqual(key_loaded, key)

            key_from_json = Key.load(json.loads(json.dumps(key.dump())))
            self.assertEqual(key_from_json, key)

    def test_key_operations_for_sum_with_single_node(self):
        """
        Test key generate, dump, JSONify, and load methods for the sum operation
        with a single node.
        """
        sk = blindfold.SecretKey.generate(cluster(1), {'sum': True})
        sk_loaded = blindfold.SecretKey.load(sk.dump())
        self.assertTrue(isinstance(sk, blindfold.SecretKey))
        self.assertEqual(sk_loaded, sk)

        sk_from_json = blindfold.SecretKey.load(json.loads(json.dumps(sk.dump())))
        self.assertEqual(sk_from_json, sk)

        pk = blindfold.PublicKey.generate(sk)
        pk_loaded = blindfold.PublicKey.load(pk.dump())
        self.assertTrue(isinstance(pk, blindfold.PublicKey))
        self.assertEqual(pk_loaded, pk)

        pk_from_json = blindfold.PublicKey.load(json.loads(json.dumps(pk.dump())))
        self.assertEqual(pk_from_json, pk)

    def test_key_operations_for_sum_with_multiple_nodes(self):
        """
        Test key generate, dump, JSONify, and load methods for the sum operation
        with multiple (without/with threshold) nodes.
        """
        for (Key, cluster_, threshold) in [
            (blindfold.SecretKey, cluster(3), None),
            (blindfold.SecretKey, cluster(3), 2),
            (blindfold.ClusterKey, cluster(3), None),
            (blindfold.ClusterKey, cluster(3), 2)
        ]:
            key = Key.generate(cluster_, {'sum': True}, threshold)
            key_loaded = Key.load(key.dump())
            self.assertTrue(isinstance(key, Key))
            self.assertEqual(key_loaded, key)

            key_from_json = Key.load(json.loads(json.dumps(key.dump())))
            self.assertEqual(key_from_json, key)

    def test_secret_key_from_seed_for_store(self):
        """
        Test key generation from seed for store operation both with a single
        node and multiple (without/with threshold) nodes.
        """
        for (cluster_, threshold) in [
            (cluster(1), None),
            (cluster(3), 1),
            (cluster(3), 2),
            (cluster(3), 3)
        ]:
            sk_from_seed = blindfold.SecretKey.generate(
                cluster_,
                {'store': True},
                threshold,
                _SEED
            )
            self.assertEqual(
                to_hash_base64(sk_from_seed['material']),
                '2bW6BLeeCTqsCqrijSkBBPGjDb/gzjtGnFZt0nsZP8w='
            )
            sk = blindfold.SecretKey.generate(
                cluster_,
                {'store': True},
                threshold
            )
            self.assertNotEqual(
                to_hash_base64(sk['material']),
                '2bW6BLeeCTqsCqrijSkBBPGjDb/gzjtGnFZt0nsZP8w='
            )

    def test_secret_key_from_seed_for_match(self):
        """
        Test key generation from seed for match operation with a single node.
        """
        for cluster_ in [cluster(1), cluster(3)]:
            sk_from_seed = blindfold.SecretKey.generate(cluster_, {'match': True}, seed=_SEED)
            self.assertEqual(
                to_hash_base64(sk_from_seed['material']),
                'qbcFGTOGTPo+vs3EChnVUWk5lnn6L6Cr/DIq8li4H+4='
            )
            sk = blindfold.SecretKey.generate(cluster_, {'match': True})
            self.assertNotEqual(
                to_hash_base64(sk['material']),
                'qbcFGTOGTPo+vs3EChnVUWk5lnn6L6Cr/DIq8li4H+4='
            )

    def test_secret_key_from_seed_for_sum_with_multiple_nodes(self):
        """
        Test key generation from seed for the sum operation with multiple
        (without/with a threshold) nodes.
        """
        for threshold in [None, 1, 2, 3]:
            sk_from_seed = blindfold.SecretKey.generate(
                cluster(3),
                {'sum': True},
                threshold,
                seed=_SEED
            )
            self.assertEqual(
                to_hash_base64(sk_from_seed['material']),
                'L8RiHNq2EUgt/fDOoUw9QK2NISeUkAkhxHHIPoHPZ84='
            )
            sk = blindfold.SecretKey.generate(cluster(3), {'sum': True}, threshold)
            self.assertNotEqual(
                to_hash_base64(sk['material']),
                'L8RiHNq2EUgt/fDOoUw9QK2NISeUkAkhxHHIPoHPZ84='
            )

class TestKeysError(TestCase):
    """
    Tests of errors thrown by methods of cryptographic key classes.
    """
    def test_secret_key_and_cluster_key_generation_errors(self):
        """
        Test errors in secret key generation.
        """
        for Key in [
            blindfold.SecretKey,
            blindfold.ClusterKey
        ]:
            with pytest.raises(
                ValueError,
                match='valid cluster configuration is required'
            ):
                Key.generate(123, {'store': True})

            with pytest.raises(
                ValueError,
                match='cluster configuration must contain at least one node'
            ):
                Key.generate({'nodes': []}, {'store': True})

            with pytest.raises(
                ValueError,
                match='valid operations specification is required'
            ):
                Key.generate(cluster(1), 123)

            with pytest.raises(
                ValueError,
                match='secret key must support exactly one operation'
            ):
                Key.generate(cluster(1), {})

            with pytest.raises(
                ValueError,
                match='threshold must be a positive integer not larger than the cluster size'
            ):
                Key.generate(cluster(2), {'store': True}, threshold=0)

            with pytest.raises(
                ValueError,
                match='threshold must be a positive integer not larger than the cluster size'
            ):
                Key.generate(cluster(2), {'store': True}, threshold=3)

            with pytest.raises(
                ValueError,
                match='thresholds are only supported for multiple-node clusters'
            ):
                Key.generate(cluster(1), {'store': True}, threshold=1)

            with pytest.raises(
                ValueError,
                match='thresholds are only supported for the store and sum operations'
            ):
                Key.generate(cluster(2), {'match': True}, threshold=1)

    def test_public_key_generation_errors(self):
        """
        Test errors in public key generation.
        """
        with pytest.raises(
            ValueError,
            match='cannot create public key for supplied secret key'
        ):
            sk = blindfold.SecretKey.generate(cluster(2), {'sum': True})
            blindfold.PublicKey.generate(sk)

class TestFunctions(TestCase):
    """
    Tests of the functional and algebraic properties of encryption/decryption functions.
    """
    def test_encrypt_decrypt_for_store(self):
        """
        Test encryption and decryption for the store operation with single/multiple
        nodes and without/with threshold (including subcluster combinations).
        """
        for (cluster_, threshold, combinations) in [
            (cluster(1), None, [{0}]),
            (cluster(3), None, [{0, 1, 2}]),

            # Scenarios with thresholds but no missing shares.
            (cluster(3), 1, [{0, 1, 2}]),
            (cluster(3), 2, [{0, 1, 2}]),
            (cluster(3), 3, [{0, 1, 2}]),

            # Scenarios with thresholds and missing shares.
            (cluster(3), 1, [{0}, {1}, {2}, {1, 2}, {0, 1}, {0, 2}]),
            (cluster(3), 2, [{1, 2}, {0, 1}, {0, 2}]),
            (cluster(4), 2, [{0, 1}, {1, 2}, {2, 3}, {0, 2}, {1, 3}, {0, 3}, {0, 1, 2}]),
            (cluster(4), 3, [{0, 1, 2}, {1, 2, 3}, {0, 1, 3}, {0, 2, 3}]),
            (cluster(5), 2, [{0, 4}, {1, 3}, {0, 2}, {2, 3}]),
            (cluster(5), 3, [{0, 1, 4}, {1, 3, 4}, {0, 2, 4}, {1, 2, 3}, {1, 2, 3, 4}]),
            (cluster(5), 4, [{0, 1, 4, 2}, {0, 1, 3, 4}])
        ]:
            for Key in ( # Test cluster keys only for multiple-node clusters.
                [blindfold.SecretKey] +
                [blindfold.ClusterKey] if len(cluster_['nodes']) > 1 else []
            ):
                key = Key.generate(cluster_, {'store': True}, threshold)
                for plaintext in (
                    [-(2 ** 31), -123, 0, 123, (2 ** 31) - 1] +
                    ['', 'abc', 'X' * 4096] # Last item has maximum plaintext length.
                ):
                    ciphertext = blindfold.encrypt(key, plaintext)
                    for combination in combinations:
                        decrypted = blindfold.decrypt(
                            key,
                            (
                                ciphertext
                                if threshold is None else
                                [ciphertext[i] for i in combination]
                            )
                        )
                        self.assertEqual(decrypted, plaintext)

    def test_encrypt_for_match(self):
        """
        Test encryption for the match operation.
        """
        for cluster_ in [cluster(1), cluster(3)]:
            sk = blindfold.SecretKey.generate(cluster_, {'match': True})
            ciphertext_one = blindfold.encrypt(sk, 123)
            ciphertext_two = blindfold.encrypt(sk, 123)
            ciphertext_three = blindfold.encrypt(sk, 'abc')
            ciphertext_four = blindfold.encrypt(sk, 'abc')
            ciphertext_five = blindfold.encrypt(sk, 'ABC')
            self.assertEqual(ciphertext_one, ciphertext_two)
            self.assertEqual(ciphertext_three, ciphertext_four)
            self.assertNotEqual(ciphertext_four, ciphertext_five)

    def test_encrypt_decrypt_for_sum_with_single_node(self):
        """
        Test encryption and decryption for the sum operation with a single node.
        """
        sk = blindfold.SecretKey.generate(cluster(1), {'sum': True})
        pk = blindfold.PublicKey.generate(sk)
        for plaintext in [-(2 ** 31), -123, 0, 123, (2 ** 31) - 1]:
            ciphertext = blindfold.encrypt(pk, plaintext)
            decrypted = blindfold.decrypt(sk, ciphertext)
            self.assertEqual(decrypted, plaintext)

    def test_encrypt_decrypt_for_sum_with_multiple_nodes(self):
        """
        Test encryption and decryption for the sum operation with single/multiple
        nodes and without/with threshold (including subcluster combinations).
        """
        for (cluster_, threshold, combinations) in [
            (cluster(3), None, [{0, 1, 2}]),

            # Scenarios with thresholds but no missing shares.
            (cluster(3), 1, [{0, 1, 2}]),
            (cluster(3), 2, [{0, 1, 2}]),
            (cluster(3), 3, [{0, 1, 2}]),

            # Scenarios with thresholds and missing shares.
            (cluster(3), 1, [{0}, {1}, {2}, {1, 2}, {0, 1}, {0, 2}]),
            (cluster(3), 2, [{0, 1}, {1, 2}, {0, 2}]),
            (cluster(4), 2, [{0, 1}, {1, 2}, {2, 3}, {0, 2}, {1, 3}, {0, 3}, {0, 1, 2}]),
            (cluster(4), 3, [{0, 1, 2}, {1, 2, 3}, {0, 1, 3}, {0, 2, 3}]),
            (cluster(5), 2, [{0, 4}, {1, 3}, {0, 2}, {2, 3}]),
            (cluster(5), 3, [{0, 1, 4}, {1, 3, 4}, {0, 2, 4}, {1, 2, 3}, {1, 2, 3, 4}]),
            (cluster(5), 4, [{0, 1, 4, 2}, {0, 1, 3, 4}])
        ]:
            for Key in [
                blindfold.SecretKey,
                blindfold.ClusterKey
            ]:
                key = Key.generate(cluster_, {'sum': True}, threshold)
                for plaintext in [-(2 ** 31), -123, 0, 123, (2 ** 31) - 1]:
                    ciphertext = blindfold.encrypt(key, plaintext)
                    for combination in combinations:
                        decrypted = blindfold.decrypt(
                            key,
                            [ciphertext[i] for i in combination]
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
            'material': 'SnC3NBHUXwCbvpayZy9mNZqM3OZa7DlbF9ocHM4nT8Q=',
            'cluster': {'nodes': [{}]}, 'operations': {'store': True}
        })
        self.assertEqual(
            sk,
            blindfold.SecretKey.generate(cluster(1), {'store': True}, seed=_SEED)
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
            'cluster': {'nodes': [{}, {}, {}]},
            'operations': {'store': True}
        })
        self.assertEqual(ck, blindfold.ClusterKey.generate(cluster(3), {'store': True}))
        ciphertext = ['Ifkz2Q==', '8nqHOQ==', '0uLWgw==']
        self.assertEqual(blindfold.decrypt(ck, ciphertext), plaintext)

        sk = blindfold.SecretKey.load({
            'material': 'SnC3NBHUXwCbvpayZy9mNZqM3OZa7DlbF9ocHM4nT8Q=',
            'cluster': {'nodes': [{}, {}, {}]},
            'operations': {'store': True}
        })
        self.assertEqual(
            sk,
            blindfold.SecretKey.generate(cluster(3), {'store': True}, seed=_SEED)
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
            'cluster': {'nodes': [{}, {}, {}]},
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
            'material': 'SnC3NBHUXwCbvpayZy9mNZqM3OZa7DlbF9ocHM4nT8Q=',
            'cluster': {'nodes': [{}, {}, {}]},
            'operations': {'store': True},
            'threshold': 2
        })
        self.assertEqual(
            sk,
            blindfold.SecretKey.generate(cluster(3), {'store': True}, threshold=2, seed=_SEED)
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
            },
            'cluster': {'nodes': [{}]},
            'operations': {'sum': True}
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
            'cluster': {'nodes': [{}, {}, {}]},
            'operations': {'sum': True}
        })
        self.assertEqual(ck, blindfold.ClusterKey.generate(cluster(3), {'sum': True}))
        ciphertext = [456, 246, 4294967296 + 15 - 123 - 456]
        self.assertEqual(blindfold.decrypt(ck, ciphertext), plaintext)

        sk = blindfold.SecretKey.load({
            'material': [2677312581, 321207441, 2186773557],
            'cluster': {'nodes': [{}, {}, {}]},
            'operations': {'sum': True}
        })
        self.assertEqual(sk, blindfold.SecretKey.generate(cluster(3), {'sum': True}, seed=_SEED))
        ciphertext = [3874430451, 3116877887, 2318008363]
        self.assertEqual(blindfold.decrypt(sk, ciphertext), plaintext)

    def test_representations_for_sum_with_multiple_nodes_with_threshold(self):
        """
        Confirm ability to handle representation of keys and ciphertexts for
        summation (with threshold) in a multiple-node cluster.
        """
        plaintext = 123

        ck = blindfold.ClusterKey.load({
            'cluster': {'nodes': [{}, {}, {}]},
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
            'material': [2677312581, 321207441, 2186773557],
            'cluster': {'nodes': [{}, {}, {}]},
            'operations': {'sum': True},
            'threshold': 2
        })
        self.assertEqual(
            sk,
            blindfold.SecretKey.generate(cluster(3), {'sum': True}, threshold=2, seed=_SEED)
        )
        ciphertext = [(1, 177325002), (2, 986000561), (3, 2621193783)]
        self.assertEqual(blindfold.decrypt(sk, ciphertext), plaintext)

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
            operations = {'store': True}
            sk = blindfold.SecretKey.generate(cluster(1), operations)
            plaintext = 2 ** 32
            blindfold.encrypt(sk, plaintext)

    def test_encrypt_of_str_for_store_error(self):
        """
        Test range error during encryption of string for matching.
        """
        with pytest.raises(
            ValueError,
            match='string or binary plaintext must be possible to encode in 4096 bytes or fewer'
        ):
            operations = {'store': True}
            sk = blindfold.SecretKey.generate(cluster(1), operations)
            plaintext = 'X' * 4097
            blindfold.encrypt(sk, plaintext)

    def test_encrypt_of_int_for_match_error(self):
        """
        Test range error during encryption of integer for matching.
        """
        with pytest.raises(
            ValueError,
            match='numeric plaintext must be a valid 32-bit signed integer'
        ):
            operations = {'match': True}
            sk = blindfold.SecretKey.generate(cluster(1), operations)
            plaintext = 2 ** 32
            blindfold.encrypt(sk, plaintext)

    def test_encrypt_of_str_for_match_error(self):
        """
        Test range error during encryption of string for matching.
        """
        with pytest.raises(
            ValueError,
            match='string or binary plaintext must be possible to encode in 4096 bytes or fewer'
        ):
            operations = {'match': True}
            sk = blindfold.SecretKey.generate(cluster(1), operations)
            plaintext = 'X' * 4097
            blindfold.encrypt(sk, plaintext)

    def test_encrypt_of_int_for_sum_error(self):
        """
        Test range error during encryption of integer for matching.
        """
        for cluster_ in [cluster(1), cluster(3)]:
            with pytest.raises(
                TypeError,
                match='plaintext to encrypt for sum operation must be an integer'
            ):
                sk = blindfold.SecretKey.generate(cluster_, {'sum': True})
                ek = blindfold.PublicKey.generate(sk) if len(cluster_['nodes']) == 1 else sk
                blindfold.encrypt(ek, 'abc')

            with pytest.raises(
                ValueError,
                match='numeric plaintext must be a valid 32-bit signed integer'
            ):
                sk = blindfold.SecretKey.generate(cluster_, {'sum': True})
                ek = blindfold.PublicKey.generate(sk) if len(cluster_['nodes']) == 1 else sk
                blindfold.encrypt(ek, 2 ** 32)

    def test_decrypt_for_store_cluster_size_mismatch_error(self):
        """
        Test errors in decryption for store operation due to cluster size mismatch.
        """
        sk_one = blindfold.SecretKey.generate(cluster(1), {'store': True})
        sk_two = blindfold.SecretKey.generate(cluster(2), {'store': True})
        sk_three = blindfold.SecretKey.generate(cluster(3), {'store': True})
        ciphertext_one = blindfold.encrypt(sk_one, 123)
        ciphertext_two = blindfold.encrypt(sk_two, 123)

        with pytest.raises(
            ValueError,
            match='secret key requires a valid ciphertext from a single-node cluster'
        ):
            blindfold.decrypt(sk_one, ciphertext_two)

        with pytest.raises(
            ValueError,
            match='secret key requires a valid ciphertext from a multiple-node cluster'
        ):
            blindfold.decrypt(sk_two, ciphertext_one)

        with pytest.raises(
            ValueError,
            match='ciphertext must have enough shares for cluster size or threshold'
        ):
            blindfold.decrypt(sk_three, ciphertext_two)

    def test_decrypt_for_store_key_mismatch_error(self):
        """
        Test errors in decryption for store operation due to key mismatch.
        """
        with pytest.raises(
            ValueError,
            match='cannot decrypt the supplied ciphertext using the supplied key'
        ):
            sk = blindfold.SecretKey.generate(cluster(1), {'store': True})
            sk_alt = blindfold.SecretKey.generate(cluster(1), {'store': True})
            plaintext = 123
            ciphertext = blindfold.encrypt(sk, plaintext)
            blindfold.decrypt(sk_alt, ciphertext)

class TestSecureComputations(TestCase):
    """
    Tests consisting of end-to-end workflows involving secure computation.
    """
    # pylint: disable=protected-access # To access ``SecretKey._modulus`` method.
    def test_workflow_for_secure_sum_mul_with_single_node(self):
        """
        Test secure summation workflow for a cluster that has a single node.
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
        Test secure summation workflow for a cluster that has multiple nodes.
        """
        sk = blindfold.SecretKey.generate(cluster(3), {'sum': True})

        (a0, a1, a2) = blindfold.encrypt(sk, 123)
        (b0, b1, b2) = blindfold.encrypt(sk, 456)
        (c0, c1, c2) = blindfold.encrypt(sk, 789)
        (r0, r1, r2) = (
            ((2 * a0) + (-1 * b0) + c0) % sk._modulus(),
            ((2 * a1) + (-1 * b1) + c1) % sk._modulus(),
            ((2 * a2) + (-1 * b2) + c2) % sk._modulus()
        )

        decrypted = blindfold.decrypt(sk, [r0, r1, r2])
        self.assertEqual(decrypted, (2 * 123) + (-1 * 456) + 789)

    def test_workflow_for_secure_sum_mul_with_multiple_nodes_with_threshold(self):
        """
        Test secure summation workflow with a threshold for a cluster that has
        multiple nodes.
        """
        sk = blindfold.SecretKey.generate(cluster(3), {'sum': True}, threshold=2)

        xs = [shamirs.share(*s) for s in blindfold.encrypt(sk, 123)]
        ys = [shamirs.share(*s) for s in blindfold.encrypt(sk, 456)]
        zs = [shamirs.share(*s) for s in blindfold.encrypt(sk, 789)]
        rs = shamirs.add(
            shamirs.mul(xs, 2, modulus=sk._modulus()),
            shamirs.mul(ys, -1, modulus=sk._modulus()),
            zs,
            modulus=sk._modulus()
        )

        decrypted = blindfold.decrypt(sk, rs)
        self.assertEqual(decrypted, (2 * 123) + (-1 * 456) + 789)

class TestDocumentFunctions(TestCase):
    """
    Test the allot and unify functions for working with secret-shared documents.
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
