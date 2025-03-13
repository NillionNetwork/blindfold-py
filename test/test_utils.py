import json
from unittest import TestCase

import nilql

CLUSTER_KEY_FOR_STORE_WITH_THREE_NODES = nilql.ClusterKey.generate(
    {"nodes": [{}] * 3}, {"store": True}
)

with open("test/testdata/cluster_encrypted_data.json", "r") as f:
    cluster_encrypted_data = json.load(f)

with open("test/testdata/expected_allot_split.json", "r") as f:
    expected_allot_split = json.load(f)

with open("test/testdata/shares.json", "r") as f:
    shares_from_nildb = json.load(f)

with open("test/testdata/plaintext.json", "r") as f:
    plaintext_record = json.load(f)


class TestUtils(TestCase):
    """
    Test that the allot and unify functions complete as expected.
    """

    def test_allot(self):
        """
        Check that the module properly restructures the inputs
        """
        allot_split_for_N_nodes = nilql.allot(cluster_encrypted_data)
        self.assertEqual(allot_split_for_N_nodes, expected_allot_split)

    def test_unify(self):
        """
        Check that the module properly restores the shares
        """
        decrypted = nilql.unify(
            CLUSTER_KEY_FOR_STORE_WITH_THREE_NODES,
            shares_from_nildb["85ce66f5-9049-47cc-a81b-403cd6b49227"],
        )

        self.assertEqual(decrypted, plaintext_record)
