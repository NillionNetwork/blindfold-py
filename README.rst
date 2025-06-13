=========
blindfold
=========

Library for working with encrypted data within nilDB queries and replies.

|pypi| |readthedocs| |actions| |coveralls|

.. |pypi| image:: https://badge.fury.io/py/blindfold.svg#
   :target: https://badge.fury.io/py/blindfold
   :alt: PyPI version and link.

.. |readthedocs| image:: https://readthedocs.org/projects/blindfold/badge/?version=latest
   :target: https://blindfold.readthedocs.io/en/latest/?badge=latest
   :alt: Read the Docs documentation status.

.. |actions| image:: https://github.com/nillionnetwork/blindfold-py/workflows/lint-test-cover-docs/badge.svg#
   :target: https://github.com/nillionnetwork/blindfold-py/actions/workflows/lint-test-cover-docs.yml
   :alt: GitHub Actions status.

.. |coveralls| image:: https://coveralls.io/repos/github/NillionNetwork/blindfold-py/badge.svg?branch=main
   :target: https://coveralls.io/github/NillionNetwork/blindfold-py?branch=main
   :alt: Coveralls test coverage summary.

Description and Purpose
-----------------------
This library provides cryptographic operations that are compatible with nilDB nodes and clusters, allowing developers to leverage certain privacy-enhancing technologies (PETs) when storing, operating upon, and retrieving data while working with nilDB. The table below summarizes the functionalities that blindfold makes available.

+-------------+-----------+------------------------------------------+------------------------------+
| Cluster     | Operation | Implementation Details                   | Supported Types              |
+=============+===========+==========================================+==============================+
|             | store     | | XSalsa20 stream cipher                 | | 32-bit signed integer      |
|             |           | | Poly1305 MAC                           | | UTF-8 string (<4097 bytes) |
|             +-----------+------------------------------------------+------------------------------+
| | single    | match     | | deterministic salted hashing           | | 32-bit signed integer      |
| | node      |           | | via SHA-512                            | | UTF-8 string (<4097 bytes) |
|             +-----------+------------------------------------------+------------------------------+
|             | sum       | | non-deterministic Paillier             | 32-bit signed integer        |
|             |           | | with 2048-bit primes                   |                              |
+-------------+-----------+------------------------------------------+------------------------------+
|             | store     | XOR-based secret sharing                 | | 32-bit signed integer      |
|             |           |                                          | | UTF-8 string (<4097 bytes) |
|             +-----------+------------------------------------------+------------------------------+
| | multiple  | match     | | deterministic salted hashing           | | 32-bit signed integer      |
| | nodes     |           | | via SHA-512                            | | UTF-8 string (<4097 bytes) |
|             +-----------+------------------------------------------+------------------------------+
|             | sum       | | additive secret sharing (no threshold) | 32-bit signed integer        |
|             |           | | Shamir secret sharing (with threshold) |                              |
|             |           | | (prime modulus 2^32 + 15 for both)     |                              |
+-------------+-----------+------------------------------------------+------------------------------+

The library supports two categories of keys:

1. ``SecretKey``: Keys in this category support operations within a single node or across multiple nodes. These contain cryptographic material for encryption, decryption, and other operations. Notably, a ``SecretKey`` instance includes blinding masks that a client need not share with the cluster. By using ``SecretKey`` instances a client can retain exclusive access to its data *even if all servers in a cluster collude*. 

2. ``ClusterKey``: Keys in this category represent cluster configurations but do not contain cryptographic material. These can be used only when working with multiple-node clusters. Unlike ``SecretKey`` instances, ``ClusterKey`` instances do not incorporate blinding masks. This means each node in a cluster has access to a raw secret share of the encrypted data and, therefore, the data is only protected if the nodes in the cluster do not collude.

Threshold secret sharing is supported when encrypting in a summation-compatible way for multiple-node clusters. A threshold specifies the minimum number of nodes required to reconstruct the original data. Shamir's secret sharing is employed when encrypting with a threshold value, ensuring that encrypted data can only be decrypted if the required number of shares is available.

Installation and Usage
----------------------
The library can be imported in the usual ways:

.. code-block:: python

    import blindfold
    from blindfold import *

Example: Generating Keys
^^^^^^^^^^^^^^^^^^^^^^^^

The example below generates a ``SecretKey`` instance for a single-node cluster:

.. code-block:: python

    cluster = {'nodes': [{}]}
    secret_key = blindfold.SecretKey.generate(cluster, {'store': True})

The example below generates a ``SecretKey`` instance for a multiple-node (*i.e.*, three-node) cluster with a two-share decryption threshold:

.. code-block:: python

    cluster = {'nodes': [{}, {}, {}]}
    secret_key = blindfold.SecretKey.generate(cluster, {'sum': True}, threshold=2)

Example: Encrypting and Decrypting Data
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The below example encrypts and decrypts a string:

.. code-block:: python

    secret_key = blindfold.SecretKey.generate({'nodes': [{}]}, {'store': True})
    plaintext = "abc"
    ciphertext = blindfold.encrypt(secret_key, plaintext)
    decrypted = blindfold.decrypt(secret_key, ciphertext)
    assert plaintext == decrypted

The below example encrypts and decrypts an integer:

.. code-block:: python

    secret_key = blindfold.SecretKey.generate({'nodes': [{}, {}, {}]}, {'sum': True})
    plaintext = 123
    ciphertext = blindfold.encrypt(secret_key, plaintext)
    decrypted = blindfold.decrypt(secret_key, ciphertext)
    assert plaintext == decrypted

Development
-----------
All installation and development dependencies are fully specified in ``pyproject.toml``. The ``project.optional-dependencies`` object is used to `specify optional requirements <https://peps.python.org/pep-0621>`__ for various development tasks. This makes it possible to specify additional options (such as ``docs``, ``lint``, and so on) when performing installation using `pip <https://pypi.org/project/pip>`__:

.. code-block:: bash

    python -m pip install ".[docs,lint]"

Documentation
^^^^^^^^^^^^^
The documentation can be generated automatically from the source files using `Sphinx <https://www.sphinx-doc.org>`__:

.. code-block:: bash

    python -m pip install ".[docs]"
    cd docs
    sphinx-apidoc -f -E --templatedir=_templates -o _source .. && make html

Testing and Conventions
^^^^^^^^^^^^^^^^^^^^^^^
All unit tests are executed and their coverage is measured when using `pytest <https://docs.pytest.org>`__ (see the ``pyproject.toml`` file for configuration details):

.. code-block:: bash

    python -m pip install ".[test]"
    python -m pytest

The subset of the unit tests included in the module itself and can be executed using `doctest <https://docs.python.org/3/library/doctest.html>`__:

.. code-block:: bash

    python src/blindfold/blindfold.py -v

Style conventions are enforced using `Pylint <https://pylint.readthedocs.io>`__:

.. code-block:: bash

    python -m pip install ".[lint]"
    python -m pylint src/blindfold test/test_blindfold.py

Contributions
^^^^^^^^^^^^^
In order to contribute to the source code, open an issue or submit a pull request on the `GitHub page <https://github.com/nillionnetwork/blindfold-py>`__ for this library.

Versioning
^^^^^^^^^^
The version number format for this library and the changes to the library associated with version number increments conform with `Semantic Versioning 2.0.0 <https://semver.org/#semantic-versioning-200>`__.

Publishing
^^^^^^^^^^
This library can be published as a `package on PyPI <https://pypi.org/project/blindfold>`__ via the GitHub Actions workflow found in ``.github/workflows/build-publish-sign-release.yml`` that follows the `recommendations found in the Python Packaging User Guide <https://packaging.python.org/en/latest/guides/publishing-package-distribution-releases-using-github-actions-ci-cd-workflows/>`__.

Ensure that any links in this README document to the Read the Docs documentation of this package (or its dependencies) have appropriate version numbers. Also ensure that the Read the Docs project for this library has an `automation rule <https://docs.readthedocs.io/en/stable/automation-rules.html>`__ that activates and sets as the default all tagged versions.
