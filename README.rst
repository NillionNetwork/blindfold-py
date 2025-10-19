=========
blindfold
=========

Library for working with encrypted data within `nilDB <https://docs.nillion.com/build/nildb>`__ queries and replies.

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

Purpose
-------
This library provides cryptographic operations that are compatible with `nilDB <https://docs.nillion.com/build/nildb>`__ nodes and clusters, allowing developers to leverage certain privacy-enhancing technologies (PETs) when storing, operating upon, and retrieving data while working with nilDB.

Installation and Usage
----------------------
This library is available as a `package on PyPI <https://pypi.org/project/blindfold>`__:

.. code-block:: bash

    python -m pip install blindfold

The library can be imported in the usual manner:

.. code-block:: python

    import blindfold
    from blindfold import *

Supported Protocols
^^^^^^^^^^^^^^^^^^^
The table below summarizes the data encryption protocols that this library makes available. The table also specifies which operation involving ciphertexts is supported by each protocol. Note that support for summation of encrypted data implies support both for subtraction of encrypted values from other encrypted values and for multiplication of encrypted data by a plaintext signed integer scalar.

+-------------+-----------+--------------------------------------------+------------------------------+
| Cluster     | Operation | Implementation Details                     | Supported Types              |
+=============+===========+============================================+==============================+
|             | store     | XSalsa20 stream cipher and Poly1305 MAC    | | 32-bit signed integer or   |
|             |           |                                            | | UTF-8 string (<4097 bytes) |
|             +-----------+--------------------------------------------+------------------------------+
| | single    | match     | deterministic salted hashing (SHA-512)     | | 32-bit signed integer or   |
| | node      |           |                                            | | UTF-8 string (<4097 bytes) |
|             +-----------+--------------------------------------------+------------------------------+
|             | sum       | Paillier cryptosystem (2048-bit primes)    | 32-bit signed integer        |
|             |           |                                            |                              |
+-------------+-----------+--------------------------------------------+------------------------------+
|             | store     | | XOR-based secret sharing or              | | 32-bit signed integer or   |
|             |           | | Shamir's secret sharing (with threshold) | | UTF-8 string (<4097 bytes) |
|             +-----------+--------------------------------------------+------------------------------+
| | multiple  | match     | deterministic salted hashing (SHA-512)     | | 32-bit signed integer or   |
| | nodes     |           |                                            | | UTF-8 string (<4097 bytes) |
|             +-----------+--------------------------------------------+------------------------------+
|             | sum       | | additive secret sharing or               | 32-bit signed integer        |
|             |           | | Shamir's secret sharing (with threshold) |                              |
+-------------+-----------+--------------------------------------------+------------------------------+

Categories of Encryption Keys
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. |SecretKey| replace:: ``SecretKey``
.. _SecretKey: https://blindfold.readthedocs.io/en/0.1.0/_source/blindfold.html#blindfold.blindfold.SecretKey

.. |ClusterKey| replace:: ``ClusterKey``
.. _ClusterKey: https://blindfold.readthedocs.io/en/0.1.0/_source/blindfold.html#blindfold.blindfold.ClusterKey

.. |PublicKey| replace:: ``PublicKey``
.. _PublicKey: https://blindfold.readthedocs.io/en/0.1.0/_source/blindfold.html#blindfold.blindfold.PublicKey

This library uses the attributes of a key object (instantiated using an appropriate constructor) to determine what protocol to use when encrypting a plaintext. Keys fall into one of two categories:

1. |SecretKey|_/|PublicKey|_: Keys in this category support operations within a single node or across multiple nodes. These contain cryptographic material for encryption, decryption, and other operations. Notably, a |SecretKey|_ instance includes cryptographic material (such as symmetric keys) that a client should not share with the cluster. Using a |SecretKey|_ instance helps ensure that a client can retain exclusive access to a plaintext *even if all servers in a cluster collude*. 

2. |ClusterKey|_: Keys in this category represent cluster configurations but do not contain cryptographic material. These can be used only when working with multiple-node clusters. Unlike |SecretKey|_ and |PublicKey|_ instances, |ClusterKey|_ instances do not incorporate additional cryptographic material. This means each node in a cluster has access to a raw secret share of the plaintext and, therefore, the plaintext is only protected if the nodes in the cluster do not collude.

More Details on Secret Sharing
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
When working with multiple-node clusters and encrypting data for compatibility with the store operation using a |SecretKey|_ instance, each secret share is encrypted  using a symmetric key (the material for which is stored inside the |SecretKey|_ instance). However, when encrypting for compatibility with the sum operation (without or with a threshold), each secret share is instead *masked* via multiplication with a secret nonzero scalar (with one secret scalar per node stored in the |SecretKey|_ instance). While this ensures that the secret-shared plaintexts encrypted in this way are compatible with addition and scalar multiplication, users should use this feature only if they have a thorough understanding of the privacy and security trade-offs involved.

Threshold secret sharing is supported when encrypting for multiple-node clusters (with the exception of encrypting for compatibility with the match operation). A threshold specifies the minimum number of nodes required to reconstruct the original data. Shamir's secret sharing is employed when encrypting with support for a threshold, ensuring that encrypted data can only be decrypted if the required number of shares is available.

Examples
^^^^^^^^
Extensive documentation, examples, and developer tools that can assist anyone interested in using this library are available in the `Nillion Docs on Private Storage with nilDB <https://docs.nillion.com/build/private-storage/overview>`__. Numerous examples can also be found within docstrings in the library's `source code <https://blindfold.readthedocs.io/en/0.1.0/_source/blindfold.html>`__ and in its `testing script <https://blindfold.readthedocs.io/en/0.1.0/_source/test_blindfold.html>`__.

The example below generates a |SecretKey|_ instance for encrypting data to be stored within a single-node cluster:

.. code-block:: python

    >>> cluster = {'nodes': [{}]}
    >>> secret_key = blindfold.SecretKey.generate(cluster, {'store': True})

The example below generates a |ClusterKey|_ instance for converting data into secret shares (such that summation on secret-shared data is supported) to be stored in a three-node cluster with a two-share decryption threshold:

.. code-block:: python

    >>> cluster = {'nodes': [{}, {}, {}]}
    >>> cluster_key = blindfold.ClusterKey.generate(cluster, {'sum': True}, threshold=2)

The example below encrypts and decrypts a string:

.. code-block:: python

    >>> secret_key = blindfold.SecretKey.generate({'nodes': [{}]}, {'store': True})
    >>> plaintext = 'abc'
    >>> ciphertext = blindfold.encrypt(secret_key, plaintext)
    >>> decrypted = blindfold.decrypt(secret_key, ciphertext)
    >>> assert plaintext == decrypted

The example below generates three secret shares of an integer and then reconstructs that integer using only two of the shares: 

.. code-block:: python

    >>> secret_key = blindfold.SecretKey.generate({
    ...     'nodes': [{}, {}, {}]},
    ...     {'sum': True},
    ...     threshold=2
    ... )
    >>> plaintext = 123
    >>> (share_a, share_b, share_c) = blindfold.encrypt(secret_key, plaintext)
    >>> decrypted = blindfold.decrypt(secret_key, [share_a, share_c])
    >>> assert plaintext == decrypted

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

Ensure that the correct version number appears in ``pyproject.toml``, and that any links in this README document to the Read the Docs documentation of this package (or its dependencies) have appropriate version numbers. Also ensure that the Read the Docs project for this library has an `automation rule <https://docs.readthedocs.io/en/stable/automation-rules.html>`__ that activates and sets as the default all tagged versions.

To publish the package, create and push a tag for the version being published (replacing ``?.?.?`` with the version number):

.. code-block:: bash

    git tag ?.?.?
    git push origin ?.?.?
