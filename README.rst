=====
nilql
=====

Library for working with encrypted data within nilDB queries and replies.

|pypi| |readthedocs| |actions| |coveralls|

.. |pypi| image:: https://badge.fury.io/py/nilql.svg#
   :target: https://badge.fury.io/py/nilql
   :alt: PyPI version and link.

.. |readthedocs| image:: https://readthedocs.org/projects/nilql/badge/?version=latest
   :target: https://nilql.readthedocs.io/en/latest/?badge=latest
   :alt: Read the Docs documentation status.

.. |actions| image:: https://github.com/nillionnetwork/nilql-py/workflows/lint-test-cover-docs/badge.svg#
   :target: https://github.com/nillionnetwork/nilql-py/actions/workflows/lint-test-cover-docs.yml
   :alt: GitHub Actions status.

.. |coveralls| image:: https://coveralls.io/repos/github/NillionNetwork/nilql-py/badge.svg?branch=main
   :target: https://coveralls.io/github/NillionNetwork/nilql-py?branch=main
   :alt: Coveralls test coverage summary.

Description and Purpose
-----------------------
This library provides cryptographic operations that are compatible with nilDB nodes and clusters, allowing developers to leverage certain privacy-enhancing technologies (PETs) when storing, operating upon, and retrieving data while working with nilDB. The table below summarizes the functionalities that nilQL makes available,

+-------------+------------+------------------------------------+------------------------------------+
| Cluster     | Operation  | Implementation Details             | Supported Types                    |
+=============+============+====================================+====================================+
|             | store      | | XSalsa20 stream cipher           | | 32-bit signed integer            |
|             |            | | Poly1305 MAC                     | | UTF-8 string (<4097 bytes)       |
|             +------------+------------------------------------+------------------------------------+
| | single    | match      | | deterministic salted hashing     | | 32-bit signed integer            |
| | node      |            | | via SHA-512                      | | UTF-8 string (<4097 bytes)       |
|             +------------+------------------------------------+------------------------------------+
|             | sum        | | non-deterministic Paillier       | 32-bit signed integer              |
|             |            | | with 2048-bit primes             |                                    |
+-------------+------------+------------------------------------+------------------------------------+
|             | store      | XOR-based secret sharing           | | 32-bit signed integer            |
|             |            |                                    | | UTF-8 string (<4097 bytes)       |
|             +------------+------------------------------------+------------------------------------+
| | multiple  | match      | | deterministic salted hashing     | | 32-bit signed integer            |
| | nodes     |            | | via SHA-512                      | | UTF-8 string (<4097 bytes)       |
|             +------------+------------------------------------+------------------------------------+
|             | sum        | | additive secret sharing          | 32-bit signed integer              |
|             |            | | with modulus 2^32                |                                    |
+-------------+------------+------------------------------------+------------------------------------+

Installation and Usage
----------------------
The library can be imported in the usual ways:

.. code-block:: python

    import nilql
    from nilql import *

Example
^^^^^^^^
An example workflow that demonstrates the use of the library is presented below:

.. code-block:: python

    import nilql
    cluster = {'nodes': [{}, {}, {}]}
    secret_key = nilql.SecretKey.generate(cluster, {'store': True})
    plaintext = 123
    ciphertext = nilql.encrypt(secret_key, plaintext)
    decrypted = nilql.decrypt(secret_key, ciphertext)
    assert(plaintext == decrypted)

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

    python src/nilql/nilql.py -v

Style conventions are enforced using `Pylint <https://pylint.readthedocs.io>`__:

.. code-block:: bash

    python -m pip install ".[lint]"
    python -m pylint src/nilql test/test_nilql.py

Contributions
^^^^^^^^^^^^^
In order to contribute to the source code, open an issue or submit a pull request on the `GitHub page <https://github.com/nillionnetwork/nilql-py>`__ for this library.

Versioning
^^^^^^^^^^
The version number format for this library and the changes to the library associated with version number increments conform with `Semantic Versioning 2.0.0 <https://semver.org/#semantic-versioning-200>`__.

Publishing
^^^^^^^^^^
This library can be published as a `package on PyPI <https://pypi.org/project/nilql>`__ via the GitHub Actions workflow found in ``.github/workflows/build-publish-sign-release.yml`` that follows the `recommendations found in the Python Packaging User Guide <https://packaging.python.org/en/latest/guides/publishing-package-distribution-releases-using-github-actions-ci-cd-workflows/>`__.

Ensure that any links in this README document to the Read the Docs documentation of this package (or its dependencies) have appropriate version numbers. Also ensure that the Read the Docs project for this library has an `automation rule <https://docs.readthedocs.io/en/stable/automation-rules.html>`__ that activates and sets as the default all tagged versions.
